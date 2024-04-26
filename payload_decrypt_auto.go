package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
)

var (
	done = make(chan struct{})
)

var OutputFilePath string

var (

	// "This program cannot be run in DOS mode"
	signatureBytes = []byte{
		0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E,
		0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F,
		0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65,
	}
	maxSignatureBytes = 38
	chunkSize         = 4
	maxChunkCount     = 90
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: payload_decrypt_auto.exe <input_file> <output_file>")
		return
	}
	inputFilePath := os.Args[1]
	OutputFilePath = os.Args[2]

	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		fmt.Println("Error opening input file:", err)
		return
	}
	defer inputFile.Close()

	// Read the first chunk (initial value)
	var firstChunk uint32
	err = binary.Read(inputFile, binary.LittleEndian, &firstChunk)
	if err != nil {
		fmt.Println("Error reading first chunk:", err)
		return
	}

	// Read the entire file into memory
	fileData, err := ioutil.ReadAll(inputFile)
	if err != nil {
		fmt.Println("Error reading input file:", err)
		return
	}

	startKey := uint32(0x00000001)
	endKey := uint32(0xFFFFFFFF)
	c := runtime.NumCPU()
	totalKeys := endKey - startKey + 1
	keysPerRoutine := totalKeys / uint32(c)
	remainder := totalKeys % uint32(c)

	var wg sync.WaitGroup

	for t := 0; t < c; t++ {
		wg.Add(1)
		start := startKey + uint32(t)*keysPerRoutine
		end := start + keysPerRoutine - 1

		if t == c-1 {
			end += remainder
		}

		go func(start, end uint32) {
			defer wg.Done()

			for i := start; i <= end; i++ {
				select {
				// Switch off all threads
				case <-done:
					return
				default:
					_, b := decryptData(firstChunk, fileData, i)
					if b == true {
						fmt.Printf("\nKey: 0x%08X\n", i)
						close(done)
						return
					}

				}
			}
		}(start, end)
	}
	wg.Wait()
}

func hasSignature(data []byte) bool {
	// Check if the data contains the specified signature
	for i := 0; i <= len(data)-maxSignatureBytes; i++ {
		//fmt.Printf("0x%08X\n", data[i:i+maxSignatureBytes])
		if compareBytes(data[i:i+maxSignatureBytes], signatureBytes) {
			return true
		}
	}
	return false
}

func compareBytes(slice1, slice2 []byte) bool {
	// Compare two byte slices
	if len(slice1) != len(slice2) {
		return false
	}
	for i := 0; i < len(slice1); i++ {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

func decryptData(firstChunk uint32, fileData []byte, key uint32) (error, bool) {

	decryptedData := make([]byte, 0, chunkSize*maxChunkCount)

	for i := int64(1); i <= int64(len(fileData)/4); i++ {
		encryptedChunk := binary.LittleEndian.Uint32(fileData[(i-1)*4 : i*4])

		// Decrypt the chunk
		result := firstChunk ^ (encryptedChunk - key)
		val1Ror := (encryptedChunk >> 3) & 7
		rotationAmount := encryptedChunk & 7
		firstChunk = (firstChunk << (rotationAmount + 1)) | (firstChunk >> (32 - (rotationAmount + 1)))
		key = (key << (32 - val1Ror - 1)) | (key >> (val1Ror + 1))
		
		decryptedData = append(decryptedData, byte(result), byte(result>>8), byte(result>>16), byte(result>>24))

		// Check if we need to stop decryption and check for the signature
		if i == int64(maxChunkCount) {
			if !hasSignature(decryptedData) {
				return nil, false
			}
		}
	}

	outputFile, err := os.Create(OutputFilePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err), false
	}
	defer outputFile.Close()

	_, err = outputFile.Write(decryptedData)
	if err != nil {
		return fmt.Errorf("error writing to output file: %v", err), false
	}

	fmt.Printf("Decryption complete. Decrypted data saved to %s", OutputFilePath)
	return nil, true
}
