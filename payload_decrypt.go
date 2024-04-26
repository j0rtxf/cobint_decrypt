package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: payload_decrypt.exe <input_file>")
		return
	}
	inputFilePath := os.Args[1]

	inputFile, err := os.OpenFile(inputFilePath, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening input file:", err)
		return
	}
	defer inputFile.Close()

	outputFilePath := "decrypted.bin"
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer outputFile.Close()

	fileInfo, err := inputFile.Stat()
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}
	fileSize := fileInfo.Size()
	_ = fileSize


	counter := (fileSize - 4) / 4

	// Xor key
	var key uint32 = 0xFD21D402
	var firstChunk uint32

	// Read the first chunk (initial value)
	err = binary.Read(inputFile, binary.LittleEndian, &firstChunk)
	if err != nil {
		fmt.Println("Error reading first chunk:", err)
		return
	}

	for i := int64(0); i < counter; i++ {
		var encryptedChunk uint32
		err := binary.Read(inputFile, binary.LittleEndian, &encryptedChunk)
		if err != nil {
			fmt.Println("Error reading from file", err)
			return
		}

		result := firstChunk ^ (encryptedChunk - key)
		_ = result

		val1Ror := (encryptedChunk >> 3) & 7
		rotationAmount := encryptedChunk & 7
		firstChunk = (firstChunk << (rotationAmount + 1)) | (firstChunk >> (32 - (rotationAmount + 1)))
		key = (key << (32 - val1Ror - 1)) | (key >> (val1Ror + 1))

		// Write the decrypted chunk to the output file
		err = binary.Write(outputFile, binary.LittleEndian, result)
		if err != nil {
			fmt.Println("Error writing to output file:", err)
			return
		}
	}

	fmt.Printf("Decryption complete. Decrypted data saved to %s\n", outputFilePath)

}