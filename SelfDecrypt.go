package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Println("Usage: cob_selfdec.exe <file_path>")
		return
	}

	filePath := os.Args[1]

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// Xorkey
	xorKey := uint32(0x3493D9DE)

	// Decrypt the data
	for i := 0; i < len(data); i += 4 {

		var dword uint32
		if i+4 <= len(data) {
			dword = binary.LittleEndian.Uint32(data[i : i+4])
		} else {

			padLen := 4 - (len(data) - i)
			paddedData := append(data[i:], make([]byte, padLen)...)
			dword = binary.LittleEndian.Uint32(paddedData)
		}

		// XOR the DWORD with the XOR key
		dword ^= xorKey

		// Rotate the XOR key left by 1 bit
		xorKey = rotateLeft(xorKey)

		binary.LittleEndian.PutUint32(data[i:i+4], dword)
	}

	inputFileName := filepath.Base(filePath)
	fileNameWithoutExt := inputFileName[:len(inputFileName)-len(filepath.Ext(inputFileName))]

	outputFilePath := fileNameWithoutExt + "_dec" + filepath.Ext(inputFileName)
	err = os.WriteFile(outputFilePath, data, 0644)
	if err != nil {
		fmt.Println("Error writing decrypted data to file:", err)
		return
	}

	fmt.Printf("Decryption complete. Decrypted data saved to %s\n", outputFilePath)
}

// rotates the bits of a uint32 left by 1 bit
func rotateLeft(x uint32) uint32 {
	return (x << 1) | (x >> 31)
}
