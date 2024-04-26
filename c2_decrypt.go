package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: c2_decrypt.exe <input_file>")
	}

	inputFilePath := os.Args[1]

	data, err := ioutil.ReadFile(inputFilePath)
	if err != nil {
		log.Fatal(err)
	}

	// Define the hex signature to search for
	signature := []byte{0x80, 0x38, 0x01, 0x00, 0x40, 0x9C}
	signature_x86 := []byte{0x41, 0x50, 0x49, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c}

	var index_x86 int
	_ = index_x86
	
	index := findSignature(data, signature)

	// If x64 signature not found, try to find x86
	if index == -1 {
		index_x86 = findSignature(data, signature_x86)

		var keyStart_x86 int
		_ = keyStart_x86

		if index_x86 != -1 {

			for i := 0; ; i++ {
				if data[index_x86+i] != byte(0) {
					keyStart_x86 = index_x86 + i
					break
				}
			}

			dataStart_x86 := keyStart_x86 + 98

			result_x86 := ""

			for i := 0; i < 20; i++ {
				resultByte_x86 := data[keyStart_x86+i] ^ data[dataStart_x86+i]
				result_x86 += string(resultByte_x86)

			}
			fmt.Println(cleanResult(result_x86))
			return

		}
	}

	keyStart := index + 12
	dataStart := keyStart + 94

	result := ""

	for i := 0; i < 20; i++ {
		resultByte := data[keyStart+i] ^ data[dataStart+i]
		result += string(resultByte)
	}

	fmt.Println(cleanResult(result))
}

func findSignature(data []byte, signature []byte) int {
	for i := 0; i < len(data)-len(signature); i++ {
		if bytesEqual(data[i:i+len(signature)], signature) {
			return i + len(signature)
		}
	}
	return -1
}

func bytesEqual(b1, b2 []byte) bool {
	return len(b1) == len(b2) && hex.EncodeToString(b1) == hex.EncodeToString(b2)
}

func cleanResult(s string) string {
	var cleanedResult string

	for _, char := range s {
		if char >= 32 && char <= 126 {
			cleanedResult += string(char)
		}
	}
	return cleanedResult
}
