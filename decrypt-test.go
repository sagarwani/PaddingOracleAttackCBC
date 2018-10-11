// Copyright (c) 2018 Sagar Wani
// ssswanil@gmail.com 

package main

import (
	"crypto/aes"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func XorByteArray(bytearray1 []byte, bytearray2 []byte) []byte {
	bytearrayfinal := make([]byte, len(bytearray1))
	for i := 0 ; i < len(bytearray1); i++{
		bytearrayfinal[i] = bytearray1[i] ^ bytearray2[i]
	}
	return bytearrayfinal
}

func hmac_sha256(messagex string, kmacx string) []byte {
	var result []byte
	kmacx = "1111111111111111"

	kmac := make([]byte, 64)
	for j := 0; j < len(kmacx); j++ {
		kmac[j] = kmacx[j]
	}

	//fmt.Println("The value of kmac in bytes is: ", kmac)
	message := make([]byte, len(messagex))
	message = []byte(messagex)

	//Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
	if (len(kmac) == 64) {

		opad_xor1 := strings.Repeat( "\\", 64)
		opad := make([]byte, len(opad_xor1))
		opad = []byte(opad_xor1)

		ipad_xor := strings.Repeat("6", 64)
		ipad := make([]byte, len(ipad_xor))
		ipad = []byte(ipad_xor)


		innerhash := XorByteArray(kmac, ipad)
		for i := 0; i < len(message); i++ {
			innerhash = append(innerhash, message[i])
		}

		sha256z := sha256.Sum256(innerhash)
		outerhash := XorByteArray(kmac, opad)

		for i := 0; i < len(sha256z); i++ {
			outerhash = append(outerhash, sha256z[i])
		}

		finalsha256 := sha256.Sum256(outerhash)
		result = finalsha256[:]

	}
	return result
}

func decrypt(kencx string, kmacx string, ciphertextx []byte) []byte {
	var ciphertext []byte
	//Get the IV
	iv := make([]byte, 16)
	for i := 0; i < 16; i++{
		iv[i] = ciphertextx[i]
	}
	//fmt.Println("The value of IV for decryption is: ", iv)

	//Get the ciphertext
	for i := 16; i < len(ciphertextx); i++{
		ciphertext = append(ciphertext, ciphertextx[i])
	}
	//fmt.Println("The value of ciphertext without IV is: ", ciphertext)

	kenc := make([]byte, len(kencx))
	for j := 0; j < len(kencx); j++ {
		kenc[j] = kencx[j]
	}
	//fmt.Println("The key for decryption is: ", kenc)

	//Dividing ciphertext into blocks
	numberofblocks := len(ciphertext) / 16
	start := 0
	stop := 16
	cipherblocks := make([][]byte, numberofblocks)
	for i := 0; i < numberofblocks; i++ {
		cipherblocks[i] = ciphertext[start:stop]
		start += 16
		stop += 16
	}
	//fmt.Println("The blocks of cipher are: ", cipherblocks)

	//Decrypt 1st block.
	BlockDecrypt, _ := aes.NewCipher(kenc)
	plaintextblocks := make([][]byte, numberofblocks)

	xorvalue := make([]byte, 16)
	BlockDecrypt.Decrypt(xorvalue, cipherblocks[0])
	//fmt.Println("The xorvalue is: ", xorvalue)

	pt0 := make([]byte, 16)
	for i := 0; i < 16; i++{
		pt0[i] = xorvalue[i] ^ iv[i]
	}
	plaintextblocks[0] = pt0
	//fmt.Println("The value of first block of plaintext is: ", pt0)

	//Decrypt all blocks.
	for k := 1; k <numberofblocks; k++ {
		plainvalue := make([]byte, 16)
		temp := make([]byte, 16)
		BlockDecrypt.Decrypt(temp, cipherblocks[k])
		for i := 0; i < 16; i++{
			plainvalue[i] = temp[i] ^ cipherblocks[k-1][i]
		}
		plaintextblocks[k] = plainvalue
	}
	//fmt.Println("The plaintext blocks are: ", plaintextblocks)

	//Get a single plaintext block from blocks of plaintext
	datablock := make([]byte, numberofblocks * 16)
	r := 0
	for p := 0; p<numberofblocks; p++{
		for q := 0; q < 16; q++{
			datablock[r] = plaintextblocks[p][q]
			r++
		}
	}
	//Padding check
	lastbytevalue := datablock[len(datablock) - 1]
	//h := len(datablock) - lastbytevalue
	/*if lastbytevalue > 16 {
		fmt.Println("INVALID PADDING")
		os.Exit(1)
	}*/
	//fmt.Println("Value of last byte: ", int(lastbytevalue))
	//fmt.Println("Value of datablock before padding check is: ", datablock)

	if int(lastbytevalue) != 0 {
		for i := len(datablock) - 1; i >= len(datablock)-int(lastbytevalue); i-- {
			if datablock[i] != lastbytevalue {
				fmt.Println("INVALID PADDING")
				os.Exit(1)
			}
		}
	} else {
		fmt.Println("INVALID PADDING")
		os.Exit(1)
	}
	/*datablockwithoutpadding := make([]byte, int(h))
	for i := 0; i < len(datablockwithoutpadding); i++{
		datablockwithoutpadding[i] = datablock[i]
	}
	//fmt.Println("Value of plaintext without padding: ", datablockwithoutpadding)*/


	//HMAC Test
	//fmt.Println("The datablock before HMAC test is: ", datablock)
	hmac := make([]byte, 32)
	last := len(datablock) - 1 - int(lastbytevalue)
	for i := 0; i < 32; i++{
		hmac[31 - i] = datablock[last]
		last--
	}
	//fmt.Println("The value of HMAC in ciphertext is: ", hmac)
	datablockwithouthmac := make([]byte, len(datablock) - len(hmac) - int(lastbytevalue))
	for j := 0; j < last+1; j++ {
		datablockwithouthmac[j] = datablock[j]
	}
	//fmt.Println("The datablock is: ", datablockwithouthmac)

	originalhmac := hmac_sha256(string(datablockwithouthmac), kmacx)
	//fmt.Println("The value of original HMAC is: ", originalhmac)

	//compare hmac
	for i := 0; i < 32; i++{
		if originalhmac[i] != hmac[i] {
			fmt.Println("INVALID MAC")
			os.Exit(1)
		}
	}
	//fmt.Println("HMAC check successful.")
	return datablockwithouthmac
}


func main() {
    cipherfile := os.Args[2]

	//Simply reading the text file and taking contents into a variable.
	file, err := os.Open(cipherfile)
	if err != nil {
		log.Fatal(err)
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	//inputfile := string(data)
	//fmt.Println("Contents of the file are: ", inputfile)
	//fmt.Println("Mode: ", mode)
	//fmt.Println("Output written to the file: ", output_file)
	//fmt.Println()
	file.Close()

	//Call Decryption
	//Explicitly defining inputs to the program.
	kenc := "1111111111111111"
	kmac := "1111111111111111"
	strx := "1111111111111111" //IV
	iv := make([]byte, 16)
	for i := 0; i < 16; i++{
		iv[i] = strx[i]
	}
	output := decrypt(kenc, kmac, data)
	fmt.Println("The decrypted value is: ", string(output))
}
