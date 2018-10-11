// Copyright (c) 2018 Sagar Wani
// ssswanil@gmail.com 

package main

import (
	"crypto/aes"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/exec"
)

func XorByteArray(bytearray1 []byte, bytearray2 []byte) []byte {
	bytearrayfinal := make([]byte, len(bytearray1))
	for i := 0 ; i < len(bytearray1); i++{
		bytearrayfinal[i] = bytearray1[i] ^ bytearray2[i]
	}
	return bytearrayfinal
}

func DivideIntoBlocks(bytearray []byte, AESBlockSize int) [][]byte{
	AESBlockSize = 16
	numberofblocks := len(bytearray) / AESBlockSize
	start := 0
	stop := AESBlockSize
	bytearrayblocks := make([][]byte, numberofblocks)
	for i := 0; i < numberofblocks; i++ {
		bytearrayblocks[i] = bytearray[start:stop]
		start += AESBlockSize
		stop += AESBlockSize
	}
	return bytearrayblocks
}

func RemoveBlocks(bytearray [][]byte, AESBlockSize int) []byte{
	numberofblocks := len(bytearray)
	datablock := make([]byte, numberofblocks * 16)
	r := 0
	for p := 0; p<numberofblocks; p++{
		for q := 0; q < 16; q++{
			datablock[r] = bytearray[p][q]
			r++
		}
	}
	return datablock
}

func CombineBlocks(byteArray1 []byte, byteArray2 []byte) []byte{
	//byteArray2 will be appended to byteArray1
	for i := 0; i < len(byteArray2); i++{
		byteArray1 = append(byteArray1, byteArray2[i])
	}
	return byteArray1
}

func  CopyBlocks(byteArray1 []byte, byteArray2 []byte) []byte{
	//ByteArray1 is copied into ByteArray2
	for i := 0; i < 16; i++{
		byteArray2[i] = byteArray1[i]
	}
	return byteArray2
}

func FindPadding(cipherblocks [][]byte, AESBlockSize int, outputFile string) int{

	var padding = 0
	for i := 0; i < AESBlockSize; i++{
		cipherblocks[len(cipherblocks) - 2][i] = byte(0x0) //Changing IV from previous block
		cipherbytearray := RemoveBlocks(cipherblocks, 16)
		err_write := ioutil.WriteFile(outputFile, cipherbytearray, 0644)
		if err_write!=nil {
			fmt.Println("ERROR: ", err_write)
		}
		result, _ := exec.Command("./decrypt-test", "-i", outputFile).Output()

		result_str := string(result)
		if string(result_str) == "INVALID PADDING"{
			padding += 1
		}
	}
	return padding
}

func Decrypt(message []byte, cipherArray [][]byte, ivx []byte, pad int, outputFile string, AESBlockSize int) []byte{
	plaintextBlock := make([]byte, AESBlockSize)
	xoriv := make([]byte, AESBlockSize)
	xoriv = CopyBlocks(ivx, xoriv)
	tempiv := make([]byte, AESBlockSize)
	tempiv = CopyBlocks(ivx, tempiv)
	newiv := make([]byte, AESBlockSize)
	newiv = CopyBlocks(ivx, newiv)
	//Copy Ciphers ByteArray of ByteArrays into new variable.
	numberOfBlocks := len(cipherArray)
	/*cipherArrayCopy := make([][]byte, numberOfBlocks)
	for m := 0; m < numberOfBlocks; m++{
		cipherArrayCopy[m] = CopyBlocks(cipherArray[m], cipherArrayCopy[m])
	}*/
	plaintextArrays := make([][]byte, int(math.Ceil(float64((numberOfBlocks * 16) - (pad + 32))/float64(16))))
	for h := 0; h < len(plaintextArrays); h++{
		fillPlaintextWithZeros := make([]byte, AESBlockSize)
		plaintextArrays[h] = fillPlaintextWithZeros
	}
	//Variables for IV in else statement.
	xorivx := make([]byte, AESBlockSize)
	tempivx := make([]byte, AESBlockSize)
	start := 0
	iv := ivx

	if len(message) <= AESBlockSize{
		for p := AESBlockSize - 1; p >=0; p--{
			for q := 0x00; q <= 0xff; q++{
					xorvalue := iv[p] ^ byte(q) ^ byte(AESBlockSize-p)
					xoriv[p] = xorvalue
					if p != AESBlockSize -1 {
						for x := p+1; x <= AESBlockSize - 1; x++{
							xoriv[x] = tempiv[x] ^ byte(AESBlockSize - p)
						}
					}
					makeCipherArray := CombineBlocks(xoriv, cipherArray[0])
					err_write := ioutil.WriteFile(outputFile, makeCipherArray, 0644)
					if err_write != nil {
						fmt.Println("ERROR: ", err_write)
					}
					result, _ := exec.Command("./decrypt-test", "-i", outputFile).Output()
					result_str := string(result)
					if result_str != "INVALID PADDING" {
						plaintextBlock[p] = byte(q)
						tempiv[p] = byte(xorvalue ^ byte(AESBlockSize - p))
					}
				}
			}
		return plaintextBlock[:(numberOfBlocks * 16) - (pad + 32)]
		} else {
				start = int(math.Ceil(float64((numberOfBlocks * 16) - (pad + 32))/float64(16)))
				for s := start - 1; s >= 0; s--{
				if s == 0{
					iv = ivx
					tempivx = CopyBlocks(ivx, tempivx)
					xorivx = CopyBlocks(ivx, xorivx)
				} else {
					iv = cipherArray[s-1]
					tempivx = CopyBlocks(cipherArray[s-1], tempivx)
					xorivx = CopyBlocks(cipherArray[s-1], xorivx)
				}
				for p := AESBlockSize - 1; p >=0; p--{
					for q := 0x00; q <= 0xff; q++{
						xorvalue := iv[p] ^ byte(q) ^ byte(AESBlockSize-p)
						xorivx[p] = xorvalue
						if p != AESBlockSize -1 {
							for x := p+1; x <= AESBlockSize - 1; x++{
								xorivx[x] = tempivx[x] ^ byte(AESBlockSize - p)
							}
						}

						blockToSend := make([][]byte, s + 2)
						blockToSend[0] = newiv
						for m := 1; m < s; m++{
							blockToSend[m] = cipherArray[m - 1]
						}
						blockToSend[len(blockToSend) - 2] = xorivx
						blockToSend[len(blockToSend) - 1] = cipherArray[s]
						cipherArrayToSend := make([]byte, (s+2) * AESBlockSize) //Initial IV too.
						cipherArrayToSend = RemoveBlocks(blockToSend, AESBlockSize)
						err_write := ioutil.WriteFile(outputFile, cipherArrayToSend, 0644)
						if err_write != nil {
							fmt.Println("ERROR: ", err_write)
						}
						result, _ := exec.Command("./decrypt-test", "-i", outputFile).Output()
						result_str := string(result)
						if result_str != "INVALID PADDING" {
							plaintextArrays[s][p] = byte(q)
							tempivx[p] = byte(xorvalue ^ byte(AESBlockSize - p))
						}
					}
				}
			}
	}
	return (RemoveBlocks(plaintextArrays, aes.BlockSize))[:(numberOfBlocks * 16) - (pad + 32)]
	}


func main() {

	cipherfile := os.Args[2]
	AESBlockSize := 16

	//Simply reading the text file and taking contents into a variable.
	file, err := os.Open(cipherfile)
	if err != nil {
		log.Fatal(err)
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	file.Close()

	cipherblockswithiv := DivideIntoBlocks(data, AESBlockSize)

	//Finding the padding.
	tempFile := "attack-temp-file.txt"
	pad := FindPadding(cipherblockswithiv, AESBlockSize, tempFile)

	//Opening the cipher file.
	fileNew, _ := os.Open(cipherfile)
	dataNew, _ := ioutil.ReadAll(fileNew)

	//Strip the IV
	iv := dataNew[:AESBlockSize]
	dataNew = dataNew[AESBlockSize:] //Contains message+HMAC+padding

	//Strip padding and HMAC
	HMACSize := 32
	message := dataNew[:len(dataNew) - pad - HMACSize]

	//Calling the decrypt function.
	encryptedBlocks := DivideIntoBlocks(dataNew, AESBlockSize)
	plaintext := Decrypt(message, encryptedBlocks, iv, pad, tempFile, AESBlockSize)
	log.Printf("%s", plaintext)
	}
