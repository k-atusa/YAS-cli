// test773 : cli basic functions

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/sha3"
)

// little endian encoding
func Encode(num int, length int) []byte {
	temp := make([]byte, length)
	for i := 0; i < length; i++ {
		temp[i] = byte(num % 256)
		num = num / 256
	}
	return temp
}

// little endian decoding
func Decode(data []byte) int {
	temp := 0
	for i, r := range data {
		if r != 0 {
			exp := 1
			for j := 0; j < i; j++ {
				exp = exp * 256
			}
			temp = temp + int(r)*exp
		}
	}
	return temp
}

// absolute path (folder : */, file : *)
func Abspath(path string) string {
	path, _ = filepath.Abs(path)
	path = strings.Replace(path, "\\", "/", -1)
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
	} else {
		return path
	}
	fileinfo, _ := file.Stat()
	if fileinfo.IsDir() {
		if path[len(path)-1] != '/' {
			path = path + "/"
		}
	}
	return path
}

// get file Size (-1 : not Exist)
func Getsize(path string) int {
	fileinfo, err := os.Stat(path)
	if err == nil {
		return int(fileinfo.Size())
	} else {
		return -1
	}
}

// file read
func Readfile(f *os.File, size int) ([]byte, error) {
	res := make([]byte, size)
	_, err := f.Read(res)
	return res, err
}

// generate true random nB
func Genrand(n int) []byte {
	temp := make([]byte, n)
	rand.Read(temp)
	return temp
}

// base64 encode
func B64en(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// base64 decode
func B64de(data string) []byte {
	res, _ := base64.StdEncoding.DecodeString(data)
	return res
}

// crc32 hash
func Crc32(data []byte) []byte {
	return Encode(int(crc32.ChecksumIEEE(data)), 4)
}

// sha3-256 hash
func Sha3256(data []byte) []byte {
	temp := sha3.New256()
	temp.Write(data)
	return temp.Sum(nil)
}

// AES128, auto update data & iv
func Aes128(data []byte, key []byte, iv []byte, ispad bool, isenc bool) []byte {
	var res []byte
	block, _ := aes.NewCipher(key)
	if isenc {
		if ispad {
			plen := 16 - len(data)%16
			for i := 0; i < plen; i++ {
				data = append(data, byte(plen))
			}
		}
		res = make([]byte, len(data))
		encrypter := cipher.NewCBCEncrypter(block, iv)
		encrypter.CryptBlocks(res, data)
		copy(iv, res[len(res)-16:])
	} else {
		res = make([]byte, len(data))
		decrypter := cipher.NewCBCDecrypter(block, iv)
		decrypter.CryptBlocks(res, data)
		copy(iv, data[len(data)-16:])
		if ispad {
			plen := res[len(res)-1]
			res = res[:len(res)-int(plen)]
		}
	}
	return res
}
