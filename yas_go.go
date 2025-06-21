// test764 : YAS go crypto module v3

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/sha3"
)

// ask q, get str input
func Input(q string) string {
	fmt.Print(q)
	temp, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if len(temp) == 0 {
		return ""
	} else if temp[len(temp)-1] == '\n' {
		temp = temp[0 : len(temp)-1]
	}
	if len(temp) == 0 {
		return ""
	} else if temp[len(temp)-1] == '\r' {
		temp = temp[0 : len(temp)-1]
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

// little endian encoding
func encode(num int, length int) []byte {
	temp := make([]byte, length)
	for i := 0; i < length; i++ {
		temp[i] = byte(num % 256)
		num = num / 256
	}
	return temp
}

// little endian decoding
func decode(data []byte) int {
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

// get file Size (-1 : not Exist)
func getsize(path string) int {
	fileinfo, err := os.Stat(path)
	if err == nil {
		return int(fileinfo.Size())
	} else {
		return -1
	}
}

// file read
func readfile(f *os.File, size int) ([]byte, error) {
	res := make([]byte, size)
	_, err := f.Read(res)
	return res, err
}

// file copy, size -1 : path -> f else f[size] -> path
func copyfile(f *os.File, path string, size int) error {
	var t *os.File
	var err error
	var temp []byte
	if size < 0 { // path -> f
		size = getsize(path)
		t, err = os.Open(path)
		if err == nil {
			defer t.Close()
		} else {
			return err
		}
		for i := 0; i < size/10485760; i++ {
			temp, _ = readfile(t, 10485760)
			f.Write(temp)
		}
		if size%10485760 != 0 {
			temp, _ = readfile(t, size%10485760)
			f.Write(temp)
		}
	} else { // f[size] -> path
		t, err = os.Create(path)
		if err == nil {
			defer t.Close()
		} else {
			return err
		}
		for i := 0; i < size/10485760; i++ {
			temp, _ = readfile(f, 10485760)
			t.Write(temp)
		}
		if size%10485760 != 0 {
			temp, _ = readfile(f, size%10485760)
			t.Write(temp)
		}
	}
	return nil
}

// generate true random nB
func genrand(n int) []byte {
	temp := make([]byte, n)
	rand.Read(temp)
	return temp
}

// sha3-256 hash
func sha3256(data []byte) []byte {
	temp := sha3.New256()
	temp.Write(data)
	return temp.Sum(nil)
}

// AES128, auto update data & iv
func aes128(data []byte, key []byte, iv []byte, ispad bool, isenc bool) []byte {
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

// dozip files -> ./temp
func dozip(files []string) error {
	f, err := os.Create("./yas_temp")
	if err == nil {
		defer f.Close()
	} else {
		return err
	}
	f.Write(encode(len(files), 2))
	for _, r := range files {
		r = Abspath(r)
		name := []byte(r[strings.LastIndex(r, "/")+1:])
		f.Write(encode(len(name), 2))
		f.Write(name)
		f.Write(encode(getsize(r), 8))
		err = copyfile(f, r, -1)
		if err != nil {
			return err
		}
	}
	return nil
}

// unzip ./temp -> path/files
func unzip(path string) error {
	path = Abspath(path)
	if path[len(path)-1] != '/' {
		return errors.New("path should be folder")
	}
	f, err := os.Open("./yas_temp")
	if err == nil {
		defer f.Close()
	} else {
		return err
	}
	temp, err := readfile(f, 2)
	if err != nil {
		return err
	}
	num := decode(temp)
	for i := 0; i < num; i++ {
		temp, _ = readfile(f, 2)
		temp, _ = readfile(f, decode(temp))
		name := string(temp)
		temp, _ = readfile(f, 8)
		err = copyfile(f, path+name, decode(temp))
		if err != nil {
			return err
		}
	}
	return err
}

// generate keys & ivs, 128B ckey -> 32x 16B keys
func genkey(ckey []byte) [][]byte {
	out := make([][]byte, 32)
	inline := func(pre []byte, sub []byte, out [][]byte, num int, wg *sync.WaitGroup) {
		defer wg.Done()
		temp := append(make([]byte, 0), sub...)
		for j := 0; j < 10000; j++ {
			temp = sha3256(append(append(make([]byte, 0), pre...), temp...))
		}
		out[num] = temp[0:16]
		out[num+16] = temp[16:32]
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		var pre []byte
		var sub []byte
		ti := (7 * i) % 16
		if ti > 8 {
			pre = ckey[8*ti-64 : 8*ti]
			sub = append(ckey[8*ti:], ckey[0:8*ti-64]...)
		} else {
			pre = append(ckey[8*ti+64:], ckey[0:8*ti]...)
			sub = ckey[8*ti : 8*ti+64]
		}
		wg.Add(1)
		go inline(pre, sub, out, i, &wg)
	}
	wg.Wait()
	return out
}

// generate (pwhash, masterkey) from (password, salt)
func genpwh(pw []byte, salt []byte) ([]byte, []byte) {
	pwhash := append(make([]byte, 0), pw...)
	for i := 0; i < 100000; i++ {
		pwhash = sha3256(append(append(make([]byte, 0), salt...), pwhash...))
	}
	mkey := append(make([]byte, 0), pw...)
	for i := 0; i < 10000; i++ {
		mkey = sha3256(append(append(make([]byte, 0), mkey...), salt...))
	}
	return pwhash, mkey
}

// enc & dec calculation
func ende(indata []byte, outdata [][]byte, num int, keys [][]byte, ivs [][]byte, isenc bool, wg *sync.WaitGroup) {
	defer wg.Done()
	outdata[num] = aes128(indata[131072*num:131072*num+131072], keys[num], ivs[num], false, isenc)
}

// encrypt ./temp -> path
func encrypt(msg []byte, pw []byte, path string) error {
	salt := genrand(32)
	iv := genrand(16)
	ckey := genrand(128)
	pwhash, mkey := genpwh(pw, salt)
	ckeydata := aes128(ckey, mkey[16:32], mkey[0:16], false, true)
	keys := genkey(ckey)
	ivs := make([][]byte, 32)
	for i := 0; i < 32; i++ {
		ivs[i] = append(make([]byte, 0), iv...)
	}

	f, err := os.Create(path)
	if err == nil {
		defer f.Close()
	} else {
		return err
	}
	f.Write(append(append([]byte("OTE1"), encode(len(msg), 2)...), msg...))
	f.Write(append(append(append(salt, pwhash...), ckeydata...), iv...))

	var t *os.File
	t, err = os.Open("./yas_temp")
	if err == nil {
		defer t.Close()
	} else {
		return err
	}
	fsize := getsize("./yas_temp")
	num0 := fsize / 131072
	num1 := fsize % 131072
	var inbuf []byte
	exbuf := make([][]byte, 32)
	var wg sync.WaitGroup

	for i := 0; i < num0/32; i++ {
		inbuf, _ = readfile(t, 4194304)
		for j := 0; j < 32; j++ {
			wg.Add(1)
			go ende(inbuf, exbuf, j, keys, ivs, true, &wg)
		}
		wg.Wait()
		for j := 0; j < 32; j++ {
			f.Write(exbuf[j])
		}
	}
	if num0%32 != 0 {
		inbuf, _ = readfile(t, 131072*(num0%32))
		for j := 0; j < num0%32; j++ {
			wg.Add(1)
			go ende(inbuf, exbuf, j, keys, ivs, true, &wg)
		}
		wg.Wait()
		for j := 0; j < num0%32; j++ {
			f.Write(exbuf[j])
		}
	}
	inbuf, _ = readfile(t, num1)
	f.Write(aes128(inbuf, keys[num0%32], ivs[num0%32], true, true))
	return nil
}

// decrypt path -> ./temp
func decrypt(pw []byte, path string) error {
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
	} else {
		return err
	}
	readfile(f, 4)
	temp, _ := readfile(f, 2)
	msglen := decode(temp)
	readfile(f, msglen)
	salt, _ := readfile(f, 32)
	pwhash, _ := readfile(f, 32)
	ckeydata, _ := readfile(f, 128)
	iv, _ := readfile(f, 16)

	nph, mkey := genpwh(pw, salt)
	if !bytes.Equal(nph, pwhash) {
		return errors.New("InvalidPW")
	}
	ckey := aes128(ckeydata, mkey[16:32], mkey[0:16], false, false)
	keys := genkey(ckey)
	ivs := make([][]byte, 32)
	for i := 0; i < 32; i++ {
		ivs[i] = append(make([]byte, 0), iv...)
	}

	var t *os.File
	t, err = os.Create("./yas_temp")
	if err == nil {
		defer t.Close()
	} else {
		return err
	}
	fsize := getsize(path) - 214 - msglen
	num0 := fsize / 131072
	num1 := fsize % 131072
	if num1 == 0 {
		num0 = num0 - 1
		num1 = 131072
	}
	var inbuf []byte
	exbuf := make([][]byte, 32)
	var wg sync.WaitGroup

	for i := 0; i < num0/32; i++ {
		inbuf, _ = readfile(f, 4194304)
		for j := 0; j < 32; j++ {
			wg.Add(1)
			go ende(inbuf, exbuf, j, keys, ivs, false, &wg)
		}
		wg.Wait()
		for j := 0; j < 32; j++ {
			t.Write(exbuf[j])
		}
	}
	if num0%32 != 0 {
		inbuf, _ = readfile(f, 131072*(num0%32))
		for j := 0; j < num0%32; j++ {
			wg.Add(1)
			go ende(inbuf, exbuf, j, keys, ivs, false, &wg)
		}
		wg.Wait()
		for j := 0; j < num0%32; j++ {
			t.Write(exbuf[j])
		}
	}
	inbuf, _ = readfile(f, num1)
	t.Write(aes128(inbuf, keys[num0%32], ivs[num0%32], true, false))
	return nil
}

// check file validity, returns msg
func view(path string) (string, error) {
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
	} else {
		return "", err
	}
	temp, _ := readfile(f, 4)
	if !bytes.Equal(temp, []byte("OTE1")) {
		return "", errors.New("InvalidFile")
	}
	temp, _ = readfile(f, 2)
	temp, _ = readfile(f, decode(temp))
	return string(temp), nil
}

// yas go
type YAS_go struct {
	Msg     string
	Err     string
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

// encrypt files -> result
func (tbox *YAS_go) Encrypt(files []string, result string, pw string) {
	tbox.Err = ""
	err := dozip(files)
	if err == nil {
		defer os.Remove("./yas_temp")
		err = encrypt([]byte(tbox.Msg), []byte(pw), result)
		if err != nil {
			tbox.Err = err.Error()
		}
	} else {
		tbox.Err = err.Error()
	}
}

// decrypt path -> unpack/files
func (tbox *YAS_go) Decrypt(path string, unpack string, pw string) {
	tbox.Err = ""
	err := decrypt([]byte(pw), path)
	if err == nil {
		defer os.Remove("./yas_temp")
		err = unzip(unpack)
		if err != nil {
			tbox.Err = err.Error()
		}
	} else {
		tbox.Err = err.Error()
	}
}

// view path, update msg & err
func (tbox *YAS_go) View(path string) {
	tbox.Err = ""
	msg, err := view(path)
	if err == nil {
		tbox.Msg = msg
	} else {
		tbox.Err = err.Error()
	}
}

// generate RSA key (T 4096 F 2048)
func (tbox *YAS_go) GenKey(extSec bool) []byte {
	tbox.Err = ""
	var err error
	if extSec {
		tbox.private, err = rsa.GenerateKey(rand.Reader, 4096)
	} else {
		tbox.private, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		tbox.Err = err.Error()
		return nil
	}
	tbox.public = &tbox.private.PublicKey
	temp, err := x509.MarshalPKIXPublicKey(tbox.public)
	if err == nil {
		return temp
	} else {
		tbox.Err = err.Error()
		return nil
	}
}

// load RSA public key
func (tbox *YAS_go) LoadKey(public []byte) {
	tbox.Err = ""
	temp, err := x509.ParsePKIXPublicKey(public)
	conv, ok := temp.(*rsa.PublicKey)
	if err != nil {
		tbox.Err = err.Error()
	} else if !ok {
		tbox.Err = "not an RSA public key"
	}
	tbox.public = conv
}

// encrypt & decrypt with RSA-OAEP SHA-1
func (tbox *YAS_go) RSAcrypt(data []byte, isEnc bool) []byte {
	tbox.Err = ""
	var res []byte
	var err error
	if isEnc {
		res, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, tbox.public, data, nil)
	} else {
		res, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, tbox.private, data, nil)
	}
	if err == nil {
		return res
	} else {
		tbox.Err = err.Error()
		return nil
	}
}
