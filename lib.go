// test774 : YAS cli library

package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/sha3"
)

// file copy, size -1 : path -> f else f[size] -> path
func copyfile(f *os.File, path string, size int) error {
	var t *os.File
	var err error
	var temp []byte
	if size < 0 { // path -> f
		size = Getsize(path)
		t, err = os.Open(path)
		if err == nil {
			defer t.Close()
		} else {
			return err
		}
		for i := 0; i < size/10485760; i++ {
			temp, _ = Readfile(t, 10485760)
			f.Write(temp)
		}
		if size%10485760 != 0 {
			temp, _ = Readfile(t, size%10485760)
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
			temp, _ = Readfile(f, 10485760)
			t.Write(temp)
		}
		if size%10485760 != 0 {
			temp, _ = Readfile(f, size%10485760)
			t.Write(temp)
		}
	}
	return nil
}

// dozip files -> ./temp
func dozip(files []string) error {
	f, err := os.Create("./yas_temp")
	if err == nil {
		defer f.Close()
	} else {
		return err
	}
	f.Write(Encode(len(files), 2))
	for _, r := range files {
		r = Abspath(r)
		name := []byte(r[strings.LastIndex(r, "/")+1:])
		f.Write(Encode(len(name), 2))
		f.Write(name)
		f.Write(Encode(Getsize(r), 8))
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
	temp, err := Readfile(f, 2)
	if err != nil {
		return err
	}
	num := Decode(temp)
	for i := 0; i < num; i++ {
		temp, _ = Readfile(f, 2)
		temp, _ = Readfile(f, Decode(temp))
		name := string(temp)
		temp, _ = Readfile(f, 8)
		err = copyfile(f, path+name, Decode(temp))
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
			temp = Sha3256(append(append(make([]byte, 0), pre...), temp...))
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
		pwhash = Sha3256(append(append(make([]byte, 0), salt...), pwhash...))
	}
	mkey := append(make([]byte, 0), pw...)
	for i := 0; i < 10000; i++ {
		mkey = Sha3256(append(append(make([]byte, 0), mkey...), salt...))
	}
	return pwhash, mkey
}

// enc & dec calculation
func ende(indata []byte, outdata [][]byte, num int, keys [][]byte, ivs [][]byte, isenc bool, wg *sync.WaitGroup) {
	defer wg.Done()
	outdata[num] = Aes128(indata[131072*num:131072*num+131072], keys[num], ivs[num], false, isenc)
}

// encrypt ./temp -> path
func encrypt(msg []byte, pw []byte, path string) error {
	salt := Genrand(32)
	iv := Genrand(16)
	ckey := Genrand(128)
	pwhash, mkey := genpwh(pw, salt)
	ckeydata := Aes128(ckey, mkey[16:32], mkey[0:16], false, true)
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
	f.Write(append(append([]byte("OTE1"), Encode(len(msg), 2)...), msg...))
	f.Write(append(append(append(salt, pwhash...), ckeydata...), iv...))

	var t *os.File
	t, err = os.Open("./yas_temp")
	if err == nil {
		defer t.Close()
	} else {
		return err
	}
	fsize := Getsize("./yas_temp")
	num0 := fsize / 131072
	num1 := fsize % 131072
	var inbuf []byte
	exbuf := make([][]byte, 32)
	var wg sync.WaitGroup

	for i := 0; i < num0/32; i++ {
		inbuf, _ = Readfile(t, 4194304)
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
		inbuf, _ = Readfile(t, 131072*(num0%32))
		for j := 0; j < num0%32; j++ {
			wg.Add(1)
			go ende(inbuf, exbuf, j, keys, ivs, true, &wg)
		}
		wg.Wait()
		for j := 0; j < num0%32; j++ {
			f.Write(exbuf[j])
		}
	}
	inbuf, _ = Readfile(t, num1)
	f.Write(Aes128(inbuf, keys[num0%32], ivs[num0%32], true, true))
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
	Readfile(f, 4)
	temp, _ := Readfile(f, 2)
	msglen := Decode(temp)
	Readfile(f, msglen)
	salt, _ := Readfile(f, 32)
	pwhash, _ := Readfile(f, 32)
	ckeydata, _ := Readfile(f, 128)
	iv, _ := Readfile(f, 16)

	nph, mkey := genpwh(pw, salt)
	if !bytes.Equal(nph, pwhash) {
		return errors.New("InvalidPW")
	}
	ckey := Aes128(ckeydata, mkey[16:32], mkey[0:16], false, false)
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
	fsize := Getsize(path) - 214 - msglen
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
		inbuf, _ = Readfile(f, 4194304)
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
		inbuf, _ = Readfile(f, 131072*(num0%32))
		for j := 0; j < num0%32; j++ {
			wg.Add(1)
			go ende(inbuf, exbuf, j, keys, ivs, false, &wg)
		}
		wg.Wait()
		for j := 0; j < num0%32; j++ {
			t.Write(exbuf[j])
		}
	}
	inbuf, _ = Readfile(f, num1)
	t.Write(Aes128(inbuf, keys[num0%32], ivs[num0%32], true, false))
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
	temp, _ := Readfile(f, 4)
	if !bytes.Equal(temp, []byte("OTE1")) {
		return "", errors.New("InvalidFile")
	}
	temp, _ = Readfile(f, 2)
	temp, _ = Readfile(f, Decode(temp))
	return string(temp), nil
}

// yas lib : aes encryption
type YAS_aes struct {
	Msg string
	Err string
}

// encrypt files -> result
func (tbox *YAS_aes) Encrypt(files []string, result string, pw string) {
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
func (tbox *YAS_aes) Decrypt(path string, unpack string, pw string) {
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
func (tbox *YAS_aes) View(path string) {
	tbox.Err = ""
	msg, err := view(path)
	if err == nil {
		tbox.Msg = msg
	} else {
		tbox.Err = err.Error()
	}
}

// yas lib : rsa encryption
type YAS_rsa struct {
	Err     string
	public  *rsa.PublicKey
	private *rsa.PrivateKey
}

// Generate RSA key (T 4096 F 2048), (public, private)
func (tbox *YAS_rsa) Genkey(ext bool) ([]byte, []byte) {
	tbox.Err = ""
	tbox.public = nil
	tbox.private = nil
	var err error
	if ext {
		tbox.private, err = rsa.GenerateKey(rand.Reader, 4096)
	} else {
		tbox.private, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		tbox.Err = err.Error()
		return nil, nil
	}
	tbox.public = &tbox.private.PublicKey
	a, _ := x509.MarshalPKIXPublicKey(tbox.public)
	b, _ := x509.MarshalPKCS8PrivateKey(tbox.private)
	return a, b
}

// Load RSA key, only loads non-nil
func (tbox *YAS_rsa) Loadkey(public []byte, private []byte) {
	tbox.Err = ""
	tbox.public = nil
	tbox.private = nil
	if public != nil {
		a, err := x509.ParsePKIXPublicKey(public)
		if err == nil {
			tbox.public = a.(*rsa.PublicKey)
		} else {
			tbox.Err = err.Error()
			return
		}
	}
	if private != nil {
		b, err := x509.ParsePKCS8PrivateKey(private)
		if err == nil {
			tbox.private = b.(*rsa.PrivateKey)
		} else {
			tbox.Err = err.Error()
			return
		}
	}
}

// RSA encryption with public key
func (tbox *YAS_rsa) Encrypt(data []byte) []byte {
	tbox.Err = ""
	enc, err := rsa.EncryptOAEP(sha3.New256(), rand.Reader, tbox.public, data, nil)
	if err != nil {
		tbox.Err = err.Error()
		return nil
	}
	return enc
}

// RSA decryption with private key
func (tbox *YAS_rsa) Decrypt(data []byte) []byte {
	tbox.Err = ""
	dec, err := rsa.DecryptOAEP(sha3.New256(), rand.Reader, tbox.private, data, nil)
	if err != nil {
		tbox.Err = err.Error()
		return nil
	}
	return dec
}

// RSA sign with private key
func (tbox *YAS_rsa) Sign(data []byte) []byte {
	tbox.Err = ""
	for i := 0; i < 10000; i++ {
		data = Sha3256(data)
	}
	hashed := sha256.Sum256(data)
	enc, err := rsa.SignPKCS1v15(nil, tbox.private, crypto.SHA256, hashed[:])
	if err != nil {
		tbox.Err = err.Error()
		return nil
	}
	return enc
}

// RSA verify with public key
func (tbox *YAS_rsa) Verify(data []byte, sign []byte) bool {
	tbox.Err = ""
	for i := 0; i < 10000; i++ {
		data = Sha3256(data)
	}
	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(tbox.public, crypto.SHA256, hashed[:], sign)
	if err != nil {
		tbox.Err = err.Error()
		return false
	}
	return true
}

// zip file reader & writer
type Zipper struct {
	file   *os.File
	reader *zip.ReadCloser
	writer *zip.Writer
}

func (tbox *Zipper) Open(path string, isReader bool) error {
	var err error
	if isReader {
		tbox.reader, err = zip.OpenReader(path)
	} else {
		tbox.file, err = os.Create(path)
		if err == nil {
			tbox.writer = zip.NewWriter(tbox.file)
		}
	}
	return err
}

func (tbox *Zipper) Close() {
	if tbox.reader != nil {
		tbox.reader.Close()
	}
	if tbox.writer != nil {
		tbox.writer.Close()
	}
	if tbox.file != nil {
		tbox.file.Close()
	}
}

func (tbox *Zipper) Unzip(path string) error {
	path = Abspath(path)
	for _, file := range tbox.reader.File {
		path := filepath.Join(path, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, os.ModePerm)
			continue
		}

		srcFile, err := file.Open()
		if err != nil {
			return err
		}
		defer srcFile.Close()

		dstFile, err := os.Create(path)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func (tbox *Zipper) Write(path string) error {
	upper := Abspath(path)
	if upper[len(upper)-1] == '/' {
		upper = upper[0 : len(upper)-1]
	}
	upper = upper[:strings.LastIndex(upper, "/")+1]

	zsub := func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Method = zip.Deflate

		header.Name = Abspath(filePath)[len(upper):]
		writer, err := tbox.writer.Create(header.Name)
		if info.IsDir() || err != nil {
			return err
		}
		srcFile, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		_, err = io.Copy(writer, srcFile)
		return err
	}
	return filepath.Walk(path, zsub)
}

// progress percentage bar
type ProgBar struct {
	max     int
	current int
}

func (tbox *ProgBar) Init(m int) {
	tbox.max = m
	tbox.current = 0
	fmt.Printf("[%s]\n[", strings.Repeat("=", m))
}

func (tbox *ProgBar) Set(f float64) {
	num := min(int(float64(tbox.max)*f), tbox.max)
	if tbox.current < num {
		fmt.Print(strings.Repeat("=", num-tbox.current))
		tbox.current = num
		if num == tbox.max {
			fmt.Println("]")
		}
	}
}
