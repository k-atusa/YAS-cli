// test775 : YAS cli main

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

// go mod init example.com
// go mod tidy
// go build -ldflags="-s -w" -trimpath main.go lib.go basic.go

type worker struct {
	mode   int
	input  []string
	output string
	pw     string
	msg    string
	me     string
	you    string
	debug  bool
	sign   bool
}

func (tbox *worker) init() {
	tbox.mode = 0
	tbox.input = make([]string, 0)
	tbox.output = ""
	tbox.pw = ""
	tbox.msg = ""
	tbox.me = ""
	tbox.you = ""
	tbox.debug = false
	tbox.sign = false
}

func (tbox *worker) check() error {
	switch tbox.mode {
	case 1:
		for i, r := range tbox.input {
			tbox.input[i] = Abspath(r)
		}
		if tbox.output == "" {
			tbox.output = "result.bin"
		}
		tbox.output = Abspath(tbox.output)
		if tbox.output[len(tbox.output)-1] == '/' {
			return errors.New("output path should be a file")
		}

	case 2:
		if len(tbox.input) == 0 {
			return errors.New("no input file")
		}
		tbox.input[0] = Abspath(tbox.input[0])
		if tbox.input[0][len(tbox.input[0])-1] == '/' {
			return errors.New("input path should be a file")
		}
		if tbox.output == "" {
			tbox.output = "./"
		}
		tbox.output = Abspath(tbox.output)
		if tbox.output[len(tbox.output)-1] != '/' {
			return errors.New("output path should be a directory")
		}

	case 3:
		for i, r := range tbox.input {
			tbox.input[i] = Abspath(r)
		}

	case 4:
		if len(tbox.input) == 0 {
			return errors.New("no ip address")
		}
		if tbox.output == "" {
			tbox.output = "./"
		}
		tbox.output = Abspath(tbox.output)
		if tbox.output[len(tbox.output)-1] != '/' {
			return errors.New("output path should be a directory")
		}

	case 5:
		if len(tbox.input) == 0 {
			return errors.New("no input text")
		}
		if tbox.me != "" {
			tbox.me = Abspath(tbox.me)
			if tbox.me[len(tbox.me)-1] == '/' {
				return errors.New("pgp key file should be a file")
			}
		}
		if tbox.you == "" {
			return errors.New("no pgp key file")
		}
		if tbox.you != "" {
			tbox.you = Abspath(tbox.you)
			if tbox.you[len(tbox.you)-1] == '/' {
				return errors.New("pgp key file should be a file")
			}
		}
		return tbox.load()

	case 6:
		if len(tbox.input) == 0 {
			return errors.New("no input text")
		}
		if tbox.me == "" {
			return errors.New("no pgp key file")
		}
		if tbox.me != "" {
			tbox.me = Abspath(tbox.me)
			if tbox.me[len(tbox.me)-1] == '/' {
				return errors.New("pgp key file should be a file")
			}
		}
		if tbox.you != "" {
			tbox.you = Abspath(tbox.you)
			if tbox.you[len(tbox.you)-1] == '/' {
				return errors.New("pgp key file should be a file")
			}
		}
		return tbox.load()

	case 7:
		for i, r := range tbox.input {
			tbox.input[i] = Abspath(r)
		}
		if tbox.output == "" {
			tbox.output = "result.bin"
		}
		tbox.output = Abspath(tbox.output)
		if tbox.output[len(tbox.output)-1] == '/' {
			return errors.New("output path should be a file")
		}
		if tbox.me != "" {
			tbox.me = Abspath(tbox.me)
			if tbox.me[len(tbox.me)-1] == '/' {
				return errors.New("pgp key file should be a file")
			}
		}
		if tbox.you == "" {
			return errors.New("no pgp key file")
		}
		if tbox.you != "" {
			tbox.you = Abspath(tbox.you)
			if tbox.you[len(tbox.you)-1] == '/' {
				return errors.New("pgp key file should be a file")
			}
		}
		return tbox.load()

	case 8:
		if len(tbox.input) == 0 {
			return errors.New("no input file")
		}
		tbox.input[0] = Abspath(tbox.input[0])
		if tbox.input[0][len(tbox.input[0])-1] == '/' {
			return errors.New("input path should be a file")
		}
		if tbox.output == "" {
			tbox.output = "./"
		}
		tbox.output = Abspath(tbox.output)
		if tbox.output[len(tbox.output)-1] != '/' {
			return errors.New("output path should be a directory")
		}
		if tbox.me == "" {
			return errors.New("no pgp key file")
		}
		if tbox.me != "" {
			tbox.me = Abspath(tbox.me)
			if tbox.me[len(tbox.me)-1] == '/' {
				return errors.New("pgp key file should be a file")
			}
		}
		if tbox.you != "" {
			tbox.you = Abspath(tbox.you)
			if tbox.you[len(tbox.you)-1] == '/' {
				return errors.New("pgp key file should be a file")
			}
		}
		return tbox.load()

	case 9:
		if tbox.output == "" {
			tbox.output = "./"
		}
		tbox.output = Abspath(tbox.output)
		if tbox.output[len(tbox.output)-1] != '/' {
			return errors.New("output path should be a directory")
		}
	}
	return nil
}

// load pgp key from file
func (tbox *worker) load() error {
	if tbox.me != "" {
		sz := Getsize(tbox.me)
		if sz < 1 {
			return errors.New("pgp key file not found")
		}
		f, err := os.Open(tbox.me)
		if err == nil {
			defer f.Close()
		} else {
			return err
		}
		private, err := Readfile(f, sz)
		if err != nil {
			return err
		}
		tbox.me = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(private), " ", ""), "\n", ""), "\r", "")
	}

	if tbox.you != "" {
		sz := Getsize(tbox.you)
		if sz < 1 {
			return errors.New("pgp key file not found")
		}
		t, err := os.Open(tbox.you)
		if err == nil {
			defer t.Close()
		} else {
			return err
		}
		public, err := Readfile(t, sz)
		if err != nil {
			return err
		}
		tbox.you = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(public), " ", ""), "\n", ""), "\r", "")
	}
	return nil
}

// manual file encryption
func (tbox *worker) enc() error {
	for r := range tbox.input {
		if tbox.input[r][len(tbox.input[r])-1] == '/' {
			return errors.New("input path should be a file")
		}
	}
	var engine YAS_aes
	engine.Msg = tbox.msg
	engine.Encrypt(tbox.input, tbox.output, tbox.pw)
	if engine.Err == "" {
		fmt.Println("Done!")
		return nil
	} else {
		return errors.New(engine.Err)
	}
}

// manual file decryption
func (tbox *worker) dec() error {
	var engine YAS_aes
	engine.View(tbox.input[0])
	if engine.Err == "" {
		fmt.Printf("MSG : %s\n", engine.Msg)
	} else {
		return errors.New(engine.Err)
	}
	engine.Decrypt(tbox.input[0], tbox.output, tbox.pw)
	if engine.Err == "" {
		fmt.Println("Done!")
		return nil
	} else {
		return errors.New(engine.Err)
	}
}

// automatic send
func (tbox *worker) send() error {
	var secure YAS_rsa
	fmt.Println("generating RSA key...") // make key and open port
	public, private := secure.Genkey(false)
	if secure.Err != "" {
		return errors.New(secure.Err)
	}
	if tbox.debug {
		fmt.Printf("session public key : %s\n", B64en(public))
		fmt.Printf("session private key : %s\n", B64en(private))
	}
	port := 5000 + rand.Intn(60000)
	fmt.Printf("opening port %d...\n", port)
	svr, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err == nil {
		defer svr.Close()
	} else {
		return err
	}

	addrs, err := net.InterfaceAddrs() // get local ip
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					fmt.Printf("IP %s:%d\n", ipnet.IP.String(), port)
				}
			}
		}
	} else {
		return err
	}

	conn, err := svr.Accept() // make connection
	if err == nil {
		defer conn.Close()
		fmt.Println("starting session...")
	} else {
		return err
	}

	// step 1 : send public key & receive pw
	fmt.Println("exchanging secret key...")
	if _, err = conn.Write(append(Encode(len(public), 8), public...)); err != nil {
		return err
	}
	buf := make([]byte, 8)
	conn.Read(buf)
	buf = make([]byte, Decode(buf))
	conn.Read(buf)
	pw := strings.ToLower(hex.EncodeToString(secure.Decrypt(buf)))
	if secure.Err != "" {
		return errors.New(secure.Err)
	}
	if tbox.debug {
		fmt.Printf("session password : %s\n", pw)
	}

	// step 2 : wait zip & encryption
	var engine YAS_aes
	done := make(chan bool)
	cycle := true
	go tbox.send_sub(&engine, pw, done)
	if !tbox.debug {
		defer os.Remove("./yas_buffer")
	}
	for cycle {
		select {
		case <-done:
			cycle = false
		default:
			conn.Write(make([]byte, 8))
			time.Sleep(1 * time.Second)
		}
	}
	if engine.Err != "" {
		conn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		return errors.New(engine.Err)
	}

	// step 3 : send buffer file
	var prog ProgBar
	fmt.Println("start transmitting...")
	prog.Init(50)
	f, err := os.Open("./yas_buffer")
	if err == nil {
		defer f.Close()
	} else {
		return err
	}
	sz := Getsize("./yas_buffer")
	if _, e := conn.Write(Encode(sz, 8)); e != nil {
		return e
	}
	count := 0
	buf = make([]byte, 1024)
	for count < sz {
		f.Seek(int64(count), 0)
		n, e := f.Read(buf)
		if e != nil && e != io.EOF {
			return e
		}
		n, e = conn.Write(buf[:n])
		if e != nil {
			return e
		}
		count = count + n
		prog.Set(float64(count) / float64(sz))
	}
	buf = make([]byte, 8)
	conn.Read(buf)
	if Decode(buf) != 0 {
		fmt.Println("Warning : invalid socket exit sign")
	}
	prog.Set(2.0)
	fmt.Println("Done!")
	return nil
}

func (tbox *worker) send_sub(engine *YAS_aes, pw string, s chan bool) {
	defer func() { s <- true }()
	fmt.Println("making zip file...")
	var zf Zipper
	err := zf.Open("./yas_chunk.zip", false)
	if !tbox.debug {
		defer os.Remove("./yas_chunk.zip")
	}
	if err != nil {
		engine.Err = err.Error()
		zf.Close()
		return
	}
	for _, r := range tbox.input {
		fmt.Printf("target : %s\n", r)
		if err := zf.Write(r); err != nil {
			engine.Err = err.Error()
			zf.Close()
			return
		}
	}
	zf.Close()
	fmt.Println("encrypting...")
	engine.Encrypt([]string{"./yas_chunk.zip"}, "./yas_buffer", pw)
}

// automatic receive
func (tbox *worker) receive() error {
	fmt.Println("starting session...") // make connection
	cli, err := net.Dial("tcp", tbox.input[0])
	if err == nil {
		defer cli.Close()
	} else {
		return err
	}

	// step 1 : get public key & send pw
	var secure YAS_rsa
	fmt.Println("exchanging secret key...")
	buf := make([]byte, 8)
	if _, err = cli.Read(buf); err != nil {
		return err
	}
	buf = make([]byte, Decode(buf))
	if _, err = cli.Read(buf); err != nil {
		return err
	}
	secure.Loadkey(buf, nil)
	if secure.Err != "" {
		return errors.New(secure.Err)
	}
	if tbox.debug {
		fmt.Printf("session public key : %s\n", B64en(buf))
	}

	pwb := Genrand(32)
	pw := strings.ToLower(hex.EncodeToString(pwb))
	buf = secure.Encrypt(pwb)
	cli.Write(Encode(len(buf), 8))
	cli.Write(buf)
	if secure.Err != "" {
		return errors.New(secure.Err)
	}
	if tbox.debug {
		fmt.Printf("session password : %s\n", pw)
	}

	// step 2 : wait & receive file
	fmt.Println("waiting for sender...")
	sz := 0
	cycle := true
	for cycle {
		buf = make([]byte, 8)
		if _, err = cli.Read(buf); err != nil {
			return err
		}
		if bytes.Equal(buf, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
			return errors.New("sender quit transmittion")
		}
		if sz = Decode(buf); sz != 0 {
			cycle = false
		}
	}

	fmt.Println("start receiving...")
	var prog ProgBar
	prog.Init(50)
	f, err := os.Create("./yas_buffer")
	if !tbox.debug {
		defer os.Remove("./yas_buffer")
	}
	if err != nil {
		f.Close()
		return err
	}
	count := 0
	buf = make([]byte, 1024)
	for count < sz {
		n, e := cli.Read(buf)
		if e != nil {
			f.Close()
			return e
		}
		n, e = f.Write(buf[:n])
		if e != nil {
			f.Close()
			return e
		}
		count = count + n
		prog.Set(float64(count) / float64(sz))
	}
	f.Close()
	cli.Write(make([]byte, 8))
	prog.Set(2.0)

	// step 3 : decryption & unzip
	var engine YAS_aes
	fmt.Println("decrypting...")
	engine.Decrypt("./yas_buffer", "./", pw)
	if !tbox.debug {
		defer os.Remove("./yas_chunk.zip")
	}
	if engine.Err != "" {
		return errors.New(engine.Err)
	}
	fmt.Println("unzipping file...")
	var zf Zipper
	err = zf.Open("./yas_chunk.zip", true)
	if err == nil {
		defer zf.Close()
	} else {
		return err
	}
	if err = zf.Unzip(tbox.output); err != nil {
		return err
	}
	fmt.Println("Done!")
	return nil
}

// pgp text encryption
func (tbox *worker) pgpenc() error {
	// step 1 : load keys
	var secure_me YAS_rsa
	var secure_you YAS_rsa
	fmt.Println("loading key...")
	if tbox.me != "" {
		secure_me.Loadkey(nil, B64de(tbox.me))
		if secure_me.Err != "" {
			return errors.New(secure_me.Err)
		}
	}
	if tbox.you != "" {
		secure_you.Loadkey(B64de(tbox.you), nil)
		if secure_you.Err != "" {
			return errors.New(secure_you.Err)
		}
	}

	// step 2 : encrypt key
	fmt.Println("encrypting key...")
	pwb := Genrand(32)
	pwb_data := secure_you.Encrypt(pwb)
	if secure_you.Err != "" {
		return errors.New(secure_you.Err)
	}

	// step 3 : sign message
	var sign_data []byte
	if tbox.sign {
		fmt.Println("signing key...")
		sign_data = secure_me.Sign(pwb)
		if secure_me.Err != "" {
			return errors.New(secure_me.Err)
		}
	}

	// step 4 : encrypt message
	fmt.Println("encrypting message...")
	msg_data := Aes128([]byte(tbox.input[0]), pwb[16:], pwb[:16], true, true)
	fmt.Println("========== BEGIN MESSAGE ==========")
	fmt.Printf("%s,%s,%s\n", B64en(pwb_data), B64en(sign_data), B64en(msg_data))
	fmt.Println("========== END MESSAGE ==========")
	fmt.Println("Done!")
	return nil
}

// pgp text decryption
func (tbox *worker) pgpdec() error {
	// step 1 : load keys
	var secure_me YAS_rsa
	var secure_you YAS_rsa
	fmt.Println("loading key...")
	if tbox.me != "" {
		secure_me.Loadkey(nil, B64de(tbox.me))
		if secure_me.Err != "" {
			return errors.New(secure_me.Err)
		}
	}
	if tbox.you != "" {
		secure_you.Loadkey(B64de(tbox.you), nil)
		if secure_you.Err != "" {
			return errors.New(secure_you.Err)
		}
	}

	// step 2 : decrypt key
	fmt.Println("decrypting key...")
	data := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(tbox.input[0], " ", ""), "\n", ""), "\r", "")
	parts := strings.Split(strings.ReplaceAll(data, ".", ","), ",")
	if len(parts) != 3 {
		return errors.New("invalid message format")
	}
	pwb_data := B64de(parts[0])
	pwb := secure_me.Decrypt(pwb_data)
	if secure_me.Err != "" {
		return errors.New(secure_me.Err)
	}

	// step 3 : verify signature
	if tbox.sign {
		fmt.Println("verifying signature...")
		if len(parts[1]) == 0 {
			fmt.Println("WARN : no signature data")
		} else {
			sign_data := B64de(parts[1])
			res := secure_you.Verify(pwb, sign_data)
			if secure_me.Err != "" {
				return errors.New(secure_me.Err)
			}
			if res {
				fmt.Println("signature verified")
			} else {
				fmt.Println("WARN : signature verification failed")
			}
		}
	}

	// step 4 : decrypt message
	fmt.Println("decrypting message...")
	msg_data := B64de(parts[2])
	msg := string(Aes128(msg_data, pwb[16:], pwb[:16], true, false))
	fmt.Println("========== BEGIN MESSAGE ==========")
	fmt.Println(msg)
	fmt.Println("========== END MESSAGE ==========")
	fmt.Println("Done!")
	return nil
}

// pgp data encryption
func (tbox *worker) pgpsend() error {
	// step 1 : load keys
	var secure_me YAS_rsa
	var secure_you YAS_rsa
	fmt.Println("loading key...")
	if tbox.me != "" {
		secure_me.Loadkey(nil, B64de(tbox.me))
		if secure_me.Err != "" {
			return errors.New(secure_me.Err)
		}
	}
	if tbox.you != "" {
		secure_you.Loadkey(B64de(tbox.you), nil)
		if secure_you.Err != "" {
			return errors.New(secure_you.Err)
		}
	}

	// step 2 : encrypt key
	fmt.Println("encrypting key...")
	pwb := Genrand(32)
	pwb_data := secure_you.Encrypt(pwb)
	pw := strings.ToLower(hex.EncodeToString(pwb))
	if secure_you.Err != "" {
		return errors.New(secure_you.Err)
	}

	// step 3 : sign message
	var sign_data []byte
	if tbox.sign {
		fmt.Println("signing key...")
		sign_data = secure_me.Sign(pwb)
		if secure_me.Err != "" {
			return errors.New(secure_me.Err)
		}
	}

	// step 4 : zip data
	fmt.Println("making zip file...")
	var zf Zipper
	err := zf.Open("./yas_chunk.zip", false)
	if !tbox.debug {
		defer os.Remove("./yas_chunk.zip")
	}
	if err != nil {
		zf.Close()
		return err
	}
	for _, r := range tbox.input {
		fmt.Printf("target : %s\n", r)
		if err := zf.Write(r); err != nil {
			zf.Close()
			return err
		}
	}
	zf.Close()

	// step 5 : encrypt data
	var engine YAS_aes
	fmt.Println("encrypting...")
	engine.Msg = B64en(pwb_data) + "," + B64en(sign_data)
	if tbox.debug {
		fmt.Printf("session password : %s\n", pw)
		fmt.Printf("session message : %s\n", engine.Msg)
	}
	engine.Encrypt([]string{"./yas_chunk.zip"}, tbox.output, pw)
	if engine.Err == "" {
		fmt.Println("Done!")
		return nil
	} else {
		return errors.New(engine.Err)
	}
}

// pgp data decryption
func (tbox *worker) pgpreceive() error {
	// step 1 : load keys
	var secure_me YAS_rsa
	var secure_you YAS_rsa
	fmt.Println("loading key...")
	if tbox.me != "" {
		secure_me.Loadkey(nil, B64de(tbox.me))
		if secure_me.Err != "" {
			return errors.New(secure_me.Err)
		}
	}
	if tbox.you != "" {
		secure_you.Loadkey(B64de(tbox.you), nil)
		if secure_you.Err != "" {
			return errors.New(secure_you.Err)
		}
	}

	// step 2 : decrypt key
	fmt.Println("decrypting key...")
	var engine YAS_aes
	engine.View(tbox.input[0])
	if engine.Err != "" {
		return errors.New(engine.Err)
	}
	parts := strings.Split(engine.Msg, ",")
	if len(parts) != 2 {
		return errors.New("invalid message format")
	}
	pwb_data := B64de(parts[0])
	pwb := secure_me.Decrypt(pwb_data)
	pw := strings.ToLower(hex.EncodeToString(pwb))
	if secure_me.Err != "" {
		return errors.New(secure_me.Err)
	}
	if tbox.debug {
		fmt.Printf("session password : %s\n", pw)
		fmt.Printf("session message : %s\n", engine.Msg)
	}

	// step 3 : verify signature
	if tbox.sign {
		fmt.Println("verifying signature...")
		if len(parts[1]) == 0 {
			fmt.Println("WARN : no signature data")
		} else {
			sign_data := B64de(parts[1])
			res := secure_you.Verify(pwb, sign_data)
			if secure_me.Err != "" {
				return errors.New(secure_me.Err)
			}
			if res {
				fmt.Println("signature verified")
			} else {
				fmt.Println("WARN : signature verification failed")
			}
		}
	}

	// step 4 : decrypt data
	fmt.Println("decrypting data...")
	engine.Decrypt(tbox.input[0], "./", pw)
	if !tbox.debug {
		defer os.Remove("./yas_chunk.zip")
	}
	if engine.Err != "" {
		return errors.New(engine.Err)
	}

	// step 5 : unzip data
	fmt.Println("unzipping file...")
	var zf Zipper
	err := zf.Open("./yas_chunk.zip", true)
	if err == nil {
		defer zf.Close()
	} else {
		return err
	}
	if err = zf.Unzip(tbox.output); err != nil {
		return err
	}
	fmt.Println("Done!")
	return nil
}

// generate pgp key
func (tbox *worker) pgpgenkey() error {
	var secure YAS_rsa
	fmt.Println("generating RSA key...")
	public, private := secure.Genkey(tbox.sign)
	if secure.Err != "" {
		return errors.New(secure.Err)
	}
	f, err := os.Create(tbox.output + "public.txt")
	if err == nil {
		defer f.Close()
	} else {
		return err
	}
	if _, err = f.Write([]byte(B64en(public))); err != nil {
		return err
	}
	t, err := os.Create(tbox.output + "private.txt")
	if err == nil {
		defer t.Close()
	} else {
		return err
	}
	if _, err = t.Write([]byte(B64en(private))); err != nil {
		return err
	}
	fmt.Println("Done!")
	return nil
}

// print help message
func (tbox *worker) prthelp() {
	fmt.Print("YAS-cli v2.0 [2025 k-atusa]\n\n")
	fmt.Print("manual file encryption\nyas -e [-i file|dir] [-o output] [-pw password] [-msg message] [-debug]\n\n")
	fmt.Print("manual file decryption\nyas -d [-i file] [-o output] [-pw password] [-debug]\n\n")
	fmt.Print("automatic send\nyas -s [-i file|dir] [-debug]\n\n")
	fmt.Print("automatic receive\nyas -r [-i ip:port] [-o output] [-debug]\n\n")
	fmt.Print("pgp text encryption\nyas -pe [-i text] [-me file] [-you file] [-sign]\n\n")
	fmt.Print("pgp text decryption\nyas -pd [-i text] [-me file] [-you file] [-sign]\n\n")
	fmt.Print("pgp data encryption\nyas -ps [-i file|dir] [-o output] [-me file] [-you file] [-sign] [-debug]\n\n")
	fmt.Print("pgp data decryption\nyas -pr [-i file] [-o output] [-me file] [-you file] [-sign] [-debug]\n\n")
	fmt.Print("generate pgp key\nyas -pk [-o output] [-sign]\n\n")
	fmt.Print("help message\nyas -h\n\n")
}

func main() {
	var k worker
	k.init()
	defer time.Sleep(3 * time.Second)
	if len(os.Args) < 2 {
		fmt.Println("use 'yas -h' for help")
		return
	}

	pos := 1
	for pos < len(os.Args) {
		switch os.Args[pos] {
		case "-e":
			k.mode = 1
		case "-d":
			k.mode = 2
		case "-s":
			k.mode = 3
		case "-r":
			k.mode = 4
		case "-pe":
			k.mode = 5
		case "-pd":
			k.mode = 6
		case "-ps":
			k.mode = 7
		case "-pr":
			k.mode = 8
		case "-pk":
			k.mode = 9
		case "-h":
			k.mode = 0
		case "-i":
			pos = pos + 1
			if pos < len(os.Args) {
				k.input = append(k.input, os.Args[pos])
			} else {
				fmt.Println("WARN : no word after -i")
			}
		case "-o":
			pos = pos + 1
			if pos < len(os.Args) {
				k.output = os.Args[pos]
			} else {
				k.output = ""
				fmt.Println("WARN : no word after -o")
			}
		case "-pw":
			pos = pos + 1
			if pos < len(os.Args) {
				k.pw = os.Args[pos]
			} else {
				k.pw = ""
				fmt.Println("WARN : no word after -pw")
			}
		case "-msg":
			pos = pos + 1
			if pos < len(os.Args) {
				k.msg = os.Args[pos]
			} else {
				k.msg = ""
				fmt.Println("WARN : no word after -msg")
			}
		case "-me":
			pos = pos + 1
			if pos < len(os.Args) {
				k.me = os.Args[pos]
			} else {
				k.me = ""
				fmt.Println("WARN : no word after -me")
			}
		case "-you":
			pos = pos + 1
			if pos < len(os.Args) {
				k.you = os.Args[pos]
			} else {
				k.you = ""
				fmt.Println("WARN : no word after -you")
			}
		case "-debug":
			k.debug = true
		case "-sign":
			k.sign = true
		default:
			k.input = append(k.input, os.Args[pos])
			fmt.Println("WARN : implicit option -i for " + os.Args[pos])
		}
		pos = pos + 1
	}

	err := k.check()
	if err != nil {
		fmt.Printf("ERROR : %s\n", err)
		return
	}
	switch k.mode {
	case 1:
		err = k.enc()
	case 2:
		err = k.dec()
	case 3:
		err = k.send()
	case 4:
		err = k.receive()
	case 5:
		err = k.pgpenc()
	case 6:
		err = k.pgpdec()
	case 7:
		err = k.pgpsend()
	case 8:
		err = k.pgpreceive()
	case 9:
		err = k.pgpgenkey()
	default:
		k.prthelp()
	}
	if err != nil {
		fmt.Printf("ERROR : %s\n", err)
	}
}
