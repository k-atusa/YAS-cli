package main

// go mod init example.com
// go mod tidy
// go build -ldflags="-s -w" -trimpath main.go yas_go.go

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

type worker struct {
	debug  bool
	mode   int // send 0, recv 1, enc 2, dec 3
	pw     string
	msg    string
	input  []string // files, folder, ip
	output string   // file, folder
	engine YAS_go
}

// send files or folder
func (tbox *worker) send() error {
	fmt.Println("generating RSA key...") // make key and open port
	public := tbox.engine.GenKey(len(tbox.input) > 1)
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
	if _, err = conn.Write(append(encode(len(public), 8), public...)); err != nil {
		return err
	}
	buf := make([]byte, 8)
	conn.Read(buf)
	buf = make([]byte, decode(buf))
	conn.Read(buf)
	pw := strings.ToLower(hex.EncodeToString(tbox.engine.RSAcrypt(buf, false)))

	// step 2 : wait zip & encryption
	done := make(chan bool)
	cycle := true
	go tbox.send_sub(pw, done)
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
	if tbox.engine.Err != "" {
		conn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		return errors.New(tbox.engine.Err)
	}

	// step 3 : send buffer file
	fmt.Println("start transmitting...")
	var prog ProgBar
	prog.Init(50)
	f, err := os.Open("./yas_buffer")
	if err == nil {
		defer f.Close()
	} else {
		return err
	}
	sz := getsize("./yas_buffer")
	if _, e := conn.Write(encode(sz, 8)); e != nil {
		return e
	}
	count := 0
	buf = make([]byte, 1024)
	for count < sz {
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
	prog.Set(2.0)
	fmt.Println("Done!")
	return nil
}

func (tbox *worker) send_sub(pw string, s chan bool) {
	defer func() { s <- true }()
	fmt.Println("making zip file...")
	var zf Zipper
	err := zf.Open("./yas_chunk.zip", false)
	if !tbox.debug {
		defer os.Remove("./yas_chunk.zip")
	}
	if err != nil {
		tbox.engine.Err = err.Error()
		zf.Close()
		return
	}
	for _, r := range tbox.input {
		fmt.Printf("target : %s\n", r)
		if err := zf.Write(r); err != nil {
			tbox.engine.Err = err.Error()
			zf.Close()
			return
		}
	}
	zf.Close()
	fmt.Println("encrypting...")
	tbox.engine.Encrypt([]string{"./yas_chunk.zip"}, "./yas_buffer", pw)
}

// recv from ip and port
func (tbox *worker) recv() error {
	fmt.Println("starting session...") // make connection
	cli, err := net.Dial("tcp", tbox.input[0])
	if err == nil {
		defer cli.Close()
	} else {
		return err
	}

	// step 1 : get public key & send pw
	fmt.Println("exchanging secret key...")
	buf := make([]byte, 8)
	if _, err = cli.Read(buf); err != nil {
		return err
	}
	buf = make([]byte, decode(buf))
	if _, err = cli.Read(buf); err != nil {
		return err
	}
	tbox.engine.LoadKey(buf)

	pwb := genrand(32)
	pw := strings.ToLower(hex.EncodeToString(pwb))
	buf = tbox.engine.RSAcrypt(pwb, true)
	cli.Write(encode(len(buf), 8))
	cli.Write(buf)

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
		if sz = decode(buf); sz != 0 {
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
	prog.Set(2.0)

	// step 3 : decryption & unzip
	fmt.Println("decrypting...")
	tbox.engine.Decrypt("./yas_buffer", "./", pw)
	if !tbox.debug {
		defer os.Remove("./yas_chunk.zip")
	}
	if tbox.engine.Err != "" {
		return errors.New(tbox.engine.Err)
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

// encrypt files
func (tbox *worker) enc() error {
	for _, r := range tbox.input {
		if r == "" {
			return errors.New("cannot encrypt empty path")
		} else if r[len(r)-1] == '/' {
			return errors.New("cannot encrypt folder")
		}
	}
	if tbox.output == "" {
		tbox.output = "./encrypt.bin"
	}
	tbox.engine.Msg = tbox.msg
	tbox.engine.Encrypt(tbox.input, tbox.output, tbox.pw)
	if tbox.engine.Err == "" {
		fmt.Println("Done!")
		return nil
	} else {
		return errors.New(tbox.engine.Err)
	}
}

// decrypt files
func (tbox *worker) dec() error {
	if len(tbox.input) == 0 {
		return errors.New("no input file")
	} else if tbox.input[0][len(tbox.input[0])-1] == '/' {
		return errors.New("cannot decrypt folder")
	}
	tbox.engine.View(tbox.input[0])
	if tbox.engine.Err == "" {
		fmt.Printf("MSG : %s\n", tbox.engine.Msg)
	} else {
		return errors.New(tbox.engine.Err)
	}
	if tbox.output == "" {
		tbox.output = "./"
	}
	tbox.engine.Decrypt(tbox.input[0], tbox.output, tbox.pw)
	if tbox.engine.Err == "" {
		fmt.Println("Done!")
		return nil
	} else {
		return errors.New(tbox.engine.Err)
	}
}

// manual config input
func (tbox *worker) getconfig() {
	fmt.Println("===== manual configuration =====")
	switch strings.ToLower(Input("mode ( send s / recv r / enc e / dec d ) : ")) {
	case "send", "s":
		tbox.mode = 0
	case "recv", "r":
		tbox.mode = 1
		tbox.input = append(tbox.input, Input("address (IP:port) : "))
	case "enc", "e":
		tbox.mode = 2
		tbox.pw = Input("password : ")
		tbox.msg = Input("message : ")
	case "dec", "d":
		tbox.mode = 3
		tbox.input = []string{Input("target path : ")}
		tbox.pw = Input("password : ")
	default:
		fmt.Println("WARN : invalid mode, SEND selected")
		tbox.mode = 0
	}

	if tbox.mode == 1 || tbox.mode == 2 || tbox.mode == 3 {
		tbox.output = Input("output path : ")
	}
	if tbox.mode == 0 || tbox.mode == 2 {
		temp := Input("target path (ENTER to finish) : ")
		for temp != "" {
			tbox.input = append(tbox.input, Abspath(temp))
			temp = Input("target path (ENTER to finish) : ")
		}
	}
}

func main() {
	var k worker
	k.debug = false
	k.mode = 0
	k.pw = ""
	k.msg = ""
	k.input = make([]string, 0)

	if len(os.Args) < 2 {
		k.getconfig()
	} else {
		pos := 1
		for pos < len(os.Args) {
			switch os.Args[pos] {
			case "-s":
				k.mode = 0
			case "-r":
				k.mode = 1
			case "-e":
				k.mode = 2
			case "-d":
				k.mode = 3
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
			case "-o":
				pos = pos + 1
				if pos < len(os.Args) {
					k.output = os.Args[pos]
				} else {
					k.output = ""
					fmt.Println("WARN : no word after -o")
				}
			case "-debug":
				k.debug = true
			default:
				if k.mode == 1 {
					k.input = append(k.input, os.Args[pos])
				} else {
					k.input = append(k.input, Abspath(os.Args[pos]))
				}
			}
			pos = pos + 1
		}
	}

	var err error
	switch k.mode {
	case 0:
		err = k.send()
	case 1:
		err = k.recv()
	case 2:
		err = k.enc()
	case 3:
		err = k.dec()
	default:
		err = errors.New("invalid mode")
	}
	if err != nil {
		fmt.Printf("ERROR : %s\n", err)
	}
	time.Sleep(3 * time.Second)
}
