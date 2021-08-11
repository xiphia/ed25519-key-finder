package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
)

const headerString string = "openssh-key-v1\x00"
const fixedValue0 uint8 = 0
const fixedValue1 uint32 = 1
const encryptionMode string = "none"
const kdfMode string = "none"
var kdfBody []byte = nil
const keyType string = "ssh-ed25519"
const pemType string = "OPENSSH PRIVATE KEY"

func writeStringWithLength(buf *bytes.Buffer, str string) int {
	l := uint32(len(str))
	err := binary.Write(buf, binary.BigEndian, l)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	n, err := buf.WriteString(str)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	return n
}

func writeBytesWithLength(buf *bytes.Buffer, b []byte) int {
	l := uint32(len(b))
	err := binary.Write(buf, binary.BigEndian, l)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	n, err := buf.Write(b)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	return n
}

func generateHeader(buf *bytes.Buffer) {
	buf.WriteString(headerString)
	buf.WriteByte(fixedValue0)
	writeStringWithLength(buf, encryptionMode)
	writeStringWithLength(buf, kdfMode)
	writeBytesWithLength(buf, kdfBody)
	err := binary.Write(buf, binary.BigEndian, fixedValue1)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

func generatePublicKeyRecord(buf *bytes.Buffer, key ed25519.PublicKey) {
	writeBytesWithLength(buf, key)
}

func createRandomNumber() []byte {
	random := make([]byte, 4)
	n, err := rand.Read(random)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	if n != 4 {
		log.Fatalf("Error: couldn't read random number.")
	}
	return random
}

func generatePrivateKeyRecord(buf *bytes.Buffer, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, comment string) {
	random := createRandomNumber()
	recordLength := len(random) * 2 + 4 + len(keyType) + 4 + len(publicKey) + 4 + len(privateKey) + 4 + len(comment)
	padding := (8 - (recordLength % 8)) % 8
	err := binary.Write(buf, binary.BigEndian, uint32(recordLength + padding))
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	writeStringWithLength(buf, comment)
	writeBytesWithLength(buf, publicKey)
	writeBytesWithLength(buf, privateKey)
	writeStringWithLength(buf, comment)
	for i := 0; i < padding; i++ {
		buf.WriteByte(uint8(i + 1))
	}
}

func generatePrivateKeyData(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, comment string) []byte {
	buf := new(bytes.Buffer)
	generateHeader(buf)
	generatePublicKeyRecord(buf, publicKey)
	generatePrivateKeyRecord(buf, publicKey, privateKey, comment)
	return buf.Bytes()
}

func generatePublicKeyData(key ed25519.PublicKey) []byte {
	buf := new(bytes.Buffer)
	writeStringWithLength(buf, keyType)
	writeBytesWithLength(buf, key)
	return buf.Bytes()
}

func createPrivateKeyFile(path string, data []byte) (e error) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	defer func() { e = f.Close() }()
	err = pem.Encode(f, &pem.Block{ Type: pemType, Bytes: data })
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	return nil
}

func createPublicKeyFile(path string, data string, comment string) (e error) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	defer func() { e = f.Close() }()
	_, err = f.WriteString(keyType + " " + data + " " + comment + "\n")
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	return nil
}

func getDefaultComment() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	username := currentUser.Username
	return username + "@" + hostname
}

var (
	cond = kingpin.Arg("condition", "search condition").Required().Regexp()
	comment = kingpin.Flag("comment", "comment for key").Default(getDefaultComment()).Short('c').String()
	limited = kingpin.Flag("limited", "search until find the specified number of key pairs").Default("1").Short('l').Int()
	unlimited = kingpin.Flag("unlimited", "search key pairs until you stop").Default("false").Short('u').Bool()
	parallel = kingpin.Flag("parallel", "concurrency of key pair search").Default("1").Short('p').Int()
)

type Message struct {
	ID int
	Message string
}

type KeyPair struct {
	Public ed25519.PublicKey
	Private ed25519.PrivateKey
}

const msgFound = "found"
const msgCount = "count"
const msgQuit = "quit"

func searchHandler(n int) {
	ch := make([]chan Message, n)
	mch := make(chan Message, 16)
	defer close(mch)
	rch := make(chan KeyPair, *limited)
	defer close(rch)
	sch := make(chan int, n)
	defer close(sch)

	start := time.Now().UnixNano()

	for i := range ch {
		ch[i] = make(chan Message)
		go searchKeyPair(mch, ch[i], rch, sch, i)
	}

	found := 0
	var count uint64 = 0
	MessageLoop:
	for {
		select {
		case m := <-mch:
			if strings.HasPrefix(m.Message, msgFound) {
				found++
				log.Println("Found: " + strings.TrimSpace(strings.TrimPrefix(m.Message, msgFound)))
				if found >= *limited && !(*unlimited) {
					for i := range ch {
						ch[i] <- Message{ID: -1, Message: msgQuit}
					}
				}
			} else if strings.HasPrefix(m.Message, msgCount) {
				cnt, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(m.Message, msgCount)))
				if err != nil {
					log.Fatalf("Error: %v", err)
				}
				count += uint64(cnt)
			}
			if found >= *limited && !(*unlimited) && len(sch) == n && len(mch) == 0 {
				break MessageLoop
			}
		default:
		}
	}
	end := time.Now().UnixNano()

	suffix := 0
	for {
		r := <-rch
		basename := fmt.Sprintf("id_ed25519_%02d", suffix)
		err := createPrivateKeyFile(basename, generatePrivateKeyData(r.Public, r.Private, *comment))
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		err = createPublicKeyFile(fmt.Sprintf("%s.pub", basename), base64.StdEncoding.EncodeToString(generatePublicKeyData(r.Public)), *comment)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		suffix++
		if len(rch) == 0 {
			break
		}
	}

	duration := end - start
	throughput := count * uint64(1000000000) / uint64(duration)
	log.Printf("Time: %d sec", duration / 1000000000)
	log.Printf("Total Generated Pairs: %d pairs", count)
	log.Printf("Throughput: %d pairs/sec", throughput)
}

func searchKeyPair(msg chan Message, ctrl chan Message, result chan KeyPair, sig chan int, id int) {
	var count uint64 = 0
	SearchLoop:
	for {
		count++
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		publicKeyBody := generatePublicKeyData(publicKey)
		b64PublicKeyBody := base64.StdEncoding.EncodeToString(publicKeyBody)
		if (*cond).MatchString(b64PublicKeyBody) {
			msg <- Message{ ID: id, Message: fmt.Sprintf("%s %s", msgFound, b64PublicKeyBody) }
			msg <- Message{ ID: id, Message: fmt.Sprintf("%s %d", msgCount, count) }
			count = 0
			result <- KeyPair{ Public: publicKey, Private: privateKey }
		}
		select {
		case m := <-ctrl:
			if m.Message == msgQuit {
				close(ctrl)
				break SearchLoop
			}
		default:
		}
	}
	msg <- Message{ID: id, Message: fmt.Sprintf("%s %d", msgCount, count)}
	sig <- id
}

func main() {
	kingpin.Parse()
	log.Println("Start ed25519 key search")
	searchHandler(*parallel)
	log.Println("Complete ed25519 key search")
}
