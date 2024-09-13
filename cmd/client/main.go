package main

import (
	"crypto/cipher"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Iam54r1n4/Gordafarid/core/net/stream"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

const (
	laddr       = "127.0.0.1:8080"
	raddr       = "127.0.0.1:9090"
	dialTimeout = time.Second * 10

	password = "00000000000000000000000000000000"
)

func main() {
	// Init logger
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)
	log.SetOutput(os.Stdout)

	// Listen for incoming connections
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Fatal(errors.Join(proxy_error.ErrClientListenFailed, err))
	}
	log.Println("Client is listening on: ", laddr)

	// Init crypto
	chacha, err := chacha20poly1305.New([]byte(password))
	if err != nil {
		log.Fatal(errors.Join(proxy_error.ErrChacha20poly1305Failed, err))
	}

	// Accept & Handle incoming connections
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(errors.Join(proxy_error.ErrConnectionAccepting, err))
			continue
		}
		log.Println("Accepted connection from:", conn.RemoteAddr())
		go handleConnection(chacha, conn)
	}

}

func handleConnection(chacha cipher.AEAD, c net.Conn) {
	defer c.Close()

	// Dial remote server (normal tcp)
	rc, err := net.DialTimeout("tcp", raddr, dialTimeout)
	if err != nil {
		log.Println(errors.Join(proxy_error.ErrClientToServerDialFailed, err))
		return
	}
	// Convert incoming tcp connection into cipher stream (Read/Write methods are overrided)
	rc = stream.NewCipherStream(rc, chacha)
	defer rc.Close()

	// Init bidirectional data transfering
	wg := sync.WaitGroup{}
	wg.Add(2)
	errChan := make(chan error, 2)

	// Goroutine to copy data from client to remote
	go utils.DataTransfering(&wg, errChan, rc, c)
	// Goroutine to copy data from remote to client
	go utils.DataTransfering(&wg, errChan, c, rc)

	// Close the errChan after the dataTransfering goroutines are finished
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Print the possible errors if there any
	for err := range errChan {
		// the EOF error is common for now
		if !errors.Is(err, io.EOF) {
			log.Println(err)
		}
	}
}
