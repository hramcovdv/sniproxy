package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

func main() {
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}

	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go handleConnection(connection)
	}
}

func peekClientHello(in io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	buf := new(bytes.Buffer)
	info, err := readClientHello(io.TeeReader(in, buf))
	if err != nil {
		return nil, nil, err
	}
	return info, io.MultiReader(buf, in), nil
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	hello := new(tls.ClientHelloInfo)

	config := &tls.Config{
		GetConfigForClient: func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
			*hello = *clientHello
			return nil, nil
		},
	}

	conn := tls.Server(readOnlyConn{reader: reader}, config)
	err := conn.Handshake()
	if err != nil {
		return nil, err
	}

	return hello, nil
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set initial read deadline
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}

	hello, clientReader, err := peekClientHello(clientConn)
	if err != nil {
		return
	}

	// Clear read deadline
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	backendConn, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort(hello.ServerName, "443"),
		5*time.Second,
	)
	if err != nil {
		return
	}
	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Forward client to backend
	go func() {
		defer wg.Done()
		io.Copy(clientConn, backendConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Forward backend to client
	go func() {
		defer wg.Done()
		io.Copy(backendConn, clientReader)
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}
