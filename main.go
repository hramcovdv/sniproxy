package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

var (
	errClientHelloPeeked = errors.New("client hello peeked")
	logger               = slog.Default()

	dialBackend = func(serverName string) (net.Conn, error) {
		return net.DialTimeout(
			"tcp",
			net.JoinHostPort(serverName, "443"),
			5*time.Second,
		)
	}
)

func main() {
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		logger.Error("listen failed", "addr", ":443", "err", err)
		return
	}

	logger.Info("server started", "addr", listener.Addr())

	for {
		connection, err := listener.Accept()
		if err != nil {
			logger.Error("accept failed", "err", err)
			continue
		}

		logger.Info("incoming connection", "remote_addr", connection.RemoteAddr(), "local_addr", connection.LocalAddr())

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
			return nil, errClientHelloPeeked
		},
	}

	conn := tls.Server(readOnlyConn{reader: reader}, config)
	if err := conn.Handshake(); err != nil {
		if errors.Is(err, errClientHelloPeeked) {
			return hello, nil
		}
		return nil, err
	}

	return hello, nil
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set initial read deadline
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		logger.Error("set initial read deadline failed", "remote_addr", clientConn.RemoteAddr(), "err", err)
		return
	}

	hello, clientReader, err := peekClientHello(clientConn)
	if err != nil {
		logger.Error("peek client hello failed", "remote_addr", clientConn.RemoteAddr(), "err", err)
		return
	}

	// Clear read deadline
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		logger.Error("clear read deadline failed", "remote_addr", clientConn.RemoteAddr(), "server_name", hello.ServerName, "err", err)
		return
	}

	if hello.ServerName == "" {
		logger.Error("missing server name in client hello", "remote_addr", clientConn.RemoteAddr())
		return
	}

	backendConn, err := dialBackend(hello.ServerName)
	if err != nil {
		logger.Error("dial backend failed", "remote_addr", clientConn.RemoteAddr(), "server_name", hello.ServerName, "err", err)
		return
	}
	defer backendConn.Close()

	var wg sync.WaitGroup

	wg.Go(func() {
		if _, err := io.Copy(clientConn, backendConn); err != nil {
			logger.Error("copy backend to client failed", "remote_addr", clientConn.RemoteAddr(), "server_name", hello.ServerName, "err", err)
		}
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			if err := tcpConn.CloseWrite(); err != nil {
				logger.Error("close client write failed", "remote_addr", clientConn.RemoteAddr(), "server_name", hello.ServerName, "err", err)
			}
		}
	})

	// Forward backend to client
	wg.Go(func() {
		if _, err := io.Copy(backendConn, clientReader); err != nil {
			logger.Error("copy client to backend failed", "remote_addr", clientConn.RemoteAddr(), "server_name", hello.ServerName, "err", err)
		}
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			if err := tcpConn.CloseWrite(); err != nil {
				logger.Error("close backend write failed", "remote_addr", clientConn.RemoteAddr(), "server_name", hello.ServerName, "err", err)
			}
		}
	})

	wg.Wait()
}
