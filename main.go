package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

var (
	listenAddress string
	logLevel      string
	dialTimeout   time.Duration = 5 * time.Second

	logger = slog.Default()

	errClientHelloPeeked = errors.New("client hello peeked")

	dialBackend = func(serverName string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(listenAddress)
		if err != nil {
			return nil, err
		}

		return net.DialTimeout("tcp", net.JoinHostPort(serverName, port), dialTimeout)
	}
)

func configureLogger(levelName string) {
	var level slog.Level
	switch levelName {
	// case "debug":
	// 	level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logOpts := &slog.HandlerOptions{
		Level: level,
	}

	logger = slog.New(slog.NewTextHandler(os.Stdout, logOpts))
	slog.SetDefault(logger)
}

func init() {
	flag.StringVar(&listenAddress, "listen", ":443", "Set listen address (default: :443)")
	flag.StringVar(&logLevel, "log-level", "info", "Set logging level (info, warn, error)")
	flag.DurationVar(&dialTimeout, "dial-timeout", 5*time.Second, "Set dial timeout (default: 5s)")
}

func main() {
	flag.Parse()
	configureLogger(logLevel)

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		logger.Error("listen failed", "address", listenAddress, "error", err)
		return
	}
	defer listener.Close()

	logger.Info("server started", "listen_addr", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("accept failed", "error", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	connLogger := logger.With("remote_addr", clientConn.RemoteAddr())
	connLogger.Info("client connected")

	if err := clientConn.SetReadDeadline(time.Now().Add(dialTimeout)); err != nil {
		connLogger.Error("set read deadline failed", "error", err)
		return
	}

	hello, clientReader, err := peekClientHello(clientConn)
	if err != nil {
		connLogger.Warn("client hello rejected", "error", err)
		return
	}

	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		connLogger.Error("clear read deadline failed", "error", err)
		return
	}

	if hello.ServerName == "" {
		connLogger.Warn("missing sni")
		return
	}

	connLogger = connLogger.With("server_name", hello.ServerName)
	connLogger.Info("proxy target selected")

	backendConn, err := dialBackend(hello.ServerName)
	if err != nil {
		connLogger.Warn("backend dial failed", "error", err)
		return
	}
	defer backendConn.Close()

	connLogger.Info("backend connected", "backend_addr", backendConn.RemoteAddr())

	var wg sync.WaitGroup

	// Client -> Backend
	wg.Go(func() {
		if _, err := io.Copy(backendConn, clientReader); err != nil {
			connLogger.Debug("client to backend copy stopped", "error", err)
		}
	})

	// Backend -> Client
	wg.Go(func() {
		if _, err := io.Copy(clientConn, backendConn); err != nil {
			connLogger.Debug("backend to client copy stopped", "error", err)
		}
	})

	wg.Wait()
}

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	buf := new(bytes.Buffer)
	info, err := readClientHello(io.TeeReader(reader, buf))
	if err != nil {
		return nil, nil, err
	}

	return info, io.MultiReader(buf, reader), nil
}

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	hello := new(tls.ClientHelloInfo)

	config := &tls.Config{
		GetConfigForClient: func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
			*hello = *clientHello

			return nil, errClientHelloPeeked
		},
	}

	err := tls.Server(readOnlyConn{reader: reader}, config).Handshake()
	if errors.Is(err, errClientHelloPeeked) {
		return hello, nil
	}

	return nil, err
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
