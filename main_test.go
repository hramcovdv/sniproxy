package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func TestHandleConnectionProxiesTLSStream(t *testing.T) {
	cert := mustTestCertificate(t)
	backendListener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendListener.Close()

	restoreDialBackend := dialBackend
	dialBackend = func(serverName string) (net.Conn, error) {
		if serverName != "allowed.example" {
			t.Fatalf("unexpected server name: %q", serverName)
		}
		return net.DialTimeout("tcp", backendListener.Addr().String(), 5*time.Second)
	}
	defer func() {
		dialBackend = restoreDialBackend
	}()

	backendDone := make(chan error, 1)
	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer conn.Close()

		payload := make([]byte, 4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			backendDone <- err
			return
		}
		if string(payload) != "ping" {
			backendDone <- io.ErrUnexpectedEOF
			return
		}

		_, err = conn.Write([]byte("pong"))
		backendDone <- err
	}()

	clientSide, proxySide := net.Pipe()
	var proxyWG sync.WaitGroup
	proxyWG.Add(1)
	go func() {
		defer proxyWG.Done()
		handleConnection(proxySide)
	}()

	tlsClient := tls.Client(clientSide, &tls.Config{
		ServerName:         "allowed.example",
		InsecureSkipVerify: true,
	})
	defer tlsClient.Close()

	if err := tlsClient.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := tlsClient.Write([]byte("ping")); err != nil {
		t.Fatalf("write via proxy: %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(tlsClient, reply); err != nil {
		t.Fatalf("read via proxy: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", string(reply))
	}

	if err := <-backendDone; err != nil {
		t.Fatalf("backend failed: %v", err)
	}

	_ = tlsClient.Close()
	proxyWG.Wait()
}

func TestHandleConnectionRejectsMissingSNI(t *testing.T) {
	restoreDialBackend := dialBackend
	dialBackend = func(serverName string) (net.Conn, error) {
		t.Fatalf("dialBackend should not be called for empty SNI")
		return nil, nil
	}
	defer func() {
		dialBackend = restoreDialBackend
	}()

	clientSide, proxySide := net.Pipe()
	var proxyWG sync.WaitGroup
	proxyWG.Add(1)
	go func() {
		defer proxyWG.Done()
		handleConnection(proxySide)
	}()

	tlsClient := tls.Client(clientSide, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer tlsClient.Close()

	if err := tlsClient.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	_, err := tlsClient.Write([]byte("ping"))
	if err == nil {
		t.Fatal("expected client write to fail without SNI")
	}

	_ = tlsClient.Close()
	proxyWG.Wait()
}

func mustTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"localhost"},
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}
}
