// Package sshtest provides an in-process SSH server for tests.
package sshtest

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Server is an SSH server that authenticates one generated user key and
// forwards direct-tcpip channels to the requested address.
type Server struct {
	Host string
	Port int
	Addr string

	HostKey        ssh.PublicKey
	UserKey        crypto.PrivateKey
	PrivateKeyFile string
	KnownHostsFile string

	ln    net.Listener
	done  chan struct{}
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// Start launches an SSH server on 127.0.0.1 and registers cleanup.
func Start(t testing.TB) *Server {
	t.Helper()
	hostSigner, _ := newSigner(t)
	userSigner, userPriv := newSigner(t)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), userSigner.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown public key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	block, err := ssh.MarshalPrivateKey(userPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	khPath := filepath.Join(dir, "known_hosts")
	line := knownhosts.Line([]string{ln.Addr().String()}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(khPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Host:           host,
		Port:           port,
		Addr:           ln.Addr().String(),
		HostKey:        hostSigner.PublicKey(),
		UserKey:        userPriv,
		PrivateKeyFile: keyPath,
		KnownHostsFile: khPath,
		ln:             ln,
		done:           make(chan struct{}),
		conns:          make(map[net.Conn]struct{}),
	}
	t.Cleanup(s.Close)
	go s.serve(cfg)
	return s
}

func newSigner(t testing.TB) (ssh.Signer, crypto.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, priv
}

func (s *Server) serve(cfg *ssh.ServerConfig) {
	defer close(s.done)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.handle(conn, cfg)
		}()
	}
}

func (s *Server) handle(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		var req struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(nc.ExtraData(), &req); err != nil {
			nc.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)

		target := net.JoinHostPort(req.DestAddr, strconv.Itoa(int(req.DestPort)))
		tc, err := net.Dial("tcp", target)
		if err != nil {
			ch.Close()
			continue
		}
		go func() {
			io.Copy(tc, ch)
			tc.Close()
		}()
		io.Copy(ch, tc)
		ch.Close()
	}
}

// Close stops the listener and waits for active handlers to finish.
func (s *Server) Close() {
	select {
	case <-s.done:
		return
	default:
	}
	s.ln.Close()
	<-s.done

	// Unblock handlers that are waiting on a client that did not close
	// its connection, otherwise wg.Wait below would hang.
	s.mu.Lock()
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
}

// EchoServer starts a TCP echo server and returns its address.
func EchoServer(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}
