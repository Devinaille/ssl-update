package sshtunnel

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssl-update/internal/sshtunnel/sshtest"
)

func newSigner(t *testing.T) (ssh.Signer, crypto.PrivateKey) {
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

func writePrivateKey(t *testing.T, priv crypto.PrivateKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeKnownHosts(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{addr}, key) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTunnel(t *testing.T, srv *sshtest.Server, mutate func(*Config)) *Tunnel {
	t.Helper()
	cfg := Config{
		Host:           srv.Host,
		Port:           srv.Port,
		User:           "tester",
		PrivateKeyFile: srv.PrivateKeyFile,
		KnownHostsFile: srv.KnownHostsFile,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	tun, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tun.Close() })
	return tun
}

func TestNew_RequiresFields(t *testing.T) {
	key := writePrivateKey(t, mustPrivateKey(t))
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "host", cfg: Config{User: "u", PrivateKeyFile: key}},
		{name: "user", cfg: Config{Host: "127.0.0.1", PrivateKeyFile: key}},
		{name: "private key", cfg: Config{Host: "127.0.0.1", User: "u"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func mustPrivateKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestNew_DefaultsPort22(t *testing.T) {
	cfg := Config{
		Host:                  "127.0.0.1",
		User:                  "u",
		PrivateKeyFile:        writePrivateKey(t, mustPrivateKey(t)),
		InsecureIgnoreHostKey: true,
	}
	tun, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tun.cfg.Port != 22 {
		t.Fatalf("Port = %d, want 22", tun.cfg.Port)
	}
}

func TestTunnel_DialThroughSSH(t *testing.T) {
	srv := sshtest.Start(t)
	echo := sshtest.EchoServer(t)
	tun := newTunnel(t, srv, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tun.DialContext(ctx, "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want hello", buf)
	}
}

func TestTunnel_TargetOverride(t *testing.T) {
	srv := sshtest.Start(t)
	echo := sshtest.EchoServer(t)
	tun := newTunnel(t, srv, func(c *Config) { c.Target = echo })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tun.DialContext(ctx, "tcp", "example.invalid:1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
}

func TestTunnel_AuthFailure(t *testing.T) {
	srv := sshtest.Start(t)
	tun := newTunnel(t, srv, func(c *Config) {
		c.PrivateKeyFile = writePrivateKey(t, mustPrivateKey(t))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := tun.DialContext(ctx, "tcp", "127.0.0.1:1")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
}

func TestTunnel_RejectsUnknownHostKey(t *testing.T) {
	srv := sshtest.Start(t)
	otherSigner, _ := newSigner(t)
	tun := newTunnel(t, srv, func(c *Config) {
		c.KnownHostsFile = writeKnownHosts(t, srv.Addr, otherSigner.PublicKey())
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := tun.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected host key error, got nil")
	}
	if errors.Is(err, ErrAuth) {
		t.Fatalf("host key error must not be ErrAuth: %v", err)
	}
}

func TestTunnel_InsecureIgnoreHostKey(t *testing.T) {
	srv := sshtest.Start(t)
	echo := sshtest.EchoServer(t)
	tun := newTunnel(t, srv, func(c *Config) {
		c.KnownHostsFile = ""
		c.InsecureIgnoreHostKey = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tun.DialContext(ctx, "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestTunnel_ContextCancelled(t *testing.T) {
	srv := sshtest.Start(t)
	tun := newTunnel(t, srv, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tun.DialContext(ctx, "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("expected context error, got nil")
	}
}

func TestNew_MissingKnownHosts(t *testing.T) {
	cfg := Config{
		Host:           "127.0.0.1",
		User:           "u",
		PrivateKeyFile: writePrivateKey(t, mustPrivateKey(t)),
		KnownHostsFile: filepath.Join(t.TempDir(), "does-not-exist"),
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error for missing known_hosts, got nil")
	}
}
