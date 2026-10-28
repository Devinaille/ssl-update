// Package sshtunnel provides a TCP dialer whose connections are routed
// through an SSH jump host. It is used by destinations whose management
// API is only reachable from inside a private network.
package sshtunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Sentinel errors allow destinations to map tunnel failures onto their
// own error classes (auth vs. network).
var (
	ErrAuth    = errors.New("ssh authentication failed")
	ErrConnect = errors.New("ssh connection failed")
)

// Config describes how to reach the SSH jump host and which address to
// dial through it.
type Config struct {
	Host                  string `mapstructure:"host"`
	Port                  int    `mapstructure:"port"`
	User                  string `mapstructure:"user"`
	PrivateKeyFile        string `mapstructure:"private_key_file"`
	KnownHostsFile        string `mapstructure:"known_hosts_file"`
	InsecureIgnoreHostKey bool   `mapstructure:"insecure_ignore_host_key"`

	// Target overrides the address passed to DialContext. When empty,
	// the caller's addr is dialed through the jump host (the common
	// case: api_url points at 127.0.0.1:<port>).
	Target string `mapstructure:"target"`
}

// Tunnel lazily establishes and reuses a single SSH client.
type Tunnel struct {
	cfg          Config
	clientConfig *ssh.ClientConfig

	mu     sync.Mutex
	client *ssh.Client
}

// New validates the configuration and loads the private key and host-key
// callback. It does not open a network connection.
func New(cfg Config) (*Tunnel, error) {
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.User = strings.TrimSpace(cfg.User)
	if cfg.Host == "" {
		return nil, errors.New("ssh_tunnel: host required")
	}
	if cfg.User == "" {
		return nil, errors.New("ssh_tunnel: user required")
	}
	if cfg.PrivateKeyFile == "" {
		return nil, errors.New("ssh_tunnel: private_key_file required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("ssh_tunnel: port %d out of range", cfg.Port)
	}

	keyBytes, err := os.ReadFile(expandHome(cfg.PrivateKeyFile))
	if err != nil {
		return nil, fmt.Errorf("ssh_tunnel: read private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("ssh_tunnel: private key is encrypted; passphrase-protected keys are not supported")
		}
		return nil, fmt.Errorf("ssh_tunnel: parse private key: %w", err)
	}

	hostKey, err := hostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}

	return &Tunnel{
		cfg: cfg,
		clientConfig: &ssh.ClientConfig{
			User:            cfg.User,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKey,
		},
	}, nil
}

func hostKeyCallback(cfg Config) (ssh.HostKeyCallback, error) {
	if cfg.InsecureIgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path := cfg.KnownHostsFile
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("ssh_tunnel: locate known_hosts: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	path = expandHome(path)
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("ssh_tunnel: load known_hosts %s: %w", path, err)
	}
	return cb, nil
}

// DialContext opens a connection to addr (or Config.Target when set)
// through the SSH jump host. The SSH client is created on first use and
// reused for subsequent calls.
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("ssh_tunnel: unsupported network %q", network)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	client, err := t.ensureClient(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	target := t.cfg.Target
	if target == "" {
		target = addr
	}

	conn, err := client.Dial("tcp", target)
	if err == nil {
		return conn, nil
	}

	// The cached SSH connection may be stale (e.g. idle timeout). Drop
	// it and retry once with a fresh connection.
	t.reset(client)
	client, err = t.ensureClient(ctx)
	if err != nil {
		return nil, err
	}
	conn, err = client.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %v", ErrConnect, target, err)
	}
	return conn, nil
}

func (t *Tunnel) ensureClient(ctx context.Context) (*ssh.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	c, err := t.connect(ctx)
	if err != nil {
		return nil, err
	}
	t.client = c
	return c, nil
}

func (t *Tunnel) connect(ctx context.Context) (*ssh.Client, error) {
	addr := net.JoinHostPort(t.cfg.Host, strconv.Itoa(t.cfg.Port))
	raw, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %v", ErrConnect, addr, err)
	}

	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	raw.SetDeadline(deadline)

	// context.AfterFunc is race-free: if the callback has already started
	// (stop returns false) the connection may be closed, so treat the
	// handshake as cancelled rather than returning a half-dead client.
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	cc, chans, reqs, err := ssh.NewClientConn(raw, addr, t.clientConfig)
	if !stop() {
		if cc != nil {
			cc.Close()
		}
		raw.Close()
		return nil, fmt.Errorf("%w: connection cancelled", ErrConnect)
	}
	raw.SetDeadline(time.Time{})
	if err != nil {
		raw.Close()
		// x/crypto/ssh does not expose a typed client-side auth error;
		// host-key failures are typed and must stay classified as
		// connection errors.
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) && strings.Contains(err.Error(), "unable to authenticate") {
			return nil, fmt.Errorf("%w: %v", ErrAuth, err)
		}
		return nil, fmt.Errorf("%w: handshake %s: %v", ErrConnect, addr, err)
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

func (t *Tunnel) reset(old *ssh.Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == old {
		t.client.Close()
		t.client = nil
	}
}

// Close releases the cached SSH connection. It is safe to call multiple
// times.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == nil {
		return nil
	}
	err := t.client.Close()
	t.client = nil
	return err
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
