// Package safeline implements the destination.Destination interface for
// the Safeline (长亭雷池) WAF Community Edition management API.
//
// API reference: the WAF's own swagger (mgt API v2) — basePath /api,
// cert endpoints under /open/cert (tag ssl_cert), authenticated with the
// X-SLCE-API-TOKEN header (generated in the console "个人中心 → OPEN API").
//
// Note: earlier docs and the WAF swagger itself use "API-TOKEN" as a
// placeholder name, but the WAF's HTTP middleware (per official docs at
// help.waf-ce.chaitin.cn) actually requires the literal header
// `X-SLCE-API-TOKEN`. Sending `API-TOKEN` returns 401.
package safeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"

	"ssl-update/internal/cert"
	"ssl-update/internal/destination"
)

const TypeName = "safeline"

// certTypeManualUpload matches the WAF's cert library type enum.
//
// History: the WAF swagger marks type=1 as the manual-upload enum, but
// in practice all working community integrations (yojigen.cn, GitHub
// discussion #1148, knowsafe tutorial) send type=2. Sending type=1 to
// recent WAF versions returns HTTP 500 with
// "Error occurred when extracting params" (the WAF middleware can't bind
// the value to its known type enum). 2 is the value the WAF actually
// accepts for certs uploaded via the OPEN API.
//
// If you find a WAF version that requires a different value, change this
// constant — but verify with a real deploy first, since the WAF's error
// message for a wrong type is misleading.
const certTypeManualUpload = 2

func init() {
	destination.Register(TypeName, New)
}

type Config struct {
	APIURL    string `mapstructure:"api_url"`
	APIToken  string `mapstructure:"api_token"`
	CertName  string `mapstructure:"cert_name"`
	VerifyTLS *bool  `mapstructure:"verify_tls"`
}

type Safeline struct {
	name string
	cfg  Config
	hc   *http.Client
}

// shouldVerify returns whether TLS cert verification should be performed.
// Default is true (verify) for safety. Set verify_tls: false in config to
// skip verification (e.g. for self-signed internal CAs).
func (c Config) shouldVerify() bool {
	if c.VerifyTLS == nil {
		return true
	}
	return *c.VerifyTLS
}

func New(name string, raw map[string]any) (destination.Destination, error) {
	var c Config
	if err := mapstructure.Decode(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: safeline: %v", destination.ErrInvalidConfig, err)
	}
	if c.APIURL == "" {
		return nil, fmt.Errorf("%w: safeline: api_url required", destination.ErrInvalidConfig)
	}
	if c.APIToken == "" {
		return nil, fmt.Errorf("%w: safeline: api_token required", destination.ErrInvalidConfig)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !c.shouldVerify(),
		},
	}
	return &Safeline{
		name: name,
		cfg:  c,
		hc: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

func (s *Safeline) Name() string { return s.name }

// CertName returns the cert_name this Safeline instance will use.
// The Safeline API identifies certs by integer id (no user-facing name),
// so cert_name here is only used as the stable component of the state key.
func (s *Safeline) CertName(b cert.CertBundle) string {
	if s.cfg.CertName != "" {
		return s.cfg.CertName
	}
	return cert.SanitizeName(b.MainDomain)
}

// Deploy pushes the cert to Safeline via POST /api/open/cert (upsert).
//
//   - If certIDHint is non-empty: upsert with that id (update in place).
//   - Else: list certs and reuse an existing cert whose domains contain the
//     bundle's main domain; only create a new one if none matches.
//
// The response returns the cert id, which is recorded in state for the
// next renewal.
func (s *Safeline) Deploy(ctx context.Context, b cert.CertBundle, hint string) (destination.DeployResult, error) {
	certName := s.CertName(b)
	fp := fingerprint(b.Certificate)
	slog.Debug("deploying cert",
		"dest", s.name,
		"cert_name", certName,
		"fingerprint", "sha256:"+fp,
		"cert_pem_bytes", len(b.Certificate),
		"hint", hint,
	)

	certID := hint
	var err error
	if certID == "" {
		certID, err = s.findByDomain(ctx, b.MainDomain)
		if err != nil {
			return destination.DeployResult{CertName: certName}, err
		}
	}

	id, err := s.upsert(ctx, certID, b)
	if err != nil {
		return destination.DeployResult{CertName: certName}, err
	}

	return destination.DeployResult{
		CertID:      id,
		CertName:    certName,
		DeployedAt:  time.Now().UTC(),
		Fingerprint: "sha256:" + fp,
	}, nil
}

// Validate checks token + API connectivity with GET /api/open/cert.
func (s *Safeline) Validate(ctx context.Context) error {
	u, err := s.url("/api/open/cert")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	s.setAuth(req)
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("%w: http %d", destination.ErrAuth, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("safeline: http %d", resp.StatusCode)
	}
	return nil
}

// findByDomain returns the id of the first cert whose domains contain the
// given domain, or "" if none matches.
func (s *Safeline) findByDomain(ctx context.Context, domain string) (string, error) {
	if domain == "" {
		return "", nil
	}
	u, err := s.url("/api/open/cert")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", err
	}
	s.setAuth(req)
	resp, err := s.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", classifyHTTP(resp.StatusCode, body)
	}
	var parsed struct {
		Data struct {
			Nodes []struct {
				ID      int      `json:"id"`
				Domains []string `json:"domains"`
			} `json:"nodes"`
		} `json:"data"`
		Err any `json:"err"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("safeline: parse list: %w (body=%s)", err, string(body))
	}
	if parsed.Err != nil {
		return "", fmt.Errorf("safeline: api err: %v", parsed.Err)
	}
	for _, n := range parsed.Data.Nodes {
		for _, d := range n.Domains {
			if d == domain {
				return strconv.Itoa(n.ID), nil
			}
		}
	}
	return "", nil
}

// upsert calls POST /api/open/cert. If certID is non-empty the body
// includes the id (update); otherwise it creates a new cert. Returns the
// cert id from the response.
func (s *Safeline) upsert(ctx context.Context, certID string, b cert.CertBundle) (string, error) {
	body := map[string]any{
		"type": certTypeManualUpload,
		"manual": map[string]string{
			"crt": string(b.Certificate),
			"key": string(b.PrivateKey),
		},
	}
	if certID != "" {
		if id, err := strconv.Atoi(certID); err == nil {
			body["id"] = id
		}
	}
	u, err := s.url("/api/open/cert")
	if err != nil {
		return "", err
	}
	return s.postJSON(ctx, u, body)
}

func (s *Safeline) url(p string) (string, error) {
	base := strings.TrimRight(s.cfg.APIURL, "/")
	u, err := url.Parse(base + p)
	if err != nil {
		return "", fmt.Errorf("safeline: bad api_url: %w", err)
	}
	return u.String(), nil
}

func (s *Safeline) setAuth(req *http.Request) {
	req.Header.Set("X-SLCE-API-TOKEN", s.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")
}

func (s *Safeline) postJSON(ctx context.Context, u string, body any) (string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("safeline: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	s.setAuth(req)
	resp, err := s.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	defer resp.Body.Close()
	body2, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", classifyHTTP(resp.StatusCode, body2)
	}
	var parsed struct {
		Data json.Number `json:"data"`
		Err  any         `json:"err"`
	}
	if err := json.Unmarshal(body2, &parsed); err != nil {
		return "", fmt.Errorf("safeline: parse response: %w (body=%s)", err, string(body2))
	}
	if parsed.Err != nil {
		return "", fmt.Errorf("safeline: api err: %v", parsed.Err)
	}
	return string(parsed.Data), nil
}

func classifyHTTP(code int, body []byte) error {
	switch code {
	case 401, 403:
		return fmt.Errorf("%w: http %d (body=%s)", destination.ErrAuth, code, string(body))
	case 404:
		return fmt.Errorf("%w: http %d (body=%s)", destination.ErrCertNotFound, code, string(body))
	case 400:
		if bytes.Contains(bytes.ToLower(body), []byte("quota")) {
			return fmt.Errorf("%w: http %d (body=%s)", destination.ErrQuota, code, string(body))
		}
		return fmt.Errorf("%w: http %d (body=%s)", destination.ErrCertRejected, code, string(body))
	default:
		return fmt.Errorf("safeline: http %d (body=%s)", code, string(body))
	}
}

func fingerprint(pem []byte) string {
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:])
}

var _ destination.Destination = (*Safeline)(nil)
