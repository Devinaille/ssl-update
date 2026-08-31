// Package safeline implements the destination.Destination interface for
// the Safeline (长亭雷池) WAF Community Edition management API.
package safeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"

	"ssl-update/internal/cert"
	"ssl-update/internal/destination"
)

const TypeName = "safeline"

func init() {
	destination.Register(TypeName, New)
}

type Config struct {
	APIURL    string `mapstructure:"api_url"`
	APIToken  string `mapstructure:"api_token"`
	CertName  string `mapstructure:"cert_name"`
	VerifyTLS bool   `mapstructure:"verify_tls"`
}

type Safeline struct {
	name string
	cfg  Config
	hc   *http.Client
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
	return &Safeline{
		name: name,
		cfg:  c,
		hc:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *Safeline) Name() string { return s.name }

// CertName returns the cert_name this Safeline instance will use.
func (s *Safeline) CertName(b cert.CertBundle) string {
	if s.cfg.CertName != "" {
		return s.cfg.CertName
	}
	return cert.SanitizeName(b.MainDomain)
}

// Deploy pushes the cert to Safeline. If hint is non-empty it PUTs the
// existing cert; otherwise it POSTs a new one. Returns DeployResult with
// the cert id in CertID and the resolved cert name in CertName.
func (s *Safeline) Deploy(ctx context.Context, b cert.CertBundle, hint string) (destination.DeployResult, error) {
	certName := s.CertName(b)

	var (
		certID string
		err    error
	)
	if hint != "" {
		certID, err = s.update(ctx, hint, b)
	} else {
		certID, err = s.upload(ctx, b)
	}
	if err != nil {
		return destination.DeployResult{CertName: certName}, err
	}

	fp := fingerprint(b.Certificate)
	return destination.DeployResult{
		CertID:      certID,
		CertName:    certName,
		DeployedAt:  time.Now().UTC(),
		Fingerprint: "sha256:" + fp,
	}, nil
}

func (s *Safeline) Validate(ctx context.Context) error {
	u, err := s.url("/api/CertAPI?page=1&page_size=1")
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

func (s *Safeline) upload(ctx context.Context, b cert.CertBundle) (string, error) {
	body := map[string]any{
		"crt":  string(b.Certificate),
		"key":  string(b.PrivateKey),
		"type": 2,
		"name": s.CertName(b),
	}
	// The exact body for POST /api/UploadSSLCertAPI is not fully
	// documented; this is a best-effort mapping. The implementation will
	// be validated against a real Safeline CE instance during manual QA
	// (see plan task 12 step 12.1).
	u, err := s.url("/api/UploadSSLCertAPI")
	if err != nil {
		return "", err
	}
	return s.postJSON(ctx, u, body, "id")
}

func (s *Safeline) update(ctx context.Context, certID string, b cert.CertBundle) (string, error) {
	body := map[string]any{
		"manual": map[string]string{
			"crt": string(b.Certificate),
			"key": string(b.PrivateKey),
		},
		"type": 2,
	}
	u, err := s.url("/api/open/cert/" + certID)
	if err != nil {
		return "", err
	}
	_, err = s.putJSON(ctx, u, body)
	if err != nil {
		return "", err
	}
	return certID, nil
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
	req.Header.Set("API-TOKEN", s.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")
}

func (s *Safeline) postJSON(ctx context.Context, u string, body any, idField string) (string, error) {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(data))
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
		Data struct {
			ID json.Number `json:"id"`
		} `json:"data"`
		Err any `json:"err"`
	}
	if err := json.Unmarshal(body2, &parsed); err != nil {
		return "", fmt.Errorf("safeline: parse response: %w (body=%s)", err, string(body2))
	}
	if parsed.Err != nil {
		return "", fmt.Errorf("safeline: api err: %v", parsed.Err)
	}
	return string(parsed.Data.ID), nil
}

func (s *Safeline) putJSON(ctx context.Context, u string, body any) (any, error) {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "PUT", u, bytes.NewReader(data))
	s.setAuth(req)
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	defer resp.Body.Close()
	body2, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, classifyHTTP(resp.StatusCode, body2)
	}
	return body2, nil
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

// verify we satisfy the interface
var _ destination.Destination = (*Safeline)(nil)
