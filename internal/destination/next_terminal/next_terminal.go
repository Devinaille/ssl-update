// Package next_terminal implements the destination.Destination interface for
// Next Terminal (https://github.com/next-terminal/next-terminal), a bastion
// host / jump server whose reverse proxy serves HTTPS web assets from a
// managed certificate library.
//
// API reference: https://www.next-terminal.com/zh/docs/api/certificate.html
//
// Certificates are written through a single "update or create" endpoint:
//
//	PUT /api/admin/certificates/upsert
//	{"commonName", "type", "certificate", "privateKey", "renewBefore"}
//
// The request is authenticated with the header `X-Auth-Token`, holding an
// access token created in the console (账号 → 访问令牌, type=api). The header
// name is inherited from the last open-source backend (v1.3.9
// server/common/nt/const.go: `const Token = "X-Auth-Token"`) and is still the
// name the v2+ frontend cleans out of localStorage.
//
// The upsert endpoint is documented as update-or-create keyed by commonName.
// To guarantee "import or update" and never accumulate duplicate entries,
// Deploy first lists the existing certificates and, on a commonName match,
// includes the existing id in the upsert body so the server updates that
// record in place (preserving the id that reverse-proxy bindings reference).
package next_terminal

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
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"

	"ssl-update/internal/cert"
	"ssl-update/internal/destination"
)

const TypeName = "next_terminal"

const (
	// upsertPath is the documented automation endpoint: update or create.
	upsertPath = "/api/admin/certificates/upsert"
	// listPath is used by Validate and by the duplicate-prevention lookup.
	listPath = "/api/admin/certificates"
	// authHeader is the header Next Terminal reads the access token from.
	authHeader = "X-Auth-Token"
	// defaultCertType is the cert type enum for externally-issued certs
	// (acme.sh). The other documented values are "self-signed" and "issued".
	defaultCertType = "imported"
)

func init() {
	destination.Register(TypeName, New)
}

type Config struct {
	APIURL      string `mapstructure:"api_url"`
	APIToken    string `mapstructure:"api_token"`
	CommonName  string `mapstructure:"common_name"`
	CertType    string `mapstructure:"cert_type"`
	RenewBefore int    `mapstructure:"renew_before"`
	VerifyTLS   *bool  `mapstructure:"verify_tls"`
}

type NextTerminal struct {
	name string
	cfg  Config
	hc   *http.Client
}

// shouldVerify returns whether TLS cert verification should be performed.
// Default is true (verify). Set verify_tls: false for self-signed consoles.
func (c Config) shouldVerify() bool {
	if c.VerifyTLS == nil {
		return true
	}
	return *c.VerifyTLS
}

// certType returns the configured cert type, defaulting to "imported".
func (c Config) certType() string {
	if c.CertType != "" {
		return c.CertType
	}
	return defaultCertType
}

func New(name string, raw map[string]any) (destination.Destination, error) {
	var c Config
	if err := mapstructure.Decode(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: next_terminal: %v", destination.ErrInvalidConfig, err)
	}
	if c.APIURL == "" {
		return nil, fmt.Errorf("%w: next_terminal: api_url required", destination.ErrInvalidConfig)
	}
	if c.APIToken == "" {
		return nil, fmt.Errorf("%w: next_terminal: api_token required", destination.ErrInvalidConfig)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !c.shouldVerify(),
		},
	}
	return &NextTerminal{
		name: name,
		cfg:  c,
		hc: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

func (n *NextTerminal) Name() string { return n.name }

// CertName returns the commonName this destination uses. Next Terminal keys
// certificates by commonName, so we send the real domain (wildcards allowed)
// rather than the filesystem-safe sanitized form used by other destinations.
func (n *NextTerminal) CertName(b cert.CertBundle) string {
	if n.cfg.CommonName != "" {
		return n.cfg.CommonName
	}
	return b.MainDomain
}

// Deploy performs an "import or update" against Next Terminal.
//
// It first looks up an existing certificate by commonName (best effort). If
// one exists its id is included in the upsert body so the server updates that
// record in place; otherwise the body omits the id and a new record is
// created. This prevents duplicate imports across acme.sh renewals.
func (n *NextTerminal) Deploy(ctx context.Context, b cert.CertBundle, _ string) (destination.DeployResult, error) {
	certName := n.CertName(b)
	fp := fingerprint(b.Certificate)
	slog.Debug("deploying cert",
		"dest", n.name,
		"common_name", certName,
		"fingerprint", "sha256:"+fp,
		"cert_pem_bytes", len(b.Certificate),
	)

	existingID, err := n.findExisting(ctx, certName)
	if err != nil {
		// Lookup is best-effort: the upsert endpoint still creates-or-updates
		// by commonName. Never block a deploy on the pre-check.
		slog.Warn("next_terminal: cert lookup failed, falling back to upsert by commonName", "dest", n.name, "err", err.Error())
		existingID = ""
	}

	body := map[string]any{
		"commonName":  certName,
		"type":        n.cfg.certType(),
		"certificate": string(b.Certificate),
		"privateKey":  string(b.PrivateKey),
		"renewBefore": n.cfg.RenewBefore,
	}
	if existingID != "" {
		body["id"] = existingID
		slog.Info("updating existing certificate", "dest", n.name, "common_name", certName, "id", existingID)
	} else {
		slog.Info("importing new certificate", "dest", n.name, "common_name", certName)
	}

	if err := n.putJSON(ctx, n.url(upsertPath), body); err != nil {
		return destination.DeployResult{CertName: certName}, err
	}

	id := existingID
	if id == "" {
		id = certName
	}
	return destination.DeployResult{
		CertID:      id,
		CertName:    certName,
		DeployedAt:  time.Now().UTC(),
		Fingerprint: "sha256:" + fp,
	}, nil
}

// Validate checks token + connectivity with GET /api/admin/certificates.
func (n *NextTerminal) Validate(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", n.url(listPath), nil)
	if err != nil {
		return fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	n.setAuth(req)
	resp, err := n.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return classifyHTTP(resp.StatusCode, body)
	}
	return nil
}

// findExisting lists certificates and returns the id whose commonName equals
// the given name, or "" if none matches.
func (n *NextTerminal) findExisting(ctx context.Context, commonName string) (string, error) {
	if commonName == "" {
		return "", nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", n.url(listPath), nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	n.setAuth(req)
	resp, err := n.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", classifyHTTP(resp.StatusCode, body)
	}
	items, err := parseCertList(body)
	if err != nil {
		return "", fmt.Errorf("next_terminal: parse cert list: %w (body=%s)", err, string(body))
	}
	for _, it := range items {
		if it.CommonName == commonName && it.ID != "" {
			return string(it.ID), nil
		}
	}
	return "", nil
}

// putJSON sends a JSON PUT and maps failures onto the sentinel errors.
func (n *NextTerminal) putJSON(ctx context.Context, u string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("next_terminal: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	n.setAuth(req)
	resp, err := n.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return classifyHTTP(resp.StatusCode, respBody)
	}
	return nil
}

func (n *NextTerminal) url(p string) string {
	return strings.TrimRight(n.cfg.APIURL, "/") + p
}

func (n *NextTerminal) setAuth(req *http.Request) {
	req.Header.Set(authHeader, n.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")
}

// certItem is one entry of GET /api/admin/certificates. id is tolerated as a
// JSON string or number because the closed-source v2+ backend is not pinned
// to either representation.
type certItem struct {
	ID         flexString `json:"id"`
	CommonName string     `json:"commonName"`
}

// flexString unmarshals a JSON string or number into a string.
type flexString string

func (f *flexString) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "null" || s == "" {
		*f = ""
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var v string
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
		*f = flexString(v)
		return nil
	}
	// Number (or something else scalar): keep the raw token.
	*f = flexString(s)
	return nil
}

// parseCertList accepts the several shapes the list endpoint may return: a
// bare array, or an object wrapping the array under "data" or "items".
func parseCertList(body []byte) ([]certItem, error) {
	var arr []certItem
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}
	var wrapper struct {
		Data  []certItem `json:"data"`
		Items []certItem `json:"items"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Data != nil {
		return wrapper.Data, nil
	}
	return wrapper.Items, nil
}

// classifyHTTP maps an HTTP failure onto the destination sentinel errors and
// surfaces the API's {"message": ...} body when present.
func classifyHTTP(code int, body []byte) error {
	msg := messageFromBody(body)
	switch code {
	case 401, 403:
		return fmt.Errorf("%w: http %d (body=%s)", destination.ErrAuth, code, string(body))
	case 404:
		return fmt.Errorf("%w: http %d (body=%s)", destination.ErrCertNotFound, code, string(body))
	case 400, 422:
		if bytes.Contains(bytes.ToLower(body), []byte("quota")) {
			return fmt.Errorf("%w: http %d (body=%s)", destination.ErrQuota, code, string(body))
		}
		if msg != "" {
			return fmt.Errorf("%w: http %d: %s", destination.ErrCertRejected, code, msg)
		}
		return fmt.Errorf("%w: http %d (body=%s)", destination.ErrCertRejected, code, string(body))
	default:
		return fmt.Errorf("next_terminal: http %d (body=%s)", code, string(body))
	}
}

// messageFromBody extracts the "message" field from an error body, returning
// "" when the body is not JSON or has no message.
func messageFromBody(body []byte) string {
	var parsed struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Message != "" {
		return parsed.Message
	}
	return ""
}

func fingerprint(pem []byte) string {
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:])
}

var _ destination.Destination = (*NextTerminal)(nil)
