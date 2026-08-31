package safeline

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ssl-update/internal/cert"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Safeline) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	sIface, err := New("test-dest", map[string]any{
		"api_url":    ts.URL,
		"api_token":  "tok",
		"verify_tls": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := sIface.(*Safeline)
	s.hc = ts.Client()
	return ts, s
}

func TestNew_RequiresAPIToken(t *testing.T) {
	_, err := New("x", map[string]any{"api_url": "https://x"})
	if err == nil {
		t.Error("expected error when api_token missing")
	}
}

// TestDeploy_FirstTime_Creates: no hint + no existing cert by domain →
// GET list (empty) → POST upsert without id → returns id from response.
func TestDeploy_FirstTime_Creates(t *testing.T) {
	var (
		sawList bool
		sawPost bool
	)
	ts, s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/open/cert" {
			t.Errorf("unexpected path %q, want /api/open/cert", r.URL.Path)
		}
		switch r.Method {
		case "GET":
			sawList = true
			w.Write([]byte(`{"data":{"nodes":[],"total":0},"err":null}`))
		case "POST":
			sawPost = true
			// body must NOT contain an id (create)
			w.Write([]byte(`{"data":42,"err":null}`))
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
	defer ts.Close()
	res, err := s.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----"),
		PrivateKey:  []byte("-----BEGIN RSA PRIVATE KEY-----\nYYY\n-----END RSA PRIVATE KEY-----"),
		MainDomain:  "*.a.com",
	}, "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if !sawList {
		t.Error("expected GET list on first deploy (find by domain)")
	}
	if !sawPost {
		t.Error("expected POST upsert to create the cert")
	}
	if res.CertID != "42" {
		t.Errorf("CertID = %q, want 42", res.CertID)
	}
	if res.CertName != "wildcard-a-com" {
		t.Errorf("CertName = %q, want wildcard-a-com", res.CertName)
	}
}

// TestDeploy_ReusesExistingByDomain: no hint, but list contains a cert
// whose domains match the main domain → upsert with that id.
func TestDeploy_ReusesExistingByDomain(t *testing.T) {
	var (
		postID        int
		postType      int
		postCrt       string
		postKey       string
		hasManual     bool
	)
	ts, s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.Write([]byte(`{"data":{"nodes":[
				{"id":5,"domains":["*.a.com","a.com"]},
				{"id":9,"domains":["*.b.com"]}
			],"total":2},"err":null}`))
		case "POST":
			var body map[string]any
			_ = jsonUnmarshal(r.Body, &body)
			if v, ok := body["id"].(float64); ok {
				postID = int(v)
			}
			if v, ok := body["type"].(float64); ok {
				postType = int(v)
			}
			if m, ok := body["manual"].(map[string]any); ok {
				hasManual = true
				if c, ok := m["crt"].(string); ok {
					postCrt = c
				}
				if k, ok := m["key"].(string); ok {
					postKey = k
				}
			}
			w.Write([]byte(`{"data":5,"err":null}`))
		}
	})
	defer ts.Close()
	res, err := s.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if postID != 5 {
		t.Errorf("upsert used id %d, want 5 (matched existing cert by domain)", postID)
	}
	if res.CertID != "5" {
		t.Errorf("CertID = %q, want 5", res.CertID)
	}
	// Body format must match what the WAF OPEN API actually accepts
	// (community-verified: type=2, manual={crt, key}). Sending type=1
	// returns HTTP 500 "Error occurred when extracting params" on
	// recent WAF versions.
	if postType != 2 {
		t.Errorf("body type=%d, want 2 (WAF rejects type=1 with 500)", postType)
	}
	if !hasManual {
		t.Error("body missing \"manual\" sub-object (must contain {crt, key})")
	}
	if postCrt != "c" {
		t.Errorf("body manual.crt=%q, want %q", postCrt, "c")
	}
	if postKey != "k" {
		t.Errorf("body manual.key=%q, want %q", postKey, "k")
	}
}

// TestDeploy_WithHint_UpdatesInPlace: hint "7" → POST upsert with id=7,
// no list call.
func TestDeploy_WithHint_UpdatesInPlace(t *testing.T) {
	var (
		sawList bool
		postID  int
	)
	ts, s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			sawList = true
			t.Error("should not list when hint is present")
		case "POST":
			var body map[string]any
			_ = jsonUnmarshal(r.Body, &body)
			if v, ok := body["id"].(float64); ok {
				postID = int(v)
			}
			w.Write([]byte(`{"data":7,"err":null}`))
		}
	})
	defer ts.Close()
	res, err := s.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "7")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if sawList {
		t.Error("list should not be called when hint present")
	}
	if postID != 7 {
		t.Errorf("upsert used id %d, want 7", postID)
	}
	if res.CertID != "7" {
		t.Errorf("CertID = %q, want 7", res.CertID)
	}
}

func TestValidate_401ReturnsAuthError(t *testing.T) {
	ts, s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer ts.Close()
	err := s.Validate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Errorf("expected auth error, got %v", err)
	}
}

func TestValidate_200OK(t *testing.T) {
	ts, s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-SLCE-API-TOKEN"); got != "tok" {
			t.Errorf("X-SLCE-API-TOKEN = %q, want tok", got)
		}
		if r.URL.Path != "/api/open/cert" {
			t.Errorf("path = %q, want /api/open/cert", r.URL.Path)
		}
		w.Write([]byte(`{"data":{"nodes":[],"total":0},"err":null}`))
	})
	defer ts.Close()
	if err := s.Validate(context.Background()); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestCertName_OverrideFromConfig(t *testing.T) {
	s := &Safeline{name: "x", cfg: Config{CertName: "explicit-name"}}
	if got := s.CertName(cert.CertBundle{MainDomain: "*.a.com"}); got != "explicit-name" {
		t.Errorf("CertName = %q, want explicit-name", got)
	}
}

func TestCertName_SanitizeDefault(t *testing.T) {
	s := &Safeline{name: "x", cfg: Config{}}
	if got := s.CertName(cert.CertBundle{MainDomain: "*.a.com"}); got != "wildcard-a-com" {
		t.Errorf("CertName = %q, want wildcard-a-com", got)
	}
}

func jsonUnmarshal(body io.ReadCloser, v any) error {
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// generateHostnameOnlyCert makes a self-signed cert whose only SAN is a
// DNS name (e.g. "safeline.example"). No IP SANs, so Go's strict
// cert check (default since Go 1.15) rejects connections made via IP
// (the "no IP SANs" error OR the "unknown authority" error from the
// self-signed chain).
func generateHostnameOnlyCert(t *testing.T, hostname string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{hostname},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        tmpl,
	}
}

// newHostnameOnlyTLSServer starts a TLS server whose cert is only valid
// for the given hostname (no IP SANs). Connecting via 127.0.0.1 to this
// server fails cert verification for either reason: missing IP SAN OR
// self-signed chain. Both are exactly what the user's WAF scenario
// triggers, and the regression test only cares that verify_tls controls
// whether the error is raised.
func newHostnameOnlyTLSServer(t *testing.T, hostname string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{generateHostnameOnlyCert(t, hostname)},
	}
	ts.StartTLS()
	return ts
}

// Regression test: the WAF middleware requires the literal header
// `X-SLCE-API-TOKEN`. Earlier code (and the WAF's own swagger) used the
// placeholder name "API-TOKEN", which the WAF silently rejected with 401.
// This test locks in the correct header name so future refactors don't
// regress to the wrong one.
func TestSetAuth_SendsCorrectHeaderName(t *testing.T) {
	ts, s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Must have correct header.
		if got := r.Header.Get("X-SLCE-API-TOKEN"); got != "tok" {
			t.Errorf("X-SLCE-API-TOKEN = %q, want tok (this is the WAF-required header)", got)
		}
		// Must NOT have the wrong header (otherwise we might be sending
		// both and just happening to pass via the right one).
		if got := r.Header.Get("API-TOKEN"); got != "" {
			t.Errorf("must not send wrong header API-TOKEN (WAF middleware ignores it and returns 401), got %q", got)
		}
		w.Write([]byte(`{"data":{"nodes":[],"total":0},"err":null}`))
	})
	defer ts.Close()
	if err := s.Validate(context.Background()); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// Regression test: verify_tls: false must let us connect to a cert that
// is NOT valid for the IP we connect via. (Bug previously: field was
// accepted in config but never applied to http.Client.Transport.)
func TestNew_VerifyTLS_False_SkipsHostnameCertVerify(t *testing.T) {
	ts := newHostnameOnlyTLSServer(t, "safeline.example", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"nodes":[],"total":0},"err":null}`))
	})
	defer ts.Close()

	sIface, err := New("test-dest", map[string]any{
		"api_url":    ts.URL,
		"api_token":  "tok",
		"verify_tls": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := sIface.(*Safeline)
	// CRITICAL: do NOT replace s.hc with ts.Client(); that would bypass
	// the verify_tls code path and mask the bug we are guarding against.

	if err := s.Validate(context.Background()); err != nil {
		t.Fatalf("Validate with verify_tls=false should skip cert check, got: %v", err)
	}
}

// Regression test: verify_tls unset (default) must STILL perform cert
// verification (secure-by-default). The request should fail with some
// TLS error (either SAN mismatch or self-signed chain rejection — the
// test only cares that verification runs).
func TestNew_VerifyTLS_Default_RejectsBadCert(t *testing.T) {
	ts := newHostnameOnlyTLSServer(t, "safeline.example", func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be reached when cert verify fails")
	})
	defer ts.Close()

	sIface, err := New("test-dest", map[string]any{
		"api_url":   ts.URL,
		"api_token": "tok",
		// verify_tls intentionally omitted — should default to verify=true
	})
	if err != nil {
		t.Fatal(err)
	}
	s := sIface.(*Safeline)
	// CRITICAL: do NOT replace s.hc with ts.Client()

	err = s.Validate(context.Background())
	if err == nil {
		t.Fatal("expected TLS verification failure when verify_tls not set, got nil")
	}
	if !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "tls:") {
		t.Errorf("expected TLS-related error, got: %v", err)
	}
}

// Regression test: verify_tls: true explicitly must perform cert
// verification (same expected behavior as unset).
func TestNew_VerifyTLS_True_RejectsBadCert(t *testing.T) {
	ts := newHostnameOnlyTLSServer(t, "safeline.example", func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be reached when cert verify fails")
	})
	defer ts.Close()

	sIface, err := New("test-dest", map[string]any{
		"api_url":    ts.URL,
		"api_token":  "tok",
		"verify_tls": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := sIface.(*Safeline)
	// CRITICAL: do NOT replace s.hc with ts.Client()

	err = s.Validate(context.Background())
	if err == nil {
		t.Fatal("expected TLS verification failure when verify_tls=true, got nil")
	}
	if !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "tls:") {
		t.Errorf("expected TLS-related error, got: %v", err)
	}
}
