package safeline

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestDeploy_FirstTime_UploadsAndReturnsID(t *testing.T) {
	var (
		sawUpload bool
		sawList   bool
	)
	ts, s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/CertAPI":
			sawList = true
			w.Write([]byte(`{"data":{"nodes":[]},"err":null}`))
		case "/api/UploadSSLCertAPI":
			sawUpload = true
			w.Write([]byte(`{"data":{"id":42},"err":null}`))
		default:
			w.WriteHeader(404)
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
	if !sawUpload {
		t.Error("expected POST /api/UploadSSLCertAPI on first deploy")
	}
	if sawList {
		t.Error("did not expect list call on first deploy")
	}
	if res.CertID != "42" {
		t.Errorf("CertID = %q, want 42", res.CertID)
	}
	if res.CertName != "wildcard-a-com" {
		t.Errorf("CertName = %q, want wildcard-a-com", res.CertName)
	}
}

func TestDeploy_WithHint_UpdatesByID(t *testing.T) {
	var sawUpdate bool
	ts, s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/open/cert/7" && r.Method == "PUT" {
			sawUpdate = true
			w.Write([]byte(`{"err":null}`))
			return
		}
		w.WriteHeader(404)
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
	if !sawUpdate {
		t.Error("expected PUT /api/open/cert/7 when hint present")
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
		if got := r.Header.Get("API-TOKEN"); got != "tok" {
			t.Errorf("API-TOKEN = %q, want tok", got)
		}
		w.Write([]byte(`{"data":{"nodes":[]},"err":null}`))
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

// Regression test: verify_tls: false must let us connect to a cert that
// is NOT valid for the IP we connect via. (Bug previously: field was
// accepted in config but never applied to http.Client.Transport.)
func TestNew_VerifyTLS_False_SkipsHostnameCertVerify(t *testing.T) {
	ts := newHostnameOnlyTLSServer(t, "safeline.example", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"nodes":[]},"err":null}`))
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
