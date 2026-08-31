package safeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
