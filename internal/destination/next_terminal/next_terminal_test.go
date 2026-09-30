package next_terminal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ssl-update/internal/cert"
	"ssl-update/internal/destination"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *NextTerminal) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	iface, err := New("test-dest", map[string]any{
		"api_url":    ts.URL,
		"api_token":  "tok",
		"verify_tls": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	n := iface.(*NextTerminal)
	n.hc = ts.Client()
	return ts, n
}

func readJSON(t *testing.T, body io.ReadCloser) map[string]any {
	t.Helper()
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal body %q: %v", string(data), err)
	}
	return m
}

func TestNew_RequiresAPIURLAndToken(t *testing.T) {
	if _, err := New("x", map[string]any{"api_token": "t"}); err == nil {
		t.Error("expected error when api_url missing")
	}
	if _, err := New("x", map[string]any{"api_url": "https://x"}); err == nil {
		t.Error("expected error when api_token missing")
	}
}

// No existing cert with the same commonName → import: PUT upsert with the
// documented body and no id. The server-assigned id is then read back so state
// records the real id for the next renewal.
func TestDeploy_ImportsNew(t *testing.T) {
	var (
		putBody map[string]any
		gets    int
	)
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == listPath:
			gets++
			if gets == 1 {
				w.Write([]byte(`[]`))
				return
			}
			// Read-back after create: the new cert is now visible.
			w.Write([]byte(`[{"id":"new-1","commonName":"*.a.com"}]`))
		case r.Method == "PUT" && r.URL.Path == upsertPath:
			putBody = readJSON(t, r.Body)
			w.Write([]byte(`{"message":"ok"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	defer ts.Close()

	res, err := n.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----"),
		PrivateKey:  []byte("-----BEGIN PRIVATE KEY-----\nYYY\n-----END PRIVATE KEY-----"),
		MainDomain:  "*.a.com",
	}, "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if gets != 2 {
		t.Errorf("expected lookup + read-back (2 GETs), got %d", gets)
	}
	if _, hasID := putBody["id"]; hasID {
		t.Errorf("import body must not contain id, got %v", putBody["id"])
	}
	if putBody["commonName"] != "*.a.com" {
		t.Errorf("commonName = %v, want *.a.com", putBody["commonName"])
	}
	if putBody["type"] != "imported" {
		t.Errorf("type = %v, want imported", putBody["type"])
	}
	if putBody["renewBefore"] != float64(0) {
		t.Errorf("renewBefore = %v, want 0", putBody["renewBefore"])
	}
	if !strings.Contains(putBody["certificate"].(string), "BEGIN CERTIFICATE") {
		t.Errorf("certificate not forwarded: %v", putBody["certificate"])
	}
	if res.CertID != "new-1" {
		t.Errorf("CertID = %q, want the server-assigned id new-1", res.CertID)
	}
	if res.CertName != "*.a.com" {
		t.Errorf("CertName = %q, want *.a.com", res.CertName)
	}
}

// When the just-created cert is not yet visible on read-back, CertID must be
// left empty rather than storing a non-id value.
func TestDeploy_ImportsNew_NoReadbackLeavesIDEmpty(t *testing.T) {
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET":
			w.Write([]byte(`[]`))
		case r.Method == "PUT":
			w.Write([]byte(`{"message":"ok"}`))
		}
	})
	defer ts.Close()

	res, err := n.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if res.CertID != "" {
		t.Errorf("CertID = %q, want empty when the new id cannot be read back", res.CertID)
	}
}

// A stored certIDHint skips the lookup and is sent straight through (update in
// place, no duplicate).
func TestDeploy_WithHint_SkipsList(t *testing.T) {
	var putBody map[string]any
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			t.Error("must not list when certIDHint is present")
		case "PUT":
			putBody = readJSON(t, r.Body)
			w.Write([]byte(`{"message":"ok"}`))
		}
	})
	defer ts.Close()

	res, err := n.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "existing-7")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if putBody["id"] != "existing-7" {
		t.Errorf("update body id = %v, want existing-7", putBody["id"])
	}
	if res.CertID != "existing-7" {
		t.Errorf("CertID = %q, want existing-7", res.CertID)
	}
}

// A failed lookup with no hint must not block the deploy: fall back to a plain
// upsert and leave CertID empty (the id is unknown).
func TestDeploy_LookupFails_FallsBackToUpsert(t *testing.T) {
	var (
		sawPut  bool
		putBody map[string]any
	)
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == listPath:
			w.WriteHeader(500)
			w.Write([]byte(`{"message":"boom"}`))
		case r.Method == "PUT" && r.URL.Path == upsertPath:
			sawPut = true
			putBody = readJSON(t, r.Body)
			w.Write([]byte(`{"message":"ok"}`))
		}
	})
	defer ts.Close()

	res, err := n.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "")
	if err != nil {
		t.Fatalf("Deploy should succeed on lookup failure: %v", err)
	}
	if !sawPut {
		t.Fatal("expected upsert call after failed lookup")
	}
	if _, hasID := putBody["id"]; hasID {
		t.Errorf("fallback body must not contain id, got %v", putBody["id"])
	}
	if res.CertID != "" {
		t.Errorf("CertID = %q, want empty (id unknown)", res.CertID)
	}
}

// Existing cert with the same commonName → update: upsert body carries its id
// and the returned CertID is that id (so state and reverse-proxy bindings stay
// pointed at the same record).
func TestDeploy_UpdatesExisting(t *testing.T) {
	var putBody map[string]any
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == listPath:
			w.Write([]byte(`[{"id":"abc-123","commonName":"*.a.com"},{"id":"zzz","commonName":"*.b.com"}]`))
		case r.Method == "PUT" && r.URL.Path == upsertPath:
			putBody = readJSON(t, r.Body)
			w.Write([]byte(`{"message":"ok"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	defer ts.Close()

	res, err := n.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if putBody["id"] != "abc-123" {
		t.Errorf("update body id = %v, want abc-123", putBody["id"])
	}
	if res.CertID != "abc-123" {
		t.Errorf("CertID = %q, want abc-123", res.CertID)
	}
}

// Numeric ids must be tolerated (backend representation is not pinned).
func TestDeploy_UpdatesExistingNumericID(t *testing.T) {
	var putBody map[string]any
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == listPath:
			w.Write([]byte(`[{"id":42,"commonName":"*.a.com"}]`))
		case r.Method == "PUT" && r.URL.Path == upsertPath:
			putBody = readJSON(t, r.Body)
			w.Write([]byte(`{"message":"ok"}`))
		}
	})
	defer ts.Close()

	res, err := n.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if putBody["id"] != "42" {
		t.Errorf("update body id = %v, want \"42\"", putBody["id"])
	}
	if res.CertID != "42" {
		t.Errorf("CertID = %q, want 42", res.CertID)
	}
}

func TestDeploy_UnauthorizedReturnsAuthError(t *testing.T) {
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(401)
		w.Write([]byte(`{"message":"unauthorized"}`))
	})
	defer ts.Close()

	_, err := n.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "")
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected auth error, got %v", err)
	}
}

// A 400 rejection should surface the API's message.
func TestDeploy_RejectedIncludesMessage(t *testing.T) {
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET":
			w.Write([]byte(`[]`))
		case r.Method == "PUT":
			w.WriteHeader(400)
			w.Write([]byte(`{"message":"invalid private key"}`))
		}
	})
	defer ts.Close()

	_, err := n.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"),
		PrivateKey:  []byte("k"),
		MainDomain:  "*.a.com",
	}, "")
	if err == nil || !strings.Contains(err.Error(), "invalid private key") {
		t.Errorf("expected rejection message, got %v", err)
	}
}

func TestValidate_SendsAuthHeaderOnList(t *testing.T) {
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != listPath {
			t.Errorf("path = %q, want %q", r.URL.Path, listPath)
		}
		if got := r.Header.Get(authHeader); got != "tok" {
			t.Errorf("X-Auth-Token = %q, want tok", got)
		}
		w.Write([]byte(`[]`))
	})
	defer ts.Close()

	if err := n.Validate(context.Background()); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestValidate_401ReturnsAuthError(t *testing.T) {
	ts, n := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer ts.Close()

	err := n.Validate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected auth error, got %v", err)
	}
}

func TestCertName_DefaultAndOverride(t *testing.T) {
	n := &NextTerminal{name: "x", cfg: Config{}}
	if got := n.CertName(cert.CertBundle{MainDomain: "*.a.com"}); got != "*.a.com" {
		t.Errorf("CertName default = %q, want *.a.com (unsanitized)", got)
	}
	n = &NextTerminal{name: "x", cfg: Config{CommonName: "explicit"}}
	if got := n.CertName(cert.CertBundle{MainDomain: "*.a.com"}); got != "explicit" {
		t.Errorf("CertName override = %q, want explicit", got)
	}
}

func TestCertType_Default(t *testing.T) {
	if got := (Config{}).certType(); got != "imported" {
		t.Errorf("certType default = %q, want imported", got)
	}
	if got := (Config{CertType: "self-signed"}).certType(); got != "self-signed" {
		t.Errorf("certType override = %q, want self-signed", got)
	}
}

func TestParseCertList_Shapes(t *testing.T) {
	cases := []string{
		`[{"id":"1","commonName":"a.com"}]`,
		`{"data":[{"id":"1","commonName":"a.com"}]}`,
		`{"items":[{"id":"1","commonName":"a.com"}]}`,
	}
	for _, in := range cases {
		items, err := parseCertList([]byte(in))
		if err != nil {
			t.Errorf("parseCertList(%q): %v", in, err)
			continue
		}
		if len(items) != 1 || items[0].CommonName != "a.com" || string(items[0].ID) != "1" {
			t.Errorf("parseCertList(%q) = %+v", in, items)
		}
	}
}

func TestClassifyHTTP(t *testing.T) {
	cases := []struct {
		name string
		code int
		body string
		want error
	}{
		{"401 auth", 401, ``, destination.ErrAuth},
		{"403 auth", 403, `{"message":"forbidden"}`, destination.ErrAuth},
		{"404 not found", 404, `{"message":"nope"}`, destination.ErrCertNotFound},
		{"422 rejected", 422, `{"message":"bad key"}`, destination.ErrCertRejected},
		{"400 rejected", 400, `{"message":"bad cert"}`, destination.ErrCertRejected},
		{"400 quota", 400, `{"message":"quota exceeded"}`, destination.ErrQuota},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := classifyHTTP(c.code, []byte(c.body))
			if !errors.Is(err, c.want) {
				t.Errorf("classifyHTTP(%d, %q) = %v, want wrapping %v", c.code, c.body, err, c.want)
			}
		})
	}
}

func TestValidate_NetworkError(t *testing.T) {
	iface, err := New("d", map[string]any{"api_url": "http://127.0.0.1:1", "api_token": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	n := iface.(*NextTerminal)
	if err := n.Validate(context.Background()); !errors.Is(err, destination.ErrNetwork) {
		t.Errorf("Validate = %v, want ErrNetwork", err)
	}
}

// Regression: verify_tls: false must let us reach a cert not valid for the
// host we connect via; the default must still verify.
func TestNew_VerifyTLS_DefaultRejectsAndFalseSkips(t *testing.T) {
	ts := newHostnameOnlyTLSServer(t, "nt.example", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	defer ts.Close()

	strict, err := New("d", map[string]any{"api_url": ts.URL, "api_token": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if err := strict.Validate(context.Background()); err == nil {
		t.Error("expected TLS verification failure by default")
	}

	insecure, err := New("d", map[string]any{"api_url": ts.URL, "api_token": "tok", "verify_tls": false})
	if err != nil {
		t.Fatal(err)
	}
	if err := insecure.Validate(context.Background()); err != nil {
		t.Errorf("verify_tls=false should skip cert check, got %v", err)
	}
}

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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: tmpl}
}

func newHostnameOnlyTLSServer(t *testing.T, hostname string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{generateHostnameOnlyCert(t, hostname)}}
	ts.StartTLS()
	return ts
}
