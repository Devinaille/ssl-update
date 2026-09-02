package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeTestCert(t *testing.T) (certPath, keyPath string, main string) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "*.a.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"*.a.com", "a.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, "*.a.com"
}

func TestSanitizeName_Wildcard(t *testing.T) {
	got := SanitizeName("*.a.com")
	if got != "wildcard-a-com" {
		t.Errorf("SanitizeName(*.a.com) = %q, want wildcard-a-com", got)
	}
}

func TestSanitizeName_PlainDomain(t *testing.T) {
	got := SanitizeName("a.com")
	if got != "a-com" {
		t.Errorf("SanitizeName(a.com) = %q, want a-com", got)
	}
}

func TestSanitizeName_Subdomain(t *testing.T) {
	got := SanitizeName("www.a.com")
	if got != "www-a-com" {
		t.Errorf("SanitizeName(www.a.com) = %q, want www-a-com", got)
	}
}

func TestSanitizeName_Empty(t *testing.T) {
	if got := SanitizeName(""); got != "" {
		t.Errorf("SanitizeName(\"\") = %q, want empty", got)
	}
}

func TestReadBundle_FromFiles(t *testing.T) {
	certPath, keyPath, main := makeTestCert(t)
	b, err := ReadBundle(certPath, keyPath, main)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if b.MainDomain != main {
		t.Errorf("MainDomain = %q, want %q", b.MainDomain, main)
	}
	if len(b.Domains) != 2 {
		t.Errorf("len(Domains) = %d, want 2", len(b.Domains))
	}
	if b.Domains[0] != "*.a.com" || b.Domains[1] != "a.com" {
		t.Errorf("Domains = %v, want [*.a.com a.com] (from leaf SAN)", b.Domains)
	}
	if b.NotAfter.IsZero() {
		t.Error("NotAfter should be parsed from PEM")
	}
}

func TestReadBundle_MissingFile(t *testing.T) {
	_, err := ReadBundle("/no/such/file", "/no/such/key", "")
	if err == nil {
		t.Error("expected error for missing cert file")
	}
}

func TestReadBundle_BadPEM(t *testing.T) {
	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad.pem")
	badKey := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badCert, []byte("not pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badKey, []byte("not pem"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadBundle(badCert, badKey, "")
	if err == nil {
		t.Error("expected error for non-PEM cert")
	}
}
