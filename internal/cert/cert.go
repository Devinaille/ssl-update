// Package cert reads and parses PEM certificate bundles and sanitizes names.
package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// CertBundle is the cert material passed to a Destination for deployment.
type CertBundle struct {
	Certificate []byte    // PEM full chain
	PrivateKey  []byte    // PEM private key
	Domains     []string  // SAN list
	MainDomain  string    // primary domain (e.g., "*.a.com")
	NotAfter    time.Time // parsed from the leaf cert
}

// ReadBundle loads cert + key from disk, parses the leaf certificate to
// extract NotAfter and the SAN list, and validates basic PEM structure.
// Domains is populated from the leaf cert's DNSNames — callers don't pass
// it in. mainDomain is the user-configured primary domain (e.g. "*.a.com"),
// typically from $Le_DomainMain / config.cert.domain.
func ReadBundle(certPath, keyPath string, mainDomain string) (CertBundle, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return CertBundle{}, fmt.Errorf("read cert %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return CertBundle{}, fmt.Errorf("read key %s: %w", keyPath, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return CertBundle{}, errors.New("cert file is not valid PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertBundle{}, fmt.Errorf("parse cert: %w", err)
	}
	return CertBundle{
		Certificate: certPEM,
		PrivateKey:  keyPEM,
		Domains:     leaf.DNSNames,
		MainDomain:  mainDomain,
		NotAfter:    leaf.NotAfter,
	}, nil
}

// SanitizeName converts a domain into a cert name acceptable to services
// (alphanumeric, dash, underscore, period only; no asterisks).
//
// Rules:
//   - strip leading "*." and prepend "wildcard-"
//   - replace remaining "." with "-"
//   - empty stays empty
func SanitizeName(domain string) string {
	if domain == "" {
		return ""
	}
	if strings.HasPrefix(domain, "*.") {
		return "wildcard-" + strings.ReplaceAll(strings.TrimPrefix(domain, "*."), ".", "-")
	}
	return strings.ReplaceAll(domain, ".", "-")
}
