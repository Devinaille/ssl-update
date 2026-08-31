// Package destination defines the interface for a cert push target and
// the registry that maps type-name strings to constructors.
package destination

import (
	"context"
	"errors"
	"time"

	"ssl-update/internal/cert"
)

// CertBundle is the cert material passed to a Destination for deployment.
// We re-export cert.CertBundle under this name so destinations don't
// need to import the cert package directly (avoids import cycles in
// tests). The two types are identical.
type CertBundle = cert.CertBundle

// DeployResult identifies the cert in the service side so subsequent
// renewals can update it in place.
type DeployResult struct {
	CertID      string
	CertName    string
	DeployedAt  time.Time
	Fingerprint string
}

// Destination is implemented by every push target.
type Destination interface {
	// Name returns the destination's reference name from config.
	Name() string

	// CertName returns the cert_name this destination will use for
	// the given bundle. Must be deterministic and stable for the
	// same input — used by the runner to build the state key and
	// look up the prior cert_id hint before calling Deploy.
	CertName(bundle CertBundle) string

	// Deploy pushes the cert. If certIDHint is non-empty the
	// destination should update the existing cert with that id;
	// otherwise it should create a new cert. The returned
	// DeployResult.CertName must equal what CertName(bundle) returned.
	Deploy(ctx context.Context, bundle CertBundle, certIDHint string) (DeployResult, error)

	// Validate checks connectivity + credentials without pushing a cert.
	Validate(ctx context.Context) error
}

// Sentinel errors a Destination may return (or wrap).
var (
	ErrInvalidConfig = errors.New("invalid destination config")
	ErrUnknownType   = errors.New("unknown destination type")
	ErrCertNotFound  = errors.New("certificate not found in service")
	ErrAuth          = errors.New("authentication failed")
	ErrNetwork       = errors.New("network error")
	ErrCertRejected  = errors.New("certificate rejected by service")
	ErrQuota         = errors.New("service quota exceeded")
)
