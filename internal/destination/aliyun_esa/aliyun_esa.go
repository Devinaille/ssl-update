// Package aliyun_esa implements the destination.Destination interface for
// the Aliyun Edge Security Acceleration (ESA) service via its OpenAPI.
package aliyun_esa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mitchellh/mapstructure"

	"ssl-update/internal/cert"
	"ssl-update/internal/destination"
)

const TypeName = "aliyun_esa"

func init() {
	destination.Register(TypeName, New)
}

type Config struct {
	AccessKeyID     string `mapstructure:"access_key_id"`
	AccessKeySecret string `mapstructure:"access_key_secret"`
	Region          string `mapstructure:"region"`
	SiteID          int64  `mapstructure:"site_id"`
	CertName        string `mapstructure:"cert_name"`
	Endpoint        string `mapstructure:"endpoint"`
}

type AliyunESA struct {
	name string
	cfg  Config
	hc   *http.Client
}

func New(name string, raw map[string]any) (destination.Destination, error) {
	var c Config
	if err := mapstructure.Decode(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: aliyun_esa: %v", destination.ErrInvalidConfig, err)
	}
	if c.AccessKeyID == "" || c.AccessKeySecret == "" {
		return nil, fmt.Errorf("%w: aliyun_esa: access_key_id and access_key_secret required", destination.ErrInvalidConfig)
	}
	if c.Region == "" {
		c.Region = "cn-hangzhou"
	}
	if c.SiteID == 0 {
		return nil, fmt.Errorf("%w: aliyun_esa: site_id required", destination.ErrInvalidConfig)
	}
	if c.Endpoint == "" {
		c.Endpoint = "esa.aliyuncs.com"
	}
	return &AliyunESA{
		name: name,
		cfg:  c,
		hc:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (a *AliyunESA) Name() string { return a.name }

// CertName returns the cert_name this AliyunESA instance will use.
func (a *AliyunESA) CertName(b cert.CertBundle) string {
	if a.cfg.CertName != "" {
		return a.cfg.CertName
	}
	return cert.SanitizeName(b.MainDomain)
}

func (a *AliyunESA) Deploy(ctx context.Context, b cert.CertBundle, hint string) (destination.DeployResult, error) {
	certName := a.CertName(b)

	params := map[string]string{
		"SiteId":      fmt.Sprintf("%d", a.cfg.SiteID),
		"Type":        "upload",
		"Name":        certName,
		"Certificate": string(b.Certificate),
		"PrivateKey":  string(b.PrivateKey),
	}
	if hint != "" {
		params["Id"] = hint
	}

	body, status, err := a.call(ctx, "SetCertificate", params)
	if err != nil {
		return destination.DeployResult{CertName: certName}, err
	}
	if status >= 400 {
		return destination.DeployResult{CertName: certName}, fmt.Errorf("aliyun_esa: http %d: %s", status, string(body))
	}
	var resp struct {
		Id        string `json:"Id"`
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestId string `json:"RequestId"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return destination.DeployResult{CertName: certName}, fmt.Errorf("aliyun_esa: parse: %w", err)
	}
	if resp.Code != "" && resp.Code != "OK" && resp.Code != "200" {
		return destination.DeployResult{CertName: certName}, fmt.Errorf("aliyun_esa: api code=%s msg=%s", resp.Code, resp.Message)
	}
	certID := resp.Id
	if certID == "" {
		certID = hint
	}
	if certID == "" {
		return destination.DeployResult{CertName: certName}, errors.New("aliyun_esa: no Id in response")
	}
	fp := fingerprint(b.Certificate)
	return destination.DeployResult{
		CertID:      certID,
		CertName:    certName,
		DeployedAt:  time.Now().UTC(),
		Fingerprint: "sha256:" + fp,
	}, nil
}

func (a *AliyunESA) Validate(ctx context.Context) error {
	_, status, err := a.call(ctx, "ListSites", map[string]string{
		"PageNumber": "1",
		"PageSize":   "1",
	})
	if err != nil {
		return err
	}
	if status == 401 || status == 403 {
		return fmt.Errorf("%w: http %d", destination.ErrAuth, status)
	}
	if status >= 400 {
		return fmt.Errorf("aliyun_esa: http %d", status)
	}
	return nil
}

func (a *AliyunESA) call(ctx context.Context, action string, params map[string]string) ([]byte, int, error) {
	qs, err := sign(a.cfg.AccessKeyID, a.cfg.AccessKeySecret, action, params, a.cfg.Region, time.Now().UTC())
	if err != nil {
		return nil, 0, err
	}
	url := "https://" + a.cfg.Endpoint + "/?" + qs
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", destination.ErrNetwork, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

func fingerprint(pem []byte) string {
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:])
}

var _ destination.Destination = (*AliyunESA)(nil)
