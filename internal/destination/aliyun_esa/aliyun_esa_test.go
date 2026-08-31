package aliyun_esa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ssl-update/internal/cert"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *AliyunESA) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	aIface, err := New("test-dest", map[string]any{
		"access_key_id":     "ak",
		"access_key_secret": "sk",
		"region":            "cn-hangzhou",
		"site_id":           123,
		"endpoint":          strings.TrimPrefix(ts.URL, "https://"),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := aIface.(*AliyunESA)
	a.hc = ts.Client() // trust the test server's self-signed cert
	return ts, a
}

func TestNew_RequiresCredentials(t *testing.T) {
	_, err := New("x", map[string]any{"site_id": 1})
	if err == nil {
		t.Error("expected error for missing credentials")
	}
}

func TestDeploy_FirstTime_ReturnsID(t *testing.T) {
	ts, a := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Action") != "SetCertificate" {
			t.Errorf("Action = %q, want SetCertificate", r.URL.Query().Get("Action"))
		}
		if r.URL.Query().Get("Signature") == "" {
			t.Error("Signature missing")
		}
		w.Write([]byte(`{"Id":"babaabcd****","RequestId":"r-1"}`))
	})
	defer ts.Close()
	res, err := a.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("cert"),
		PrivateKey:  []byte("key"),
		MainDomain:  "*.a.com",
	}, "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if res.CertID != "babaabcd****" {
		t.Errorf("CertID = %q", res.CertID)
	}
	if res.CertName != "wildcard-a-com" {
		t.Errorf("CertName = %q, want wildcard-a-com", res.CertName)
	}
}

func TestDeploy_WithHint_PassesId(t *testing.T) {
	var seenId string
	ts, a := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenId = r.URL.Query().Get("Id")
		w.Write([]byte(`{"Id":"babaabcd****","RequestId":"r"}`))
	})
	defer ts.Close()
	_, err := a.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"), PrivateKey: []byte("k"), MainDomain: "*.a.com",
	}, "stored-id")
	if err != nil {
		t.Fatal(err)
	}
	if seenId != "stored-id" {
		t.Errorf("Id param = %q, want stored-id", seenId)
	}
}

func TestDeploy_ApiError_ReturnsError(t *testing.T) {
	ts, a := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Code":"InvalidParameter.SiteId","Message":"bad site id"}`))
	})
	defer ts.Close()
	_, err := a.Deploy(context.Background(), cert.CertBundle{
		Certificate: []byte("c"), PrivateKey: []byte("k"), MainDomain: "*.a.com",
	}, "")
	if err == nil {
		t.Error("expected error on API code")
	}
}

func TestValidate_OK(t *testing.T) {
	ts, a := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Action") != "ListSites" {
			t.Errorf("Action = %q, want ListSites", r.URL.Query().Get("Action"))
		}
		w.Write([]byte(`{"Sites":[{"SiteId":123}]}`))
	})
	defer ts.Close()
	if err := a.Validate(context.Background()); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestCertName_OverrideFromConfig(t *testing.T) {
	a := &AliyunESA{name: "x", cfg: Config{CertName: "explicit-name"}}
	if got := a.CertName(cert.CertBundle{MainDomain: "*.a.com"}); got != "explicit-name" {
		t.Errorf("CertName = %q, want explicit-name", got)
	}
}

func TestCertName_SanitizeDefault(t *testing.T) {
	a := &AliyunESA{name: "x", cfg: Config{}}
	if got := a.CertName(cert.CertBundle{MainDomain: "*.a.com"}); got != "wildcard-a-com" {
		t.Errorf("CertName = %q, want wildcard-a-com", got)
	}
}
