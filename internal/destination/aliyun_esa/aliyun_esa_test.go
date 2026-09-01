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
		if r.Method != "POST" {
			t.Errorf("method = %q, want POST (SetCertificate is a write action; bug #6)", r.Method)
		}
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
		if r.Method != "POST" {
			t.Errorf("method = %q, want POST", r.Method)
		}
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

// Regression test: the default endpoint MUST be region-specific
// (esa.<region>.aliyuncs.com), not the bare "esa.aliyuncs.com" which
// doesn't resolve. Bug reported 2026-09-01 by user trying to validate
// prod-esa on cn-hangzhou.
func TestNew_DefaultsEndpointFromRegion(t *testing.T) {
	cases := []struct {
		region, want string
	}{
		{"cn-hangzhou", "esa.cn-hangzhou.aliyuncs.com"},
		{"ap-southeast-1", "esa.ap-southeast-1.aliyuncs.com"},
	}
	for _, tc := range cases {
		t.Run(tc.region, func(t *testing.T) {
			aIface, err := New("x", map[string]any{
				"access_key_id":     "ak",
				"access_key_secret": "sk",
				"region":            tc.region,
				"site_id":           1,
			})
			if err != nil {
				t.Fatal(err)
			}
			a := aIface.(*AliyunESA)
			if a.cfg.Endpoint != tc.want {
				t.Errorf("default endpoint = %q, want %q", a.cfg.Endpoint, tc.want)
			}
		})
	}
}

func TestNew_RespectsExplicitEndpoint(t *testing.T) {
	aIface, err := New("x", map[string]any{
		"access_key_id":     "ak",
		"access_key_secret": "sk",
		"region":            "cn-hangzhou",
		"site_id":           1,
		"endpoint":          "esa-vpc.cn-hangzhou.aliyuncs.com", // VPC variant
	})
	if err != nil {
		t.Fatal(err)
	}
	a := aIface.(*AliyunESA)
	if a.cfg.Endpoint != "esa-vpc.cn-hangzhou.aliyuncs.com" {
		t.Errorf("explicit endpoint overridden: got %q", a.cfg.Endpoint)
	}
}

func TestListSites_ParsesResponse(t *testing.T) {
	ts, a := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Action") != "ListSites" {
			t.Errorf("Action = %q, want ListSites", r.URL.Query().Get("Action"))
		}
		if got := r.URL.Query().Get("PageSize"); got != "500" {
			t.Errorf("PageSize = %q, want 500 (max)", got)
		}
		w.Write([]byte(`{
			"RequestId": "r-1",
			"TotalCount": 2,
			"Sites": [
				{"SiteId":12345,"SiteName":"example.com","Status":"active","AccessType":"NS","Coverage":"domestic","PlanName":"pro"},
				{"SiteId":67890,"SiteName":"test.com","Status":"pending","AccessType":"CNAME","Coverage":"global","PlanName":"free"}
			]
		}`))
	})
	defer ts.Close()
	sites, err := a.ListSites(context.Background())
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(sites) != 2 {
		t.Fatalf("len(sites) = %d, want 2", len(sites))
	}
	if sites[0].SiteID != 12345 || sites[0].SiteName != "example.com" || sites[0].Status != "active" {
		t.Errorf("site[0] wrong: %+v", sites[0])
	}
	if sites[1].SiteID != 67890 || sites[1].AccessType != "CNAME" || sites[1].Coverage != "global" {
		t.Errorf("site[1] wrong: %+v", sites[1])
	}
}

func TestListSites_HttpError(t *testing.T) {
	ts, a := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"Code":"Forbidden","Message":"no perm"}`))
	})
	defer ts.Close()
	_, err := a.ListSites(context.Background())
	if err == nil {
		t.Error("expected error on http 403")
	}
}
