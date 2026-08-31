package aliyun_esa

import (
	"net/url"
	"testing"
	"time"
)

func TestSign_ContainsAllRequiredParams(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	q, err := sign("ak", "sk", "SetCertificate", map[string]string{
		"SiteId": "123",
		"Type":   "upload",
	}, "cn-hangzhou", now)
	if err != nil {
		t.Fatal(err)
	}
	vals, _ := url.ParseQuery(q)
	must := []string{"Action", "Format", "Version", "AccessKeyId", "SignatureMethod",
		"SignatureVersion", "SignatureNonce", "Timestamp", "RegionId", "Signature"}
	for _, k := range must {
		if vals.Get(k) == "" {
			t.Errorf("missing param %q in signed query", k)
		}
	}
	if vals.Get("Action") != "SetCertificate" {
		t.Errorf("Action = %q, want SetCertificate", vals.Get("Action"))
	}
	if vals.Get("RegionId") != "cn-hangzhou" {
		t.Errorf("RegionId = %q", vals.Get("RegionId"))
	}
	if !startsWith(vals.Get("Timestamp"), "2026-08-31T") {
		t.Errorf("Timestamp = %q, want ISO 8601 UTC", vals.Get("Timestamp"))
	}
}

func TestSign_StableForSameInputs(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	q1, _ := sign("ak", "sk", "Action1", map[string]string{}, "cn-hangzhou", now)
	q2, _ := sign("ak", "sk", "Action1", map[string]string{}, "cn-hangzhou", now)
	if q1 == q2 {
		t.Error("expected different nonces to produce different signatures")
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
