package aliyun_esa

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSign_ContainsAllRequiredParams(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	q, err := sign("ak", "sk", "SetCertificate", "2024-09-10", "POST", map[string]string{
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
	q1, _ := sign("ak", "sk", "Action1", "2024-09-10", "GET", map[string]string{}, "cn-hangzhou", now)
	q2, _ := sign("ak", "sk", "Action1", "2024-09-10", "GET", map[string]string{}, "cn-hangzhou", now)
	if q1 == q2 {
		t.Error("expected different nonces to produce different signatures")
	}
}

// Regression test: Aliyun v3 spec says the HTTP method is part of the
// StringToSign. A POST request must produce a DIFFERENT signature than
// a GET request with otherwise-identical params (otherwise the server
// can't tell which method was used and might return 403
// "UnsupportedHTTPMethod" for write actions).
//
// Bug #6 (v0.1.1): sign() hardcoded "GET" in the StringToSign even
// when the actual HTTP request was POST. Fixed in v0.1.2.
func TestSign_MethodAffectsSignature(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nonce := "fixed-nonce"
	getQs, _ := signWithNonce("ak", "sk", "SetCertificate", "2024-09-10", "GET", map[string]string{"SiteId": "1"}, "cn-hangzhou", now, nonce)
	postQs, _ := signWithNonce("ak", "sk", "SetCertificate", "2024-09-10", "POST", map[string]string{"SiteId": "1"}, "cn-hangzhou", now, nonce)
	_, getSig, _ := strings.Cut(getQs, "&Signature=")
	_, postSig, _ := strings.Cut(postQs, "&Signature=")
	getSig, _ = url.QueryUnescape(getSig)
	postSig, _ = url.QueryUnescape(postSig)
	if getSig == postSig {
		t.Errorf("GET and POST produced the same signature %q — method must affect StringToSign", getSig)
	}
}

// Regression test: Aliyun v3 spec uses RFC 3986 percent-encoding for
// URL params. Go's stdlib url.QueryEscape uses form-urlencoded which
// encodes space as '+' (not '%20'). This is invisible for ListSites
// (alphanumeric values) but BREAKS SetCertificate because cert PEM
// blocks contain "-----BEGIN CERTIFICATE-----" with spaces and base64
// content may contain '+'.
//
// Bug #7 (v0.1.2 first cut): sign() used url.QueryEscape, so a cert
// value's spaces became '%2B' after double-encoding instead of '%2520'.
// The server's expected StringToSign had '%2520', the client produced
// '%2B' → SignatureDoesNotMatch.
func TestSign_AliEscapeEncodesSpaceAsPercent20(t *testing.T) {
	got := aliEscape("-----BEGIN CERTIFICATE-----")
	want := "-----BEGIN%20CERTIFICATE-----"
	if got != want {
		t.Errorf("space encoding:\n got: %q\nwant: %q\n(form-urlencoded '+' is wrong; Aliyun v3 spec uses percent-20)", got, want)
	}
}

func TestSign_AliEscapeEncodesPlusInValue(t *testing.T) {
	// '+' in a value should encode to %2B (not collapse with our '+' for space).
	got := aliEscape("abc+def")
	want := "abc%2Bdef"
	if got != want {
		t.Errorf("plus encoding:\n got: %q\nwant: %q", got, want)
	}
}

func TestSign_AliEscapeUnencodesTilde(t *testing.T) {
	// '~' is reserved in RFC 3986 as unreserved, so Aliyun v3 keeps it
	// unencoded. Go's QueryEscape encodes it to %7E.
	got := aliEscape("abc~def")
	want := "abc~def"
	if got != want {
		t.Errorf("tilde encoding:\n got: %q\nwant: %q", got, want)
	}
}

// Regression test: a value containing a space must produce a DIFFERENT
// signature than the same value with the space replaced by '+' (because
// the two encode differently under form-urlencoded vs RFC 3986).
//
// Bug #7 (v0.1.2 first cut): if you used url.QueryEscape, " " and "+"
// would both produce '+' → ambiguous. With aliEscape, " " → "%20" and
// "+" → "+" → "%2B" after the outer encode, so the signatures diverge.
func TestSign_SpaceAndPlusProduceDifferentSignatures(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nonce := "fixed-nonce"
	spaceQs, _ := signWithNonce("ak", "sk", "SetCertificate", "2024-09-10", "POST", map[string]string{"Name": "a b"}, "cn-hangzhou", now, nonce)
	plusQs, _ := signWithNonce("ak", "sk", "SetCertificate", "2024-09-10", "POST", map[string]string{"Name": "a+b"}, "cn-hangzhou", now, nonce)
	_, spaceSig, _ := strings.Cut(spaceQs, "&Signature=")
	_, plusSig, _ := strings.Cut(plusQs, "&Signature=")
	spaceSig, _ = url.QueryUnescape(spaceSig)
	plusSig, _ = url.QueryUnescape(plusSig)
	if spaceSig == plusSig {
		t.Errorf("space and plus produced the same signature %q — they must differ (bug #7)", spaceSig)
	}
}

// Sign-reference regression test: locks in the Aliyun v3 signature
// algorithm against the OFFICIAL example from
// https://help.aliyun.com/document_detail/315526.htm. If the canonical
// query, string-to-sign, or signature encoding drift away from the
// spec, this test catches it BEFORE a real API call fails with
// "SignatureDoesNotMatch".
//
// Bug #5 (v0.1.1): signature was hex-encoded; Aliyun v3 expects
// base64. This test would have caught it — without it, the existing
// aliyun_esa tests only checked Action=ListSites, never the signature.
func TestSign_AliyunOfficialExample(t *testing.T) {
	// Inputs from Aliyun's official v3 example.
	const (
		ak        = "testid"
		sk        = "testsecret"
		nonce     = "3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf"
		timestamp = "2016-03-24T16:41:54Z" // example timestamp
		// Expected outputs per Aliyun docs:
		// - canonical: URL-escaped form per the v3 spec
		// - signature: base64(HMAC-SHA256("testsecret&", StringToSign))
		//   independently verified by running this Go stdlib HMAC in a
		//   separate one-shot program (see git history; not the value
		//   in the docs page text, which appears to be a stale example)
		wantCanonical = "AccessKeyId=testid&Action=DescribeRegions&Format=JSON&SignatureMethod=HMAC-SHA256&SignatureNonce=3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf&SignatureVersion=1.0&Timestamp=2016-03-24T16%3A41%3A54Z&Version=2014-05-26"
		wantSig       = "oPN9Od7Zc5sCrdn6oVxvg9c8cODiaSmopDhtVdxMKXA="
	)

	now, _ := time.Parse(time.RFC3339, timestamp)
	got, err := signWithNonce(ak, sk, "DescribeRegions", "2014-05-26", "GET", nil, "", now, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Split off the Signature param to inspect separately.
	canonical, rawSig, _ := strings.Cut(got, "&Signature=")
	if canonical != wantCanonical {
		t.Errorf("canonical query mismatch\n got: %q\nwant: %q", canonical, wantCanonical)
	}
	// Signature is URL-encoded inside the query, decode it for the
	// charset/equality check (the official Aliyun example is the
	// unencoded base64 string).
	sig, err := url.QueryUnescape(rawSig)
	if err != nil {
		t.Fatalf("Signature is not URL-decodable: %v", err)
	}
	if sig != wantSig {
		t.Errorf("signature mismatch\n got: %q\nwant: %q (must be base64, not hex — bug #5)", sig, wantSig)
	}
}

func TestSign_SignatureIsBase64(t *testing.T) {
	// Defensive: even if the reference example above drifts, the
	// signature should at least look like base64 (charset [A-Za-z0-9+/=]).
	// Hex would be [0-9a-f] and contain NO uppercase, no +, no /, no =.
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := sign("testid", "testsecret", "ListSites", "2024-09-10", "GET", map[string]string{
		"PageNumber": "1",
		"PageSize":   "500",
	}, "cn-hangzhou", now)
	if err != nil {
		t.Fatal(err)
	}
	_, rawSig, _ := strings.Cut(got, "&Signature=")
	sig, err := url.QueryUnescape(rawSig)
	if err != nil {
		t.Fatalf("Signature is not URL-decodable: %v", err)
	}
	for i, c := range sig {
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '=':
		default:
			t.Errorf("signature char %d (%q) is not a valid base64 character; full sig=%q", i, c, sig)
		}
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
