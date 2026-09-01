package aliyun_esa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

// aliEscape is the Aliyun v3-specific URL encoding.
//
// The Aliyun v3 spec uses RFC 3986 percent-encoding, but Go's
// stdlib url.QueryEscape uses the form-urlencoded variant where
// space is encoded as '+' (not '%20'). This difference doesn't
// matter for ListSites (values are alphanumeric) but BREAKS
// SetCertificate because cert PEM blocks contain spaces
// (-----BEGIN CERTIFICATE-----) and base64 contains '+'.
//
// Bug #7 (v0.1.2 first cut): sign() used url.QueryEscape, so
// the cert's spaces became '%2B' after double-encoding instead
// of '%2520'. The server's expected StringToSign had '%2520',
// the client produced '%2B' → SignatureDoesNotMatch.
//
// Rules vs url.QueryEscape:
//   - space  ' ' → '+' → '%20'   (FIXED: convert '+' to '%20')
//   - '*'    →  %2A (same in both, kept explicit for clarity)
//   - '~'    →  %7E → '~'         (FIXED: un-encode; RFC 3986 unreserved)
//
// Everything else is identical to url.QueryEscape.
func aliEscape(s string) string {
	s = url.QueryEscape(s)
	s = strings.ReplaceAll(s, "+", "%20")
	s = strings.ReplaceAll(s, "*", "%2A")
	s = strings.ReplaceAll(s, "%7E", "~")
	return s
}

// sign produces an Aliyun v3 signed query string for an RPC-style GET
// or POST request. Returns the URL-encoded query (without leading "?").
//
// Reference: Aliyun OpenAPI v3 RPC signature spec.
//
//	StringToSign = METHOD + "&" + URLEncode("/") + "&" + URLEncode(canonicalQuery)
//	Signature    = base64( HMAC-SHA256(accessKeySecret + "&", StringToSign) )
//
// where canonicalQuery is "k1=v1&k2=v2&..." with keys sorted ascending
// and each k/v pair individually URL-encoded (using Aliyun's RFC 3986
// variant — see aliEscape), then the whole string URL-encoded again
// before going into StringToSign.
//
// IMPORTANT: Signature is base64-encoded (NOT hex). Hex gives a
// SignatureDoesNotMatch error on every Aliyun v3 API. Bug #5
// (fixed earlier).
//
// IMPORTANT: Use the Aliyun-specific escape function, NOT stdlib
// url.QueryEscape. Bug #7 (fixed here).
func sign(accessKeyID, accessKeySecret, action, version, method string, params map[string]string, region string, now time.Time) (string, error) {
	return signWithNonce(accessKeyID, accessKeySecret, action, version, method, params, region, now, randNonce())
}

// signWithNonce is sign() with an explicit nonce — exposed so tests can
// use a deterministic nonce and compare against the Aliyun official
// reference signature.
func signWithNonce(accessKeyID, accessKeySecret, action, version, method string, params map[string]string, region string, now time.Time, nonce string) (string, error) {
	if method == "" {
		method = "GET"
	}
	p := map[string]string{}
	for k, v := range params {
		p[k] = v
	}
	p["Action"] = action
	p["Format"] = "JSON"
	p["Version"] = version
	p["AccessKeyId"] = accessKeyID
	p["SignatureMethod"] = "HMAC-SHA256"
	p["SignatureVersion"] = "1.0"
	p["SignatureNonce"] = nonce
	p["Timestamp"] = now.UTC().Format("2006-01-02T15:04:05Z")
	if region != "" {
		p["RegionId"] = region
	}

	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(aliEscape(k))
		sb.WriteByte('=')
		sb.WriteString(aliEscape(p[k]))
	}
	canonicalQuery := sb.String()

	// The HTTP method is part of StringToSign. Server will compute the
	// expected StringToSign with whatever method the HTTP request
	// actually used — so client and server must agree.
	stringToSign := method + "&%2F&" + aliEscape(canonicalQuery)
	h := hmac.New(sha256.New, []byte(accessKeySecret+"&"))
	h.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return canonicalQuery + "&Signature=" + aliEscape(sig), nil
}

func randNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
