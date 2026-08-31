package aliyun_esa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sign produces an Aliyun v3 signed query string for an RPC-style GET
// request. Returns the URL-encoded query (without leading "?").
//
// Reference: Aliyun OpenAPI v3 RPC signature spec.
//   StringToSign = "GET&%2F&" + URLEncode(canonicalQuery)
//   Signature    = HMAC-SHA256(accessKeySecret + "&", StringToSign)
//
// where canonicalQuery is "k1=v1&k2=v2&..." with keys sorted ascending.
func sign(accessKeyID, accessKeySecret, action string, params map[string]string, region string, now time.Time) (string, error) {
	p := map[string]string{}
	for k, v := range params {
		p[k] = v
	}
	p["Action"] = action
	p["Format"] = "JSON"
	p["Version"] = "2024-09-10"
	p["AccessKeyId"] = accessKeyID
	p["SignatureMethod"] = "HMAC-SHA256"
	p["SignatureVersion"] = "1.0"
	p["SignatureNonce"] = randNonce()
	p["Timestamp"] = now.UTC().Format("2006-01-02T15:04:05Z")
	p["RegionId"] = region

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
		sb.WriteString(url.QueryEscape(k))
		sb.WriteByte('=')
		sb.WriteString(url.QueryEscape(p[k]))
	}
	canonicalQuery := sb.String()

	stringToSign := "GET&%2F&" + url.QueryEscape(canonicalQuery)
	h := hmac.New(sha256.New, []byte(accessKeySecret+"&"))
	h.Write([]byte(stringToSign))
	sig := hex.EncodeToString(h.Sum(nil))

	return canonicalQuery + "&Signature=" + url.QueryEscape(sig), nil
}

func randNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
