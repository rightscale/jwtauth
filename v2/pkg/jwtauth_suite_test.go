package jwtauth_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	jwtpkg "github.com/dgrijalva/jwt-go"
	"github.com/onsi/gomega/types"
	jwtauth "github.com/rightscale/jwtauth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestJWTSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "jwtauth")
}

type bogusClaims struct{}

func (bc *bogusClaims) Valid() error {
	return nil
}

var hmacKey1 = []byte("I like tacos")

var hmacKey2 = []byte("I hate oysters")

var rsaKey1Pem = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArZIJcPQd7aSGb80wgFpy5SVjzzsGpfIysZ30SdWlTcWMVbAT
XmsDNgw98TzIeoyikSbSHEeORbKWKS2clgNsdLjYKv3XLTBaXfLcU3x9mhnk/kUL
N/AQgyvsRGynPris2oVzGSib7uOZK/9+u+QAKIrp7prcmMmnwvdcjFXjwzx83RTF
1b+iuVGCdV0T4m1XQdm/YtIUh7JNbYrUolkdwZlOxMZuV0FDC+ms02+gyj580Pyl
TuAD4JmtSmmijyWfEx5dsZYtGALyUxcm5Hz15RP3FACrv4B++BHI6smO4sWdrSYV
l3sHJ60Bm6zbwuyB2twJPOdL5nVIGiIDdf+1IwIDAQABAoIBACF3MtLQfqS/QBx2
V4+n4NdFqkTegJ2mYRfV+K/zvXeNS02KMXHW+DuHiLnmmlDmpMGP1psVQN03XbR6
0uIprtOigCtp3f8cf4/1r315V05LB9fuwAb9BnIEGf3nZSe2u702VcbYCZi50WKm
VG0tvMoUXp5exYG//9SblQCJ3uxZf9D8y5RnrUZtP4Pnjkn/3YeJCF+Kked55Cvi
gv56/aiyWp9xEGsSWig5Zt8VNXihgT7D2KZzxcQDQlxw0CR5ECT7/4w7sZVvwc7B
I76JJDvpD0UGvzoUgx928efGKxJBrcjzvTNSKgHJYYCvaa6+qX2tjkmOqdG4xl27
/TaBISECgYEA4YJ32HKaS2ikn5J2C1qlHy4nRuVNhX8T9qvp6OBdbE2BQq3O5IUt
+wdTcjhD88aDdHCZmAd8i3FC4l+CKsQ5sTwRk0vTOZ7axC6+zDHg+na5/+NCq+xm
ffoaZ5jsZFyqfbsFn8NiLWLo2JSFV1AnUxwpPA2jbuylAuZVvVbLYHcCgYEAxQnO
L+U6NwTvN6EJgt3h1jHfXiQnapsj0O0XgK+g2K6vMovpXAf9noO+r3Qbx/aKxuRg
TvRQ08T5yyqysz+sYe0rp8oaMUhYQFMgJOUUBlmUVGxYdARMD6kTy/384B9Azoex
UCosMSEAD909MAsyQWB4X6OJKd+V68QpFYeIx7UCgYBHgaRY6PYOBU92He36abLE
MVFZBKrRMtt0s0yHgGV/SxA6wXxCMAzFdaw7IqZBbWgPiwjZET6nxLFNsLVItFIK
5h44k6mVss5xuNTdUM+i+/S8tCZW964EMkMfKHmE1XFmTuBYqY6/D4b/7hBeAFeH
3f0hQr3ZFYa5Zao4UIZKvwKBgGL8lhUBt8lENVlhEYIpLfeJfomw6AxqfAfN1GzV
zpyMxX9DQqz1ZrhnvzgtwHcoqHda6/c+TgzVfBhRDw12A4f+ulvE8HupuIw4NoHS
g8jc3+O5uoYuUnfbnRJyOsPtb4VSLgXz6deUmI9fugmU1l55tH93jMT4ijyzg2BJ
grGxAoGAWX24Yx9qoasqEQ2rgdTsgylwL28UczKQ5KNHt2PcEfPNw6/GpfK7YmlU
Heef2umEzb1K2ZK95wlMbF8zpNDWBf4PkxgfW+JEE+pO1kb5KXysBymymyXhGHAP
CwH9XHqbjVlsD358AbPeKqLgTCaGo9JgsEZDBpESmBDnIPUahMc=
-----END RSA PRIVATE KEY-----
`)

var rsaKey1, _ = jwtpkg.ParseRSAPrivateKeyFromPEM([]byte(rsaKey1Pem))

var rsaKey2Pem = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4jr/DGbPt0UDGvu6Xo2LV0F6Wf8OnyxF2IFPdG5B4X0YS3DC
9SF3clbbBivDVa2bEXppyj+eLEKlfohCWXTrJK0LxTEcneuDkF4re+BdP3q9cKRz
FtI/ZVhVnD7+PS1wps7OiTM0iOaIDo9+uFrC6zBTRAiPyrdwh1ApttLdoD6i5D9D
7zzvpTXLC/UWaRz/phAaaop6dPPR1YblZEckWgqTMC3KrRX/6QJFFfpgyQzFT09W
DYnmXl2gS7C2sk4UejygqmVg96JxaIaT3WiQSjxXddjR/krcA9EGNNEkpZB2W6Ux
6d63yWsNG9YJUacwI+M2q5ZW964J1s//FiNZZQIDAQABAoIBAQCoqYtU16Gs5Qq3
p0z/CVAFMY/iYMGp8fvwuhdemoULc5QVSnBPCTBgUljgdOggjFm74iPU4TEvllCD
0VqGDyDwKwNHdKH9KoTfsRWCOXfLx9pMjI4xSXZyPDU3U8+AFMyT0EMzDrXwCs8M
6/Zxw1jmtxSc+DUb0T9X4m/3GaaZvDGGShnU8/XnEh2uEHrNwWnGWYPJ/rZjNZPy
PZ9W2VpcHKBMVEowK/cOoouNuflAISoLCCLMNYygr9T4Ylm3HGP9o7JuWL+wGQsa
aXrE5qTOpsxmBqTQ8pglnxnhDEFXmx3O+bwRfIwDSYe+wvCINpdIstWuybh4Ed2i
ZgLTlx8BAoGBAP9LwmfZ/2XNHBzk+f09TnTnhXzVsKkHu5BlXvWoDigVv4Dzl44j
X1Ade5PjiOf0Jti2QCkAaI+CjExdP1zCqDZBQFpKI3QQgvlWoKXHVFV9ziC8gcX+
I6M8wmtIoK8ISnC6A5s1wKIvOPsZyP7aVZgu805BKfVqtFWCK42vnRVRAoGBAOLa
t2pOzVttd3vPgzGovD+Mf3RsPg6ygazj0GiDRspRCnoeopFEoBPFcKIQZlPp8rfT
NLOuwVkW5TqntrCW0UwixZMXicIaPDo0idXInIfP0+f7JxSYb5q7vmbyRt8uAYY9
GU4L/ZIn127JbgQ5n5nuODMvTe7m5Ky+FUYHw43VAoGAE6QOdtLstTZMfWSYXwVC
bfgJ6wq9pqNzqK5D2f5t6GOT8iXLeSH7iTxbb4tH0yCThISw9vaTFMdkZ9OctlQ7
gMEQZGHjzGAg03H4tghZ0qH1I8uc6FCfCUX5ZyuVQSIQKBAHiv9drJyZc6gOMJ03
jJfAHDsjMUBeU13KYAIswaECgYBTYiNSzv5KodTuTFsjsKrpDOJ4T6ULz+88NkyP
bdliWiFou8Pzc28HdWYuG6sRIwfVK6vOc+ibr3+4bJcJF5Z8zrcilt9K2kvS9SbI
zsFCZlC0jytRNaqoDGQzANCuDgH/bovTlTKyOzTDgwSORwP0F4zOu4+AxZu+Juw4
3nextQKBgEAGLuChkztZCVt0W2D8wJYFR7XjezcbsfpoXx9H8htk6u4STu9TwB76
DxoYj3qiTV2kRRBQQZRAli1TbDOnJuqFMnRL0aPsqebuW2sqY9Hx9G6TxokN8Nc6
RlTE+CbPcjBgAx+AANL/X2KYoXLAjOrYY5kQD8Qbt8Wkme7m6hiP
-----END RSA PRIVATE KEY-----
`)

var rsaKey2, _ = jwtpkg.ParseRSAPrivateKeyFromPEM([]byte(rsaKey2Pem))

var ecKey1Pem = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4zAVusfF+Xl4Z5a5LaspGk+OIwGQweubphSqC1R9+VoAoGCCqGSM49
AwEHoUQDQgAE3tWSknhfssUVytNbPz3TB7giFfxKtHsFW27Yls+Ohfuui9NW4eEk
fLOxYkTI9tyoKfh9Dan5kJFA7ZYEwZ0zMQ==
-----END EC PRIVATE KEY-----
`)

var ecKey1, _ = jwtpkg.ParseECPrivateKeyFromPEM([]byte(ecKey1Pem))

var ecKey2Pem = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKQ7EyFGaYMuFpMLnqK+mBnT9CrWOqzVxsF8wBlGrTq/oAoGCCqGSM49
AwEHoUQDQgAE8IX3mOtLvBpvrylaRjFpadqGrirXh9dkjJfM/t1dnLu5qPhybMIY
tEr3Xs8vYp2wyaSTVKsyj9y+t344T5Bhdw==
-----END EC PRIVATE KEY-----
`)

var ecKey2, _ = jwtpkg.ParseECPrivateKeyFromPEM([]byte(ecKey2Pem))

var rsaPKCSPubPem = []byte(`
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAO6NndZW3iD45Qi5VSqLkgr7k/Ya8BCL3d8wN7sexvcrgR6u5VxljRd5
zkH/JVK1IV7ik7h/LsI/CpDDwAfGQWQ9HCF1qozIinEfFCsdURt25L0rk8Uax11n
ugUc4XgnaUV55WV6CROoZDX/sKTdW3/BbVeSgk0pHfM2jzYMmKeTAgMBAAE=
-----END RSA PUBLIC KEY-----
`)

var rsaPKIXPubPem = []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKjjrYD61f02XciwnAKjcHT0Wr
ywf7SnM9PHBZ/2+oKwhUDYzHxl2OLn7EGJ0FSPtsJIr5BGay+9oA7W+OpfDqxDUU
Rz7EiDzW69onM3GVXMrS/pQhKpJmFHmJsSXGE26ahfegowx6ChFLZrY01y0lBxkQ
tm2ouoqEVhJbO0QosQIDAQAB
-----END PUBLIC KEY-----
`)

var ecPKIXPubPem = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOfy4eFmaXiqvXh9ay0J8CB0BzqI7
XdeFVfxnFhx8YOLMCuXyEX2Wtc+av9jlWaV7htgnuIcA0frqM822+2EYaQ==
-----END PUBLIC KEY-----
`)

func makeToken(issuer, subject string, key interface{}, scopes ...string) string {
	now := time.Now()
	return makeTokenWithTimestamps(issuer, subject, key, now, now, now.Add(time.Minute), scopes...)
}

func publicKey(key interface{}) interface{} {
	switch tk := key.(type) {
	case []byte:
		return tk
	case *rsa.PrivateKey:
		return tk.Public()
	case *ecdsa.PrivateKey:
		return tk.Public()
	default:
		panic(fmt.Sprintf("Unsupported key type for tests: %T", key))
	}
}

func makeTokenWithTimestamps(issuer, subject string, key interface{}, iat, nbf, exp time.Time, scopes ...string) string {
	claims := jwtauth.Claims{}
	claims["iss"] = issuer
	claims["iat"] = iat.Unix()
	claims["nbf"] = nbf.Unix()
	claims["exp"] = exp.Unix()
	claims["sub"] = subject
	claims["scopes"] = scopes

	token, err := jwtauth.NewToken(key, claims)
	if err != nil {
		panic(err)
	}
	return token
}

func modifyToken(token string) string {
	// modify a single byte
	return strings.Replace(token, token[25:26], string(byte(token[25])+1), 1)
}

func setBearerHeader(req *http.Request, token string) {
	header := fmt.Sprintf("Bearer %s", token)
	req.Header.Set("Authorization", header)
}

func HaveResponseStatus(expected int) types.GomegaMatcher {
	return &statusMatcher{
		expected: expected,
	}
}

type statusMatcher struct {
	expected int
}

func (matcher *statusMatcher) Match(actual interface{}) (success bool, err error) {
	response, ok := actual.(interface {
		ResponseStatus() int
	})
	if !ok {
		return false, fmt.Errorf("HaveResponseStatus expects a type with a method\n\tResponseStatus() int\nbut got\n\t%#v", actual)
	}
	match := reflect.DeepEqual(response.ResponseStatus(), matcher.expected)
	return match, nil
}

func (matcher *statusMatcher) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected\n\t%#v\nto have ResponseStatus\n\t%#v", actual, matcher.expected)
}

func (matcher *statusMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected\n\t%#v\nnot to contain the JSON representation of\n\t%#v", actual, matcher.expected)
}
