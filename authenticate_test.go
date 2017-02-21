package jwtauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"golang.org/x/net/context"

	jwtpkg "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/jwtauth"
)

var _ = Describe("Authenticate() middleware", func() {
	Context("error handling", func() {
		var stack goa.Handler
		var resp *httptest.ResponseRecorder
		var req *http.Request

		BeforeEach(func() {
			resp = httptest.NewRecorder()
			req, _ = http.NewRequest("GET", "http://example.com/", nil)
			stack = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
				return nil
			}

			middleware := jwtauth.Authenticate(commonScheme, &jwtauth.SimpleKeystore{hmacKey1})
			stack = middleware(stack)
		})

		It("rejects unknown issuers", func() {
			store := &jwtauth.NamedKeystore{}
			middleware := jwtauth.Authenticate(commonScheme, store)

			setBearerHeader(req, makeToken("suspicious-issuer", "", hmacKey1))

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).Should(HaveResponseStatus(401))
		})

		It("fails when JWTSecurity.Location is unsupported", func() {
			scheme := &goa.JWTSecurity{In: goa.LocQuery, Name: "jwt"}
			store := &jwtauth.NamedKeystore{}
			middleware := jwtauth.Authenticate(scheme, store)

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).Should(HaveResponseStatus(500))
		})

		It("converts issuers to string", func() {
			middleware := jwtauth.Authenticate(commonScheme, &jwtauth.SimpleKeystore{hmacKey1})
			claims := jwtpkg.MapClaims{}
			claims["iss"] = 7
			token := jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, &claims)
			s, err := token.SignedString(hmacKey1)
			if err != nil {
				panic(err)
			}
			setBearerHeader(req, s)

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).ShouldNot(HaveOccurred())
		})
	})

	Context("given any keystore", func() {
		var resp *httptest.ResponseRecorder
		var req *http.Request

		var stack goa.Handler
		var middleware goa.Middleware
		var claims jwtauth.Claims

		BeforeEach(func() {
			resp = httptest.NewRecorder()
			req, _ = http.NewRequest("GET", "http://example.com/", nil)
			stack = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
				claims = jwtauth.ContextClaims(ctx)
				return nil
			}

			middleware = jwtauth.Authenticate(commonScheme, &jwtauth.SimpleKeystore{hmacKey1})
		})

		It("accepts requests that lack tokens", func() {
			result := middleware(stack)(context.Background(), resp, req)
			Ω(result).ShouldNot(HaveOccurred())
			Ω(claims).Should(HaveLen(0))
		})

	})

	testKeyType("HMAC", hmacKey1, hmacKey2)
	testKeyType("RSA", rsaKey1, rsaKey2)
	testKeyType("ECDSA", ecKey1, ecKey2)
})

// testKeyType defines test cases that are repeated for every supported key
// type.
func testKeyType(name string, trusted, untrusted interface{}) {
	var resp *httptest.ResponseRecorder
	var req *http.Request

	var stack goa.Handler
	var middleware goa.Middleware
	var claims jwtauth.Claims

	Context(fmt.Sprintf("given %s keys"), func() {
		BeforeEach(func() {
			resp = httptest.NewRecorder()
			req, _ = http.NewRequest("GET", "http://example.com/", nil)
			stack = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
				claims = jwtauth.ContextClaims(ctx)
				return nil
			}

			store := &jwtauth.SimpleKeystore{publicKey(trusted)}
			middleware = jwtauth.Authenticate(commonScheme, store)
		})

		AfterEach(func() {
			claims = nil
		})

		It("accepts valid tokens", func() {
			setBearerHeader(req, makeToken("alice", "bob", trusted))

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).ShouldNot(HaveOccurred())
			Ω(claims.String("sub")).Should(Equal("bob"))
		})

		It("rejects modified tokens", func() {
			bad := modifyToken(makeToken("alice", "bob", trusted))
			setBearerHeader(req, bad)

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).Should(HaveResponseStatus(401))
			Ω(claims).Should(HaveLen(0))
		})

		It("rejects untrusted tokens", func() {
			setBearerHeader(req, makeToken("_", "alice", untrusted))

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).Should(HaveResponseStatus(401))
			Ω(claims).Should(HaveLen(0))
		})

		It("rejects expired tokens", func() {
			iat := time.Now().Add(-time.Hour)
			exp := iat.Add(time.Minute)
			bad := makeTokenWithTimestamps("_", "_", trusted, iat, iat, exp)
			setBearerHeader(req, bad)

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).Should(HaveResponseStatus(401))
			Ω(claims).Should(HaveLen(0))
		})

		It("rejects not-yet-valid tokens", func() {
			iat := time.Now()
			nbf := iat.Add(time.Minute)
			exp := nbf.Add(time.Minute)
			bad := makeTokenWithTimestamps("_", "_", trusted, iat, nbf, exp)
			setBearerHeader(req, bad)

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).Should(HaveResponseStatus(401))
			Ω(claims).Should(HaveLen(0))
		})
	})
}
