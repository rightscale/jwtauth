package jwtauth_test

import (
	"context"
	"fmt"
	"time"

	jwtpkg "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/jwtauth"
)

var _ = Describe("Authenticate", func() {
	Context("error handling", func() {
		It("rejects unknown issuers", func() {
			store := &jwtauth.NamedKeystore{}
			token := makeToken("suspicious-issuer", "", hmacKey1)

			_, err := jwtauth.Authenticate(context.Background(), token, store)
			Ω(err).To(HaveOccurred())
			Ω(err).Should(HaveMessageSubstring("Untrusted issuer suspicious-issuer"))
		})

		It("converts issuers to string", func() {
			store := &jwtauth.SimpleKeystore{Key: hmacKey1}
			token := jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, &jwtpkg.MapClaims{"iss": 7})

			tok, err := token.SignedString(hmacKey1)
			Ω(err).NotTo(HaveOccurred())

			_, err = jwtauth.Authenticate(context.Background(), tok, store)
			Ω(err).NotTo(HaveOccurred())
		})

		It("creates a new context containing claims", func() {
			var (
				store  = &jwtauth.SimpleKeystore{Key: hmacKey1}
				claims = jwtpkg.MapClaims{"potatoes": "fried"}
				token  = jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, claims)
				ctx    = context.Background()
			)

			tok, err := token.SignedString(hmacKey1)
			Ω(err).NotTo(HaveOccurred())

			ctx, err = jwtauth.Authenticate(ctx, tok, store)
			Ω(err).NotTo(HaveOccurred())

			Expect(jwtauth.ContextClaims(ctx)).To(Equal(jwtauth.Claims(claims)))
		})
	})

	testKeyType("HMAC", hmacKey1, hmacKey2)
	testKeyType("RSA", rsaKey1, rsaKey2)
	testKeyType("ECDSA", ecKey1, ecKey2)
})

// testKeyType defines test cases that are repeated for every supported key
// type.
func testKeyType(name string, trusted, untrusted interface{}) {
	var (
		err error
		ctx context.Context

		store = &jwtauth.SimpleKeystore{Key: publicKey(trusted)}
	)

	Context(fmt.Sprintf("given %s keys", name), func() {
		BeforeEach(func() {
			ctx = context.Background()
		})

		AfterEach(func() {
			err = nil
		})

		It("accepts valid tokens", func() {
			tok := makeToken("alice", "bob", trusted)
			ctx, err = jwtauth.Authenticate(ctx, tok, store)
			Ω(jwtauth.ContextClaims(ctx).String("sub")).Should(Equal("bob"))
		})

		It("rejects modified tokens", func() {
			tok := modifyToken(makeToken("alice", "bob", trusted))
			ctx, err = jwtauth.Authenticate(ctx, tok, store)
			Ω(jwtauth.ContextClaims(ctx)).Should(HaveLen(0))
		})

		It("rejects untrusted tokens", func() {
			tok := makeToken("_", "alice", untrusted)
			ctx, err = jwtauth.Authenticate(ctx, tok, store)
			Ω(jwtauth.ContextClaims(ctx)).Should(HaveLen(0))
		})

		It("rejects expired tokens", func() {
			iat := time.Now().Add(-time.Hour)
			exp := iat.Add(time.Minute)
			tok := makeTokenWithTimestamps("_", "_", trusted, iat, iat, exp)
			ctx, err = jwtauth.Authenticate(ctx, tok, store)
			Ω(err).Should(HaveMessageSubstring("expired"))
			Ω(jwtauth.ContextClaims(ctx)).Should(HaveLen(0))
		})

		It("rejects not-yet-valid tokens", func() {
			iat := time.Now()
			nbf := iat.Add(time.Minute)
			exp := nbf.Add(time.Minute)
			tok := makeTokenWithTimestamps("_", "_", trusted, iat, nbf, exp)
			ctx, err = jwtauth.Authenticate(ctx, tok, store)
			Ω(err).Should(HaveMessageSubstring("not valid yet"))
			Ω(jwtauth.ContextClaims(ctx)).Should(HaveLen(0))
		})
	})
}
