package jwtauth_test

import (
	"context"

	jwtpkg "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/jwtauth"
)

var _ = Describe("Secure callback", func() {
	var (
		store = &jwtauth.SimpleKeystore{Key: publicKey(hmacKey1)}
	)

	It("passes authenticated and authorized requests", func() {
		var (
			claims = jwtpkg.MapClaims{"scopes": "scope1:action1"}
			token  = jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, claims)
		)
		tok, err := token.SignedString(hmacKey1)
		Ω(err).NotTo(HaveOccurred())

		ctx, err := jwtauth.Secure(store)(context.Background(), tok, commonScheme)
		Ω(err).NotTo(HaveOccurred())
		Expect(jwtauth.ContextClaims(ctx)).To(Equal(jwtauth.Claims(claims)))
	})

	It("forbids unauthenticated requests", func() {
		var (
			claims = jwtpkg.MapClaims{}
			token  = jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, claims)
		)
		tok, err := token.SignedString(hmacKey1)
		Ω(err).NotTo(HaveOccurred())

		ctx, err := jwtauth.Secure(store)(context.Background(), tok, commonScheme)
		Ω(err).To(HaveOccurred())
		Ω(err).Should(HaveMessageSubstring("authentication required"))
		Expect(jwtauth.ContextClaims(ctx)).Should(BeEmpty())
	})

	It("forbids unauthorized requests", func() {
		var (
			claims = jwtpkg.MapClaims{"potatoes": "fried"}
			token  = jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, claims)
		)
		tok, err := token.SignedString(hmacKey1)
		Ω(err).NotTo(HaveOccurred())

		ctx, err := jwtauth.Secure(store)(context.Background(), tok, commonScheme)
		Ω(err).To(HaveOccurred())
		Ω(err).Should(HaveMessageSubstring("missing scopes"))
		Expect(jwtauth.ContextClaims(ctx)).To(Equal(jwtauth.Claims(claims)))
	})
})
