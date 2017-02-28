package jwtauth

import (
	"golang.org/x/net/context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Context accessor functions", func() {
	var (
		ctx    context.Context
		token  = TestToken("potatoes", "fried")
		claims = Claims{"potatoes": "fried"}
	)

	Describe("WithClaims", func() {
		It("returns a new context with only the claims", func() {
			ctx = WithClaims(context.Background(), claims)

			Ω(ContextClaims(ctx)).Should(Equal(claims))
			Ω(ContextToken(ctx)).Should(Equal(""))
		})
	})
	Describe("ContextClaims", func() {
		Context("with an authInfo context", func() {
			BeforeEach(func() {
				ctx = withAuthInfo(ctx, token, claims)
			})
			It("returns the claims", func() {
				Ω(ContextClaims(ctx)).Should(Equal(claims))
			})
		})

		Context("with a non-authInfo context", func() {
			BeforeEach(func() {
				ctx = context.Background()
			})
			It("returns nil", func() {
				Ω(ContextClaims(ctx)).Should(BeNil())
			})
		})
	})
	Describe("ContextToken", func() {
		Context("with an authInfo context", func() {
			BeforeEach(func() {
				ctx = withAuthInfo(ctx, token, claims)
			})
			It("returns the token", func() {
				Ω(ContextToken(ctx)).Should(Equal(token))
			})
		})

		Context("with a non-authInfo context", func() {
			BeforeEach(func() {
				ctx = context.Background()
			})
			It("returns an empty string", func() {
				Ω(ContextToken(ctx)).Should(Equal(""))
			})
		})
	})
})
