package jwtauth

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Context accessor functions", func() {
	var (
		ctx    context.Context
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
		Context("given a context with claims", func() {
			BeforeEach(func() {
				ctx = WithClaims(ctx, claims)
			})
			It("returns the claims", func() {
				Ω(ContextClaims(ctx)).Should(Equal(claims))
			})
		})

		Context("given a context without claims", func() {
			BeforeEach(func() {
				ctx = context.Background()
			})
			It("returns nil", func() {
				Ω(ContextClaims(ctx)).Should(BeNil())
			})
		})
	})
})
