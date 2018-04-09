package jwtauth_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/jwtauth"
)

var _ = Describe("Authorize", func() {
	var (
		store = &jwtauth.SimpleKeystore{Key: publicKey(hmacKey1)}
	)

	Context("before authentication", func() {
		It("requires authentication", func() {
			token := makeToken("alice", "bob", hmacKey1)
			_, err := jwtauth.Authorize(context.Background(), token, commonScheme)
			Ω(err).Should(HaveOccurred())
			Ω(err).Should(HaveMessageSubstring("authentication required"))
		})
	})

	Context("after authentication", func() {
		It("passes authorized requests", func() {
			token := makeToken("good-issuer", "good-subject", hmacKey1, "scope1:action1")
			ctx, err := jwtauth.Authenticate(context.Background(), token, store)
			Ω(err).NotTo(HaveOccurred())

			_, err = jwtauth.Authorize(ctx, token, commonScheme)
			Ω(err).ShouldNot(HaveOccurred())
		})

		It("forbids unauthorized requests", func() {
			token := makeToken("good-issuer", "bad-subject", hmacKey1)
			ctx, err := jwtauth.Authenticate(context.Background(), token, store)
			Ω(err).NotTo(HaveOccurred())

			_, err = jwtauth.Authorize(ctx, token, commonScheme)
			Ω(err).To(HaveOccurred())
			Ω(err).Should(HaveMessageSubstring("missing scopes"))
		})
	})
})
