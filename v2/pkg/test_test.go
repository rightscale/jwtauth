package jwtauth_test

import (
	"github.com/rightscale/jwtauth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TestToken()", func() {
	It("returns a token", func() {
		tok := jwtauth.TestToken("iss", "alice")
		Ω(tok).ShouldNot(Equal(""))
	})

	It("adds issuer if none present", func() {
		tok := jwtauth.TestToken()
		Ω(tok).ShouldNot(Equal(""))
	})

	It("panics on invalid claims", func() {
		Expect(func() {
			illegal := make(chan int)
			jwtauth.TestToken("illegal", illegal)
		}).To(Panic())
	})
})
