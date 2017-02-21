package jwtauth_test

import (
	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/goa-jwtauth"
)

var _ = Describe("TestAuthenticate()", func() {
	scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}

	It("returns a middleware", func() {
		mw := jwtauth.TestAuthenticate(scheme)
		Ω(mw).ShouldNot(BeNil())
	})
})

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
