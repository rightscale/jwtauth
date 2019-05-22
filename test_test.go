package jwtauth

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TestToken()", func() {
	It("returns a token", func() {
		tok := TestToken("iss", "alice")
		Ω(tok).ShouldNot(Equal(""))
	})

	It("adds issuer if none present", func() {
		tok := TestToken()
		Ω(tok).ShouldNot(Equal(""))
	})

	It("panics on invalid claims", func() {
		Expect(func() {
			illegal := make(chan int)
			TestToken("illegal", illegal)
		}).To(Panic())
	})
})
