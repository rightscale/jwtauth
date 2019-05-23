package jwtauth

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SimpleKeystore", func() {
	store := &SimpleKeystore{Key: hmacKey1}

	Context("Trust()", func() {
		It("accepts the single key", func() {
			dupe := make([]byte, len(hmacKey1))
			copy(dupe, hmacKey1)
			Ω(store.Trust("moo", hmacKey1)).ShouldNot(HaveOccurred())
			Ω(store.Trust("bah", hmacKey1)).ShouldNot(HaveOccurred())
			Ω(store.Trust("oink", dupe)).ShouldNot(HaveOccurred())
		})

		It("rejects any other key", func() {
			Ω(store.Trust("moo", hmacKey2)).Should(HaveOccurred())
		})
	})

	Context("RevokeTrust()", func() {
		It("does nothing", func() {
			store.RevokeTrust("moo")
			Ω(store.Get("moo")).Should(Equal(hmacKey1))
		})
	})

	Context("Get()", func() {
		It("always returns the same key", func() {
			Ω(store.Get("moo")).Should(Equal(hmacKey1))
			Ω(store.Get("bah")).Should(Equal(hmacKey1))
		})
	})
})
