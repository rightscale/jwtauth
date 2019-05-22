package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("LoadKey", func() {
	It("loads HMAC keys", func() {
		key := LoadKey(hmacKey1)
		Expect(key).To(Equal(hmacKey1))
	})

	It("loads EC private keys", func() {
		key := LoadKey(ecKey1Pem)
		_, ok := key.(*ecdsa.PrivateKey)
		Expect(ok).To(BeTrue())
	})

	It("loads RSA private keys", func() {
		key := LoadKey(rsaKey1Pem)
		_, ok := key.(*rsa.PrivateKey)
		Expect(ok).To(BeTrue())
	})

	It("loads PKCS1 RSA public keys", func() {
		key := LoadKey(rsaPKCSPubPem)
		_, ok := key.(*rsa.PublicKey)
		Expect(ok).To(BeTrue())
	})

	It("loads PKIX EC public keys", func() {
		key := LoadKey(ecPKIXPubPem)
		_, ok := key.(*ecdsa.PublicKey)
		Expect(ok).To(BeTrue())
	})

	It("loads PKIX EC public keys", func() {
		key := LoadKey(rsaPKIXPubPem)
		_, ok := key.(*rsa.PublicKey)
		Expect(ok).To(BeTrue())
	})

	It("refuses to load garbage", func() {
		garbage := []byte("-----BEGIN DELICIOUS CHEESE-----\nyum\n-----END DELICIOUS CHEESE-----")
		Expect(func() {
			LoadKey(garbage)
		}).To(Panic())
	})
})
