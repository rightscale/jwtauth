package jwtauth_test

import (
	"crypto/ecdsa"
	"crypto/rsa"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jwtauth "github.com/rightscale/jwtauth"
)

var _ = Describe("LoadKey", func() {
	It("loads HMAC keys", func() {
		key := jwtauth.LoadKey(hmacKey1)
		Expect(key).To(Equal(hmacKey1))
	})

	It("loads EC private keys", func() {
		key := jwtauth.LoadKey(ecKey1Pem)
		_, ok := key.(*ecdsa.PrivateKey)
		Expect(ok).To(BeTrue())
	})

	It("loads RSA private keys", func() {
		key := jwtauth.LoadKey(rsaKey1Pem)
		_, ok := key.(*rsa.PrivateKey)
		Expect(ok).To(BeTrue())
	})

	It("loads PKCS1 RSA public keys", func() {
		key := jwtauth.LoadKey(rsaPKCSPubPem)
		_, ok := key.(*rsa.PublicKey)
		Expect(ok).To(BeTrue())
	})

	It("loads PKIX EC public keys", func() {
		key := jwtauth.LoadKey(ecPKIXPubPem)
		_, ok := key.(*ecdsa.PublicKey)
		Expect(ok).To(BeTrue())
	})

	It("loads PKIX EC public keys", func() {
		key := jwtauth.LoadKey(rsaPKIXPubPem)
		_, ok := key.(*rsa.PublicKey)
		Expect(ok).To(BeTrue())
	})

	It("refuses to load garbage", func() {
		garbage := []byte("-----BEGIN DELICIOUS CHEESE-----\nyum\n-----END DELICIOUS CHEESE-----")
		Expect(func() {
			jwtauth.LoadKey(garbage)
		}).To(Panic())
	})
})
