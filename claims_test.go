package jwtauth_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/jwtauth"
)

type bogusStringer struct {
}

func (bs bogusStringer) String() string {
	return fmt.Sprintf("%T", bs)
}

var _ = Describe("Claims", func() {
	falseNumbers := []interface{}{
		int(0),
		int(-1),
		uint(0),
		int32(0),
		uint32(0),
		int64(0),
		uint64(0),
		float32(0),
		float64(0),
	}
	trueNumbers := []interface{}{
		int(1),
		int(42),
		uint(1),
		int32(1),
		uint32(1),
		int64(1),
		uint64(1),
		float32(1),
		float64(1),
	}

	epochNumbers := []interface{}{
		int(0),
		int(0),
		uint(0),
		int32(0),
		uint32(0),
		int64(0),
		uint64(0),
		float32(0),
		float64(0),
	}

	It("converts to bool", func() {
		claims := jwtauth.Claims{}

		claims["foo"] = true
		Expect(claims.Bool("foo")).To(Equal(true))
		claims["foo"] = "True"
		Expect(claims.Bool("foo")).To(Equal(true))
		claims["foo"] = "f"
		Expect(claims.Bool("foo")).To(Equal(false))
		claims["foo"] = "Fal"
		Expect(claims.Bool("foo")).To(Equal(false))
		for _, n := range falseNumbers {
			claims["foo"] = n
			Expect(claims.Bool("foo")).To(Equal(false))
			Expect(claims.Int("foo")).To(BeNumerically("<=", 0))
		}
		for _, n := range trueNumbers {
			claims["foo"] = n
			Expect(claims.Bool("foo")).To(Equal(true))
			Expect(claims.Int("foo")).To(BeNumerically(">", int64(0)))
		}
		claims["foo"] = time.Now()
		Expect(claims.Bool("foo")).To(Equal(false))
	})

	It("converts to string", func() {
		claims := jwtauth.Claims{}

		claims["foo"] = bogusStringer{}
		Expect(claims.String("foo")).To(Equal("jwtauth_test.bogusStringer"))
		claims["foo"] = 42
		Expect(claims.String("foo")).To(Equal("42"))

		claims["foo"] = "bar"
		Expect(claims.Strings("foo")).To(Equal([]string{"bar"}))
		claims["foo"] = []string{"bar", "baz"}
		Expect(claims.Strings("foo")).To(Equal([]string{"bar", "baz"}))
	})

	It("converts to numeric", func() {
		claims := jwtauth.Claims{}

		claims["foo"] = "0"
		Expect(claims.Int("foo")).To(Equal(int64(0)))
		claims["foo"] = "42"
		Expect(claims.Int("foo")).To(Equal(int64(42)))
		claims["foo"] = float32(42.0)
		Expect(claims.Int("foo")).To(Equal(int64(42)))
		claims["foo"] = float64(42.0)
		Expect(claims.Int("foo")).To(Equal(int64(42)))
	})

	It("converts to Time", func() {
		claims := jwtauth.Claims{}

		now := time.Now().Unix()
		claims["foo"] = now
		Expect(claims.Time("foo").Unix()).To(Equal(now))

		epoch := time.Unix(0, 0).UTC()
		for _, n := range epochNumbers {
			claims["foo"] = n
			Expect(claims.Time("foo").UTC()).To(Equal(epoch))
		}
	})

	It("handles standard claims", func() {
		epoch := time.Unix(0, 0).UTC()
		then := time.Unix(0xFFFFFFFF, 0).UTC()

		claims := jwtauth.Claims{
			"iss": "Issuer",
			"sub": "Subject",
			"iat": 0,
			"nbf": 0,
			"exp": then.Unix(),
		}

		Expect(claims.Issuer()).To(Equal("Issuer"))
		Expect(claims.Subject()).To(Equal("Subject"))
		Expect(claims.IssuedAt()).To(Equal(epoch))
		Expect(claims.NotBefore()).To(Equal(epoch))
		Expect(claims.ExpiresAt()).To(Equal(then.UTC()))
	})
})
