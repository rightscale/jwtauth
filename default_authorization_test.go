package jwtauth_test

import (
	"net/http"
	"net/http/httptest"

	"golang.org/x/net/context"

	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/goa-jwtauth"
)

var _ = Describe("DefaultAuthorization()", func() {
	var stack goa.Handler
	var resp *httptest.ResponseRecorder
	var req *http.Request

	BeforeEach(func() {
		resp = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "http://example.com/", nil)
		stack = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			return nil
		}

		authentication := jwtauth.Authenticate(commonScheme, &jwtauth.SimpleKeystore{Key: hmacKey1})
		authorization := jwtauth.Authorize()
		stack = authentication(authorization(stack))
	})

	Context("given no required scopes", func() {
		It("passes", func() {
			result := stack(context.Background(), resp, req)

			Ω(result).ShouldNot(HaveOccurred())
		})
	})

	Context("given a required scope", func() {
		ctx := context.Background()
		ctx = goa.WithRequiredScopes(ctx, []string{"read"})

		It("responds with 403 Forbidden", func() {
			result := stack(ctx, resp, req)

			Ω(result).Should(HaveOccurred())
		})

		It("passes authorized requests", func() {
			setBearerHeader(req, makeToken("good-issuer", "good-subject", hmacKey1, "read"))

			result := stack(ctx, resp, req)

			Ω(result).ShouldNot(HaveOccurred())
		})

		It("forbids unauthorized requests", func() {
			setBearerHeader(req, makeToken("good-issuer", "bad-subject", hmacKey1))

			result := stack(ctx, resp, req)

			Ω(result).Should(HaveOccurred())
		})
	})
})
