package jwtauth

import (
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"golang.org/x/net/context"
)

// Authenticate creates a middleware that authenticates incoming requests.
// Specifically, the middleware parses JWTs from a location specified by
// scheme, validates their signatures using the keys in store, and adds a
// Claims object to the context, which can be accessed by calling
// ContextClaims().
//
// Authentication is not authorization! Do not use this middleware as a
// goa security scheme itself; rather, install this middleware application-wide,
// so that the authentication claims become available to your authorization
// middleware(s) that implement your security schemes.
func Authenticate(scheme *goa.JWTSecurity, store Keystore) goa.Middleware {
	return AuthenticateWithFunc(scheme, store, DefaultExtraction)
}

// AuthenticateWithFunc creates an authentication middleware that uses a
// custom ExtractionFunc.
func AuthenticateWithFunc(scheme *goa.JWTSecurity, store Keystore, extraction ExtractionFunc) goa.Middleware {
	return func(nextHandler goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			token, err := parseToken(scheme, store, extraction, req)
			if err != nil {
				return err
			}

			var claims Claims

			if token != nil && token.Claims != nil {
				// NB: jwt-go always produces MapClaims on parse; type assertion should
				// never fail, and if it were to, we'd want to panic since we count this
				// as an invariant!
				claims = Claims(token.Claims.(jwt.MapClaims))
			}

			return nextHandler(WithClaims(ctx, claims), rw, req)
		}
	}
}
