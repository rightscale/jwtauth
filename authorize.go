package jwtauth

import (
	"context"
	"net/http"

	"github.com/goadesign/goa"
)

// Authorize creates a middleware that authorizes incoming requests.
// Specifically, the middleware compares goa's required scopes against the
// claimed scopes contained in the JWT, ensuring that the claimed scopes are
// a superset of the required scopes.
//
// Most applications will require a more nuanced authorization scheme;
// to do this, use DefaultAuthorization() as a starting point for implementing
// your own authorization behavior; then, instead of calling this function,
// call AuthorizeWithFunc() to instantiate a middleware that uses your custom
// behavior.
func Authorize() goa.Middleware {
	return AuthorizeWithFunc(DefaultAuthorization)
}

// AuthorizeWithFunc creates a middleware that authorizes requests using a
// custom AuthorizationFunc.
func AuthorizeWithFunc(fn AuthorizationFunc) goa.Middleware {
	return func(nextHandler goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			claims := ContextClaims(ctx)
			err := fn(ctx, claims)

			if err == nil {
				return nextHandler(ctx, rw, req)
			}

			return err
		}
	}
}
