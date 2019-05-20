package jwtauth

import (
	"context"
	"net/http"

	"github.com/goadesign/goa"
)

type (
	// Keystore interface
	//
	// When the middleware receives a request containing a JWT, it extracts the
	// "iss" (Issuer) claim from the JWT body and gets a correspondingly-named
	// key from the keystore, which it uses to verify the JWT's integrity.
	Keystore interface {
		// Trust grants trust in an issuer.
		Trust(issuer string, key interface{}) error
		// RevokeTrust revokes trust in an issuer.
		RevokeTrust(issuer string)
		// Get returns the key associated with the named issuer.
		Get(issuer string) interface{}
	}

	// ExtractionFunc is an optional callback that allows you to customize
	// jwtauth's handling of JSON Web Tokens during authentication.
	//
	// If your use case involves a proprietary JWT encoding, or a nonstandard
	// location for the JWT, you can handle it with a custom ExtractionFunc.
	//
	// The return value from ExtractionFunc should either be the empty string
	// (if no token was present in the request), or a well-formed JWT.
	ExtractionFunc func(*goa.JWTSecurity, *http.Request) (string, error)

	// AuthorizationFunc is an optional callback that allows customization
	// of the way the middleware authorizes each request.
	AuthorizationFunc func(context.Context, Claims) error
)
