package jwtauth

import (
	"context"
)

type (
	// Keystore is used to manage trustworthiness of the given JWT keys.
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

	// AuthenticationFunc is a type to customize the authentication logic for the
	// given JWT token and Keystore.
	AuthenticationFunc func(context.Context, string, Keystore) (context.Context, error)
)
