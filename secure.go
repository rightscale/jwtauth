package jwtauth

import (
	"context"

	"goa.design/plugins/security"
)

// Secure creates a custom authorization logic which also performs
// authentication using the given Keystore. It uses the default authentication
// (verify issuer and store claims in context) and authorization (compare
// scopes in claims with required scopes from the scheme) logic.
func Secure(store Keystore) security.AuthJWTFunc {
	return SecureWithFunc(store, Authenticate, Authorize)
}

// SecureWithFunc chains the given authentication and authorization logic.
func SecureWithFunc(store Keystore, authenticateFn AuthenticationFunc, authorizeFn security.AuthJWTFunc) security.AuthJWTFunc {
	return security.AuthJWTFunc(func(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
		ctx, err := authenticateFn(ctx, token, store)
		if err != nil {
			return ctx, err
		}
		return authorizeFn(ctx, token, scheme)
	})
}
