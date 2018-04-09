package jwtauth

import (
	"context"

	jwt "github.com/dgrijalva/jwt-go"
)

// Authenticate authenticates the given token. Specifically, it parses the
// JWTs from the token, validates their signatures using the keys in store,
// and adds a Claims object to the context, which can be accessed by calling
// ContextClaims().
//
// Authentication is not authorization! Do not use this method as a security
// scheme itself; invoke this method before authorization so that the
// authentication claims become available to your authorization method(s) that
// implement your security schemes.
func Authenticate(ctx context.Context, token string, store Keystore) (context.Context, error) {
	jwtToken, err := parseToken(token, store)
	if err != nil {
		return ctx, err
	}

	var claims Claims
	if jwtToken.Claims != nil {
		// NB: jwt-go always produces MapClaims on parse; type assertion should
		// never fail, and if it were to, we'd want to panic since we count this
		// as an invariant!
		claims = Claims(jwtToken.Claims.(jwt.MapClaims))
	}
	ctx = WithClaims(ctx, claims)
	return ctx, nil
}
