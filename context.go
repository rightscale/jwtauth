package jwtauth

import (
	"golang.org/x/net/context"
)

type contextKey int

const (
	authInfoKey contextKey = iota + 1
)

// authInfo is used for storing claims & token in the context
type authInfo struct {
	claims Claims
	token  string
}

// withAuthInfo creates a child context containing the given token & claims.
func withAuthInfo(ctx context.Context, token string, claims Claims) context.Context {
	return context.WithValue(ctx, authInfoKey, &authInfo{claims: claims, token: token})
}

// WithClaims creates a child context containing the given claims.
func WithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, authInfoKey, &authInfo{claims: claims})
}

// ContextClaims retrieves the JWT claims associated with the request.
func ContextClaims(ctx context.Context) Claims {
	if authInfo, _ := ctx.Value(authInfoKey).(*authInfo); authInfo != nil {
		return authInfo.claims
	}
	return nil
}

// ContextToken retrieves the actual JWT associated with the request.
func ContextToken(ctx context.Context) string {
	if authInfo, _ := ctx.Value(authInfoKey).(*authInfo); authInfo != nil {
		return authInfo.token
	}
	return ""
}
