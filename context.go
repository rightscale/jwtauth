package jwtauth

import (
	"golang.org/x/net/context"
)

type contextKey int

const (
	claimsKey contextKey = iota + 1
	tokenKey
)

// WithClaims creates a child context containing the given JWT claims.
func WithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ContextClaims retrieves the JWT claims associated with the request.
func ContextClaims(ctx context.Context) Claims {
	if claims, _ := ctx.Value(claimsKey).(Claims); claims != nil {
		return claims
	}
	return nil
}

// WithToken creates a child context containing the given JWT.
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}

// ContextToken retrieves the actual JWT associated with the request.
func ContextToken(ctx context.Context) string {
	if token, _ := ctx.Value(tokenKey).(string); token != "" {
		return token
	}
	return ""
}
