package jwtauth

import (
	"context"

	"goa.design/plugins/security"
)

// ScopesClaim is a Private Claim Name, as stipulated in RFC7519 Section 4.3,
// that jwtauth uses to store scope information in tokens. If you need to
// interoperate with third parties w/r/t to token scope, it may be advisable
// to change this to a Collision-Resistant Claim Name instead.
var ScopesClaim = "scopes"

// Authorize is the default authorization method. It compares the
// context's required scopes against a list of scopes that are claimed in the
// JWT. If the claimed scopes satisfy all required scopes, Authorize won't
// return any errors; otherwise, it responds with ErrAuthorizationFailed.
//
// If the context requires no scopes, Authorize still verifies that SOME claims
// are present, under the assumption that the user needs to be authenticated
// even if they do not require any specific privilege.
func Authorize(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	claims, _ := ctx.Value(claimsKey).(Claims)
	if claims == nil || len(claims) == 0 {
		return ctx, ErrAuthenticationFailed("authentication required: no claims found in context")
	}
	held := claims.Strings(ScopesClaim)
	if err := scheme.Validate(held); err != nil {
		return ctx, ErrAuthorizationFailed(err.Error())
	}
	return ctx, nil
}
