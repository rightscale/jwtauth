package jwtauth

import (
	"github.com/goadesign/goa"
	"golang.org/x/net/context"
)

// ScopesClaim is a Private Claim Name, as stipulated in RFC7519 Section 4.3,
// that jwtauth uses to store scope information in tokens. If you need to
// interoperate with third parties w/r/t to token scope, it may be advisable
// to change this to a Collision-Resistant Claim Name instead.
var ScopesClaim = "scopes"

// DefaultAuthorization is the default authorization method. It compares the
// context's required scopes against a list of scopes that are claimed in the
// JWT. If the claimed scopes satisfy all required scopes, DefaultAuthorization
// passes the request; otherwise, it responds with ErrAuthorizationFailed.
//
// If the context requires no scopes, DefaultAuthorization still verifies
// that SOME claims are present, under the assumption that the user needs to
// be authenticated even if they do not require any specific privilege.
func DefaultAuthorization(ctx context.Context, claims Claims) error {
	if len(claims) == 0 {
		return ErrAuthorizationFailed("authentication required")
	}

	reqd := goa.ContextRequiredScopes(ctx)
	held := claims.Strings(ScopesClaim)

	for _, r := range reqd {
		found := false
		for _, h := range held {
			found = found || (h == r)
			if found {
				break
			}
		}
		if !found {
			return ErrAuthorizationFailed("missing scopes", "held", held, "required", reqd)
		}
	}
	return nil
}
