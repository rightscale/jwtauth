package jwtauth

import "github.com/goadesign/goa"

// TestKey is a static HMAC key used to sign and verify test JWTs.
const TestKey = "https://github.com/rightscale/goa-jwtauth#test"

// TestAuthenticate returns an authentication middleware that accepts any
// JWT signed with TestKey.
func TestAuthenticate(scheme *goa.JWTSecurity) goa.Middleware {
	return Authenticate(scheme, &SimpleKeystore{Key: []byte(TestKey)})
}

// TestToken creates a JWT with the specified claims and signs it using
// TestKey.
func TestToken(keyvals ...interface{}) string {
	key := []byte(TestKey)
	token, err := NewToken(key, NewClaims(keyvals...))
	if err != nil {
		panic(err)
	}
	return token
}
