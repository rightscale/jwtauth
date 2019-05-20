package jwtauth

// TestKey is a static HMAC key used to sign and verify test JWTs.
const TestKey = "https://github.com/rightscale/jwtauth#test"

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
