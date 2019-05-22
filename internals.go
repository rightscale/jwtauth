package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

func parseTokenMetadata(tok string) []interface{} {
	ret := make([]interface{}, 0, 4)

	bits := strings.SplitN(tok, ".", 3)

	if rawHeader, err := base64.RawURLEncoding.DecodeString(bits[0]); err == nil {
		var header map[string]interface{}
		if err := json.Unmarshal(rawHeader, &header); err == nil {
			ret = append(ret, []interface{}{"header", header}...)
		} else {
			ret = append(ret, []interface{}{"header", string(rawHeader)}...)
		}
	} else {
		ret = append(ret, []interface{}{"header", bits[0]}...)
	}

	if len(bits) > 1 {
		if rawClaims, err := base64.RawURLEncoding.DecodeString(bits[1]); err == nil {
			var claims Claims
			if err := json.Unmarshal(rawClaims, &claims); err == nil {
				ret = append(ret, []interface{}{"claims", claims}...)
			} else {
				ret = append(ret, []interface{}{"claims", string(rawClaims)}...)
			}
		} else {
			ret = append(ret, []interface{}{"claims", bits[1]}...)
		}
	}

	return ret
}

// key2method determines a JWT SigningMethod that is suitable for the given key.
func key2method(key interface{}) jwt.SigningMethod {
	switch key.(type) {
	case []byte, string:
		return jwt.SigningMethodHS256
	case rsa.PrivateKey, *rsa.PrivateKey, rsa.PublicKey, *rsa.PublicKey:
		return jwt.SigningMethodRS256
	case ecdsa.PrivateKey, *ecdsa.PrivateKey, ecdsa.PublicKey, *ecdsa.PublicKey:
		return jwt.SigningMethodES256
	default:
		return nil
	}
}
