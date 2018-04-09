package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// parseToken does the gruntwork of extracting A JWT from a request.
func parseToken(token string, store Keystore) (*jwt.Token, error) {
	// Parse the JWT and identify the issuer
	var alg, iss string
	var key interface{}
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		alg, _ = token.Header["alg"].(string)
		iss, err := identifyIssuer(token)
		if err != nil {
			return nil, err
		}
		key = store.Get(iss)
		if key == nil {
			return nil, ErrInvalidToken("Untrusted issuer %s", iss)
		}
		return key, nil
	})

	// help clients with mystery errors caused by fast-and-loose key
	// typing in crypto and dgrijalva/jwt-go
	if err != nil && strings.HasPrefix(err.Error(), "key is of invalid type") {
		err = fmt.Errorf("%s (local keystore contains %T for issuer '%s' but JWT has alg=%s)", err.Error(), key, iss, alg)
		panic(err)
	}

	if ve, ok := err.(*jwt.ValidationError); ok && ve.Inner != nil {
		if ve.Inner != nil {
			err = ve.Inner
		}
	}

	if err != nil {
		err = ErrInvalidToken(err.Error()+": %#v", parseTokenMetadata(token)...)
	}

	return parsed, err
}

// identifyIssuer inspects a JWT's claims to determine its issuer.
func identifyIssuer(token *jwt.Token) (string, error) {
	switch claims := token.Claims.(type) {
	case jwt.MapClaims:
		var issuer string
		if claims != nil {
			iss := claims["iss"]
			if iss == nil {
				return "", nil
			}
			switch it := iss.(type) {
			case string:
				issuer = it
			case fmt.Stringer:
				issuer = it.String()
			default:
				issuer = fmt.Sprintf("%v", it)
			}
		}
		return issuer, nil
	default:
		typ := fmt.Sprintf("%T", claims)
		return "", ErrUnsupported("unsupported jwt.Claims", "type", typ)
	}
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
