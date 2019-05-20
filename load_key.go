package jwtauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
)

var pemBlock = regexp.MustCompile("^[\r\n]*---+ *BEGIN")

// LoadKey is a helper function that transforms raw key material into a properly-
// typed key.
//
// LoadKey returns a different type depending on the value of material:
//
// If material is a []byte that contains a PEM-encoded PKIX key (e.g. "BEGIN
// PUBLIC KEY"), LoadKey parses it and returns a single public or private key
// of an algorithm-specific type.
//
// If material is any other []byte, LoadKey returns it unmodified so that it can
// be used as an HMAC key.
//
// Because LoadKey is designed to be used at startup, it panics if the PEM block
// is malformed.
func LoadKey(material []byte) interface{} {
	if pemBlock.Match(material) {
		parsed, err := parseKey(material)
		if err != nil {
			panic(err)
		}
		return parsed
	}
	return material
}

// Parse a public key from a block of PEM-formatted ASCII text.
func parseKey(pemBlock []byte) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemBlock))

	if block != nil {
		switch block.Type {
		case "RSA PUBLIC KEY": // PKCS1 RSA public key
			key := rsa.PublicKey{N: new(big.Int), E: 0}
			_, err := asn1.Unmarshal(block.Bytes, &key)
			return &key, err
		case "PUBLIC KEY": // PKIX algorithm-neutral public key
			return x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PRIVATE KEY": // PKCS1 RSA private key
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		default:
			return nil, fmt.Errorf("Unsupported PEM block type: %s", block.Type)
		}
	}

	return nil, fmt.Errorf("Input does not appear to be a PEM block")
}
