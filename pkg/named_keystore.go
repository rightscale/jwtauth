package jwtauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"reflect"
	"sync"
)

type (
	// NamedKeystore is a concurrency-safe, in-memory Keystore implementation
	// that allows trust to be granted/revoked from issuers at any time.
	//
	// All methods are safe to call on the zero value of this type; fields are
	// initialized as needed.
	NamedKeystore struct {
		sync.RWMutex
		keys map[string]interface{}
	}

	privateKey interface {
		Public() crypto.PublicKey
	}
)

// Trust implements jwtauth.Keystore#Trust
//
// Grants trust in an issuer. It accepts any of the following types:
//	   - []byte (for HS tokens)
//     - *rsa.PublicKey (for RS tokens)
//     - *ecdsa.PublicKey (for ES tokens)
//
// As a convenience, it converts the following to a related type:
//     - string becomes []byte
//     - *rsa.PrivateKey becomes its public key
//     - *ecdsa.PrivateKey becomes its public key
func (nk *NamedKeystore) Trust(issuer string, key interface{}) error {
	nk.Lock()
	defer nk.Unlock()

	if nk.keys == nil {
		nk.keys = map[string]interface{}{}
	}

	if old, ok := nk.keys[issuer]; ok && !reflect.DeepEqual(old, key) {
		return fmt.Errorf("already added a key for issuer '%s'; call RemoveKey first", issuer)
	}

	// For convenience, turn private keys into public and strings into bytes.
	switch kt := key.(type) {
	case privateKey:
		key = kt.Public()
	case string:
		key = []byte(kt)
	}

	switch kt := key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, []byte:
		nk.keys[issuer] = kt
	default:
		return fmt.Errorf("unsupported key type %T", key)
	}

	return nil
}

// RevokeTrust implements jwtauth.Keystore#RevokeTrust
func (nk *NamedKeystore) RevokeTrust(issuer string) {
	nk.Lock()
	defer nk.Unlock()

	if nk.keys == nil {
		return
	}

	delete(nk.keys, issuer)
	return
}

// Get implements jwtauth.Keystore#Get
func (nk *NamedKeystore) Get(issuer string) interface{} {
	nk.RLock()
	defer nk.RUnlock()

	if nk.keys != nil {
		return nk.keys[issuer]
	}

	return nil
}
