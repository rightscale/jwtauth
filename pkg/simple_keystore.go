package jwtauth

import "fmt"
import "reflect"

type (
	// SimpleKeystore is a Keystore that trusts exactly one key regardless of
	// the token's issuer.
	//
	// Trust() and RevokeTrust() have no effect, although Trust() returns an
	// error if called with a key other than the one-and-only trusted key.
	SimpleKeystore struct {
		Key interface{}
	}
)

// Trust implements jwtauth.Keystore#Trust
func (sk *SimpleKeystore) Trust(issuer string, key interface{}) error {
	if !reflect.DeepEqual(key, sk.Key) {
		return fmt.Errorf("cannot trust additional keys; call RevokeTrust first")
	}
	return nil
}

// RevokeTrust implements jwtauth.Keystore#RevokeTrust
func (sk *SimpleKeystore) RevokeTrust(issuer string) {
}

// Get implements jwtauth.Keystore#Get
func (sk *SimpleKeystore) Get(issuer string) interface{} {
	return sk.Key
}
