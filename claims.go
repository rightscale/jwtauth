package jwtauth

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Claims is a collection of claims extracted from a JWT.
type Claims map[string]interface{}

// stringify transforms your world into a magical place filled with elves and
// unicorns.
func stringify(value interface{}) string {
	if value == nil {
		return ""
	}
	switch tv := value.(type) {
	case string:
		return tv
	case fmt.Stringer:
		return tv.String()
	default:
		return fmt.Sprintf("%v", tv)
	}
}

// String returns the named claim as a string, converting from other types
// using fmt.Stringer if supported, or fmt.Sprint() otherwise. If the claim is
// absent, String returns "".
func (c Claims) String(name string) string {
	return stringify(c[name])
}

// Strings returns the named claim as a list of strings, following the same
// conversion rules as String(). If the claim is abent, Strings returns nil.
func (c Claims) Strings(name string) []string {
	s, ok := c[name]
	if !ok {
		return nil
	}

	switch ts := s.(type) {
	case []string:
		return ts
	case string:
		return []string{ts}
	case []interface{}:
		slice := make([]string, len(ts))
		for i, v := range ts {
			slice[i] = stringify(v)
		}
		return slice
	default:
		return []string{stringify(ts)}
	}
}

var trueBool = regexp.MustCompile("^([Tt]r?u?e|[1-9][0-9]+)$")

// Bool returns the named claim as a boolean, converting from other types
// as necessary. If the claim is absent or cannot be converted to a boolean,
// Bool returns false.
func (c Claims) Bool(name string) bool {
	s := c[name]

	switch ts := s.(type) {
	case bool:
		return ts
	case int:
		return ts > 0
	case uint:
		return ts > 0
	case int32:
		return ts > 0
	case uint32:
		return ts > 0
	case int64:
		return ts > 0
	case uint64:
		return ts > 0
	case float64:
		return ts > 0
	case float32:
		return ts > 0
	case string:
		return trueBool.MatchString(ts)
	default:
		return false
	}
}

// Int returns the named claim as an integer, converting from other types as
// necessary. If the claim is absent or cannot be converted to an integer,
// Int returns 0.
func (c Claims) Int(name string) int64 {
	s := c[name]
	switch ts := s.(type) {
	case uint64:
		return int64(ts)
	case uint32:
		return int64(ts)
	case uint:
		return int64(ts)
	case int64:
		return int64(ts)
	case int32:
		return int64(ts)
	case int:
		return int64(ts)
	case float64:
		return int64(ts)
	case float32:
		return int64(ts)
	case string:
		i, err := strconv.ParseInt(ts, 10, 64)
		if err == nil {
			return i
		}
	}

	return 0
}

// Time returns the named claim as a Time in the Unix epoch. If the claim
// is absent or cannot be converted to an integer, it returns 0.
func (c Claims) Time(name string) time.Time {
	switch ts := c[name].(type) {
	case uint64:
		return time.Unix(int64(ts), 0).UTC()
	case uint32:
		return time.Unix(int64(ts), 0).UTC()
	case uint:
		return time.Unix(int64(ts), 0).UTC()
	case int64:
		return time.Unix(ts, 0).UTC()
	case int32:
		return time.Unix(int64(ts), 0).UTC()
	case int:
		return time.Unix(int64(ts), 0).UTC()
	case float64:
		return time.Unix(int64(ts), 0).UTC()
	case float32:
		return time.Unix(int64(ts), 0).UTC()
	case string:
		t, err := time.Parse(time.RFC822, ts)
		if err == nil {
			return t.UTC()
		}
		return time.Unix(0, 0).UTC()
	default:
		return time.Unix(0, 0).UTC()
	}
}

// Issuer returns the value of the standard JWT "iss" claim, converting to
// string if necessary.
func (c Claims) Issuer() string {
	return c.String("iss")
}

// Subject returns the value of the standard JWT "iss" claim, converting to
// string if necessary.
func (c Claims) Subject() string {
	return c.String("sub")
}

// IssuedAt returns time at which the claims were issued.
func (c Claims) IssuedAt() time.Time {
	return c.Time("iat")
}

// NotBefore returns time at which the claims were issued.
func (c Claims) NotBefore() time.Time {
	return c.Time("nbf")
}

// ExpiresAt returns time at which the claims were issued.
func (c Claims) ExpiresAt() time.Time {
	return c.Time("exp")
}
