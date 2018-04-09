package jwtauth

import "goa.design/goa"

// ErrUnsupported indicates that the application is configured to use a
// capability that jwtauth does not support.
func ErrUnsupported(format string, v ...interface{}) *goa.ServiceError {
	return goa.PermanentError("unsupported", format, v...)
}

// ErrInvalidToken indicates that the request's JWT was malformed or
// its signature could not be verified.
func ErrInvalidToken(format string, v ...interface{}) *goa.ServiceError {
	return goa.PermanentError("invalid_token", format, v...)
}

// ErrAuthenticationFailed indicates that the request's JWT was well-formed
// but the issuer is not trusted, it has expired, or is not yet valid.
func ErrAuthenticationFailed(format string, v ...interface{}) *goa.ServiceError {
	return goa.PermanentError("authentication_failed", format, v...)
}

// ErrAuthorizationFailed indicates that the request's JWT was well-formed
// and valid, but the user is not authorized to perform the requested
// operation.
func ErrAuthorizationFailed(format string, v ...interface{}) *goa.ServiceError {
	return goa.PermanentError("authorization_failed", format, v...)
}
