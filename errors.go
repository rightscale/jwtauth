package jwtauth

import "github.com/goadesign/goa"

var (
	// ErrUnsupported indicates that the application is configured to use a
	// capability that jwtauth does not support.
	ErrUnsupported = goa.NewErrorClass("unsupported", 500)

	// ErrInvalidToken indicates that the request's JWT was malformed or
	// its signature could not be verified.
	ErrInvalidToken = goa.NewErrorClass("invalid_token", 401)

	// ErrAuthenticationFailed indicates that the request's JWT was well-formed
	// and valid, but does not contain sufficient information for the server
	// to identify the authentication principal associated with the request.
	ErrAuthenticationFailed = goa.NewErrorClass("authorization_failed", 403)

	// ErrAuthorizationFailed indicates that the request's JWT was well-formed
	// and valid, but the user is not authorized to perform the requested
	// operation.
	ErrAuthorizationFailed = goa.NewErrorClass("authorization_failed", 403)
)
