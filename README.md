[![Build Status](https://travis-ci.org/rightscale/jwtauth.png)](https://travis-ci.org/rightscale/jwtauth) [![Coverage](https://coveralls.io/repos/github/rightscale/jwtauth/badge.svg?branch=master)](https://coveralls.io/github/rightscale/jwtauth?branch=master) [![Go Report](https://goreportcard.com/badge/github.com/rightscale/jwtauth)](https://goreportcard.com/report/github.com/rightscale/jwtauth) [![Docs](https://img.shields.io/badge/docs-godoc-blue.svg)](https://godoc.org/github.com/rightscale/jwtauth)

Package jwtauth provides middlewares for the [Goa](https://github.com/goadesign/goa)
framework that perform "auth" (authentication and authorization) using JSON
WEB Tokens.

When you install the authentication middleware, it populates the context of
every request with a `Claims` object, representing all of the JWT claims
associated with the request. Unauthenticated requests have a present-but-empty
Claims object.

The authorization middleware makes use of JWT claims, comparing them against
goa's `ContextRequiredScopes` to decide whether the request may proceed.

Authentication and authorization behaviors can be customized by passing
an optional callback when the middlewares are instantiated.

Usage
=====

This is a trivial example; for thorough information, please consult the [godoc](https://godoc.org/github.com/rightscale/jwtauth).

First install jwtauth and its dependency:

```go
go get -u github.com/rightscale/jwtauth github.com/dgrijalva/jwt-go
```

In your service's design DSL, declare a JWT security scheme and protect some
of your actions with required scopes:

```go
var JWT = JWTSecurity("JWT", func() {
        Header("Authorization")
})

var _ = Resource("Bottle", func() {  
   Security(JWT)

   Action("drink", func() {
     Security(JWT, func() {
       Scope("bottle:drink")
     })
   })      
})
```

When you create your goa.Service at startup, determine which keys to trust,
then install a pair of jwtauth middlewares: one for authentication, one for
authorization.

```go
  secret := []byte("super secret HMAC key")
  store := &jwtauth.SimpleKeystore{Key: secret}

  // Authentication is not a security scheme in goa's terminology; it is
  // merely a prerequisite to authorization that handles parsing and validating
  // the JWT.
  service.Use(jwtauth.Authenticate(app.NewJWTSecurity(), store))

  // The authorization middleware should be mounted through goa's UseXxx
  // functions, so that goa knows which middleware is associated with which
  // security scheme.
  app.UseJWTMiddleware(service, jwtauth.Authorize())
```

Create a token and hand it out to your user:

```go
  claims := jwtauth.NewClaims("iss", "example.com", "sub", "Bob", "scopes", []string{"bottle:drink"})
  token := jwtauth.NewToken("super secret HMAC key", claims)
  fmt.Println("the magic password is", token)
```

Now, sit back and enjoy the security! Your user won't be able to drink your
bottles unless she includes the token as a header:

```bash
curl -X POST http://localhost:8080/bottles/drink -H "Authorization: Bearer $myjwt"
```

(The "bearer" is unimportant; it can be any word, or be absent, and jwtauth
will still parse the token.)

You can also make use of authentication claims in your controllers:

```go
func (c *BottleController) Drink(ctx app.DrinkBottleContext) {
  claims := jwtauth.ContextClaims(ctx)
  return fmt.Printf("Hello, %s", claims.Subject())
}
```
