[![Build Status](https://travis-ci.org/rightscale/goa-jwtauth.png)](https://travis-ci.org/rightscale/goa-jwtauth) [![Coverage](https://coveralls.io/repos/github/rightscale/goa-jwtauth/badge.svg?branch=master)](https://coveralls.io/github/rightscale/goa-jwtauth?branch=master) [![Go Report](https://goreportcard.com/badge/github.com/rightscale/goa-jwtauth)](https://goreportcard.com/report/github.com/rightscale/goa-jwtauth) [![Docs](https://img.shields.io/badge/docs-godoc-blue.svg)](https://godoc.org/github.com/rightscale/goa-jwtauth)

Package jwtauth provides a middleware for the [Goa](https://github.com/goadesign/goa)
framework that parses and validates JSON Web Tokens (JWTs) that appear in
requests, then adds them to the request context. It supports any JWT algorithm
that uses RSA, ECDSA or HMAC.

Usage
=====

This is a trivial example; for thorough information, please consult the [godoc](https://godoc.org/github.com/rightscale/goa-jwtauth).

First install jwtauth and its dependency:

```go
go get -u github.com/rightscale/goa-jwtauth github.com/dgrijalva/jwt-go
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
then install the jwtauth middleware:

```go
  secret := []byte("super secret HMAC key")
  store := jwtauth.SimpleKeystore{Key: secret}
  middleware := jwtauth.New(app.NewJWTSecurity(), store)
  app.UseJWTMiddleware(service, middleware)
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
