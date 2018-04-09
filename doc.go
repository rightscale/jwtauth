/*
Package jwtauth provides a callback for the Goa v2 framework that parses and
validates JSON Web Tokens (JWTs), then adds them to the context. It supports
any JWT algorithm that uses RSA, ECDSA or HMAC.

When you setup your goa v2 service, setup the jwtauth secure callback for the
endpoints secured with JWT:

    secret := []byte("super secret HMAC key")
    store := jwtauth.SimpleKeystore{Key: secret}

		endpoints := svc.NewSecureEndpoints(svc.Service, jwtauth.Secure(store))

In this example, jwtauth uses a single, static HMAC key and relies
on the default authentication and authorization behavior. Your users can now
include an authorization token with every request:

    GET /foo
    Authorization: Bearer <JWT goes here>

When someone makes a request containing a JWT, jwauth verifies that the token
contains all of the scopes that are required by your action, as determined by
by the JWT security scheme. If anything is missing, jwtauth returns an error
with a detailed message.


Authentication vs. Authorization

In Goa's parlance, a "security scheme" mostly concerns itself with authorization:
deciding whether the request may proceed to your controller. However, before
we can authorize, we must know who is making the request, i.e. we must
authenticate the request.

Package jwtauth encourages separation of concerns by performing authentication
and authorization in two separate functions. The division of responsibility is
as follows.

Authentication: determines whether a JWT is present; parses the JWT; validates
its signature; creates a jwtauth.Claims object representing the information
in the JWT; calls jwtauth.WithClaims() to create a new Context containing the
Claims.

Authorization: calls jwtauth.ContextClaims(), then decides whether the token
is allowed based on the claims, the required scopes, and potentially on other
request information.


Multiple Issuers

For real-world applications, it is advisable to register several trusted keys
so you can perform key rotation on the fly and compartmentalize trust. If you
initialize the callback with a NamedKeystore, it uses the value of the
JWT "iss" (Issuer) claim to select a verification key for each token.

		import jwtgo "github.com/dgrijalva/jwt-go"
		usKey := jwtgo.ParseRSAPublicFromPEM(ioutil.ReadFile("us.pem))
		euKey := jwtgo.ParseRSAPublicKeyFromPEM(ioutil.ReadFile("eu.pem))

		store := jwt.NamedKeystore{}
		store.Trust("us.acme.com", usKey))
		store.Trust("eu.acme.com", euKey))

		endpoints := svc.NewSecureEndpoints(svc.Service, jwtauth.Secure(store))

Using a NamedKeystore, you can grant or revoke trust at any time, even while
the application is running, and your changes will take effect on the next
request.


Custom Authentication

To change how jwtauth peforms authentication, write your own function that
matches the signature of type AuthenticationFunc, then tell jwtauth to use
your function instead of its own:

		func myAuthenticator((ctx context.Context, token string, store Keystore) (context.Context, error) {
			return ctx, fmt.Errorf("you shall not pass!")
		}

		endpoints := svc.NewSecureEndpoints(svc.Service, jwtauth.SecureWithFunc(store, myAuthenticator, jwtauth.Authorize)


Custom Authorization

To change how jwtauth performs authorization, write your own function that
matches the signature of type security.AuthJWTFunc, then tell jwtauth to use
your function instead of its own:

    func myAuthzFunc(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
			return ctx, fmt.Errorf("nobody may do anything!")
	  }

		endpoints := svc.NewSecureEndpoints(svc.Service, jwtauth.SecureWithFunc(store, jwtauth.Authenticate, myAuthzFunc))

When overriding authorization behavior, you can always delegate some work to
the default behavior. For example, to let users do anything on their birthday:

		func myAuthzFunc(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
      claims := jwtauth.ContextClaims(ctx)
      if birthday := claims.Time("birthday"); !birthday.IsZero() {
        _, bm, bd := birthday.Date()
        _, m, d := time.Now().Date()
        if bm == m && bd == d {
          // Happy birthday!
          return ctx, nil
        }
      }

			return jwtauth.Authorize(ctx, token, scheme)
		}


Token Management

If you need to create tokens, jwtauth contains a simplistic helper that helps
to shadow the dependency on dgrijalva/jwt:

		claims := jwtauth.NewClaims()
		token, err := NewToken("my HMAC key", claims)
		fmt.Println("the magic token is", token)


Error Handling

Common errors are returned as instances of a goa v2 ServiceError:

ErrUnsupported: the token or configuration uses an unsupported feature.

ErrInvalidToken: the token is malformed or its signature is bad.

ErrAuthenticationFailed: the token is well-formed but the issuer is not
trusted, it has expired, or is not yet valid.

ErrAuthorizationFailed: the token is well-formed and valid, but the
authentication principal did not satisfy all of the scopes required to call
the requested goa action.

Note that the errors don't return any specific HTTP response codes. The
generated auth function stubs in goa v2 should be responsible for returning
the correct error codes.
*/
package jwtauth
