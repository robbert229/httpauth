package jwtprovider

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/robbert229/httpauth"
	"github.com/robbert229/jwt"
)

var (
	// AuthorizationCookie is the name of the cookie that jwtprovider uses.
	AuthorizationCookie = "authorization"
	roleKey             = "role"
	userIDKey           = "userid"
)

// NewProvider returns a new authentication provider that runs on jwt.
func NewProvider(invalidRoleHandler http.HandlerFunc, loginHandler func(w http.ResponseWriter, r *http.Request, redirect string), secret string) httpauth.AuthorizationProvider {
	return &JWTAuthenticationProvider{
		InvalidRoleHandler: invalidRoleHandler,
		LoginHandler:       loginHandler,
		algorithm:          jwt.HmacSha512(secret),
	}
}

// JWTAuthenticationProvider is the default authentication provider
type JWTAuthenticationProvider struct {
	InvalidRoleHandler http.HandlerFunc
	LoginHandler       func(w http.ResponseWriter, r *http.Request, redirect string)
	algorithm          jwt.Algorithm
}

// HandleLogin calls the http.HandlerFunc called when a user needs to be redirected to the login page.
func (j *JWTAuthenticationProvider) HandleLogin(w http.ResponseWriter, r *http.Request, redirect string) {
	j.LoginHandler(w, r, redirect)
}

// HandleInvalidRole calls the http.HandlerFunc called when a user lacks permission for a certain action.
func (j *JWTAuthenticationProvider) HandleInvalidRole(w http.ResponseWriter, r *http.Request) {
	j.InvalidRoleHandler.ServeHTTP(w, r)
}

// SetIdentity sets the role of the current user.
func (j *JWTAuthenticationProvider) SetIdentity(w http.ResponseWriter, identity httpauth.Identity) error {
	claims := jwt.NewClaim()
	claims.SetTime("exp", time.Now().Add(time.Hour*8))
	claims.Set(userIDKey, identity.UserID)
	claims.Set(roleKey, identity.Role)

	payload, err := j.algorithm.Encode(claims)
	if err != nil {
		return errors.Wrap(err, "unable to encode identity")
	}

	c := &http.Cookie{
		Name:     AuthorizationCookie,
		HttpOnly: true,
		Value:    payload,
	}
	http.SetCookie(w, c)
	return nil
}

// RemoveIdentity removes all roles from the user.
func (j *JWTAuthenticationProvider) RemoveIdentity(w http.ResponseWriter) error {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthorizationCookie,
		MaxAge:   -1,
		HttpOnly: true,
	})
	return nil
}

// GetIdentity returns true if the user is any of the specified roles.
func (j *JWTAuthenticationProvider) GetIdentity(r *http.Request) (httpauth.Identity, error) {
	cookie, err := r.Cookie(AuthorizationCookie)
	if err != nil {
		return httpauth.Identity{}, errors.Wrap(err, "unable to get identity cookie")
	}

	claims, err := j.algorithm.Decode(cookie.Value)
	if err != nil {
		return httpauth.Identity{}, errors.Wrap(err, "unable to decode cookie!")
	}

	if err := j.algorithm.Validate(cookie.Value); err != nil {
		return httpauth.Identity{}, errors.Wrap(err, "invalid cookie")
	}

	userID, err := claims.Get(userIDKey)
	if err != nil {
		return httpauth.Identity{}, errors.Wrap(err, "no userid claims present")
	}

	role, err := claims.Get(roleKey)
	if err != nil {
		return httpauth.Identity{}, errors.Wrap(err, "no role claims present")
	}

	return httpauth.Identity{
		UserID: userID,
		Role:   role,
	}, nil
}
