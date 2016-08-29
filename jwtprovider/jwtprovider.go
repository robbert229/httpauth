package jwtprovider

import (
	"net/http"

	httpauth "github.com/robbert229/httpauth"
)

var (
	// AuthorizationCookie is the name of the cookie that jwtprovider uses.
	AuthorizationCookie = "authorization"
)

// JWTAuthenticationProvider is the default authentication provider
type JWTAuthenticationProvider struct {
	InvalidRoleURL string
	LoginURL       string
}

// GetLoginURL returns the url to redirect the user to when he isn't in any role.
func (j *JWTAuthenticationProvider) GetLoginURL() string {
	return j.LoginURL
}

// GetInvalidRoleURL returns the url to redirect the user to when he lacks the appropriate role required.
func (j *JWTAuthenticationProvider) GetInvalidRoleURL() string {
	return j.InvalidRoleURL
}

// SetIdentity sets the role of the current user.
func (j *JWTAuthenticationProvider) SetIdentity(w http.ResponseWriter, identity httpauth.Identity) error {
	c := &http.Cookie{
		Name:     AuthorizationCookie,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
	return nil
}

// RemoveIdentity removes all roles from the user.
func (j *JWTAuthenticationProvider) RemoveIdentity(w http.ResponseWriter) error {
	return nil
}

// GetIdentity returns true if the user is any of the specified roles.
func (j *JWTAuthenticationProvider) GetIdentity(r *http.Request) (httpauth.Identity, error) {
	return httpauth.Identity{}, nil
}
