package httpauth

import (
	"errors"
	"net/http"
)

var (
	// ErrNotInRole is returns by GetRole when the user isn't in any role.
	ErrNotInRole = errors.New("user not in role")
)

// AuthorizationProvider is the interface that describes the authorization mechanisms.
type AuthorizationProvider interface {
	// SetRole sets the role of the user.
	SetRole(w http.ResponseWriter, identity Identity) error
	// GetRoles return the users roll, or an error if the user has no role.
	GetRole(r *http.Request) (Identity, error)
	// RemoveRole removes the role from the user.
	RemoveRole(w http.ResponseWriter) error

	// IsInRole requires the user to be in the specified role. Returns an error if the user is not in the specified role.
	GetLoginURL() string
	// GetInvalidRoleURL returns the login url
	GetInvalidRoleURL() string
}

type Identity struct {
	UserID string
	Role   string
}

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

// SetRole sets the role of the current user.
func (j *JWTAuthenticationProvider) SetRole(w http.ResponseWriter, identity Identity) error {
	return nil
}

// RemoveRole removes all roles from the user.
func (j *JWTAuthenticationProvider) RemoveRole(w http.ResponseWriter) error {
	return nil
}

// GetRole returns true if the user is any of the specified roles.
func (j *JWTAuthenticationProvider) GetRole(r *http.Request) (Identity, error) {
	return Identity{}, nil
}
