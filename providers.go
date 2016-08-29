package httpauth

import "net/http"

// AuthorizationProvider is the interface that describes the authorization mechanisms.
type AuthorizationProvider interface {
	// SetIdentity sets the role of the user.
	SetIdentity(w http.ResponseWriter, identity Identity) error
	// GetIdentity return the users roll, or an error if the user has no role.
	GetIdentity(r *http.Request) (Identity, error)
	// RemoveIdentity removes the role from the user.
	RemoveIdentity(w http.ResponseWriter) error

	// IsInRole requires the user to be in the specified role. Returns an error if the user is not in the specified role.
	GetLoginURL() string
	// GetInvalidRoleURL returns the login url
	GetInvalidRoleURL() string
}

type Identity struct {
	UserID string
	Role   string
}
