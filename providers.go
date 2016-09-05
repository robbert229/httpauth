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

	// Handles when a user needs to be shown an error page for not being in the correct role.
	HandleInvalidRole(w http.ResponseWriter, r *http.Request)

	// Handles when a user needs to login.
	HandleLogin(w http.ResponseWriter, r *http.Request, redirect string)
}

// Identity is returned by GetIdentity, and set by SetIdentity. It contains a unique identifier for a user, and his Role.
type Identity struct {
	UserID string
	Role   string
}
