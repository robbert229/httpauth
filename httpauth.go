package httpauth

import (
	"net/http"
	"net/url"
)

var (
	// returnUrl is the query parameter used to specify the url to return to once authentication is completed.
	returnUrl = "ret"
)

type Config struct {
	LoginURL       string
	InvalidRoleURL string
}

func RequireRole(next http.Handler, roles []string, config Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	})
}

func redirectToLoginURL(w http.ResponseWriter, r *http.Request, config Config) {
	requested := r.URL.Path

	url, err := url.Parse(config.LoginURL)
	if err != nil {
		panic(err)
	}

	query := url.Query()
	query.Set(returnUrl, requested)
	url.RawQuery = query.Encode()

	http.Redirect(w, r, url.String(), 302)
}

// AuthorizationProvider is the interface containing all the required thingy mabbobs
type AuthorizationProvider interface {
	// SetRole sets the role of the user.
	SetRole(w http.ResponseWriter) error
	// RemoveRole removes the role from the user.
	RemoveRole(w http.ResponseWriter) error
	// IsInRole requires the user to be in the specified role.
	IsInRole(r *http.Request, role string)
	// IsInARole requires the user to be in one of the specified roles.
	IsInARole(r *http.Request, role []string)
}
