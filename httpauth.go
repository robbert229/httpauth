package httpauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var (
	// returnURL is the query parameter used to specify the url to return to once authentication is completed.
	returnURL = "ret"

	ErrDoesntHaveIdentity = errors.New("user doesn't have identity")
)

func contains(s []string, e string) bool {
	for _, a := range s {
		if strings.Compare(a, e) == 0 {
			return true
		}
	}
	return false
}

// RequireRole requires the user to have one of the specified roles.
func RequireRole(roles []string, provider AuthorizationProvider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := provider.GetIdentity(r)
		if err == ErrDoesntHaveIdentity {
			redirectToLoginURL(w, r, provider)
			return
		}

		if err != nil {
			panic(err)
		}

		if contains(roles, identity.Role) {
			next.ServeHTTP(w, r)
			return
		}

		redirectToInvalidRoleURL(w, r, provider)
	})
}

func redirectToLoginURL(w http.ResponseWriter, r *http.Request, provider AuthorizationProvider) {
	requested := r.URL.Path

	url, err := url.Parse(provider.GetLoginURL())
	if err != nil {
		panic(err)
	}

	query := url.Query()
	query.Set(returnURL, requested)
	url.RawQuery = query.Encode()

	http.Redirect(w, r, url.String(), 302)
}

func redirectToInvalidRoleURL(w http.ResponseWriter, r *http.Request, provider AuthorizationProvider) {
	http.Redirect(w, r, provider.GetInvalidRoleURL(), 401)
}
