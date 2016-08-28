package httpauth

import (
	"net/http"
	"net/url"
	"strings"
)

var (
	// returnURL is the query parameter used to specify the url to return to once authentication is completed.
	returnURL = "ret"
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
func RequireRole(next http.Handler, roles []string, provider AuthorizationProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, err := provider.GetRole(r)
		if err == ErrNotInRole {
			redirectToLoginURL(w, r, provider)
			return
		}

		if err != nil {
			panic(err)
		}

		if contains(roles, role) {
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
