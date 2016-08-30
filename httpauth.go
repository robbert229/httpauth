package httpauth

import (
	"net/http"
	"net/url"
	"strings"
)

var (
	// returnURL is the query parameter used to specify the url to return to once the user is logged in.
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

// RequireLoggedIn requires the user to be logged in to access this page.
func RequireLoggedIn(provider AuthorizationProvider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := provider.GetIdentity(r)
		if err != nil {
			redirectToLoginURL(w, r, provider)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireRole requires the user to have one of the specified roles.
func RequireRole(roles []string, provider AuthorizationProvider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := provider.GetIdentity(r)
		if err != nil {
			redirectToLoginURL(w, r, provider)
			return
		}

		if contains(roles, identity.Role) {
			next.ServeHTTP(w, r)
			return
		}

		http.Redirect(w, r, provider.GetInvalidRoleURL(), 401)
	})
}

func redirectToLoginURL(w http.ResponseWriter, r *http.Request, provider AuthorizationProvider) {
	requested := r.URL.Path

	url, err := url.Parse(provider.GetLoginURL())
	if err != nil {
		http.Redirect(w, r, provider.GetLoginURL(), 302)
	}

	query := url.Query()
	query.Set(returnURL, requested)
	url.RawQuery = query.Encode()

	http.Redirect(w, r, url.String(), 302)
}
