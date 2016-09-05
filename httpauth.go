package httpauth

import (
	"net/http"
	"net/url"
	"strings"
)

var (
	// ReturnURL is the query parameter used to specify the url to return to once the user is logged in.
	ReturnURL = "ret"
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

		provider.HandleInvalidRole(w, r)
	})
}

// RedirectToRequested returns a handler to redirect to a login url and preserve the originially requested url as a get parameter.
func RedirectToRequested(loginURL string) func(w http.ResponseWriter, r *http.Request, requested string) {
	return func(w http.ResponseWriter, r *http.Request, requested string) {
		url, _ := url.Parse(loginURL)
		query := url.Query()
		query.Set(ReturnURL, requested)
		url.RawQuery = query.Encode()

		http.Redirect(w, r, url.String(), http.StatusTemporaryRedirect)
	}
}

func redirectToLoginURL(w http.ResponseWriter, r *http.Request, provider AuthorizationProvider) {
	provider.HandleLogin(w, r, r.URL.Path)
}
