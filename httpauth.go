package httpauth

import (
	"net/http"
	"net/url"
)

var (
	// returnURL is the query parameter used to specify the url to return to once authentication is completed.
	returnURL = "ret"
)

// RequireRole requires the user to have one of the specified roles.
func RequireRole(next http.Handler, roles []string, provider AuthorizationProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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
