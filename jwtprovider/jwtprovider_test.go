package jwtprovider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/robbert229/httpauth"
	"github.com/robbert229/jwt"
)

func testInvalidRoleHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/invalid-role", http.StatusTemporaryRedirect)
}

func TestProviderSetIdentity(t *testing.T) {
	provider := NewProvider(testInvalidRoleHandler, httpauth.RedirectToRequested("/login"), "secret")
	algorithm := jwt.HmacSha512("secret")

	user := "user"
	role := "admin"

	identity := httpauth.Identity{
		UserID: user,
		Role:   role,
	}

	recorder := httptest.NewRecorder()
	err := provider.SetIdentity(recorder, identity)
	if err != nil {
		t.Fatal(errors.Wrap(err, "unable to set identity cookie"))
	}

	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}

	// Extract the dropped cookie from the request.
	cookie, err := request.Cookie(AuthorizationCookie)
	if err != nil {
		t.Fatal(errors.Wrap(err, "unable to extract cookie!"))
	}

	claims, err := algorithm.Decode(cookie.Value)
	if err != nil {
		t.Fatal(errors.Wrap(err, "unable to decode claims"))
	}

	actualUser, _ := claims.Get(userIDKey)
	actualRole, _ := claims.Get(roleKey)

	if strings.Compare(actualRole, role) != 0 {
		t.Fatal(errors.Wrap(err, "roles don't match"))
	}

	if strings.Compare(actualUser, user) != 0 {
		t.Fatal(errors.Wrap(err, "users don't match"))
	}
}

func TestProviderGetIdentity(t *testing.T) {
	provider := NewProvider(testInvalidRoleHandler, httpauth.RedirectToRequested("/login"), "secret")
	algorithm := jwt.HmacSha512("secret")

	userID := "user"
	role := "admin"

	claims := jwt.NewClaim()

	claims.Set(userIDKey, userID)
	claims.Set(roleKey, role)
	payload, err := algorithm.Encode(claims)
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to encode claims"))
	}

	recorder := httptest.NewRecorder()

	http.SetCookie(recorder, &http.Cookie{Name: AuthorizationCookie, Value: payload, HttpOnly: true})

	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}

	identity, err := provider.GetIdentity(request)
	if err != nil {
		err = errors.Wrap(err, "failed to get identity")
		fmt.Printf("%+v", err)
		t.Fatal(err)
	}

	if strings.Compare(userID, identity.UserID) != 0 {
		t.Fatal(errors.New("usernames didn't match"))
	}

	if strings.Compare(role, identity.Role) != 0 {
		t.Fatal(errors.New("roles didn't match"))
	}

}

func TestProviderRemoveIdentity(t *testing.T) {
	provider := NewProvider(testInvalidRoleHandler, httpauth.RedirectToRequested("/login"), "secret")

	user := "user"
	role := "admin"

	identity := httpauth.Identity{
		UserID: user,
		Role:   role,
	}

	recorder := httptest.NewRecorder()
	err := provider.SetIdentity(recorder, identity)
	if err != nil {
		t.Fatal(errors.Wrap(err, "unable to set identity cookie"))
	}

	setCookie := recorder.HeaderMap["Set-Cookie"]

	request := &http.Request{Header: http.Header{"Cookie": setCookie}}
	recorder = httptest.NewRecorder()

	if err := provider.RemoveIdentity(recorder); err != nil {
		t.Fatal(errors.Wrap(err, "unable to remove identity"))
	}

	request = &http.Request{Header: http.Header{"Cookie": setCookie}}

	// Extract the dropped cookie from the request.
	cookie, err := request.Cookie(AuthorizationCookie)
	if err != nil {
		t.Fatal(errors.Wrap(err, "unable to extract cookie!"))
	}

	if cookie.Expires.Before(time.Now()) == false {
		t.Fatal(errors.New("cookie didn't expire"))
	}
}
