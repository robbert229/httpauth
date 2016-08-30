package jwtprovider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/robbert229/httpauth"
	"github.com/robbert229/jwt"
)

func TestProviderSetIdentity(t *testing.T) {
	provider := NewProvider("/invalid-role", "/login", "secret")
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
	provider := NewProvider("/invalid-role", "/login", "secret")
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
		t.Fatal(errors.Wrap(err, "failed to get identity"))
	}

	if strings.Compare(userID, identity.UserID) != 0 {
		t.Fatal(errors.New("usernames didn't match"))
	}

	if strings.Compare(role, identity.Role) != 0 {
		t.Fatal(errors.New("roles didn't match"))
	}

}
