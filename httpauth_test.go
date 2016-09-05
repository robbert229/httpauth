package httpauth

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type TestProvider struct {
	identity *Identity
}

func (t *TestProvider) SetIdentity(w http.ResponseWriter, identity Identity) error {
	t.identity = &identity
	return nil
}

func (t *TestProvider) GetIdentity(r *http.Request) (Identity, error) {
	if t.identity == nil {
		return Identity{}, errors.New("user not logged in")
	}
	return *t.identity, nil
}

func (t *TestProvider) RemoveIdentity(w http.ResponseWriter) error {
	t.identity = &Identity{}
	return nil
}

func (t *TestProvider) HandleLogin(w http.ResponseWriter, r *http.Request, requested string) {
	RedirectToRequested("/Accounts/Login")(w, r, requested)
}

func (t *TestProvider) HandleInvalidRole(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/Accounts/InvalidPermissions", http.StatusUnauthorized)
}

func Success() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
}

func TestRedirectToLoginURL(t *testing.T) {
	target := "/Admin/MurderTheDb"

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	provider := &TestProvider{}

	redirectToLoginURL(recorder, request, provider)

	expected := "/Accounts/Login?ret=%2FAdmin%2FMurderTheDb"
	actual := recorder.Header().Get("Location")
	if strings.Compare(actual, expected) != 0 {
		fmt.Println("Expected: " + expected)
		fmt.Println("Actual: " + actual)
		t.Fatal("failed to redirect")
	}
}

func TestRequireRoleRedirectToLogin(t *testing.T) {
	target := "/Admin/MurderTheDb"
	provider := &TestProvider{}

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	RequireRole([]string{}, provider, http.NotFoundHandler()).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatal("Didn't redirect")
	}
}

func TestRequireRoleRedirectToInvalidRole(t *testing.T) {
	target := "/Foo/Bar"
	provider := &TestProvider{}

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	provider.SetIdentity(recorder, Identity{
		UserID: "test",
		Role:   "viewer",
	})

	RequireRole([]string{"editor"}, provider, http.NotFoundHandler()).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatal("didn't redirect to inavlid permissions url")
	}

	expected := "/Accounts/InvalidPermissions"
	actual := recorder.Header().Get("Location")
	if strings.Compare(actual, expected) != 0 {
		fmt.Println("Expected: " + expected)
		fmt.Println("Actual: " + actual)
		t.Fatal("didn't redirect to inavlid permissions url")
	}
}

func TestRequireRoleServeProtectedContent(t *testing.T) {
	target := "/Foo/Bar"
	provider := &TestProvider{}

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	provider.SetIdentity(recorder, Identity{
		UserID: "test",
		Role:   "viewer",
	})

	RequireRole([]string{"viewer"}, provider, Success()).ServeHTTP(recorder, request)

	if recorder.Code != 200 {
		t.Fatal("didn't return success code")
	}
}

func TestRequireLoggedInRedirectsToLogin(t *testing.T) {
	target := "/Foo"
	provider := &TestProvider{}

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	RequireLoggedIn(provider, Success()).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatal("didn't redirect user to login page")
	}
}

func TestRequireLoggedServeProtectedContent(t *testing.T) {
	target := "/Foo"
	provider := &TestProvider{}

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	provider.SetIdentity(recorder, Identity{
		UserID: "foo",
		Role:   "user",
	})

	RequireLoggedIn(provider, Success()).ServeHTTP(recorder, request)

	if recorder.Code != 200 {
		t.Fatal("didn't return success")
	}
}
