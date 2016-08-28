package httpauth

import (
	"bytes"
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
		return Identity{}, ErrDoesntHaveIdentity
	}
	return *t.identity, nil
}

func (t *TestProvider) RemoveIdentity(w http.ResponseWriter) error {
	t.identity = &Identity{}
	return nil
}

func (t *TestProvider) GetLoginURL() string {
	return "/Accounts/Login"
}

func (t *TestProvider) GetInvalidRoleURL() string {
	return "/Accounts/InvalidPermissions"
}

func TestRedirectToLogin(t *testing.T) {
	target := "/Admin/MurderTheDb"
	provider := &TestProvider{}

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	RequireRole([]string{}, provider, http.NotFoundHandler()).ServeHTTP(recorder, request)

	if recorder.Code != 302 {
		t.Fatal("Didn't redirect")
	}

	expected := "/Accounts/Login?ret=%2FAdmin%2FMurderTheDb"
	actual := recorder.Header().Get("Location")
	if strings.Compare(actual, expected) != 0 {
		fmt.Println("Expected: " + expected)
		fmt.Println("Actual: " + actual)
		t.Fatal("failed to redirect")
	}
}

func TestRedirectToInvalidRole(t *testing.T) {
	target := "/Foo/Bar"
	provider := &TestProvider{}

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	provider.SetIdentity(recorder, Identity{
		UserID: "test",
		Role:   "viewer",
	})

	RequireRole([]string{"editor"}, provider, http.NotFoundHandler()).ServeHTTP(recorder, request)

	if recorder.Code != 401 {
		t.Fatal("Didn't redirect")
	}

	expected := "/Accounts/InvalidPermissions"
	actual := recorder.Header().Get("Location")
	if strings.Compare(actual, expected) != 0 {
		fmt.Println("Expected: " + expected)
		fmt.Println("Actual: " + actual)
		t.Fatal("failed to redirect")
	}
}
