package httpauth

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedirectToLogin(t *testing.T) {
	target := "/Admin/MurderTheDb"
	config := &JWTAuthenticationProvider{
		LoginURL:       "/Accounts/Login",
		InvalidRoleURL: "/",
	}

	request := httptest.NewRequest("GET", target, bytes.NewBuffer(nil))
	recorder := httptest.NewRecorder()

	redirectToLoginURL(recorder, request, config)

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
