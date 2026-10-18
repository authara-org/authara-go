package authara

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestSDK(t *testing.T) *SDK {
	t.Helper()
	keys := newTestSigningKeys(t)
	jwks := newTestJWKSServer(t, keys)

	sdk, err := New(Config{
		Issuer:     "https://auth.example.com",
		Audience:   "app",
		JWKSURL:    jwks.URL,
		HTTPClient: jwks.Client(),
	})
	if err != nil {
		t.Fatalf("failed to create sdk: %v", err)
	}

	return sdk
}

/* -------------------- RequireAuth -------------------- */

func TestRequireAuth_NoCookie_BrowserRedirects(t *testing.T) {
	sdk := newTestSDK(t)

	called := false
	handler := sdk.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Accept", "text/html")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("handler should not have been called")
	}

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, LoginPath) {
		t.Fatalf("expected redirect to start with %q, got %q", LoginPath, loc)
	}
}

func TestRequireAuth_NoCookie_HTMXRedirect(t *testing.T) {
	sdk := newTestSDK(t)

	handler := sdk.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("HX-Request", "true")
	req.Header.Set("Accept", "text/html")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if got := rec.Header().Get("HX-Redirect"); got == "" {
		t.Fatal("expected HX-Redirect header to be set")
	}
}

func TestRequireAuth_NoCookie_APIReturns401(t *testing.T) {
	sdk := newTestSDK(t)

	handler := sdk.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Accept", "application/json")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireAuth_BearerTokenAuthenticates(t *testing.T) {
	sdk, keys := newTestSDKWithRefresh(t, "", nil)
	userID := uuid.New()
	access := signAccessToken(t, keys, userID, []string{"authara:user"}, time.Hour)

	handler := sdk.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID, ok := UserIDFromContext(r.Context())
		if !ok || gotID != userID {
			t.Fatalf("expected userID %v, got %v (ok=%v)", userID, gotID, ok)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/mobile/v1/sites", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireAuth_AuthorizationHeaderNeverFallsBackToCookie(t *testing.T) {
	sdk, keys := newTestSDKWithRefresh(t, "", nil)
	access := signAccessToken(t, keys, uuid.New(), []string{"authara:user"}, time.Hour)

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "unsupported scheme", values: []string{"Basic credentials"}},
		{name: "missing token", values: []string{"Bearer"}},
		{name: "empty value", values: []string{""}},
		{name: "repeated header", values: []string{"Bearer " + access, "Bearer " + access}},
		{name: "invalid bearer", values: []string{"Bearer not-a-token"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := sdk.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("handler should not be called")
			}))
			request := httptest.NewRequest(http.MethodGet, "/api/private", nil)
			request.Header.Set("Accept", "application/json")
			request.AddCookie(&http.Cookie{Name: AccessCookieName, Value: access})
			for _, value := range test.values {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestRequireAuth_RejectsRevokedAccessToken(t *testing.T) {
	sdk, keys := newTestSDKWithRefresh(t, "", nil)
	access := signAccessToken(t, keys, uuid.New(), []string{"authara:user"}, time.Hour)
	_, claims, err := sdk.verifier.verifyWithClaims(context.Background(), access)
	if err != nil {
		t.Fatalf("verify test token: %v", err)
	}
	revocationKeys, err := accessTokenRevocationKeys(claims)
	if err != nil {
		t.Fatal(err)
	}
	sdk.revocations = &accessTokenRevocations{store: &fakeRevocationStore{
		values: map[string][]byte{revocationKeys[0]: []byte("1")},
	}}

	handler := sdk.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be called for a revoked access token")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/private", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

/* -------------------- TryAuth -------------------- */

func TestTryAuth_NoCookie_AllowsThrough(t *testing.T) {
	sdk := newTestSDK(t)

	called := false
	handler := sdk.TryAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/optional", nil)
	req.Header.Set("Accept", "text/html")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("handler should have been called")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestTryAuth_MalformedAuthorizationDoesNotUseCookie(t *testing.T) {
	sdk, keys := newTestSDKWithRefresh(t, "", nil)
	access := signAccessToken(t, keys, uuid.New(), []string{"authara:user"}, time.Hour)
	handler := sdk.TryAuth(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		if _, ok := UserIDFromContext(request.Context()); ok {
			t.Fatal("malformed Authorization unexpectedly attached cookie identity")
		}
	}))
	request := httptest.NewRequest(http.MethodGet, "/optional", nil)
	request.Header.Set("Authorization", "Basic credentials")
	request.AddCookie(&http.Cookie{Name: AccessCookieName, Value: access})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}
