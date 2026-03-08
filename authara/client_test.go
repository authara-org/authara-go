package authara

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// helper to create a client pointing at a test server
func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := NewClient(
		srv.URL,
		WithHTTPClient(srv.Client()),
	)

	return client, srv
}

func TestGetCurrentUser_OK(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/api/v1/user" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "user-1",
			"email": "user@example.com",
			"username": "user"
		}`))
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  AccessCookieName,
		Value: "access-token",
	})

	user, err := client.GetCurrentUser(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user == nil {
		t.Fatal("expected user, got nil")
	}

	if user.ID != "user-1" {
		t.Errorf("unexpected id: %s", user.ID)
	}
	if user.Email != "user@example.com" {
		t.Errorf("unexpected email: %s", user.Email)
	}
	if user.Username != "user" {
		t.Errorf("unexpected username: %s", user.Username)
	}
}

func TestGetCurrentUser_Unauthorized(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := client.GetCurrentUser(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func TestGetCurrentUser_UnexpectedStatus(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := client.GetCurrentUser(context.Background(), req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if user != nil {
		t.Fatalf("expected nil user on error, got %+v", user)
	}
}

func TestGetCurrentUser_MalformedJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{ not valid json`))
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := client.GetCurrentUser(context.Background(), req)
	if err == nil {
		t.Fatal("expected JSON decode error, got nil")
	}

	if user != nil {
		t.Fatalf("expected nil user on error, got %+v", user)
	}
}

func TestGetCurrentUser_ForwardsAccessCookie(t *testing.T) {
	var sawCookie bool

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie(AccessCookieName)
		if err == nil {
			sawCookie = true
		}

		w.WriteHeader(http.StatusUnauthorized)
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  AccessCookieName,
		Value: "access-token",
	})

	_, _ = client.GetCurrentUser(context.Background(), req)

	if !sawCookie {
		t.Fatal("expected access cookie to be forwarded")
	}
}

func TestGetCurrentUser_NilIncomingRequest(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	client, _ := newTestClient(t, handler)

	user, err := client.GetCurrentUser(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func TestDoJSONRequest_OK(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value":"ok"}`))
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  AccessCookieName,
		Value: "access-token",
	})

	type Response struct {
		Value string `json:"value"`
	}

	var out Response

	resp, err := DoJSONRequest[Response](
		context.Background(),
		client,
		http.MethodGet,
		"/custom",
		req,
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	if out.Value != "ok" {
		t.Fatalf("unexpected value: %s", out.Value)
	}
}
