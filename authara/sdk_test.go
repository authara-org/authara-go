package authara

import (
	"net/http"
	"testing"
)

func TestNewDerivesJWKSURLFromBaseURL(t *testing.T) {
	sdk, err := New(Config{
		Issuer:         " authara ",
		Audience:       " app ",
		AutharaBaseURL: "https://auth.example.com/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sdk.verifier.keys.url, "https://auth.example.com"+JWKSPath; got != want {
		t.Fatalf("JWKS URL = %q, want %q", got, want)
	}
	if sdk.verifier.issuer != "authara" || sdk.verifier.audience != "app" {
		t.Fatalf("issuer/audience were not normalized: %+v", sdk.verifier)
	}
	if got := sdk.httpClient.Timeout; got != defaultHTTPTimeout {
		t.Fatalf("default HTTP timeout = %s, want %s", got, defaultHTTPTimeout)
	}
}

func TestNewPreservesCustomHTTPClient(t *testing.T) {
	client := &http.Client{}
	sdk, err := New(Config{
		Issuer:         "authara",
		Audience:       "app",
		AutharaBaseURL: "https://auth.example.com",
		HTTPClient:     client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sdk.httpClient != client {
		t.Fatal("New replaced the custom HTTP client")
	}
}

func TestNewAcceptsExplicitJWKSURLWithoutBaseURL(t *testing.T) {
	sdk, err := New(Config{
		Issuer:   "authara",
		Audience: "app",
		JWKSURL:  "https://keys.example.com/authara/jwks.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sdk.autharaBaseURL != "" {
		t.Fatalf("base URL = %q, want empty", sdk.autharaBaseURL)
	}
}

func TestNewRejectsMissingVerificationConfiguration(t *testing.T) {
	tests := []Config{
		{Issuer: " ", Audience: "app", JWKSURL: "https://keys.example.com/jwks"},
		{Issuer: "authara", Audience: " ", JWKSURL: "https://keys.example.com/jwks"},
		{Issuer: "authara", Audience: "app"},
		{Issuer: "authara", Audience: "app", AutharaBaseURL: "authara:8080"},
	}
	for _, cfg := range tests {
		if _, err := New(cfg); err == nil {
			t.Fatalf("New(%+v) unexpectedly succeeded", cfg)
		}
	}
}
