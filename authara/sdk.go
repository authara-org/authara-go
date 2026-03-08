package authara

import (
	"errors"
	"net/http"
	"strings"
)

// SDK is the main entry point for the Authara Go SDK.
//
// It holds the internal verifier used to validate Authara-issued
// access tokens and to power the provided HTTP middleware.
type SDK struct {
	verifier *verifier

	autharaBaseURL string
	httpClient     *http.Client
}

// New initializes a new Authara SDK instance using the provided configuration.
//
// All fields of Config are required. New performs validation and returns
// an error if the configuration is incomplete or invalid.
//
// Example:
//
//	sdk, err := authara.New(authara.Config{
//		Issuer:          "https://example.com",
//		Audience:        "app",
//		Keys:            keys,
//		AutharaBaseURL: "authara:3000"
//		HTTPCliet:       nil
//	})
func New(cfg Config) (*SDK, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("authara: issuer is required")
	}

	if cfg.Audience == "" {
		return nil, errors.New("authara: audience is required")
	}

	if len(cfg.Keys) == 0 {
		return nil, errors.New("authara: at least one key is required")
	}

	v, err := newVerifier(cfg)
	if err != nil {
		return nil, err
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}

	return &SDK{
		verifier:       v,
		autharaBaseURL: strings.TrimRight(cfg.AutharaBaseURL, "/"),
		httpClient:     hc,
	}, nil
}
