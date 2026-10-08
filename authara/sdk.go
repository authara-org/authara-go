package authara

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// SDK is the main entry point for the Authara Go SDK.
//
// It holds the internal verifier used to validate Authara-issued
// access tokens and to power the provided HTTP middleware.
type SDK struct {
	verifier    *verifier
	revocations *accessTokenRevocations

	autharaBaseURL   string
	internalAPIToken string
	httpClient       *http.Client
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

	sdk := &SDK{
		verifier:         v,
		autharaBaseURL:   strings.TrimRight(cfg.AutharaBaseURL, "/"),
		internalAPIToken: strings.TrimSpace(cfg.InternalAPIToken),
		httpClient:       hc,
	}
	if cfg.AccessTokenRevocationEnabled {
		store, err := newRedisRevocationStore(cfg.Redis)
		if err != nil {
			return nil, err
		}
		sdk.revocations = &accessTokenRevocations{store: store}
	}
	return sdk, nil
}

func (s *SDK) verifyAccessToken(ctx context.Context, accessToken string) (accessIdentity, error) {
	identity, claims, err := s.verifier.verifyWithClaims(accessToken)
	if err != nil {
		return accessIdentity{}, err
	}
	if err := s.revocations.check(ctx, claims); err != nil {
		return accessIdentity{}, err
	}
	return identity, nil
}

// Close releases resources held by the SDK. Applications with access-token
// revocation checks enabled should call Close during shutdown.
func (s *SDK) Close() error {
	if s == nil || s.revocations == nil || s.revocations.store == nil {
		return nil
	}
	if err := s.revocations.store.Close(); err != nil {
		return fmt.Errorf("authara: close SDK: %w", err)
	}
	return nil
}

// Client returns an Authara HTTP client using the SDK transport settings.
func (s *SDK) Client() *Client {
	return NewClient(
		s.autharaBaseURL,
		WithHTTPClient(s.httpClient),
		WithInternalAPIToken(s.internalAPIToken),
	)
}
