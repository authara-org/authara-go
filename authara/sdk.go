package authara

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultHTTPTimeout = 5 * time.Second

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
// Issuer, Audience, and either JWKSURL or AutharaBaseURL are required. New
// performs validation and returns an error for incomplete or invalid input.
//
// Example:
//
//	sdk, err := authara.New(authara.Config{
//		Issuer:         "https://example.com",
//		Audience:       "app",
//		AutharaBaseURL: "https://example.com",
//		HTTPClient:      nil,
//	})
func New(cfg Config) (*SDK, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return nil, errors.New("authara: issuer is required")
	}

	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		return nil, errors.New("authara: audience is required")
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultHTTPTimeout}
	}

	autharaBaseURL := strings.TrimRight(strings.TrimSpace(cfg.AutharaBaseURL), "/")
	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	if jwksURL == "" && autharaBaseURL != "" {
		jwksURL = autharaBaseURL + JWKSPath
	}
	if jwksURL == "" {
		return nil, errors.New("authara: JWKS URL or Authara base URL is required")
	}

	v, err := newVerifier(issuer, audience, jwksURL, hc)
	if err != nil {
		return nil, err
	}

	sdk := &SDK{
		verifier:         v,
		autharaBaseURL:   autharaBaseURL,
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
	identity, claims, err := s.verifier.verifyWithClaims(ctx, accessToken)
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
