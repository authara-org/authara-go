package authara

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultJWKSCacheTTL       = 5 * time.Minute
	maximumJWKSCacheTTL       = time.Hour
	unknownKeyRefreshCooldown = 30 * time.Second
	maximumJWKSResponseBytes  = 1 << 20
)

var errUnknownKeyID = errors.New("authara: unknown JWT key id")

type jwksCache struct {
	mu sync.Mutex

	url    string
	client *http.Client
	now    func() time.Time

	keys              map[string]ed25519.PublicKey
	etag              string
	expiresAt         time.Time
	lastForcedRefresh time.Time
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	KeyType   string   `json:"kty"`
	KeyID     string   `json:"kid"`
	Use       string   `json:"use"`
	Algorithm string   `json:"alg"`
	Curve     string   `json:"crv"`
	X         string   `json:"x"`
	Private   string   `json:"d"`
	KeyOps    []string `json:"key_ops"`
}

func newJWKSCache(rawURL string, client *http.Client) (*jwksCache, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("authara: JWKS URL must be an absolute http or https URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("authara: JWKS URL must not contain credentials, a query, or a fragment")
	}
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &jwksCache{url: parsed.String(), client: client, now: time.Now}, nil
}

func (c *jwksCache) key(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, errUnknownKeyID
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	refreshed := false
	if c.keys == nil || !now.Before(c.expiresAt) {
		if err := c.fetch(ctx, now); err != nil {
			return nil, err
		}
		refreshed = true
	}
	if key, ok := c.keys[keyID]; ok {
		return append(ed25519.PublicKey(nil), key...), nil
	}

	// A new signing key can appear before the normal cache expiry. Refresh once
	// on a miss, but rate-limit forced refreshes so arbitrary kid values cannot
	// turn token verification into an outbound-request flood.
	if !refreshed && (c.lastForcedRefresh.IsZero() || now.Sub(c.lastForcedRefresh) >= unknownKeyRefreshCooldown) {
		c.lastForcedRefresh = now
		if err := c.fetch(ctx, now); err != nil {
			return nil, err
		}
		if key, ok := c.keys[keyID]; ok {
			return append(ed25519.PublicKey(nil), key...), nil
		}
	}

	return nil, errUnknownKeyID
}

func (c *jwksCache) fetch(ctx context.Context, now time.Time) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("authara: create JWKS request: %w", err)
	}
	request.Header.Set("Accept", "application/jwk-set+json, application/json")
	if c.etag != "" && c.keys != nil {
		request.Header.Set("If-None-Match", c.etag)
	}

	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("authara: fetch JWKS: %w", err)
	}
	defer response.Body.Close()

	ttl := jwksCacheTTL(response.Header, defaultJWKSCacheTTL)
	if response.StatusCode == http.StatusNotModified {
		if c.keys == nil {
			return errors.New("authara: JWKS returned 304 without a cached key set")
		}
		c.expiresAt = now.Add(ttl)
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("authara: fetch JWKS: unexpected HTTP status %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maximumJWKSResponseBytes+1))
	if err != nil {
		return fmt.Errorf("authara: read JWKS: %w", err)
	}
	if len(body) > maximumJWKSResponseBytes {
		return errors.New("authara: JWKS response exceeds 1 MiB")
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}

	c.keys = keys
	c.etag = strings.TrimSpace(response.Header.Get("ETag"))
	c.expiresAt = now.Add(ttl)
	return nil
}

func parseJWKS(body []byte) (map[string]ed25519.PublicKey, error) {
	var set jsonWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("authara: decode JWKS: %w", err)
	}

	keys := make(map[string]ed25519.PublicKey)
	for _, jwk := range set.Keys {
		if jwk.KeyType != "OKP" || jwk.Curve != "Ed25519" {
			continue
		}
		if jwk.KeyID == "" || jwk.Algorithm != "EdDSA" || jwk.Use != "sig" || jwk.Private != "" {
			return nil, errors.New("authara: JWKS contains an invalid Ed25519 signing key")
		}
		if len(jwk.KeyOps) > 0 && !contains(jwk.KeyOps, "verify") {
			return nil, fmt.Errorf("authara: JWKS key %q does not permit verification", jwk.KeyID)
		}
		if _, duplicate := keys[jwk.KeyID]; duplicate {
			return nil, fmt.Errorf("authara: JWKS contains duplicate key id %q", jwk.KeyID)
		}
		publicKey, err := base64.RawURLEncoding.Strict().DecodeString(jwk.X)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("authara: JWKS key %q has an invalid public key", jwk.KeyID)
		}
		keys[jwk.KeyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	if len(keys) == 0 {
		return nil, errors.New("authara: JWKS contains no Ed25519 signing keys")
	}
	return keys, nil
}

func jwksCacheTTL(header http.Header, fallback time.Duration) time.Duration {
	var maxAgeSeconds int64
	maxAgeFound := false
	for directive := range strings.SplitSeq(header.Get("Cache-Control"), ",") {
		directive = strings.TrimSpace(strings.ToLower(directive))
		if directive == "no-store" || directive == "no-cache" {
			return 0
		}
		if maxAgeFound {
			continue
		}
		name, value, ok := strings.Cut(directive, "=")
		if !ok || name != "max-age" {
			continue
		}
		seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
		if err != nil || seconds < 0 {
			continue
		}
		maxAgeSeconds = seconds
		maxAgeFound = true
	}
	if !maxAgeFound {
		return fallback
	}

	ttl := maximumJWKSCacheTTL
	if maxAgeSeconds <= int64(maximumJWKSCacheTTL/time.Second) {
		ttl = time.Duration(maxAgeSeconds) * time.Second
	}
	if age, err := strconv.ParseInt(strings.TrimSpace(header.Get("Age")), 10, 64); err == nil && age > 0 {
		if age >= int64(ttl/time.Second) {
			return 0
		}
		ttl -= time.Duration(age) * time.Second
	}
	return ttl
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
