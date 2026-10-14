package authara

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSCacheRefreshesUnknownKeyOnce(t *testing.T) {
	first := newTestSigningKeys(t)
	second := newTestSigningKeys(t)
	second["rotated"] = second["test-kid"]
	delete(second, "test-kid")

	var mu sync.RWMutex
	current := first
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		mu.RLock()
		defer mu.RUnlock()
		writeTestJWKS(t, w, current)
	}))
	t.Cleanup(server.Close)

	cache, err := newJWKSCache(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.key(context.Background(), "test-kid"); err != nil {
		t.Fatalf("load initial key: %v", err)
	}
	mu.Lock()
	current = second
	mu.Unlock()
	if _, err := cache.key(context.Background(), "rotated"); err != nil {
		t.Fatalf("load rotated key: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want 2", got)
	}

	if _, err := cache.key(context.Background(), "attacker-controlled-kid"); err != errUnknownKeyID {
		t.Fatalf("unknown key error = %v", err)
	}
	if _, err := cache.key(context.Background(), "another-attacker-kid"); err != errUnknownKeyID {
		t.Fatalf("second unknown key error = %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("unknown-key cooldown allowed extra requests: %d", got)
	}
}

func TestJWKSCacheRevalidatesWithETag(t *testing.T) {
	keys := newTestSigningKeys(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=10")
		w.Header().Set("ETag", `"test"`)
		if r.Header.Get("If-None-Match") == `"test"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		writeTestJWKS(t, w, keys)
	}))
	t.Cleanup(server.Close)

	cache, err := newJWKSCache(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	if _, err := cache.key(context.Background(), "test-kid"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Second)
	if _, err := cache.key(context.Background(), "test-kid"); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want 2", got)
	}
}

func TestParseJWKSRejectsUnsafeKeySets(t *testing.T) {
	validX := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))
	tests := []struct {
		name string
		set  jsonWebKeySet
	}{
		{name: "empty"},
		{name: "private material", set: jsonWebKeySet{Keys: []jsonWebKey{{KeyType: "OKP", KeyID: "a", Use: "sig", Algorithm: "EdDSA", Curve: "Ed25519", X: validX, Private: "secret"}}}},
		{name: "wrong algorithm", set: jsonWebKeySet{Keys: []jsonWebKey{{KeyType: "OKP", KeyID: "a", Use: "sig", Algorithm: "ES256", Curve: "Ed25519", X: validX}}}},
		{name: "wrong use", set: jsonWebKeySet{Keys: []jsonWebKey{{KeyType: "OKP", KeyID: "a", Use: "enc", Algorithm: "EdDSA", Curve: "Ed25519", X: validX}}}},
		{name: "invalid public key", set: jsonWebKeySet{Keys: []jsonWebKey{{KeyType: "OKP", KeyID: "a", Use: "sig", Algorithm: "EdDSA", Curve: "Ed25519", X: "bad"}}}},
		{name: "duplicate kid", set: jsonWebKeySet{Keys: []jsonWebKey{
			{KeyType: "OKP", KeyID: "a", Use: "sig", Algorithm: "EdDSA", Curve: "Ed25519", X: validX},
			{KeyType: "OKP", KeyID: "a", Use: "sig", Algorithm: "EdDSA", Curve: "Ed25519", X: validX},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.set)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseJWKS(body); err == nil {
				t.Fatal("parseJWKS unexpectedly succeeded")
			}
		})
	}
}

func TestNewJWKSCacheRejectsUnsafeURLs(t *testing.T) {
	for _, rawURL := range []string{"", "/relative", "ftp://example.com/keys", "https://user:pass@example.com/keys", "https://example.com/keys?tenant=x", "https://example.com/keys#fragment"} {
		t.Run(rawURL, func(t *testing.T) {
			if _, err := newJWKSCache(rawURL, http.DefaultClient); err == nil {
				t.Fatalf("newJWKSCache(%q) unexpectedly succeeded", rawURL)
			}
		})
	}
}

func TestJWKSCacheTTL(t *testing.T) {
	header := make(http.Header)
	header.Set("Cache-Control", "public, max-age=600")
	header.Set("Age", "60")
	if got := jwksCacheTTL(header, time.Minute); got != 9*time.Minute {
		t.Fatalf("cache TTL = %s, want 9m", got)
	}
	header.Set("Cache-Control", "no-store")
	if got := jwksCacheTTL(header, time.Minute); got != 0 {
		t.Fatalf("no-store cache TTL = %s, want 0", got)
	}
	header.Set("Cache-Control", "public, max-age=600, no-store")
	if got := jwksCacheTTL(header, time.Minute); got != 0 {
		t.Fatalf("trailing no-store cache TTL = %s, want 0", got)
	}
	header.Set("Cache-Control", "public, max-age=600, no-cache")
	if got := jwksCacheTTL(header, time.Minute); got != 0 {
		t.Fatalf("trailing no-cache cache TTL = %s, want 0", got)
	}
	header.Set("Cache-Control", "public, max-age=999999")
	header.Del("Age")
	if got := jwksCacheTTL(header, time.Minute); got != maximumJWKSCacheTTL {
		t.Fatalf("capped cache TTL = %s, want %s", got, maximumJWKSCacheTTL)
	}
	header.Set("Cache-Control", "public, max-age=9223372036854775807")
	if got := jwksCacheTTL(header, time.Minute); got != maximumJWKSCacheTTL {
		t.Fatalf("overflowing cache TTL = %s, want %s", got, maximumJWKSCacheTTL)
	}
	header.Set("Age", "9223372036854775807")
	if got := jwksCacheTTL(header, time.Minute); got != 0 {
		t.Fatalf("overflowing cache age TTL = %s, want 0", got)
	}
}
