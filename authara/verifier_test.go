package authara

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type testSigningKeys map[string]ed25519.PrivateKey

func newTestSigningKeys(t *testing.T) testSigningKeys {
	t.Helper()
	return testSigningKeys{"test-kid": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))}
}

func newTestJWKSServer(t *testing.T, keys testSigningKeys) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJWKS(t, w, keys)
	}))
	t.Cleanup(server.Close)
	return server
}

func writeTestJWKS(t *testing.T, w http.ResponseWriter, keys testSigningKeys) {
	t.Helper()
	set := jsonWebKeySet{Keys: make([]jsonWebKey, 0, len(keys))}
	for keyID, privateKey := range keys {
		publicKey := privateKey.Public().(ed25519.PublicKey)
		set.Keys = append(set.Keys, jsonWebKey{
			KeyType:   "OKP",
			KeyID:     keyID,
			Use:       "sig",
			Algorithm: "EdDSA",
			Curve:     "Ed25519",
			X:         base64.RawURLEncoding.EncodeToString(publicKey),
			KeyOps:    []string{"verify"},
		})
	}
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "public, max-age=300")
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/jwk-set+json")
	}
	if err := json.NewEncoder(w).Encode(set); err != nil {
		t.Fatalf("encode test JWKS: %v", err)
	}
}

func newTestVerifier(t *testing.T) (*verifier, testSigningKeys) {
	t.Helper()
	keys := newTestSigningKeys(t)
	server := newTestJWKSServer(t, keys)
	v, err := newVerifier("https://auth.example.com", "app", server.URL, server.Client())
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	return v, keys
}

func signToken(t *testing.T, claims jwt.Claims, keyID string, key ed25519.PrivateKey) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = keyID
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func validAccessClaims(now time.Time) accessClaims {
	return accessClaims{
		SessionID: uuid.New(),
		OrgID:     uuid.New(),
		OrgRole:   "owner",
		Roles:     []string{"authara:user"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  []string{"app"},
			Subject:   uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
}

func TestVerify_ValidToken(t *testing.T) {
	v, keys := newTestVerifier(t)
	claims := validAccessClaims(time.Now())
	token := signToken(t, claims, "test-kid", keys["test-kid"])

	identity, err := v.verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if identity.UserID.String() != claims.Subject || identity.OrganizationID != claims.OrgID || identity.OrganizationRole != "owner" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	if len(identity.Roles) != 1 || identity.Roles[0] != "authara:user" {
		t.Fatalf("unexpected roles: %v", identity.Roles)
	}
}

func TestVerify_AcceptsOverlappingRotationKeys(t *testing.T) {
	keys := testSigningKeys{
		"old": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)),
		"new": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)),
	}
	server := newTestJWKSServer(t, keys)
	verifier, err := newVerifier("https://auth.example.com", "app", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	for _, keyID := range []string{"old", "new"} {
		t.Run(keyID, func(t *testing.T) {
			raw := signToken(t, validAccessClaims(time.Now()), keyID, keys[keyID])
			if _, err := verifier.verify(context.Background(), raw); err != nil {
				t.Fatalf("verify token signed by %q: %v", keyID, err)
			}
		})
	}
}

func TestVerify_RejectsInvalidTokens(t *testing.T) {
	v, keys := newTestVerifier(t)
	now := time.Now()
	tests := []struct {
		name   string
		mutate func(*accessClaims)
		want   error
	}{
		{name: "expired", mutate: func(c *accessClaims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Hour)) }, want: ErrTokenExpired},
		{name: "missing expiry", mutate: func(c *accessClaims) { c.ExpiresAt = nil }, want: ErrInvalidToken},
		{name: "missing issued at", mutate: func(c *accessClaims) { c.IssuedAt = nil }, want: ErrInvalidToken},
		{name: "future issued at", mutate: func(c *accessClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(10 * time.Minute)) }, want: ErrInvalidToken},
		{name: "wrong audience", mutate: func(c *accessClaims) { c.Audience = []string{"admin"} }, want: ErrInvalidToken},
		{name: "wrong issuer", mutate: func(c *accessClaims) { c.Issuer = "https://other.example.com" }, want: ErrInvalidToken},
		{name: "missing subject", mutate: func(c *accessClaims) { c.Subject = "" }, want: ErrInvalidToken},
		{name: "nil session", mutate: func(c *accessClaims) { c.SessionID = uuid.Nil }, want: ErrInvalidToken},
		{name: "nil organization", mutate: func(c *accessClaims) { c.OrgID = uuid.Nil }, want: ErrInvalidToken},
		{name: "missing organization role", mutate: func(c *accessClaims) { c.OrgRole = " " }, want: ErrInvalidToken},
		{name: "invalid role namespace", mutate: func(c *accessClaims) { c.Roles = []string{"admin"} }, want: ErrInvalidRoleNamespace},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := validAccessClaims(now)
			tt.mutate(&claims)
			token := signToken(t, claims, "test-kid", keys["test-kid"])
			if _, err := v.verify(context.Background(), token); err != tt.want {
				t.Fatalf("verify error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerify_RejectsUnknownKeyAndHS256(t *testing.T) {
	v, keys := newTestVerifier(t)
	claims := validAccessClaims(time.Now())

	unknown := signToken(t, claims, "unknown", keys["test-kid"])
	if _, err := v.verify(context.Background(), unknown); err != ErrInvalidToken {
		t.Fatalf("unknown kid error = %v, want %v", err, ErrInvalidToken)
	}

	hmac := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hmac.Header["kid"] = "test-kid"
	hmacToken, err := hmac.SignedString([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.verify(context.Background(), hmacToken); err != ErrInvalidToken {
		t.Fatalf("HS256 error = %v, want %v", err, ErrInvalidToken)
	}
}
