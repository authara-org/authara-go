package authara

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newTestVerifier(t *testing.T) (*verifier, map[string][]byte) {
	t.Helper()

	key := []byte("super-secret")
	keys := map[string][]byte{
		"test-kid": key,
	}

	v, err := newVerifier(Config{
		Issuer:   "https://auth.example.com",
		Audience: "app",
		Keys:     keys,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	return v, keys
}

func signToken(t *testing.T, claims jwt.Claims, key []byte) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "test-kid"

	s, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return s
}

func TestVerify_ValidToken(t *testing.T) {
	v, keys := newTestVerifier(t)

	userID := uuid.New()
	now := time.Now()

	claims := accessClaims{
		SessionID: "session-123",
		Roles:     []string{"authara:user"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  []string{"app"},
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := signToken(t, claims, keys["test-kid"])

	gotUserID, roles, err := v.verify(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotUserID != userID {
		t.Fatalf("expected userID %v, got %v", userID, gotUserID)
	}

	if len(roles) != 1 || roles[0] != "authara:user" {
		t.Fatalf("unexpected roles: %v", roles)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	v, keys := newTestVerifier(t)

	claims := accessClaims{
		SessionID: "session-123",
		Roles:     []string{"authara:user"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  []string{"app"},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}

	token := signToken(t, claims, keys["test-kid"])

	_, _, err := v.verify(token)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	v, keys := newTestVerifier(t)

	claims := accessClaims{
		SessionID: "session-123",
		Roles:     []string{"authara:user"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  []string{"admin"},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := signToken(t, claims, keys["test-kid"])

	_, _, err := v.verify(token)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerify_InvalidRoleNamespace(t *testing.T) {
	v, keys := newTestVerifier(t)

	claims := accessClaims{
		SessionID: "session-123",
		Roles:     []string{"user"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  []string{"app"},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := signToken(t, claims, keys["test-kid"])

	_, _, err := v.verify(token)
	if err != ErrInvalidRoleNamespace {
		t.Fatalf("expected ErrInvalidRoleNamespace, got %v", err)
	}
}

func TestVerify_UnknownKeyID(t *testing.T) {
	v, _ := newTestVerifier(t)

	claims := accessClaims{
		SessionID: "session-123",
		Roles:     []string{"authara:user"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  []string{"app"},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "unknown"

	s, err := token.SignedString([]byte("wrong-key"))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, _, err = v.verify(s)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}
