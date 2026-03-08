package authara

import (
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type accessClaims struct {
	SessionID string   `json:"sid"`
	Roles     []string `json:"roles"`

	jwt.RegisteredClaims
}

type verifier struct {
	issuer   string
	audience string
	keys     map[string][]byte
}

func newVerifier(cfg Config) (*verifier, error) {
	return &verifier{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		keys:     cfg.Keys,
	}, nil
}

func (v *verifier) verify(tokenString string) (uuid.UUID, []string, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithLeeway(clockSkew),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
	)

	token, err := parser.ParseWithClaims(
		tokenString,
		&accessClaims{},
		v.keyFunc,
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return uuid.Nil, []string{}, ErrTokenExpired
		}
		return uuid.Nil, []string{}, ErrInvalidToken
	}

	claims, ok := token.Claims.(*accessClaims)
	if !ok || !token.Valid {
		return uuid.Nil, []string{}, ErrInvalidToken
	}

	if claims.Subject == "" || claims.SessionID == "" {
		return uuid.Nil, []string{}, ErrInvalidToken
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, []string{}, ErrInvalidToken
	}

	for _, role := range claims.Roles {
		if !strings.HasPrefix(role, "authara:") {
			return uuid.Nil, []string{}, ErrInvalidRoleNamespace
		}
	}

	return userID, claims.Roles, nil
}

func (v *verifier) keyFunc(t *jwt.Token) (any, error) {
	kid, ok := t.Header["kid"].(string)
	if !ok {
		return nil, ErrInvalidToken
	}

	key, ok := v.keys[kid]
	if !ok {
		return nil, ErrInvalidToken
	}

	return key, nil
}
