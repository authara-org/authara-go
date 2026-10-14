package authara

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type accessClaims struct {
	SessionID uuid.UUID `json:"sid"`
	OrgID     uuid.UUID `json:"org_id"`
	OrgRole   string    `json:"org_role"`
	Roles     []string  `json:"roles"`

	jwt.RegisteredClaims
}

type accessIdentity struct {
	UserID           uuid.UUID
	OrganizationID   uuid.UUID
	OrganizationRole string
	Roles            []string
}

type verifier struct {
	issuer   string
	audience string
	keys     *jwksCache
}

func newVerifier(issuer, audience, jwksURL string, client *http.Client) (*verifier, error) {
	keys, err := newJWKSCache(jwksURL, client)
	if err != nil {
		return nil, err
	}
	return &verifier{issuer: issuer, audience: audience, keys: keys}, nil
}

func (v *verifier) verify(ctx context.Context, tokenString string) (accessIdentity, error) {
	identity, _, err := v.verifyWithClaims(ctx, tokenString)
	return identity, err
}

func (v *verifier) verifyWithClaims(ctx context.Context, tokenString string) (accessIdentity, *accessClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithLeeway(clockSkew),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	token, err := parser.ParseWithClaims(
		tokenString,
		&accessClaims{},
		func(token *jwt.Token) (any, error) { return v.keyFunc(ctx, token) },
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return accessIdentity{}, nil, ErrTokenExpired
		}
		return accessIdentity{}, nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*accessClaims)
	if !ok || !token.Valid {
		return accessIdentity{}, nil, ErrInvalidToken
	}

	orgRole := strings.TrimSpace(claims.OrgRole)
	if claims.Subject == "" ||
		claims.SessionID == uuid.Nil ||
		claims.OrgID == uuid.Nil ||
		claims.IssuedAt == nil ||
		orgRole == "" {
		return accessIdentity{}, nil, ErrInvalidToken
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil || userID == uuid.Nil {
		return accessIdentity{}, nil, ErrInvalidToken
	}

	for _, role := range claims.Roles {
		if !strings.HasPrefix(role, "authara:") {
			return accessIdentity{}, nil, ErrInvalidRoleNamespace
		}
	}

	return accessIdentity{
		UserID:           userID,
		OrganizationID:   claims.OrgID,
		OrganizationRole: orgRole,
		Roles:            append([]string(nil), claims.Roles...),
	}, claims, nil
}

func (v *verifier) keyFunc(ctx context.Context, token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
		return nil, ErrInvalidToken
	}
	keyID, ok := token.Header["kid"].(string)
	if !ok || strings.TrimSpace(keyID) == "" {
		return nil, ErrInvalidToken
	}
	return v.keys.key(ctx, keyID)
}
