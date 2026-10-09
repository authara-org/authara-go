package authara

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var errTokenRevoked = errors.New("authara: access token is revoked")

const (
	revokedAccessTokenKeyTemplate           = "authara:access-token:revoked:token:{token_identifier}"
	revokedAccessTokenSessionKeyTemplate    = "authara:access-token:revoked:session:{session_id}"
	revokedAccessTokenUserKeyTemplate       = "authara:access-token:revoked:user:{user_id}"
	revokedAccessTokenMembershipKeyTemplate = "authara:access-token:revoked:membership:{user_id}:{organization_id}"
)

type revocationStore interface {
	GetMany(ctx context.Context, keys ...string) ([][]byte, error)
	Close() error
}

type accessTokenRevocations struct {
	store revocationStore
}

func (r *accessTokenRevocations) check(ctx context.Context, claims *accessClaims) error {
	if r == nil || r.store == nil {
		return nil
	}
	if claims == nil || claims.IssuedAt == nil {
		return ErrInvalidToken
	}

	keys, err := accessTokenRevocationKeys(claims)
	if err != nil {
		return err
	}
	values, err := r.store.GetMany(ctx, keys...)
	if err != nil {
		return fmt.Errorf("authara: check access token revocation: %w", err)
	}
	if len(values) != len(keys) {
		return fmt.Errorf("authara: check access token revocation: expected %d values, got %d", len(keys), len(values))
	}
	if values[0] != nil {
		return errTokenRevoked
	}

	issuedAt := claims.IssuedAt.Time.UnixNano()
	for _, value := range values[1:] {
		if value == nil {
			continue
		}
		cutoff, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil {
			return fmt.Errorf("authara: check access token revocation: invalid cutoff: %w", err)
		}
		if issuedAt <= cutoff {
			return errTokenRevoked
		}
	}
	return nil
}

func accessTokenRevocationKeys(claims *accessClaims) ([]string, error) {
	tokenIdentifier, err := accessTokenIdentifier(claims)
	if err != nil {
		return nil, err
	}
	return []string{
		expandRevocationKey(revokedAccessTokenKeyTemplate,
			"{token_identifier}", tokenIdentifier,
		),
		expandRevocationKey(revokedAccessTokenSessionKeyTemplate,
			"{session_id}", claims.SessionID.String(),
		),
		expandRevocationKey(revokedAccessTokenUserKeyTemplate,
			"{user_id}", claims.Subject,
		),
		expandRevocationKey(revokedAccessTokenMembershipKeyTemplate,
			"{user_id}", claims.Subject,
			"{organization_id}", claims.OrgID.String(),
		),
	}, nil
}

func accessTokenIdentifier(claims *accessClaims) (string, error) {
	if claims == nil {
		return "", ErrInvalidToken
	}
	if claims.ID != "" {
		id, err := uuid.Parse(claims.ID)
		if err != nil {
			return "", ErrInvalidToken
		}
		return id.String(), nil
	}
	if claims.SessionID == uuid.Nil || claims.OrgID == uuid.Nil || claims.Subject == "" || claims.IssuedAt == nil {
		return "", ErrInvalidToken
	}

	// Core tokens issued before jti support use this identifier during rolling
	// upgrades. It contains only public claims and never bearer-token material.
	return strings.Join([]string{
		"legacy",
		claims.SessionID.String(),
		claims.Subject,
		claims.OrgID.String(),
		strconv.FormatInt(claims.IssuedAt.Time.Unix(), 10),
		strings.Join(claims.Audience, ","),
	}, ":"), nil
}

func expandRevocationKey(template string, replacements ...string) string {
	return strings.NewReplacer(replacements...).Replace(template)
}
