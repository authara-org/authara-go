package authara

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type revocationContractSpec struct {
	Token      string `json:"token"`
	Session    string `json:"session"`
	User       string `json:"user"`
	Membership string `json:"membership"`
}

func TestAccessTokenRevocationsMatchCoreContract(t *testing.T) {
	contract := loadRevocationContract(t)
	issuedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := &accessClaims{
		SessionID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		OrgID:     uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       "44444444-4444-4444-4444-444444444444",
			Subject:  "22222222-2222-2222-2222-222222222222",
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
	}
	wantKeys := []string{
		contractKey(contract.Token, "{token_identifier}", claims.ID),
		contractKey(contract.Session, "{session_id}", claims.SessionID.String()),
		contractKey(contract.User, "{user_id}", claims.Subject),
		contractKey(contract.Membership,
			"{user_id}", claims.Subject, "{organization_id}", claims.OrgID.String()),
	}
	got, err := accessTokenRevocationKeys(claims)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, wantKeys) {
		t.Fatalf("SDK keys differ from Core contract:\n got: %v\nwant: %v", got, wantKeys)
	}

	cutoff := []byte("1786104000000000000")
	for _, tt := range []struct {
		name   string
		values map[string][]byte
		want   error
	}{
		{name: "not revoked", values: map[string][]byte{}},
		{name: "token", values: map[string][]byte{wantKeys[0]: []byte("1")}, want: errTokenRevoked},
		{name: "session", values: map[string][]byte{wantKeys[1]: cutoff}, want: errTokenRevoked},
		{name: "user", values: map[string][]byte{wantKeys[2]: cutoff}, want: errTokenRevoked},
		{name: "membership", values: map[string][]byte{wantKeys[3]: cutoff}, want: errTokenRevoked},
		{name: "newer token", values: map[string][]byte{wantKeys[1]: []byte("1786103999999999999")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeRevocationStore{values: tt.values}
			err := (&accessTokenRevocations{store: store}).check(context.Background(), claims)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if !reflect.DeepEqual(store.keys, wantKeys) {
				t.Fatalf("lookup order differs from contract: got %v, want %v", store.keys, wantKeys)
			}
		})
	}

	lookupErr := errors.New("redis unavailable")
	if err := (&accessTokenRevocations{store: &fakeRevocationStore{err: lookupErr}}).
		check(context.Background(), claims); !errors.Is(err, lookupErr) {
		t.Fatalf("revocation lookup must fail closed: %v", err)
	}
}

func TestAccessTokenIdentifierSupportsTokensIssuedBeforeJTI(t *testing.T) {
	claims := &accessClaims{
		SessionID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		OrgID:     uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "22222222-2222-2222-2222-222222222222",
			Audience: jwt.ClaimStrings{"app"},
			IssuedAt: jwt.NewNumericDate(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)),
		},
	}

	identifier, err := accessTokenIdentifier(claims)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(identifier, "legacy:"+claims.SessionID.String()+":") {
		t.Fatalf("legacy token identifier = %q", identifier)
	}
}

func loadRevocationContract(t *testing.T) revocationContractSpec {
	t.Helper()
	data, err := os.ReadFile("../.codegen/access-token-revocations.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var contract revocationContractSpec
	if err := decoder.Decode(&contract); err != nil {
		t.Fatal(err)
	}
	return contract
}

func contractKey(template string, replacements ...string) string {
	return strings.NewReplacer(replacements...).Replace(template)
}

type fakeRevocationStore struct {
	values map[string][]byte
	err    error
	keys   []string
}

func (s *fakeRevocationStore) GetMany(_ context.Context, keys ...string) ([][]byte, error) {
	s.keys = append([]string(nil), keys...)
	if s.err != nil {
		return nil, s.err
	}
	values := make([][]byte, len(keys))
	for i, key := range keys {
		values[i] = s.values[key]
	}
	return values, nil
}

func (*fakeRevocationStore) Close() error { return nil }
