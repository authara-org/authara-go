package authara

import (
	"context"

	"github.com/google/uuid"
)

type userIDKeyType struct{}
type rolesKeyType struct{}

var (
	userIDKey = userIDKeyType{}
	rolesKey  = rolesKeyType{}
)

// withUserID returns a new context containing the authenticated user's ID.
//
// This function is used internally by the SDK to attach authentication
// information to the request context.
func withUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// UserIDFromContext extracts the authenticated user's ID from the context.
//
// The boolean return value is false if the request is unauthenticated or
// if no user ID has been attached to the context.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

// IsAuthenticated reports whether the context contains authentication
// information for a user.
func IsAuthenticated(ctx context.Context) bool {
	_, ok := UserIDFromContext(ctx)
	return ok
}

// withRoles returns a new context containing the authenticated user's roles.
//
// This function is used internally by the SDK to attach role information
// to the request context.
func withRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, rolesKey, roles)
}

// RolesFromContext extracts the authenticated user's roles from the context.
//
// The boolean return value is false if no roles have been attached to the
// context or if the request is unauthenticated.
func RolesFromContext(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(rolesKey).([]string)
	return roles, ok
}
