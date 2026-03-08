package authara

import "errors"

var (
	ErrInvalidToken         = errors.New("authara: invalid access token")
	ErrTokenExpired         = errors.New("authara: token is expired")
	ErrInvalidRoleNamespace = errors.New("authara: role namespace is invalid")
)
