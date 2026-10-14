package authara

import "net/http"

// Config defines the configuration required to initialize the Authara SDK.
//
// Issuer, Audience, and either JWKSURL or AutharaBaseURL are required. The SDK
// performs strict validation when calling New.
type Config struct {
	// Issuer is the expected issuer (iss claim) of Authara-issued access tokens.
	//
	// This must exactly match the issuer configured in Authara Core.
	Issuer string

	// Audience is the expected audience (aud claim) of access tokens.
	//
	// Typical values are application identifiers such as "app" or "admin".
	// Tokens with a different audience will be rejected.
	Audience string

	// JWKSURL is the Authara endpoint that publishes public access-token keys.
	//
	// If empty, the SDK derives it from AutharaBaseURL by appending JWKSPath.
	// The URL must use http or https and must not contain credentials, a query,
	// or a fragment.
	JWKSURL string

	// AutharaBaseURL is used to derive JWKSURL and enables refresh behavior.
	//
	// Example: "https://example.com", or in Docker: "http://authara:8080".
	// It may be empty only when JWKSURL is set; refresh is then disabled.
	AutharaBaseURL string

	// InternalAPIToken authorizes calls to /auth/internal/v1.
	//
	// It must match AUTHARA_INTERNAL_API_TOKEN configured in Authara.
	InternalAPIToken string

	// HTTPClient is used for JWKS and refresh requests.
	// If nil, the SDK uses an HTTP client with a five-second timeout.
	HTTPClient *http.Client

	// AccessTokenRevocationEnabled makes middleware reject access tokens that
	// Authara Core has revoked in Redis. Checks fail closed if Redis is
	// unavailable.
	AccessTokenRevocationEnabled bool

	// Redis configures the shared Redis used by Authara Core for access-token
	// revocations. It is only used when AccessTokenRevocationEnabled is true.
	Redis RedisConfig
}

// RedisConfig configures the Redis connection used for access-token revocation
// checks.
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}
