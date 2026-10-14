package authara

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ConfigFromEnv builds an authara.Config from environment variables.
//
// It expects the following variables:
//
//	AUTHARA_AUDIENCE
//	AUTHARA_ISSUER
//
// Optional:
//
//	AUTHARA_BASE_URL
//	AUTHARA_JWKS_URL (derived from AUTHARA_BASE_URL when omitted)
//	AUTHARA_INTERNAL_API_TOKEN
//	AUTHARA_ACCESS_TOKEN_REVOCATION_ENABLED
//	AUTHARA_REDIS_HOST
//	AUTHARA_REDIS_PORT
//	AUTHARA_REDIS_PASSWORD
//	AUTHARA_REDIS_DB
//
// This helper is intentionally minimal and does not introduce implicit behavior.
// It only maps environment variables to Config fields.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		Audience: envOrDefault("AUTHARA_AUDIENCE", "app"),
		Issuer:   envOrDefault("AUTHARA_ISSUER", "authara"),
	}

	if baseURL := strings.TrimSpace(os.Getenv("AUTHARA_BASE_URL")); baseURL != "" {
		cfg.AutharaBaseURL = baseURL
	}
	if jwksURL := strings.TrimSpace(os.Getenv("AUTHARA_JWKS_URL")); jwksURL != "" {
		cfg.JWKSURL = jwksURL
	}
	if token := strings.TrimSpace(os.Getenv("AUTHARA_INTERNAL_API_TOKEN")); token != "" {
		cfg.InternalAPIToken = token
	}

	revocationEnabled, err := optionalEnvBool("AUTHARA_ACCESS_TOKEN_REVOCATION_ENABLED")
	if err != nil {
		return Config{}, err
	}
	cfg.AccessTokenRevocationEnabled = revocationEnabled
	if revocationEnabled {
		redisPort, err := envIntOrDefault("AUTHARA_REDIS_PORT", 6379)
		if err != nil {
			return Config{}, err
		}
		redisDB, err := envIntOrDefault("AUTHARA_REDIS_DB", 0)
		if err != nil {
			return Config{}, err
		}
		cfg.Redis = RedisConfig{
			Host:     envOrDefault("AUTHARA_REDIS_HOST", "localhost"),
			Port:     redisPort,
			Password: os.Getenv("AUTHARA_REDIS_PASSWORD"),
			DB:       redisDB,
		}
	}

	return cfg, nil
}

// InternalAPITokenFromEnv returns AUTHARA_INTERNAL_API_TOKEN trimmed.
func InternalAPITokenFromEnv() string {
	return strings.TrimSpace(os.Getenv("AUTHARA_INTERNAL_API_TOKEN"))
}

// RequireWebhookHandlerFromEnv creates a WebhookHandler and fails if the
// webhook secret is not configured.
//
// It reads:
//
//	AUTHARA_WEBHOOK_SECRET
//
// This helper should be used in applications that expose a webhook endpoint,
// ensuring misconfiguration is caught at startup.
func RequireWebhookHandlerFromEnv() (*WebhookHandler, error) {
	secret := strings.TrimSpace(os.Getenv("AUTHARA_WEBHOOK_SECRET"))
	if secret == "" {
		return nil, fmt.Errorf("AUTHARA_WEBHOOK_SECRET is empty")
	}

	return &WebhookHandler{
		Secret: secret,
	}, nil
}

// WebhookHandlerFromEnv creates a WebhookHandler using environment variables.
//
// It reads:
//
//	AUTHARA_WEBHOOK_SECRET
//
// If the secret is empty, the handler is still returned, but all incoming
// requests will fail signature verification.
//
// This helper is intended for advanced or optional setups.
//
// For most applications, use RequireWebhookHandlerFromEnv instead.
func WebhookHandlerFromEnv() *WebhookHandler {
	return &WebhookHandler{
		Secret: strings.TrimSpace(os.Getenv("AUTHARA_WEBHOOK_SECRET")),
	}
}

// WebhookSecretFromEnv returns the configured webhook secret.
//
// This is useful if you want to construct the handler manually.
func WebhookSecretFromEnv() string {
	return strings.TrimSpace(os.Getenv("AUTHARA_WEBHOOK_SECRET"))
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func optionalEnvBool(key string) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return value, nil
}

func envIntOrDefault(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return value, nil
}
