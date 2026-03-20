package authara

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// ConfigFromEnv builds an authara.Config from environment variables.
//
// It expects the following variables:
//
//	AUTHARA_AUDIENCE
//	AUTHARA_ISSUER
//	AUTHARA_JWT_KEYS
//
// Optional:
//
//	AUTHARA_BASE_URL
//
// This helper is intentionally minimal and does not introduce implicit behavior.
// It only maps environment variables to Config fields.
func ConfigFromEnv() (Config, error) {
	keys, err := parseJWTKeys(os.Getenv("AUTHARA_JWT_KEYS"))
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Audience: envOrDefault("AUTHARA_AUDIENCE", "app"),
		Issuer:   envOrDefault("AUTHARA_ISSUER", "authara"),
		Keys:     keys,
	}

	if baseURL := strings.TrimSpace(os.Getenv("AUTHARA_BASE_URL")); baseURL != "" {
		cfg.AutharaBaseURL = baseURL
	}

	return cfg, nil
}

// WebhookHandlerFromEnv creates a WebhookHandler using environment variables.
//
// It expects:
//
//	AUTHARA_WEBHOOK_SECRET
//
// If the secret is empty, the handler will still be created but all requests
// will fail signature verification.
//
// This helper is optional and provided for convenience.
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

func parseJWTKeys(raw string) (map[string][]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("AUTHARA_JWT_KEYS is empty")
	}

	out := make(map[string][]byte)

	entries := strings.Split(raw, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid AUTHARA_JWT_KEYS entry: %q", entry)
		}

		keyID := strings.TrimSpace(parts[0])
		b64 := strings.TrimSpace(parts[1])

		if keyID == "" {
			return nil, fmt.Errorf("empty key id in AUTHARA_JWT_KEYS")
		}
		if b64 == "" {
			return nil, fmt.Errorf("empty key value for key id %q", keyID)
		}

		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 for key id %q: %w", keyID, err)
		}

		out[keyID] = key
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no valid keys found in AUTHARA_JWT_KEYS")
	}

	return out, nil
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}
