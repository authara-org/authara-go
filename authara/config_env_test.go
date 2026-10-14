package authara

import "testing"

func TestConfigFromEnv_Defaults(t *testing.T) {
	t.Setenv("AUTHARA_ACCESS_TOKEN_REVOCATION_ENABLED", "")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Audience != "app" {
		t.Fatalf("expected default audience %q, got %q", "app", cfg.Audience)
	}
	if cfg.Issuer != "authara" {
		t.Fatalf("expected default issuer %q, got %q", "authara", cfg.Issuer)
	}
	if cfg.AccessTokenRevocationEnabled {
		t.Fatal("expected access-token revocation checks to be disabled by default")
	}
}

func TestConfigFromEnv_BaseURL(t *testing.T) {
	t.Setenv("AUTHARA_BASE_URL", "http://example")
	t.Setenv("AUTHARA_JWKS_URL", "http://keys.example/jwks")
	t.Setenv("AUTHARA_INTERNAL_API_TOKEN", " secret ")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AutharaBaseURL != "http://example" {
		t.Fatalf("expected base url %q, got %q", "http://example", cfg.AutharaBaseURL)
	}
	if cfg.JWKSURL != "http://keys.example/jwks" {
		t.Fatalf("expected JWKS URL %q, got %q", "http://keys.example/jwks", cfg.JWKSURL)
	}
	if cfg.InternalAPIToken != "secret" {
		t.Fatalf("expected internal api token %q, got %q", "secret", cfg.InternalAPIToken)
	}
	if InternalAPITokenFromEnv() != "secret" {
		t.Fatalf("expected internal api token helper to trim")
	}
}

func TestConfigFromEnv_AccessTokenRevocation(t *testing.T) {
	t.Setenv("AUTHARA_ACCESS_TOKEN_REVOCATION_ENABLED", "true")
	t.Setenv("AUTHARA_REDIS_HOST", " redis.internal ")
	t.Setenv("AUTHARA_REDIS_PORT", "6380")
	t.Setenv("AUTHARA_REDIS_PASSWORD", " secret with spaces ")
	t.Setenv("AUTHARA_REDIS_DB", "2")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.AccessTokenRevocationEnabled {
		t.Fatal("expected access-token revocation checks to be enabled")
	}
	if cfg.Redis.Host != "redis.internal" || cfg.Redis.Port != 6380 || cfg.Redis.DB != 2 {
		t.Fatalf("unexpected Redis config: %+v", cfg.Redis)
	}
	if cfg.Redis.Password != " secret with spaces " {
		t.Fatalf("Redis password was unexpectedly trimmed: %q", cfg.Redis.Password)
	}
}

func TestWebhookHandlerFromEnv_TrimsSecret(t *testing.T) {
	t.Setenv("AUTHARA_WEBHOOK_SECRET", " secret ")

	h := WebhookHandlerFromEnv()

	if h.Secret != "secret" {
		t.Fatalf("expected trimmed secret, got %q", h.Secret)
	}
}

func TestRequireWebhookHandlerFromEnv(t *testing.T) {
	t.Setenv("AUTHARA_WEBHOOK_SECRET", " secret ")

	h, err := RequireWebhookHandlerFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.Secret != "secret" {
		t.Fatalf("expected trimmed secret, got %q", h.Secret)
	}
}

func TestRequireWebhookHandlerFromEnv_Empty(t *testing.T) {
	t.Setenv("AUTHARA_WEBHOOK_SECRET", "   ")

	h, err := RequireWebhookHandlerFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
	if h != nil {
		t.Fatal("expected nil handler")
	}
}
