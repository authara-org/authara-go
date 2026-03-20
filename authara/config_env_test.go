package authara

import "testing"

func TestParseJWTKeys_Valid(t *testing.T) {
	raw := "k1:YWJj,k2:ZGVm" // "abc", "def"

	keys, err := parseJWTKeys(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestParseJWTKeys_InvalidFormat(t *testing.T) {
	_, err := parseJWTKeys("invalid")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseJWTKeys_InvalidBase64(t *testing.T) {
	_, err := parseJWTKeys("k1:!!!")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestConfigFromEnv_Defaults(t *testing.T) {
	t.Setenv("AUTHARA_JWT_KEYS", "k1:YWJj")

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
}

func TestConfigFromEnv_BaseURL(t *testing.T) {
	t.Setenv("AUTHARA_JWT_KEYS", "k1:YWJj")
	t.Setenv("AUTHARA_BASE_URL", "http://example")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AutharaBaseURL != "http://example" {
		t.Fatalf("expected base url %q, got %q", "http://example", cfg.AutharaBaseURL)
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
