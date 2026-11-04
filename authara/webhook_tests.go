package authara

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{"id":"evt_1","type":"user.created","created_at":"2026-03-20T12:00:00Z","data":{"user_id":"123"}}`)

	header := signedHeader(secret, body)

	if !VerifyWebhookSignature(secret, body, header) {
		t.Fatal("expected signature to be valid")
	}
}

func TestVerifyWebhookSignature_Invalid(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{"id":"evt_1"}`)

	if VerifyWebhookSignature(secret, body, "sha256=wrong") {
		t.Fatal("expected signature to be invalid")
	}
}

func TestParseWebhookEvent(t *testing.T) {
	body := []byte(`{
		"id":"evt_1",
		"type":"user.created",
		"created_at":"2026-03-20T12:00:00Z",
		"data":{"user_id":"123"}
	}`)

	evt, err := ParseWebhookEvent(body)
	if err != nil {
		t.Fatalf("ParseWebhookEvent failed: %v", err)
	}

	if evt.ID != "evt_1" {
		t.Fatalf("expected id evt_1, got %q", evt.ID)
	}
	if evt.Type != WebhookEventUserCreated {
		t.Fatalf("expected type %q, got %q", WebhookEventUserCreated, evt.Type)
	}
}

func TestDecodeWebhookData(t *testing.T) {
	body := []byte(`{
		"id":"evt_1",
		"type":"user.created",
		"created_at":"2026-03-20T12:00:00Z",
		"data":{"user_id":"123"}
	}`)

	evt, err := ParseWebhookEvent(body)
	if err != nil {
		t.Fatalf("ParseWebhookEvent failed: %v", err)
	}

	data, err := DecodeWebhookData[UserCreatedData](evt)
	if err != nil {
		t.Fatalf("DecodeWebhookData failed: %v", err)
	}

	if data.UserID != "123" {
		t.Fatalf("expected user_id 123, got %q", data.UserID)
	}
}

func TestDecodeRegistrationCompletedWebhookData(t *testing.T) {
	body := []byte(`{
		"id":"evt_registration",
		"type":"registration.completed",
		"created_at":"2026-11-04T20:00:00Z",
		"data":{
			"user_id":"11111111-1111-1111-1111-111111111111",
			"organization_id":"22222222-2222-2222-2222-222222222222",
			"organization_name":"Example",
			"membership_role":"owner",
			"membership_metadata":{}
		}
	}`)

	evt, err := ParseWebhookEvent(body)
	if err != nil {
		t.Fatalf("ParseWebhookEvent failed: %v", err)
	}
	if evt.Type != WebhookEventRegistrationCompleted {
		t.Fatalf("event type = %q, want %q", evt.Type, WebhookEventRegistrationCompleted)
	}
	data, err := DecodeWebhookData[RegistrationCompletedData](evt)
	if err != nil {
		t.Fatalf("DecodeWebhookData failed: %v", err)
	}
	if data.UserID == "" || data.OrganizationID == "" || data.OrganizationName != "Example" || data.MembershipRole != "owner" || len(data.MembershipMetadata) == 0 {
		t.Fatalf("unexpected registration payload: %+v", data)
	}
}

func TestDecodeOrganizationMembershipCreatedWebhookData(t *testing.T) {
	body := []byte(`{
		"id":"evt_membership",
		"type":"organization.membership.created",
		"created_at":"2026-03-20T12:00:00Z",
		"data":{
			"organization_id":"22222222-2222-2222-2222-222222222222",
			"user_id":"33333333-3333-3333-3333-333333333333",
			"role":"admin",
			"is_initial_membership":false,
			"invitation_id":"44444444-4444-4444-4444-444444444444",
			"metadata":{"baufunk":{"role":"manager"}}
		}
	}`)

	evt, err := ParseWebhookEvent(body)
	if err != nil {
		t.Fatalf("ParseWebhookEvent failed: %v", err)
	}
	data, err := DecodeWebhookData[OrganizationMembershipCreatedData](evt)
	if err != nil {
		t.Fatalf("DecodeWebhookData failed: %v", err)
	}
	if data.IsInitialMembership || data.InvitationID == nil || data.Role != "admin" || len(data.Metadata) == 0 {
		t.Fatalf("unexpected membership payload: %+v", data)
	}
}

func TestDecodeOrganizationInvitationWebhookData(t *testing.T) {
	body := []byte(`{
		"id":"evt_2",
		"type":"organization.invitation.created",
		"created_at":"2026-03-20T12:00:00Z",
		"data":{
			"invitation_id":"44444444-4444-4444-4444-444444444444",
			"organization_id":"22222222-2222-2222-2222-222222222222",
			"email":"teammate@example.com",
			"role":"member",
			"metadata":{"baufunk":{"role":"worker"}},
			"invited_by_user_id":"33333333-3333-3333-3333-333333333333",
			"expires_at":"2026-03-27T12:00:00Z"
		}
	}`)

	evt, err := ParseWebhookEvent(body)
	if err != nil {
		t.Fatalf("ParseWebhookEvent failed: %v", err)
	}
	if evt.Type != WebhookEventOrganizationInvitationCreated {
		t.Fatalf("expected type %q, got %q", WebhookEventOrganizationInvitationCreated, evt.Type)
	}

	data, err := DecodeWebhookData[OrganizationInvitationCreatedData](evt)
	if err != nil {
		t.Fatalf("DecodeWebhookData failed: %v", err)
	}
	if data.Email != "teammate@example.com" || data.InvitedByUserID == nil || data.ExpiresAt.IsZero() || len(data.Metadata) == 0 {
		t.Fatalf("unexpected invitation payload: %+v", data)
	}
}

func TestWebhookHandler_Handle_Success(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{
		"id":"evt_1",
		"type":"user.created",
		"created_at":"2026-03-20T12:00:00Z",
		"data":{"user_id":"123"}
	}`)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/authara", bytes.NewReader(body))
	req.Header.Set(WebhookSignatureHeader, signedHeader(secret, body))
	rr := httptest.NewRecorder()

	handler := &WebhookHandler{Secret: secret}

	evt, err := handler.Handle(rr, req)
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event")
	}
	if rr.Code != 200 {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
}

func TestWebhookHandler_Handle_InvalidSignature(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{"id":"evt_1"}`)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/authara", bytes.NewReader(body))
	req.Header.Set(WebhookSignatureHeader, "sha256=wrong")
	rr := httptest.NewRecorder()

	handler := &WebhookHandler{Secret: secret}

	evt, err := handler.Handle(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}
	if evt != nil {
		t.Fatal("expected nil event")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func signedHeader(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return WebhookSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}
