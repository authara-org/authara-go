package authara

import "time"

const (
	// AccessCookieName is the name of the cookie that stores the Authara
	// access token (JWT).
	//
	// This cookie is read by the SDK to authenticate incoming requests.
	AccessCookieName = "authara_access"

	// LoginPath is the path to the Authara login endpoint.
	//
	// Unauthenticated users are redirected to this path, with an optional
	// return_to query parameter appended.
	LoginPath = "/auth/login"

	// RefreshPath is the Authara endpoint that rotates refresh cookies and
	// sets a new access cookie.
	//
	// It should be cookie-based and respond with Set-Cookie headers.
	RefreshPath = "/auth/api/v1/sessions/refresh"

	// JWKSPath publishes Authara's public Ed25519 access-token keys.
	JWKSPath = "/auth/.well-known/jwks.json"

	// clockSkew defines the allowed clock skew when validating JWT timestamps.
	//
	// This accounts for small differences between the Authara server's clock
	// and the application server's clock.
	clockSkew = 2 * time.Minute

	// CSRFCookieName is the name of the cookie that stores the CSRF token.
	//
	// The CSRF token is issued by Authara and used for CSRF protection via
	// the double-submit cookie pattern.
	CSRFCookieName = "authara_csrf"

	// CSRFHeaderName is the HTTP header used to forward the CSRF token in
	// state-changing requests (e.g. POST, PUT, DELETE).
	CSRFHeaderName = "X-CSRF-Token"

	// CSRFFormField is the name of the hidden form field used to submit the
	// CSRF token in server-rendered (SSR) applications.
	CSRFFormField = "csrf_token"

	// WebhookSignatureHeader is the HTTP header that carries the HMAC signature
	// for webhook requests sent by Authara.
	//
	// Applications must verify this signature to ensure the request originates
	// from a trusted Authara instance.
	WebhookSignatureHeader = "X-Authara-Signature"

	// WebhookEventHeader is the HTTP header that identifies the event type
	// of the webhook (e.g. user.created).
	//
	// This allows handlers to quickly route events without parsing the body.
	WebhookEventHeader = "X-Authara-Event"

	// WebhookDeliveryHeader is the HTTP header that contains the unique
	// delivery ID for the webhook request.
	//
	// This ID can be used for idempotency and deduplication of events.
	WebhookDeliveryHeader = "X-Authara-Delivery"

	// WebhookSignaturePrefix is the prefix used in the signature header value.
	//
	// The full header value has the format:
	//
	//   sha256=<hex-encoded-hmac>
	//
	// This prefix must be validated before verifying the signature.
	WebhookSignaturePrefix = "sha256="

	// WebhookEventUserCreated is emitted when a new user account is created.
	//
	// The payload contains a UserCreatedData object.
	WebhookEventUserCreated = "user.created"

	// WebhookEventUserUpdated is emitted when a user account is updated.
	WebhookEventUserUpdated = "user.updated"

	// WebhookEventUserDeleted is emitted when a user account is deleted.
	//
	// The payload contains a UserDeletedData object.
	WebhookEventUserDeleted = "user.deleted"

	WebhookEventOrganizationCreated = "organization.created"
	WebhookEventOrganizationUpdated = "organization.updated"
	WebhookEventOrganizationDeleted = "organization.deleted"

	WebhookEventOrganizationMembershipCreated = "organization.membership.created"
	WebhookEventOrganizationMembershipUpdated = "organization.membership.updated"
	WebhookEventOrganizationMembershipDeleted = "organization.membership.deleted"

	WebhookEventOrganizationInvitationCreated  = "organization.invitation.created"
	WebhookEventOrganizationInvitationAccepted = "organization.invitation.accepted"
	WebhookEventOrganizationInvitationRevoked  = "organization.invitation.revoked"
)
