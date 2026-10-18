# Authara Go SDK

A minimal Go SDK for integrating backend and SSR applications with an **Authara**
authentication server.

This SDK is intentionally small and infrastructure-focused. Its primary
responsibility is to **verify Authara-issued access tokens** and expose
authentication facts to your application in a safe, explicit way.

It does not perform authentication itself and does not own session or security
policy.

---

## Scope and design philosophy

This SDK is designed to:

- expose **facts**, not policy
- avoid hidden behavior
- keep authentication and authorization concerns separate
- cache public signing keys according to Authara's JWKS response

Authara itself remains the single source of truth for authentication,
sessions, refresh logic, CSRF enforcement, and security invariants.

---

## What this SDK does

### Token verification & middleware

- Verifies Authara-issued access tokens (JWT)
- Validates token properties:
  - issuer (`iss`)
  - audience (`aud`)
  - expiry (`exp`)
  - signature and key ID (`kid`)
- Injects authentication facts into `context.Context`
- Provides HTTP middleware for common auth patterns
- Exposes helpers for reading authentication facts from context
- Optionally checks Authara's shared Redis revocation entries

### Backend client helpers (optional)

- Provides **generated, side-effect-free HTTP helpers** for calling Authara
  endpoints from backend or SSR applications
- Forwards existing authentication context (access cookie) only
- Exposes API calls generated from the Authara OpenAPI contract

These helpers are **strict by design**:
- no token refresh
- no retries
- no cookie mutation
- no redirect behavior

---

## What this SDK does NOT do

- Does **not** authenticate users
- Does **not** manage sessions
- Does **not** enforce authorization policy
- Does **not** perform background network calls

> Exceptions: `RequireAuthWithRefresh` can perform a best-effort refresh call,
> middleware can query Redis for access-token revocations, and token validation
> fetches public signing keys from JWKS on demand. JWKS requests are cached and
> never contain private signing material.

All authentication, session management, refresh logic, and CSRF enforcement live
exclusively in **Authara itself**, not in this SDK.

---

## Installation

```bash
go get github.com/authara-org/authara-go
```

---

## Configuration (token verification)

```go
sdk, err := authara.New(authara.Config{
	Issuer:         "authara",
	Audience:       "app",
	AutharaBaseURL: "https://example.com",
})
if err != nil {
	// handle configuration error
}
```

Required values:

- `Issuer` must exactly match the issuer configured in Authara
- `Audience` must match the intended token audience
- either `AutharaBaseURL` or an explicit `JWKSURL`

The SDK fetches public Ed25519 keys from
`/auth/.well-known/jwks.json`, honors the endpoint's ETag and cache policy, and
refreshes once on a new `kid` during rotation. Core's private signing seeds are
never configured in the SDK. When `HTTPClient` is omitted, JWKS and refresh
requests use a five-second timeout; a caller-provided client is used unchanged.

---

## Configuration from environment (recommended)

For applications using environment variables, the SDK provides a helper:

```go
cfg, err := authara.ConfigFromEnv()
if err != nil {
	log.Fatal(err)
}

sdk, err := authara.New(cfg)
if err != nil {
	log.Fatal(err)
}
```

Expected environment variables:

- `AUTHARA_AUDIENCE` (default: `app`)
- `AUTHARA_ISSUER` (default: `authara`)
- `AUTHARA_BASE_URL` (required unless `AUTHARA_JWKS_URL` is set; also enables refresh)
- `AUTHARA_JWKS_URL` (optional; derived from `AUTHARA_BASE_URL` when omitted)
- `AUTHARA_INTERNAL_API_TOKEN` (optional, enables internal API helpers)
- `AUTHARA_ACCESS_TOKEN_REVOCATION_ENABLED` (default: `false`)
- `AUTHARA_REDIS_HOST` (default: `localhost`, used when revocation checks are enabled)
- `AUTHARA_REDIS_PORT` (default: `6379`, used when revocation checks are enabled)
- `AUTHARA_REDIS_PASSWORD` (optional, used when revocation checks are enabled)
- `AUTHARA_REDIS_DB` (default: `0`, used when revocation checks are enabled)

This helper is intentionally minimal and does not introduce implicit behavior.

---

## Optional configuration (refresh support)

The SDK can optionally perform a single best-effort refresh when an access token
is missing or invalid.

To enable refresh, configure the Authara base URL:

```go
sdk, err := authara.New(authara.Config{
	Issuer:         "authara",
	Audience:       "app",
	AutharaBaseURL: "http://authara:8080",
})
```

Notes:

- Refresh is performed by calling Authara’s refresh endpoint and forwarding
  the incoming request cookies.
- Authara remains the only component that knows refresh semantics. The SDK only
  triggers refresh and re-verifies the new access token.
- If `AutharaBaseURL` is not set, refresh behavior is disabled.

---

## Optional access-token revocation checks

By default, middleware verifies access-token JWTs locally. To also reject
tokens that Authara Core has revoked, connect the SDK to the same Redis database
as Core:

```env
AUTHARA_ACCESS_TOKEN_REVOCATION_ENABLED=true
AUTHARA_REDIS_HOST=redis
AUTHARA_REDIS_PORT=6379
AUTHARA_REDIS_PASSWORD=
AUTHARA_REDIS_DB=0
```

Every middleware token verification checks the exact token, session, user, and
organization-membership revocation entries. Redis connection and lookup
failures fail closed: `New` fails if Redis is unavailable at startup, and
protected requests are treated as unauthenticated if a runtime lookup fails.
`TryAuth` continues without attaching an identity in that case.
Call `sdk.Close()` during shutdown.

The Redis formats are synchronized from Authara Core's versioned
`contract/access-token-revocations.json` contract.

---

## HTTP middleware

### Require authentication

```go
r.Use(sdk.RequireAuth)
```

- Browser → redirect
- HTMX → `HX-Redirect`
- API → `401`

When an `Authorization` header is present it is authoritative. Only one valid
`Bearer <token>` value is accepted; malformed, unsupported, empty, or repeated
values fail authentication and never fall back to the access cookie. The same
precedence applies to refresh and optional-auth middleware.

---

### Require authentication with refresh

```go
r.Use(sdk.RequireAuthWithRefresh)
```

- Attempts one refresh if token missing/invalid
- Forwards `Set-Cookie`
- Continues request if refresh succeeds

---

### Optional authentication

```go
r.Use(sdk.TryAuth)
```

Never blocks — attaches auth if available.

---

## Reading authentication facts

```go
userID, ok := authara.UserIDFromContext(r.Context())
roles, _ := authara.RolesFromContext(r.Context())
organizationID, _ := authara.OrganizationIDFromContext(r.Context())
organizationRole, _ := authara.OrganizationRoleFromContext(r.Context())
```

---

## Backend client helpers

### Creating a client

```go
client := authara.NewClient("https://auth.example.com")
```

---

### Fetching current user

```go
user, err := client.CallGetCurrentUser(ctx, r)
```

---

### Internal API helpers

```go
client := authara.NewClient(
	"https://auth.example.com",
	authara.WithInternalAPIToken(os.Getenv("AUTHARA_INTERNAL_API_TOKEN")),
)
role := authara.APIOrganizationInvitationRoleAdmin
metadata := map[string]any{"baufunk": map[string]any{"role": "manager"}}

invite, err := client.CallCreateInternalOrganizationInvitation(
	ctx,
	organizationID,
	authara.APIInternalCreateInvitationRequest{
		ActorUserID: actorUserID,
		Email:       "teammate@example.com",
		Role:        &role,
		Metadata:    &metadata,
	},
)

// After your backend has checked subscriptions and product data:
err = client.CallRemoveInternalOrganizationMember(
	ctx,
	organizationID,
	userID,
	authara.APIInternalOrganizationActorRequest{ActorUserID: actorUserID},
)

err = client.CallDeleteInternalOrganization(
	ctx,
	organizationID,
	authara.APIInternalOrganizationActorRequest{ActorUserID: actorUserID},
)

err = client.CallDeleteInternalUser(ctx, userID)
```

---

## CSRF helpers

```go
token, ok := authara.CSRFToken(r)
authara.AttachCSRF(req, token)
```

---

## Webhook handling

The SDK provides helpers for handling **Authara webhooks**.

Webhook verification requires the shared secret configured in Authara:

```env
AUTHARA_WEBHOOK_SECRET=your-shared-secret
```

This secret must match the webhook secret used by Authara when signing
outgoing webhook requests.

---

### Basic usage

If you want to load the secret from the environment:

```go
handler, err := authara.RequireWebhookHandlerFromEnv()
if err != nil {
	log.Fatal(err)
}

evt, err := handler.Handle(w, r)
if err != nil {
	return
}

log.Println("event:", evt.Type)
```

You can also construct the handler manually:

```go
handler := &authara.WebhookHandler{
	Secret: os.Getenv("AUTHARA_WEBHOOK_SECRET"),
}
```

---

### Typed decoding

```go
data, _ := authara.DecodeWebhookData[authara.UserCreatedData](evt)
```

---

### Supported event payloads

- `authara.UserCreatedData`
- `authara.UserUpdatedData`
- `authara.UserDeletedData`
- `authara.OrganizationData`
- `authara.OrganizationMembershipCreatedData`
- `authara.OrganizationMembershipData`
- `authara.OrganizationInvitationCreatedData`
- `authara.OrganizationInvitationAcceptedData`
- `authara.OrganizationInvitationRevokedData`

---

### Design notes

- Signature is always verified first
- Payload is explicit (raw JSON + decode)
- No retries or queues in SDK
- Webhook delivery behavior is owned by Authara, not the SDK

---

## License

MIT
