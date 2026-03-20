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
- require explicit configuration for any network behavior

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

### Backend client helpers (optional)

- Provides **explicit, side-effect-free HTTP helpers** for calling Authara
  endpoints from backend or SSR applications
- Forwards existing authentication context (access cookie) only
- Exposes identity data via dedicated helpers (e.g. `GetCurrentUser`)
- Offers a generic escape-hatch helper for user-defined Authara endpoints

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
- Does **not** perform background or implicit network calls

> Exception: `RequireAuthWithRefresh` can perform a best-effort refresh call,
> but only if explicitly enabled via configuration.

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
	Issuer:   "https://example.com/auth",
	Audience: "app",
	Keys: map[string][]byte{
		"key-id": []byte("secret"),
	},
})
if err != nil {
	// handle configuration error
}
```

All fields are required:

- `Issuer` must exactly match the issuer configured in Authara
- `Audience` must match the intended token audience
- `Keys` maps JWT `kid` values to their signing secrets

Multiple keys may be provided to support key rotation.

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
- `AUTHARA_JWT_KEYS` (required)
- `AUTHARA_BASE_URL` (optional, enables refresh)

This helper is intentionally minimal and does not introduce implicit behavior.

---

## Optional configuration (refresh support)

The SDK can optionally perform a single best-effort refresh when an access token
is missing or invalid.

To enable refresh, configure the Authara base URL:

```go
sdk, err := authara.New(authara.Config{
	Issuer:   "https://example.com/auth",
	Audience: "app",
	Keys: map[string][]byte{
		"key-id": []byte("secret"),
	},

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

## HTTP middleware

### Require authentication

```go
r.Use(sdk.RequireAuth)
```

- Browser → redirect
- HTMX → `HX-Redirect`
- API → `401`

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
user, err := client.GetCurrentUser(ctx, r)
```

---

### Generic request helper

```go
resp, err := authara.DoJSONRequest(...)
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

---

### Basic usage

```go
handler := authara.WebhookHandlerFromEnv()

evt, err := handler.Handle(w, r)
if err != nil {
	return
}

log.Println("event:", evt.Type)
```

---

### Typed decoding

```go
data, _ := authara.DecodeWebhookData[authara.UserCreatedData](evt)
```

---

### Design notes

- Signature is always verified first
- Payload is explicit (raw JSON + decode)
- No retries or queues in SDK

---

## License

MIT
