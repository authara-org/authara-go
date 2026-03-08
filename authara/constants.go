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
)
