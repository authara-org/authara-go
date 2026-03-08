package authara

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// RequireAuthWithRefresh returns middleware that enforces authentication and
// performs a single best-effort refresh via Authara when needed.
//
// This middleware behaves like RequireAuth, with one additional step:
//
//   - If the access cookie is missing or invalid, the middleware attempts to
//     refresh the session by calling Authara's refresh endpoint.
//   - If refresh succeeds, Authara responds with Set-Cookie headers for the
//     rotated refresh token and a new access token.
//   - The middleware forwards those Set-Cookie headers to the client response,
//     verifies the newly issued access token, and then proceeds with the CURRENT
//     request authenticated.
//
// If refresh is disabled (SDK not configured with AutharaBaseURL) or refresh
// fails, the middleware falls back to the same unauthenticated behavior as
// RequireAuth:
//
//   - Browser navigations (Accept: text/html): 302 redirect to login
//   - HTMX requests (HX-Request: true): 200 with HX-Redirect header
//   - API / SPA requests: 401 Unauthorized
//
// CSRF:
//
// If Authara enforces CSRF on refresh, the CSRF token must be available on the
// incoming request so the middleware can forward it.
func (s *SDK) RequireAuthWithRefresh(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fast path: access cookie present & valid
		if c, err := r.Cookie(AccessCookieName); err == nil && c.Value != "" {
			if userID, roles, err := s.verifier.verify(c.Value); err == nil {
				ctx := withUserID(r.Context(), userID)
				ctx = withRoles(ctx, roles)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Try refresh once (if enabled)
		if userID, roles, newCookies, ok := s.tryRefreshAndVerify(w, r); ok {
			ctx := withUserID(r.Context(), userID)
			ctx = withRoles(ctx, roles)

			// Clone the request and update its Cookie header so any downstream
			// Authara client calls during THIS request see the refreshed cookies.
			r2 := r.Clone(ctx)
			applyCookiesToRequest(r2, newCookies)

			next.ServeHTTP(w, r2)
			return
		}

		// Refresh failed or disabled
		loginURL := LoginPath + "?return_to=" + url.QueryEscape(buildReturnTo(r))
		unauthenticatedResponse(w, r, loginURL)
	})
}

// applyCookiesToRequest overwrites/sets cookies in r based on the cookies returned
// by Authara. It updates the Cookie header so r.Cookie(...) and r.Header.Get("Cookie")
// reflect the new values.
//
// This is used to make refreshed cookies immediately visible to downstream code
// within the same request lifecycle.
func applyCookiesToRequest(r *http.Request, newCookies []*http.Cookie) {
	// Start with existing cookies from the request.
	jar := map[string]string{}
	for _, c := range r.Cookies() {
		jar[c.Name] = c.Value
	}

	// Overwrite/add cookies from refresh response.
	for _, c := range newCookies {
		jar[c.Name] = c.Value
	}

	// Rebuild Cookie header.
	var b strings.Builder
	first := true
	for name, val := range jar {
		if !first {
			b.WriteString("; ")
		}
		first = false
		b.WriteString(name)
		b.WriteString("=")
		b.WriteString(val)
	}

	if b.Len() == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", b.String())
}

// tryRefreshAndVerify attempts to refresh the session via Authara using the
// incoming request cookies.
//
// On success it:
//
//   - forwards Authara's Set-Cookie headers to the client response (to persist
//     rotated refresh/access cookies), and
//   - extracts and verifies the new access token cookie value so the CURRENT
//     request can proceed authenticated.
//
// It returns ok=false if refresh is disabled, the Authara call fails, the
// response does not contain a usable access cookie, or access verification fails.
func (s *SDK) tryRefreshAndVerify(w http.ResponseWriter, r *http.Request) (uuid.UUID, []string, []*http.Cookie, bool) {
	// Refresh disabled unless configured explicitly.
	if s.autharaBaseURL == "" {
		return uuid.Nil, nil, nil, false
	}

	reqURL := s.autharaBaseURL + RefreshPath + "?audience=" + s.verifier.audience
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, reqURL, nil)
	if err != nil {
		return uuid.Nil, nil, nil, false
	}

	// Forward cookies from the incoming request to Authara.
	// This is required for cookie-based refresh.
	if cookieHeader := r.Header.Get("Cookie"); cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}

	// If CSRF cookie is present on the incoming request, attach it as header.
	if token, ok := CSRFToken(r); ok {
		AttachCSRF(req, token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return uuid.Nil, nil, nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return uuid.Nil, nil, nil, false
	}

	// Forward raw Set-Cookie headers exactly as Authara sent them.
	// Note: multiple Set-Cookie headers are expected (access + refresh, etc.).
	rawSetCookies := resp.Header.Values("Set-Cookie")
	if len(rawSetCookies) == 0 {
		return uuid.Nil, nil, nil, false
	}
	for _, sc := range rawSetCookies {
		w.Header().Add("Set-Cookie", sc)
	}

	// Extract the new access token cookie value from the refresh response.
	// We need it to authenticate THIS request (the browser will only send the new
	// cookie on the next request).
	var accessToken string
	for _, c := range resp.Cookies() {
		if c.Name == AccessCookieName {
			accessToken = c.Value
			break
		}
	}
	if accessToken == "" {
		return uuid.Nil, nil, nil, false
	}

	uid, rs, err := s.verifier.verify(accessToken)
	if err != nil {
		return uuid.Nil, nil, nil, false
	}

	// Return all cookies set by Authara so the middleware can apply them to the
	// cloned request (same-request correctness for downstream Authara calls).
	return uid, rs, resp.Cookies(), true
}

// RequireAuth returns middleware that enforces authentication.
//
// Behavior on unauthenticated requests depends on the request type:
//
//   - Browser navigations (Accept: text/html):
//     Responds with an HTTP redirect (302) to the Authara login page,
//     including a return_to parameter pointing to the original request URL.
//
//   - HTMX requests (HX-Request: true):
//     Responds with status 200 and sets the HX-Redirect header, causing
//     a full client-side navigation to the login page.
//
//   - API / SPA requests:
//     Responds with 401 Unauthorized and does not perform a redirect.
//
// On successful authentication, the user's ID and roles are injected
// into the request context before calling the next handler.
func (s *SDK) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(AccessCookieName)
		if err != nil {
			loginURL := LoginPath + "?return_to=" + url.QueryEscape(buildReturnTo(r))
			unauthenticatedResponse(w, r, loginURL)
			return
		}

		userID, roles, err := s.verifier.verify(cookie.Value)
		if err != nil {
			loginURL := LoginPath + "?return_to=" + url.QueryEscape(buildReturnTo(r))
			unauthenticatedResponse(w, r, loginURL)
			return
		}

		ctx := withUserID(r.Context(), userID)
		ctx = withRoles(ctx, roles)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// buildReturnTo constructs the return_to value for redirects by
// preserving the request path and query string.
//
// This ensures users are redirected back to the exact URL they originally
// requested after authentication.
func buildReturnTo(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}

func unauthenticatedResponse(w http.ResponseWriter, r *http.Request, redirectUrl string) {
	w.Header().Add("Vary", "Accept")

	switch {
	case r.Header.Get("HX-Request") == "true":
		w.Header().Set("HX-Redirect", redirectUrl)
		w.WriteHeader(http.StatusOK)
		return

	case isAPICall(r):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return

	default:
		http.Redirect(w, r, redirectUrl, http.StatusFound)
		return
	}
}

func isAPICall(r *http.Request) bool {
	accept := r.Header.Get("Accept")

	if accept == "" {
		return true
	}

	if strings.Contains(accept, "text/html") {
		return false
	}

	return true
}

// TryAuth returns middleware that attempts authentication if an access
// token is present, but does not enforce it.
//
// If a valid access token is found, the user's ID and roles are injected
// into the request context. If no token is present or verification fails,
// the request continues without authentication data.
//
// This middleware never redirects and is suitable for routes where
// authentication is optional.
func (s *SDK) TryAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(AccessCookieName)
		if err == nil {
			userID, roles, err := s.verifier.verify(cookie.Value)
			if err == nil {
				ctx := withUserID(r.Context(), userID)
				ctx = withRoles(ctx, roles)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}
