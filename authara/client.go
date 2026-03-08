package authara

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ClientOption configures a Client.
//
// Client options are applied at construction time via NewClient and allow
// callers to customize transport-level behavior (e.g. HTTP client, timeouts)
// without changing Client semantics.
type ClientOption func(*Client)

// WithHTTPClient configures the Client to use a custom http.Client.
//
// This is useful for setting timeouts, proxies, tracing, or test transports.
// The provided client is used for all outbound requests to Authara.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// Client is a backend-facing Authara HTTP client.
//
// It is intended for server-side and SSR use cases and provides strict,
// side-effect-free helpers for calling Authara endpoints.
//
// The Client:
//   - never refreshes tokens
//   - never mutates authentication state
//   - forwards existing authentication context only
//   - treats "not authenticated" as a valid state
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Authara backend client.
//
// baseURL must point to the Authara HTTP endpoint (e.g. "https://auth.example.com").
// The base URL is normalized by trimming any trailing slash.
//
// Optional ClientOptions may be provided to customize transport behavior.
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// doJSON performs an HTTP request and decodes a JSON response.
//
// If out is non-nil, the response body is decoded into it.
// The response is always returned so callers can inspect status codes.
//
// This helper does not apply any Authara-specific semantics and does not
// perform retries, refreshes, or error classification.
func (c *Client) doJSON(req *http.Request, out any) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, err
		}
	}

	return resp, nil
}

// forwardAccessAuth forwards the Authara access cookie from an incoming request.
//
// This preserves the caller's authentication context without inspecting,
// validating, or modifying the token.
//
// If the incoming request is nil or does not contain the access cookie,
// no authentication information is forwarded.
func forwardAccessAuth(req *http.Request, incoming *http.Request) {
	if incoming == nil {
		return
	}

	if c, err := incoming.Cookie(AccessCookieName); err == nil {
		req.AddCookie(c)
	}
}

// DoJSONRequest performs a raw HTTP request against the Authara API and
// optionally decodes a successful JSON response into out.
//
// This function is a low-level transport helper intended as an escape hatch
// for calling Authara endpoints that do not yet have first-class helpers.
//
// Behavior and guarantees:
//   - Forwards the Authara access cookie from the incoming request, if present
//   - Does NOT refresh tokens
//   - Does NOT retry requests
//   - Does NOT interpret HTTP status codes
//   - Decodes JSON only for successful (2xx) responses
//
// Callers are responsible for inspecting the returned HTTP status code and
// deciding how to handle non-2xx responses.
//
// This helper intentionally provides no Authara-specific semantics.
func DoJSONRequest[T any](
	ctx context.Context,
	client *Client,
	method string,
	path string,
	incoming *http.Request,
	out *T,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		method,
		client.baseURL+path,
		nil,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	forwardAccessAuth(req, incoming)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, err
		}
	}

	return resp, nil
}

// CurrentUser represents the authenticated user's identity attributes.
//
// This struct mirrors the response of the Authara `/auth/user` endpoint and
// intentionally contains only identity data, not authorization facts.
type CurrentUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

type ErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// GetCurrentUser retrieves the identity of the currently authenticated user.
//
// The authentication context is forwarded from the incoming request using the
// Authara access cookie. This method does not refresh tokens or retry requests.
//
// Return values:
//   - (*CurrentUser, nil): the request is authenticated and the user exists
//   - (nil, nil): the request is not authenticated (401 Unauthorized)
//   - (nil, error): an unexpected failure occurred
func (c *Client) GetCurrentUser(ctx context.Context, incoming *http.Request) (*CurrentUser, error) {
	var user CurrentUser
	var errResp ErrorResponse

	resp, err := DoJSONRequest(
		ctx,
		c,
		http.MethodGet,
		"/auth/api/v1/user",
		incoming,
		&user,
	)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return &user, nil
	case http.StatusUnauthorized:
		return nil, nil
	default:
		_ = json.NewDecoder(resp.Body).Decode(&errResp)

		if errResp.Error.Code != "" {
			return nil, fmt.Errorf(
				"authara: %s (%s)",
				errResp.Error.Code,
				errResp.Error.Message,
			)
		}

		return nil, fmt.Errorf("authara: unexpected status %d", resp.StatusCode)
	}
}
