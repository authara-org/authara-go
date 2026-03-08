package authara

import (
	"net/http"
	"net/url"
)

// LogoutFormData describes the data required to render a CSRF-protected
// logout form in a server-rendered (SSR) application.
//
// The SDK does not generate HTML. Applications are expected to use this
// data to render their own form markup.
type LogoutFormData struct {
	// Action is the form action URL (e.g. "/auth/logout?return_to=/").
	Action string

	// Method is the HTTP method to use when submitting the form.
	Method string

	// CSRFName is the name of the CSRF form field.
	CSRFName string

	// CSRFValue is the CSRF token value to embed in the form.
	CSRFValue string
}

// LogoutFormDataFromRequest extracts the CSRF token from the request and
// returns the data required to render a logout form.
//
// The returnTo parameter specifies where Authara should redirect the user
// after a successful logout. If empty, no return_to parameter is added.
//
// The boolean return value is false if no CSRF token is present on the request.
func LogoutFormDataFromRequest(
	r *http.Request,
	redirect string,
) (LogoutFormData, bool) {

	token, ok := CSRFToken(r)
	if !ok {
		return LogoutFormData{}, false
	}

	action := "/auth/sessions/logout"
	if redirect != "" {
		action += "?return_to=" + url.QueryEscape(redirect)
	}

	return LogoutFormData{
		Action:    action,
		Method:    http.MethodPost,
		CSRFName:  CSRFFormField,
		CSRFValue: token,
	}, true
}

// CSRFToken returns the CSRF token stored in the Authara CSRF cookie.
//
// The boolean return value is false if the cookie is missing or empty.
func CSRFToken(req *http.Request) (string, bool) {
	c, err := req.Cookie(CSRFCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// AttachCSRF attaches the given CSRF token to an outgoing HTTP request
// using the Authara CSRF header.
//
// If the token is empty, the function does nothing.
func AttachCSRF(req *http.Request, token string) {
	if token == "" {
		return
	}
	req.Header.Set(CSRFHeaderName, token)
}

// CSRFTokenOrPanic returns the CSRF token from the request or panics if
// the token is missing.
//
// This function is intended for internal or trusted code paths where
// the absence of a CSRF token indicates a programmer error.
func CSRFTokenOrPanic(req *http.Request) string {
	token, ok := CSRFToken(req)
	if !ok {
		panic("authara: CSRF token missing from request")
	}
	return token
}
