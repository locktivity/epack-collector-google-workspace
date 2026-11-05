package googleworkspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack/componentsdk"
)

// APIError is a failed Google API call. It unwraps to the googleapi error, so
// callers can still read Google's reasons, and gives componentsdk.Classify the
// status, the headers, and the first reason. op names the call.
type APIError struct {
	Err *googleapi.Error
	err error
	op  string
}

func (e *APIError) Error() string           { return e.err.Error() }
func (e *APIError) Unwrap() error           { return e.err }
func (e *APIError) HTTPStatus() int         { return e.Err.Code }
func (e *APIError) HTTPHeader() http.Header { return e.Err.Header }
func (e *APIError) VendorCode() string      { return apiReason(e.Err) }

// CollectionCode reads a throttle Google answers with 403 instead of 429.
func (e *APIError) CollectionCode() componentsdk.Code {
	if e.Err.Code == http.StatusForbidden && rateLimitReason(apiReason(e.Err)) {
		return componentsdk.CodeRateLimited
	}
	return ""
}

// DeniedPermission returns the permission the call named op needs when
// Google's refusal shows the credential lacks it, or "". The googleapi error
// does not carry the call the SDK's transport recorded, so a gap cannot read
// the permission from the call. See NamesPermission for the reasons read.
func (e *APIError) DeniedPermission() string {
	if e.Err.Code != http.StatusForbidden || !permissionReason(apiReasons(e.Err)) {
		return ""
	}
	return Permission(e.op)
}

// apiError gives a googleapi error from the call named op the accessors
// componentsdk.Classify reads. Other errors, such as a failed token request
// or a body that is not JSON, already carry their code.
func apiError(op string, err error) error {
	var gerr *googleapi.Error
	if err == nil || !errors.As(err, &gerr) {
		return err
	}
	return &APIError{Err: gerr, err: err, op: op}
}

// listError wraps an error from a paged list call named op. An error the
// caller's callback returned passes through, so the caller can still match
// it.
func listError(op, what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", what, apiError(op, err))
}

// apiReasons lists the reasons in a googleapi error's errors and details.
func apiReasons(gerr *googleapi.Error) []string {
	var reasons []string
	for _, item := range gerr.Errors {
		reasons = append(reasons, item.Reason)
	}
	for _, detail := range gerr.Details {
		if m, ok := detail.(map[string]any); ok {
			if reason, ok := m["reason"].(string); ok {
				reasons = append(reasons, reason)
			}
		}
	}
	return reasons
}

func apiReason(gerr *googleapi.Error) string {
	for _, item := range gerr.Errors {
		if item.Reason != "" {
			return item.Reason
		}
	}
	for _, detail := range gerr.Details {
		if m, ok := detail.(map[string]any); ok {
			if reason, ok := m["reason"].(string); ok && reason != "" {
				return reason
			}
		}
	}
	return ""
}

func rateLimitReason(reason string) bool {
	switch reason {
	case "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded":
		return true
	}
	return false
}

// ClassifyResponse reads Google's throttle sent as 403, so the SDK retries it
// as it does a 429. It is componentsdk.HTTPOptions.ClassifyResponse.
func ClassifyResponse(resp *http.Response, body []byte) (componentsdk.Code, bool) {
	if resp.StatusCode != http.StatusForbidden {
		return "", false
	}
	var reply struct {
		Error struct {
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &reply) != nil {
		return "", false
	}
	for _, item := range reply.Error.Errors {
		if rateLimitReason(item.Reason) {
			return componentsdk.CodeRateLimited, true
		}
	}
	return "", false
}

func invalidResponse(format string, args ...any) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf(format, args...))
}

// TokenError is an error answer from a token endpoint: Google's OAuth
// endpoint, its Security Token Service, the IAM credentials endpoint, or the
// runner's identity endpoint.
type TokenError struct {
	Host        string
	Status      int
	Header      http.Header
	OAuthCode   string
	Description string

	// rejects400 marks Google's OAuth endpoint and its Security Token
	// Service, which answer a credential they reject with 400.
	rejects400 bool
	// code is the response's code from the SDK transport, which reads a
	// throttle sent as 403.
	code componentsdk.Code
}

func newTokenError(resp *http.Response, body []byte, rejects400 bool) *TokenError {
	e := &TokenError{Status: resp.StatusCode, Header: resp.Header, rejects400: rejects400, code: componentsdk.ClassifyResponse(resp)}
	if resp.Request != nil && resp.Request.URL != nil {
		e.Host = strings.ToLower(resp.Request.URL.Hostname())
	}
	var oauth struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &oauth) == nil {
		e.OAuthCode, e.Description = oauth.Error, oauth.ErrorDescription
	}
	return e
}

// Error names the endpoint's own error code and description, never the
// request: token requests carry assertions and identity tokens.
func (e *TokenError) Error() string {
	msg := fmt.Sprintf("%s answered the token request with status %d", e.Host, e.Status)
	if e.OAuthCode != "" {
		msg += ": " + e.OAuthCode
		if e.Description != "" {
			msg += " (" + e.Description + ")"
		}
	}
	return msg
}

func (e *TokenError) HTTPStatus() int         { return e.Status }
func (e *TokenError) HTTPHeader() http.Header { return e.Header }
func (e *TokenError) VendorCode() string      { return e.OAuthCode }

// CollectionCode reads what Google's token endpoints mean. An OAuth error
// takes the code componentsdk.OAuthErrorCode gives it, except
// unauthorized_client, which Google sends for a delegation grant that lacks
// the client or a scope: the credential works, so it is permission_denied.
// Google's OAuth endpoint and its Security Token Service answer any other
// credential they reject with 400, and x/oauth2 drops the body of a failed
// Security Token Service exchange.
func (e *TokenError) CollectionCode() componentsdk.Code {
	if e.OAuthCode == "unauthorized_client" {
		return componentsdk.CodePermissionDenied
	}
	if code, ok := componentsdk.OAuthErrorCode(e.OAuthCode); ok {
		return code
	}
	if e.rejects400 && e.Status == http.StatusBadRequest {
		return componentsdk.CodeAuthFailed
	}
	return e.code
}

// causeError keeps a message that x/oauth2 or the collector wrote and the
// error that caused it, which carries the code.
type causeError struct {
	msg   string
	cause error
}

func (e *causeError) Error() string { return e.msg }
func (e *causeError) Unwrap() error { return e.cause }

// Timeout reports whether the cause timed out. An HTTP client wraps a failed
// token request in a url.Error, which asks only its own cause, this error,
// whether it timed out.
func (e *causeError) Timeout() bool {
	var t interface{ Timeout() bool }
	return errors.As(e.cause, &t) && t.Timeout()
}

// tokenFailure is a failure to get a surface's token. It keeps the cause's
// code, vendor code, and message, but not its googleapi errors: a failed
// signing call is not the surface's own API answering, such as with a 404
// that means a feature is not licensed. scopes are the scopes the token was
// for.
type tokenFailure struct {
	err    error
	scopes []string
}

func (e *tokenFailure) Error() string                     { return e.err.Error() }
func (e *tokenFailure) CollectionCode() componentsdk.Code { return componentsdk.Classify(e.err) }
func (e *tokenFailure) VendorCode() string                { return componentsdk.VendorCodeOf(e.err) }
func (e *tokenFailure) Is(target error) bool              { return errors.Is(e.err, target) }

// DeniedPermission returns the scope the delegation grant lacks, or "".
// Google's token endpoint answers unauthorized_client for a grant without a
// scope the token asks for. Each surface's token asks for one scope, so that
// scope is the one to grant.
func (e *tokenFailure) DeniedPermission() string {
	if len(e.scopes) != 1 || componentsdk.Classify(e.err) != componentsdk.CodePermissionDenied ||
		componentsdk.VendorCodeOf(e.err) != "unauthorized_client" {
		return ""
	}
	return e.scopes[0]
}

// wrapCause prefixes err's message and keeps err as the cause.
func wrapCause(err error, format string, args ...any) error {
	return &causeError{msg: fmt.Sprintf(format, args...) + ": " + err.Error(), cause: err}
}
