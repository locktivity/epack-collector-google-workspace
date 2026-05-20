package collector

import (
	"errors"
	"testing"

	"google.golang.org/api/googleapi"
)

func TestIsScopeDenied(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "domain-wide-delegation token mint failure",
			err:  errors.New(`oauth2: cannot fetch token: 401 Unauthorized\nResponse: {"error":"unauthorized_client"}`),
			want: true,
		},
		{
			name: "403 with scope-insufficient reason",
			err:  &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}}},
			want: true,
		},
		{
			name: "403 role-insufficient is not scope-denied",
			err:  &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "INSUFFICIENT_PERMISSIONS"}}},
			want: false,
		},
		{
			name: "404 not licensed is not scope-denied",
			err:  &googleapi.Error{Code: 404},
			want: false,
		},
		{
			name: "unrelated error",
			err:  errors.New("connection reset"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isScopeDenied(tt.err); got != tt.want {
				t.Fatalf("isScopeDenied(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsAPINotEnabled(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "403 accessNotConfigured / SERVICE_DISABLED",
			err:  &googleapi.Error{Code: 403, Message: "Google Vault API has not been used in project 1 SERVICE_DISABLED", Errors: []googleapi.ErrorItem{{Reason: "accessNotConfigured"}}},
			want: true,
		},
		{
			name: "403 scope-insufficient is not api-disabled",
			err:  &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}}},
			want: false,
		},
		{
			name: "unrelated",
			err:  errors.New("connection reset"),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAPINotEnabled(tt.err); got != tt.want {
				t.Fatalf("isAPINotEnabled(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
