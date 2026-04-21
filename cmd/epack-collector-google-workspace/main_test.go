package main

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack/componentsdk"
)

func TestClassifyError_401_IsAuthError(t *testing.T) {
	err := classifyError(&googleapi.Error{Code: 401})

	var authErr componentsdk.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("401 should produce AuthError, got %T", err)
	}
}

func TestClassifyError_403_Permission_IsAuthError(t *testing.T) {
	err := classifyError(&googleapi.Error{
		Code: 403,
		Errors: []googleapi.ErrorItem{
			{Reason: "forbidden"},
		},
	})

	var authErr componentsdk.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("403 forbidden should produce AuthError, got %T", err)
	}
}

func TestClassifyError_403_RateLimit_IsNetworkError(t *testing.T) {
	for _, reason := range []string{"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"} {
		t.Run(reason, func(t *testing.T) {
			err := classifyError(&googleapi.Error{
				Code: 403,
				Errors: []googleapi.ErrorItem{
					{Reason: reason},
				},
			})

			var netErr componentsdk.NetworkError
			if !errors.As(err, &netErr) {
				t.Fatalf("403 %s should produce NetworkError, got %T", reason, err)
			}
		})
	}
}

func TestClassifyError_429_IsNetworkError(t *testing.T) {
	err := classifyError(&googleapi.Error{Code: 429})

	var netErr componentsdk.NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("429 should produce NetworkError, got %T", err)
	}
}

func TestClassifyError_400_IsConfigError(t *testing.T) {
	err := classifyError(&googleapi.Error{Code: 400})

	var cfgErr componentsdk.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("400 should produce ConfigError, got %T", err)
	}
}

func TestClassifyError_404_IsConfigError(t *testing.T) {
	err := classifyError(&googleapi.Error{Code: 404})

	var cfgErr componentsdk.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("404 should produce ConfigError, got %T", err)
	}
}

func TestClassifyError_NonGoogleError_IsNetworkError(t *testing.T) {
	err := classifyError(errors.New("connection refused"))

	var netErr componentsdk.NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("non-Google error should produce NetworkError, got %T", err)
	}
}

func TestClassifyError_ServerErrors_AreNetworkErrors(t *testing.T) {
	for _, code := range []int{500, 502, 503} {
		t.Run(fmt.Sprintf("%d", code), func(t *testing.T) {
			err := classifyError(&googleapi.Error{Code: code})

			var netErr componentsdk.NetworkError
			if !errors.As(err, &netErr) {
				t.Fatalf("%d should produce NetworkError, got %T", code, err)
			}
		})
	}
}
