package collector

import "testing"

// An activity returned for eventName authorize can hold other token events,
// such as a revoke.
func TestScanOAuthTokensCountsOnlyAuthorizeEvents(t *testing.T) {
	const authorize = `{"name":"authorize","parameters":[{"name":"client_id","value":"111.apps"},{"name":"app_name","value":"Acme Notes"},{"name":"scope","multiValue":["https://www.googleapis.com/auth/userinfo.email"]}]}`
	const revoke = `{"name":"revoke","parameters":[{"name":"client_id","value":"222.apps"},{"name":"app_name","value":"Old App"},{"name":"scope","multiValue":["https://www.googleapis.com/auth/userinfo.email"]}]}`
	for _, events := range []string{authorize, authorize + "," + revoke} {
		tenant := cleanTenant()
		tenant.activities = map[string]map[string]string{"token": {
			"authorize": `{"kind":"admin#reports#activities","items":[{"actor":{"email":"alice@example.com"},"id":{"time":"2026-04-04T10:00:00.000Z","applicationName":"token"},"events":[` + events + `]}]}`,
		}}
		tok := runKitTenant(t, tenant).OAuthTokens
		if tok == nil {
			t.Fatal("the run left out oauth_tokens")
		}
		if tok.TokensIssued != 1 || tok.AppsWithNewTokens != 1 || len(tok.Tokens) != 1 || tok.Tokens[0].ClientID != "111.apps" {
			t.Errorf("events %s gave oauth tokens %+v, want one grant to 111.apps", events, tok)
		}
	}
}

func TestScopeSensitivity(t *testing.T) {
	tests := map[string]string{
		"https://www.googleapis.com/auth/userinfo.email": "low",
		"openid": "low",
		"email":  "low",
		"https://www.googleapis.com/auth/drive.readonly":           "medium",
		"https://www.googleapis.com/auth/spreadsheets.readonly":    "medium",
		"https://www.googleapis.com/auth/devstorage.read_only":     "medium",
		"https://www.googleapis.com/auth/cloud-platform.read-only": "medium",
		"https://www.googleapis.com/auth/fitness.activity.read":    "medium",
		"https://www.googleapis.com/auth/drive":                    "high",
		"https://mail.google.com/":                                 "high",
		"https://www.googleapis.com/auth/calendar":                 "high",
		// These can edit or delete data, so none is read-only.
		"https://www.googleapis.com/auth/spreadsheets":          "high",
		"https://www.googleapis.com/auth/presentations":         "high",
		"https://www.googleapis.com/auth/forms.body":            "high",
		"https://www.googleapis.com/auth/devstorage.read_write": "high",
		"https://www.googleapis.com/auth/contacts":              "high",
		"https://www.googleapis.com/auth/tasks":                 "high",
	}
	for scope, want := range tests {
		if got := scopeSensitivity([]string{scope}); got != want {
			t.Errorf("scopeSensitivity(%q) = %q, want %q", scope, got, want)
		}
	}
	if got := scopeSensitivity([]string{"openid", "https://www.googleapis.com/auth/drive.readonly"}); got != "medium" {
		t.Errorf("a grant of openid and drive.readonly is %q, want medium", got)
	}
}
