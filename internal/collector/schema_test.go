package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// TestArtifactMatchesCommittedSchema validates a fully populated artifact
// against docs/schema/v1.0.0.json.
//
// The schema sets "additionalProperties": false throughout, so a field added to
// a Go struct without a matching schema entry makes a conforming consumer
// reject the whole artifact. Without this test that failure only appears
// downstream, in someone else's pipeline.
//
// This walks the schema rather than pulling in a JSON Schema dependency: it
// checks the constraints the artifact contract actually relies on, which are
// undeclared keys, missing required keys, and enum membership.
func TestArtifactMatchesCommittedSchema(t *testing.T) {
	raw, err := os.ReadFile("../../docs/schema/v" + SchemaVersion + ".json")
	if err != nil {
		t.Fatalf("reading committed schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parsing committed schema: %v", err)
	}

	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	c := NewWithClient(Config{AdminEmail: "super@example.com", Now: func() time.Time { return now }}, fullyPopulatedClient(now))
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	encoded, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshalling posture: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("re-parsing posture: %v", err)
	}

	if posture.Passwords.Policy == nil {
		t.Fatal("Passwords.Policy = nil, want the fixture to exercise the password policy block")
	}

	checkAgainstSchema(t, "$", schema, decoded)
}

func checkAgainstSchema(t *testing.T, path string, node map[string]any, value any) {
	t.Helper()

	if enum, ok := node["enum"].([]any); ok {
		for _, allowed := range enum {
			if allowed == value {
				return
			}
		}
		t.Errorf("%s = %v, not one of the schema's allowed values %v", path, value, enum)
		return
	}

	switch node["type"] {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return
		}
		properties, _ := node["properties"].(map[string]any)

		if additional, present := node["additionalProperties"]; present && additional == false {
			for key := range object {
				if _, declared := properties[key]; !declared {
					t.Errorf("%s.%s is emitted but not declared in the schema; a conforming consumer would reject the artifact", path, key)
				}
			}
		}
		if required, ok := node["required"].([]any); ok {
			for _, key := range required {
				name, _ := key.(string)
				if _, present := object[name]; !present {
					t.Errorf("%s.%s is required by the schema but absent from the artifact", path, name)
				}
			}
		}
		for key, child := range properties {
			childNode, ok := child.(map[string]any)
			if !ok {
				continue
			}
			if childValue, present := object[key]; present {
				checkAgainstSchema(t, path+"."+key, childNode, childValue)
			}
		}

	case "array":
		items, ok := node["items"].(map[string]any)
		if !ok {
			return
		}
		elements, ok := value.([]any)
		if !ok {
			return
		}
		for i, element := range elements {
			checkAgainstSchema(t, fmt.Sprintf("%s[%d]", path, i), items, element)
		}
	}
}
