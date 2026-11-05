// Package schema embeds the JSON Schema of the collector's detailed artifact,
// the methods for its normalized artifact, and its trace map.
package schema

import (
	_ "embed"
	"encoding/json"
)

// V1 is the schema in v1.0.0.json, which the collector checks its detailed
// artifact against when it emits.
//
//go:embed v1.0.0.json
var V1 []byte

// methods is methods.json: for each field of the evidencepack/idp-posture@v1
// artifact that the collector measures, one plain sentence on how it
// measures it.
//
//go:embed methods.json
var methods []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Methods returns the sentences in methods.json for
// componentsdk.CollectorSpec.Methods. The SDK writes each one as the
// x-epack-method of its field in the SDK's own evidencepack/idp-posture@v1
// schema.
func Methods() map[string]map[string]string {
	var byField map[string]string
	if err := json.Unmarshal(methods, &byField); err != nil {
		panic("docs/schema/methods.json: " + err.Error())
	}
	return map[string]map[string]string{"evidencepack/idp-posture@v1": byField}
}
