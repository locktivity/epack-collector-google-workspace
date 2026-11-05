// epack-collector-google-workspace collects Google Workspace identity posture.
package main

import (
	"github.com/locktivity/epack-collector-google-workspace/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(collector.Spec(Version, Commit), collector.Run)
}
