package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// The collector's name as its spec declares it, its artifact paths in the
// pack, and the schema ID of the normalized artifact. The paths are the ones
// componentsdk.ArtifactPath gives. They are constants, since epack sdk map
// finds the code behind an artifact only from a constant path.
const (
	collectorName  = "google-workspace"
	detailedPath   = "artifacts/google-workspace.details.json"
	idpPosturePath = "artifacts/google-workspace.idp-posture.json"
	idpSchema      = "evidencepack/idp-posture@v1"
)

// missing says why a value was left out: the error that stopped its read, or,
// when err is nil, a code the collector chose, such as a feature the edition
// lacks.
type missing struct {
	err    error
	code   componentsdk.Code
	detail string
}

func failed(err error) *missing { return &missing{err: err} }

func unlicensed(detail string) *missing {
	return &missing{code: componentsdk.CodeNotLicensed, detail: detail}
}

// gapLog records each value the collector leaves out in the run's recorder.
type gapLog struct {
	rec *componentsdk.Recorder
}

func newGapLog(rec *componentsdk.Recorder) *gapLog {
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &gapLog{rec: rec}
}

// leaveOut records the detailed artifact's values at pointers as left out for
// why. A nil why records nothing, so callers can pass a read's outcome as it
// is.
func (l *gapLog) leaveOut(why *missing, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.record(detailed(pointer), why, 0)
	}
}

// partial records rollups over items of which unmeasured could not be read.
func (l *gapLog) partial(unmeasured int, why *missing, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.record(detailed(pointer), why, unmeasured)
	}
}

// leaveOutAs records the detailed artifact's values at pointers as left out
// for the reason its value at from was, such as a count that needs a value
// that could not be read.
func (l *gapLog) leaveOutAs(from string, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.rec.Mirror(detailed(from), detailed(pointer))
	}
}

// mirror records, at a normalized value derived from detailed ones, the gap
// of the first source that has one.
func (l *gapLog) mirror(toPointer string, fromPointers ...string) {
	l.rec.Helper()
	to := componentsdk.Location{Path: idpPosturePath, Pointer: toPointer}
	for _, from := range fromPointers {
		l.rec.Mirror(detailed(from), to)
	}
}

func (l *gapLog) record(at componentsdk.Location, why *missing, unmeasured int) {
	l.rec.Helper()
	switch {
	case why == nil:
	case why.err == nil:
		l.rec.NotCollectedCode(at, why.code, why.detail)
	case unmeasured > 0:
		l.rec.Partial(at, unmeasured, why.err, deniedPermission(why.err)...)
	default:
		l.rec.NotCollected(at, why.err, deniedPermission(why.err)...)
	}
}

// deniedPermission names the permission to grant on a gap whose read Google
// refused for lack of it. That is a call's OAuth scope or IAM permission, or
// the scope a surface's token needs when the delegation grant lacks it. The
// Google API clients build their errors from the response themselves, so the
// gap cannot read the permission from the call.
func deniedPermission(err error) []componentsdk.AdviceOption {
	var denied interface{ DeniedPermission() string }
	if !errors.As(err, &denied) || denied.DeniedPermission() == "" {
		return nil
	}
	return []componentsdk.AdviceOption{componentsdk.MissingPermission(denied.DeniedPermission())}
}

func detailed(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: detailedPath, Pointer: pointer}
}

func itemPointer(array string, index int, field string) string {
	return fmt.Sprintf("%s/%d/%s", array, index, field)
}
