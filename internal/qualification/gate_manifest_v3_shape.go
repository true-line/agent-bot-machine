package qualification

import (
	"encoding/json"
	"strings"
)

const maxGateSegmentsV3 = 32

type gateObjectRefV3 struct {
	Role      string `json:"role"`
	URI       string `json:"uri"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Issuer    string `json:"issuer"`
}

type gateSegmentV3 struct {
	Sequence           int             `json:"sequence"`
	SegmentID          string          `json:"segment_id"`
	Purpose            string          `json:"purpose"`
	ReportAnchor       bool            `json:"report_anchor"`
	SegmentManifest    gateObjectRefV3 `json:"segment_manifest"`
	SegmentAttestation gateObjectRefV3 `json:"segment_attestation"`
}

type gateAttemptV3 struct {
	Sequence      int             `json:"sequence"`
	AttemptID     string          `json:"attempt_id"`
	Purpose       string          `json:"purpose"`
	Refusal       gateObjectRefV3 `json:"refusal"`
	TerminalState gateObjectRefV3 `json:"terminal_state"`
}

type gateManifestV3 struct {
	SchemaVersion                   int             `json:"schema_version"`
	Kind                            string          `json:"kind"`
	Gate                            string          `json:"gate"`
	Profile                         string          `json:"profile"`
	HostID                          string          `json:"host_id"`
	CohortID                        string          `json:"cohort_id"`
	SuiteRevision                   string          `json:"suite_revision"`
	OwnerPlanSHA256                 string          `json:"owner_plan_sha256"`
	PrimaryMeasurementBindingSHA256 string          `json:"primary_measurement_binding_sha256"`
	PrimarySegmentID                string          `json:"primary_segment_id"`
	SharedHostObservation           gateObjectRefV3 `json:"shared_host_observation"`
	Segments                        []gateSegmentV3 `json:"segments"`
	Attempts                        []gateAttemptV3 `json:"attempts"`
}

func exactGateFieldsV3(raw []byte, names ...string) bool {
	fields, err := strictObject(raw, maxGateManifestBytesV3)
	return err == nil && hasFields(fields, names...)
}

func parseGateObjectRefV3(raw []byte) (gateObjectRefV3, error) {
	var ref gateObjectRefV3
	if !exactGateFieldsV3(raw, "role", "uri", "sha256", "size_bytes", "issuer") ||
		json.Unmarshal(raw, &ref) != nil || !reportID.MatchString(ref.Role) ||
		!reportID.MatchString(ref.Issuer) || ref.SizeBytes < 0 || ref.SizeBytes > maxGateBlobBytesV3 ||
		!strings.HasPrefix(ref.URI, gateObjectPrefixV3+"blob/") {
		return gateObjectRefV3{}, ErrUnqualified
	}
	if _, err := gateObjectNameV3(ref.URI, ref.SHA256); err != nil {
		return gateObjectRefV3{}, ErrUnqualified
	}
	return ref, nil
}

func gatePurposeV3(purpose string) bool {
	switch purpose {
	case "initial", "restart", "outage", "recovery", "negative", "cleanup":
		return true
	default:
		return false
	}
}

// parseGateManifestV3 validates only the fixed envelope shape and local
// reference grammar. It does not resolve segment objects or authenticate any
// claimed issuer or physical observation.
func parseGateManifestV3(raw []byte) (gateManifestV3, error) {
	var manifest gateManifestV3
	fields, err := canonicalBytes(raw, maxGateManifestBytesV3)
	if err != nil || !hasFields(fields, "schema_version", "kind", "gate", "profile", "host_id", "cohort_id",
		"suite_revision", "owner_plan_sha256", "primary_measurement_binding_sha256", "primary_segment_id",
		"shared_host_observation", "segments", "attempts") || json.Unmarshal(raw, &manifest) != nil ||
		manifest.SchemaVersion != 1 || manifest.Kind != "stage2a-physical-gate-manifest" ||
		!reportID.MatchString(manifest.HostID) || !reportID.MatchString(manifest.CohortID) ||
		!reportID.MatchString(manifest.PrimarySegmentID) || !validHex(manifest.SuiteRevision, 40) ||
		!validSHA(manifest.OwnerPlanSHA256) || !validSHA(manifest.PrimaryMeasurementBindingSHA256) ||
		len(manifest.Segments) == 0 || len(manifest.Segments) > maxGateSegmentsV3 ||
		len(manifest.Attempts) > maxGateSegmentsV3 {
		return gateManifestV3{}, ErrUnqualified
	}
	if (manifest.Profile == "managed-protected" &&
		manifest.Gate != "T01" && manifest.Gate != "T02" && manifest.Gate != "T03") ||
		(manifest.Profile == "managed-cooperative" && manifest.Gate != "T21") ||
		(manifest.Profile != "managed-protected" && manifest.Profile != "managed-cooperative") {
		return gateManifestV3{}, ErrUnqualified
	}
	if _, err := parseGateObjectRefV3(fields["shared_host_observation"]); err != nil {
		return gateManifestV3{}, ErrUnqualified
	}
	var segmentsRaw, attemptsRaw []json.RawMessage
	if json.Unmarshal(fields["segments"], &segmentsRaw) != nil || len(segmentsRaw) != len(manifest.Segments) ||
		json.Unmarshal(fields["attempts"], &attemptsRaw) != nil || len(attemptsRaw) != len(manifest.Attempts) {
		return gateManifestV3{}, ErrUnqualified
	}
	seenIDs := make(map[string]bool, len(manifest.Segments)+len(manifest.Attempts))
	seenRefs := map[string]bool{manifest.SharedHostObservation.SHA256: true}
	primaryCount := 0
	for i, rawSegment := range segmentsRaw {
		segment := manifest.Segments[i]
		if !exactGateFieldsV3(rawSegment, "sequence", "segment_id", "purpose", "report_anchor", "segment_manifest", "segment_attestation") ||
			segment.Sequence != i || !reportID.MatchString(segment.SegmentID) || seenIDs[segment.SegmentID] ||
			!gatePurposeV3(segment.Purpose) {
			return gateManifestV3{}, ErrUnqualified
		}
		seenIDs[segment.SegmentID] = true
		if segment.SegmentID == manifest.PrimarySegmentID {
			primaryCount++
		}
		part, _ := strictObject(rawSegment, maxGateManifestBytesV3)
		for _, name := range []string{"segment_manifest", "segment_attestation"} {
			ref, err := parseGateObjectRefV3(part[name])
			if err != nil || seenRefs[ref.SHA256] {
				return gateManifestV3{}, ErrUnqualified
			}
			seenRefs[ref.SHA256] = true
		}
	}
	if primaryCount != 1 {
		return gateManifestV3{}, ErrUnqualified
	}
	for i, rawAttempt := range attemptsRaw {
		attempt := manifest.Attempts[i]
		if !exactGateFieldsV3(rawAttempt, "sequence", "attempt_id", "purpose", "refusal", "terminal_state") ||
			attempt.Sequence != i || !reportID.MatchString(attempt.AttemptID) || seenIDs[attempt.AttemptID] ||
			!gatePurposeV3(attempt.Purpose) {
			return gateManifestV3{}, ErrUnqualified
		}
		seenIDs[attempt.AttemptID] = true
		part, _ := strictObject(rawAttempt, maxGateManifestBytesV3)
		for _, name := range []string{"refusal", "terminal_state"} {
			ref, err := parseGateObjectRefV3(part[name])
			if err != nil || seenRefs[ref.SHA256] {
				return gateManifestV3{}, ErrUnqualified
			}
			seenRefs[ref.SHA256] = true
		}
	}
	return manifest, nil
}
