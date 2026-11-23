package qualification

import (
	"encoding/json"
	"time"
)

// ResolveSignedGateManifestsV3 authenticates a designated-host report and
// resolves its gate-manifest references to exact local bytes. It checks the
// fixed manifest shape, report selectors, distinct segments and one anchor.
// This is not physical gate verification: the caller must authenticate the
// archive root and validate segment signatures, issuers, raw observations and
// installed inputs before granting acceptance or launch.
func ResolveSignedGateManifestsV3(envelope []byte, policy VerifiedPolicy,
	root string, now time.Time) (map[string][]byte, error) {
	report, err := VerifyHostReportV3(envelope, policy, now)
	if err != nil {
		return nil, ErrUnqualified
	}
	return resolveSignedGateManifests(report, root)
}

// ResolveSignedGateManifestsV4 resolves the exact T01-T03 or T21 manifest
// bytes named by an owner-designated v4 host report. It checks local object
// integrity and manifest selectors, not segment issuers, physical observations
// or installed inputs. No gate credit or launch authority follows from it.
func ResolveSignedGateManifestsV4(envelope []byte, policy VerifiedPolicy,
	root string, now time.Time) (map[string][]byte, error) {
	report, err := VerifyHostReportV4(envelope, policy, now)
	if err != nil {
		return nil, ErrUnqualified
	}
	return resolveSignedGateManifests(report, root)
}

func resolveSignedGateManifests(report []byte, root string) (map[string][]byte, error) {
	var document struct {
		ProfileInForce string `json:"profile_in_force"`
		Host           struct {
			ID string `json:"id"`
		} `json:"host"`
		SuiteRevision string `json:"suite_revision"`
		Gates         map[string]struct {
			Evidence reportReference `json:"evidence"`
		} `json:"gates"`
	}
	if json.Unmarshal(report, &document) != nil {
		return nil, ErrUnqualified
	}
	objects := make(map[string][]byte, len(document.Gates))
	seenEventIDs := make(map[string]bool)
	seenArtifactRefs := make(map[string]bool)
	var cohortID, ownerPlanSHA256 string
	var sharedHost gateObjectRefV3
	anchors := 0
	for gate, result := range document.Gates {
		object, err := ResolveGateObjectV3(root, result.Evidence.URI,
			result.Evidence.SHA256, maxGateManifestBytesV3)
		if err != nil {
			return nil, ErrUnqualified
		}
		manifest, err := parseGateManifestV3(object)
		if err != nil || manifest.Gate != gate || manifest.Profile != document.ProfileInForce ||
			manifest.HostID != document.Host.ID || manifest.SuiteRevision != document.SuiteRevision {
			return nil, ErrUnqualified
		}
		if cohortID == "" {
			cohortID, ownerPlanSHA256, sharedHost = manifest.CohortID,
				manifest.OwnerPlanSHA256, manifest.SharedHostObservation
		} else if manifest.CohortID != cohortID || manifest.OwnerPlanSHA256 != ownerPlanSHA256 ||
			manifest.SharedHostObservation != sharedHost {
			return nil, ErrUnqualified
		}
		for _, segment := range manifest.Segments {
			if seenEventIDs[segment.SegmentID] || seenArtifactRefs[segment.SegmentManifest.SHA256] ||
				seenArtifactRefs[segment.SegmentAttestation.SHA256] {
				return nil, ErrUnqualified
			}
			seenEventIDs[segment.SegmentID] = true
			seenArtifactRefs[segment.SegmentManifest.SHA256] = true
			seenArtifactRefs[segment.SegmentAttestation.SHA256] = true
			if segment.ReportAnchor {
				anchors++
			}
		}
		for _, attempt := range manifest.Attempts {
			if seenEventIDs[attempt.AttemptID] || seenArtifactRefs[attempt.Refusal.SHA256] ||
				seenArtifactRefs[attempt.TerminalState.SHA256] {
				return nil, ErrUnqualified
			}
			seenEventIDs[attempt.AttemptID] = true
			seenArtifactRefs[attempt.Refusal.SHA256] = true
			seenArtifactRefs[attempt.TerminalState.SHA256] = true
		}
		objects[gate] = object
	}
	if anchors != 1 {
		return nil, ErrUnqualified
	}
	return objects, nil
}
