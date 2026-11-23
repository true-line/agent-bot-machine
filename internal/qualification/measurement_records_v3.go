package qualification

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	stage2aDefinitionPurposeV3 = "agent-bot/stage2a-definition-opt-closure/v1"
	stage2aLaunchPurposeV3     = "agent-bot/stage2a-launch-inputs/v1"
)

// VerifiedMeasurementRecordDigestsV3 binds exact portable JCS record bytes to
// a v3 Machine measurement binding. It does not prove installed file custody,
// the truth of a file record, owner-plan approval or a physical gate result.
type VerifiedMeasurementRecordDigestsV3 struct {
	verified                                                  bool
	DefinitionMeasurementSHA256, LaunchInputMeasurementSHA256 string
}

func scanStage2aJSONV3(decoder *json.Decoder, depth int, nodes *int) error {
	if depth > 16 || *nodes >= 4096 {
		return ErrUnqualified
	}
	*nodes++
	token, err := decoder.Token()
	if err != nil {
		return ErrUnqualified
	}
	if number, ok := token.(json.Number); ok {
		value, err := strconv.ParseFloat(string(number), 64)
		if err != nil || math.IsInf(value, 0) || math.IsNaN(value) || math.Abs(value) > (1<<53)-1 {
			return ErrUnqualified
		}
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrUnqualified
			}
			seen[name] = true
			if scanStage2aJSONV3(decoder, depth+1, nodes) != nil {
				return ErrUnqualified
			}
		}
		close, err := decoder.Token()
		if err != nil || close != json.Delim('}') {
			return ErrUnqualified
		}
	case json.Delim('['):
		for decoder.More() {
			if scanStage2aJSONV3(decoder, depth+1, nodes) != nil {
				return ErrUnqualified
			}
		}
		close, err := decoder.Token()
		if err != nil || close != json.Delim(']') {
			return ErrUnqualified
		}
	}
	return nil
}

func validStage2aSurrogatesV3(raw []byte) bool {
	quoted := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			quoted = !quoted
		case '\\':
			if !quoted || i+1 >= len(raw) {
				return false
			}
			i++
			if raw[i] != 'u' {
				continue
			}
			if i+4 >= len(raw) {
				return false
			}
			first, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if err != nil {
				return false
			}
			i += 4
			if first >= 0xdc00 && first <= 0xdfff {
				return false
			}
			if first >= 0xd800 && first <= 0xdbff {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				second, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if err != nil || second < 0xdc00 || second > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return !quoted
}

func canonicalStage2aRecordsV3(raw []byte, top byte, max int) error {
	if len(raw) == 0 || len(raw) > max || raw[0] != top || !utf8.Valid(raw) ||
		!json.Valid(raw) || !validStage2aSurrogatesV3(raw) {
		return ErrUnqualified
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	if scanStage2aJSONV3(decoder, 0, &nodes) != nil {
		return ErrUnqualified
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrUnqualified
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrUnqualified
	}
	return nil
}

// VerifyMeasurementRecordDigestsV3 independently recomputes the two distinct
// owner-approved Stage 2a domain-separated hashes over exact canonical record
// bytes. The caller must first authenticate bindingRaw through the designated
// host report and A reservation, then separately validate all record semantics
// and A's descriptor-observed installed file and snapshot custody.
func VerifyMeasurementRecordDigestsV3(bindingRaw, definitionRecords, launchInputRecords []byte) (VerifiedMeasurementRecordDigestsV3, error) {
	var zero VerifiedMeasurementRecordDigestsV3
	binding, err := parseMeasurementBindingV2(bindingRaw)
	if err != nil || !validHex(binding.SoulArtifactSHA256, 64) ||
		canonicalStage2aRecordsV3(definitionRecords, '[', 4<<20) != nil ||
		canonicalStage2aRecordsV3(launchInputRecords, '{', 1<<20) != nil {
		return zero, ErrUnqualified
	}
	definitionSHA := digest(preimage(stage2aDefinitionPurposeV3, definitionRecords))
	launchSHA := digest(preimage(stage2aLaunchPurposeV3, launchInputRecords))
	if definitionSHA != binding.DefinitionMeasurement || launchSHA != binding.LaunchInputMeasurement {
		return zero, ErrUnqualified
	}
	return VerifiedMeasurementRecordDigestsV3{verified: true,
		DefinitionMeasurementSHA256: definitionSHA, LaunchInputMeasurementSHA256: launchSHA}, nil
}
