package qualification

import (
	"encoding/json"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type candidateAdapterV3 struct {
	ComponentID             string `json:"component_id"`
	PackageSHA256           string `json:"package_sha256"`
	ExecutablePath          string `json:"executable_path"`
	ExecutableSHA256        string `json:"executable_sha256"`
	CodeInputsDigest        string `json:"code_inputs_digest"`
	CodeInputCount          int    `json:"code_input_count"`
	CandidateManifestSHA256 string `json:"candidate_manifest_sha256"`
}

// candidateMeasurementBindingV3 is a parsed first-qualification claim. The
// v2 projection is only the signed host report's summary. H/R and candidate
// authority come from the separately authenticated v3 reservation envelope.
type candidateMeasurementBindingV3 struct {
	Base                     measurementBinding
	ReportProjection         []byte
	HServiceDescriptorDigest string
	RInventory               hrInventoryRefV3
	RComponents              []hrReleaseComponentV3
	CandidateAdapter         candidateAdapterV3
	BrokerExecutable         hrBrokerExecutableV3
}

var candidateCommonBindingFieldsV3 = []string{
	"contract", "kind", "schema_version", "installation_id", "soul_id",
	"start_id", "launch_id", "host_id", "hq_epoch", "plan_id",
	"installed_plan_digest", "package_sha256", "profile_in_force",
	"claimed_definition_digest", "definition_measurement",
	"launch_input_measurement", "snapshots", "soul_artifact_sha256",
}

func commonReportProjectionV3(fields map[string]json.RawMessage) ([]byte, measurementBinding, error) {
	var zero measurementBinding
	legacy := make(map[string]json.RawMessage, len(candidateCommonBindingFieldsV3))
	for _, name := range candidateCommonBindingFieldsV3 {
		legacy[name] = fields[name]
	}
	legacy["contract"] = json.RawMessage(`"machine/v2"`)
	legacy["kind"] = json.RawMessage(`"stage2a-measurement-binding"`)
	legacy["schema_version"] = json.RawMessage("2")
	raw, err := json.Marshal(legacy)
	if err != nil {
		return nil, zero, ErrUnqualified
	}
	projection, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, zero, ErrUnqualified
	}
	base, err := parseMeasurementBindingV2(projection)
	if err != nil {
		return nil, zero, ErrUnqualified
	}
	return projection, base, nil
}

// parseCandidateMeasurementBindingV3 accepts the distinct Contracts v0.9.0
// candidate binding. It never fills an ordinary adapter_release claim.
func parseCandidateMeasurementBindingV3(raw []byte) (candidateMeasurementBindingV3, error) {
	var zero candidateMeasurementBindingV3
	fields, err := canonicalBytes(raw, MaxReportBytes)
	if err != nil || !hasFields(fields, append(append([]string{}, candidateCommonBindingFieldsV3...),
		"h_service_descriptor_digest", "r_inventory", "r_components", "broker_executable", "candidate_adapter")...) ||
		string(fields["contract"]) != `"machine/v3"` ||
		string(fields["kind"]) != `"stage2a-qualification-candidate-binding"` ||
		string(fields["schema_version"]) != "3" ||
		string(fields["profile_in_force"]) != `"managed-protected"` {
		return zero, ErrUnqualified
	}
	projection, base, err := commonReportProjectionV3(fields)
	if err != nil {
		return zero, ErrUnqualified
	}
	var hDigest string
	if json.Unmarshal(fields["h_service_descriptor_digest"], &hDigest) != nil || !validSHA(hDigest) {
		return zero, ErrUnqualified
	}
	r, err := hrInventoryRefShapeV3(fields["r_inventory"], base)
	if err != nil {
		return zero, ErrUnqualified
	}
	components, err := hrComponentsV3(fields["r_components"])
	if err != nil {
		return zero, ErrUnqualified
	}
	adapterFields, err := strictObject(fields["candidate_adapter"], MaxReportBytes)
	if err != nil || !hasFields(adapterFields, "component_id", "package_sha256",
		"executable_path", "executable_sha256", "code_inputs_digest",
		"code_input_count", "candidate_manifest_sha256") {
		return zero, ErrUnqualified
	}
	var adapter candidateAdapterV3
	if json.Unmarshal(fields["candidate_adapter"], &adapter) != nil ||
		!hrComponentIDV3.MatchString(adapter.ComponentID) ||
		!validSHA(adapter.PackageSHA256) || !validSHA(adapter.CandidateManifestSHA256) ||
		!reportPath(adapter.ExecutablePath) ||
		!strings.HasPrefix(adapter.ExecutablePath, r.Snapshot.Path+"/") ||
		!validSHA(adapter.ExecutableSHA256) || !validSHA(adapter.CodeInputsDigest) ||
		adapter.CodeInputCount < 1 || adapter.CodeInputCount > 512 {
		return zero, ErrUnqualified
	}
	matched := false
	for _, component := range components {
		if component.ComponentID == adapter.ComponentID {
			if component.ReleaseArtifactSHA256 != adapter.PackageSHA256 ||
				component.ReleaseManifestSHA256 != adapter.CandidateManifestSHA256 {
				return zero, ErrUnqualified
			}
			matched = true
		}
	}
	if !matched {
		return zero, ErrUnqualified
	}
	brokerFields, err := strictObject(fields["broker_executable"], MaxReportBytes)
	if err != nil || !hasFields(brokerFields, "path", "sha256", "provider_config_sha256") {
		return zero, ErrUnqualified
	}
	var broker hrBrokerExecutableV3
	if json.Unmarshal(fields["broker_executable"], &broker) != nil ||
		!reportPath(broker.Path) || !validSHA(broker.SHA256) ||
		!validSHA(broker.ProviderConfigSHA256) {
		return zero, ErrUnqualified
	}
	base.Contract, base.Kind, base.SchemaVersion = "machine/v3", "stage2a-qualification-candidate-binding", 3
	return candidateMeasurementBindingV3{Base: base, ReportProjection: projection,
		HServiceDescriptorDigest: hDigest, RInventory: r, RComponents: components,
		CandidateAdapter: adapter, BrokerExecutable: broker}, nil
}
