package members

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
)

const stage2aAssignmentSchemaV3 = "agent-bot-machine/soul-start-assignment/v3"

type stage2aReservationAssignmentV3 struct {
	stage2aReservationAssignment
	HDescriptorDigest string `json:"h_service_descriptor_digest"`
	RInventoryDigest  string `json:"r_inventory_digest"`
}

type stage2aReservationBrokerV3 struct {
	Path                 string `json:"path"`
	SHA256               string `json:"sha256"`
	ProviderConfigSHA256 string `json:"provider_config_sha256"`
}

type stage2aReservationAdapterV3 struct {
	ComponentID              string `json:"component_id"`
	ExecutablePath           string `json:"executable_path"`
	ExecutableSHA256         string `json:"executable_sha256"`
	PackageSHA256            string `json:"package_sha256"`
	ReleaseAttestationSHA256 string `json:"release_attestation_sha256"`
	ReleaseManifestSHA256    string `json:"release_manifest_sha256"`
	CodeInputCount           int    `json:"code_input_count"`
	CodeInputsDigest         string `json:"code_inputs_digest"`
}

type stage2aMeasurementBindingV3 struct {
	Stage2aMeasurementBinding
	HDescriptorDigest string                       `json:"h_service_descriptor_digest"`
	RInventory        stage2aDomainInventoryRefV3  `json:"r_inventory"`
	RComponents       []stage2aHReleaseComponentV3 `json:"r_components"`
	Broker            stage2aReservationBrokerV3   `json:"broker_executable"`
	Adapter           stage2aReservationAdapterV3  `json:"adapter_release"`
}

type stage2aReservationPayloadV3 struct {
	Contract                   string                         `json:"contract"`
	Kind                       string                         `json:"kind"`
	SchemaVersion              int                            `json:"schema_version"`
	HostID                     string                         `json:"host_id"`
	IssuedAt                   string                         `json:"issued_at"`
	ExpiresAt                  string                         `json:"expires_at"`
	InstalledPlanReceiptSHA256 string                         `json:"installed_plan_receipt_sha256"`
	Assignment                 stage2aReservationAssignmentV3 `json:"assignment"`
	MemberEndpoint             SoulMemberLaunchAssignment     `json:"member_endpoint"`
	MeasurementBinding         stage2aMeasurementBindingV3    `json:"measurement_binding"`
	AdmissionChallengeSHA256   string                         `json:"admission_challenge_sha256"`
}

// These private inputs come from the installed A authority. None are decoded
// from the requesting HQ's reservation selector or the envelope being checked.
type stage2aReservationEvidenceV3 struct {
	base        stage2aReservationInputs
	h           stage2aVerifiedDomainRefV3
	r           stage2aVerifiedDomainRefV3
	hEnvelope   []byte
	rInventory  stage2aDomainInventoryV3
	rComponents []stage2aHReleaseComponentV3
	broker      stage2aReservationBrokerV3
	adapter     stage2aReservationAdapterV3
	adapterCode []string
}

func stage2aCheckReservationRInventoryV3(e stage2aReservationEvidenceV3) error {
	r := e.r.ref
	inv := e.rInventory
	raw, err := marshalStage2aReservationJCS(inv)
	if err != nil {
		return errStage2aReservationAuthority
	}
	_, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != r.InventoryDigest || r.ReviewedSourceInventoryDigest != digest {
		return errStage2aReservationAuthority
	}

	if inv.Domain != r.Domain || inv.InstallationID != r.InstallationID || len(inv.Files) != r.FileCount ||
		len(inv.Directories) != r.DirectoryCount || inv.TotalBytes != r.TotalBytes ||
		!stage2aAbsolutePath(e.broker.Path) || !stage2aPrefixedDigest.MatchString(e.broker.SHA256) ||
		!stage2aPrefixedDigest.MatchString(e.broker.ProviderConfigSHA256) || len(e.rComponents) == 0 || len(e.rComponents) > 32 {
		return errStage2aReservationAuthority
	}
	components := make(map[string]bool, len(e.rComponents))
	previous := ""
	for _, component := range e.rComponents {
		if !stage2aBindingID.MatchString(component.ComponentID) || component.ComponentID <= previous ||
			!hqStage2aSourceRepository.MatchString(component.SourceRepository) || !stage2aCDHash.MatchString(component.SourceCommit) ||
			(component.SourceTag != nil && !hqStage2aSourceTag.MatchString(*component.SourceTag)) ||
			!stage2aPrefixedDigest.MatchString(component.ReleaseArtifactSHA256) || !stage2aPrefixedDigest.MatchString(component.ReleaseManifestSHA256) {
			return errStage2aReservationAuthority
		}
		components[component.ComponentID] = false
		previous = component.ComponentID
	}
	for _, row := range inv.Files {
		if _, ok := components[row.ComponentID]; !ok {
			return errStage2aReservationAuthority
		}
		components[row.ComponentID] = true
	}
	for _, used := range components {
		if !used {
			return errStage2aReservationAuthority
		}
	}
	return nil
}

func stage2aCheckReservationREvidence(e stage2aReservationEvidenceV3) error {
	for _, component := range e.rComponents {
		if component.ComponentID != e.adapter.ComponentID {
			continue
		}
		if component.ReleaseArtifactSHA256 != e.adapter.PackageSHA256 || component.ReleaseManifestSHA256 != e.adapter.ReleaseManifestSHA256 ||
			!stage2aPrefixedDigest.MatchString(e.adapter.ReleaseAttestationSHA256) {
			return errStage2aReservationAuthority
		}
	}
	codeRows := make(map[string]bool)
	executable := false
	for _, row := range e.rInventory.Files {
		if row.ComponentID != e.adapter.ComponentID {
			continue
		}
		path := filepath.Join(e.r.ref.Snapshot.Path, row.Path)
		if path == e.adapter.ExecutablePath {
			if row.Mode != "0550" || row.SHA256 != e.adapter.ExecutableSHA256 {
				return errStage2aReservationAuthority
			}
			executable = true
		}
		codeRows[path] = true
	}
	if !executable || e.adapter.CodeInputCount < 1 || e.adapter.CodeInputCount > 512 || len(e.adapterCode) != e.adapter.CodeInputCount || e.adapter.PackageSHA256 == "sha256:"+e.base.binding.PackageSHA256 {
		return errStage2aReservationAuthority
	}
	for i, path := range e.adapterCode {
		if !codeRows[path] || (i != 0 && path <= e.adapterCode[i-1]) {
			return errStage2aReservationAuthority
		}
	}
	code := slices.Clone(e.adapterCode)
	if code == nil {
		code = []string{}
	}
	canonical, err := marshalStage2aReservationJCS(code)
	if err != nil || stage2aV3PurposeDigest("agent-bot/stage2a-adapter-code-inputs/v3", canonical) != e.adapter.CodeInputsDigest {
		return errStage2aReservationAuthority
	}
	return nil
}

// Checked common binding inputs do not encode a signable reservation.
type stage2aCheckedReservationHRV3 struct {
	base             stage2aReservationPayload
	descriptorDigest string
	r                stage2aDomainInventoryRefV3
}

func prepareStage2aReservationHREvidenceV3(req stage2aReservationRequest, e stage2aReservationEvidenceV3, issued time.Time) (stage2aCheckedReservationHRV3, error) {
	var empty stage2aCheckedReservationHRV3
	base, err := prepareStage2aReservationForOwner(req, e.base, issued, uint32(e.base.machineUID), uint32(e.base.runner.GID))
	if err != nil || base.Contract != "machine/v2" || base.MeasurementBinding.ProfileInForce != "managed-protected" ||
		!issued.Before(e.base.expires) || e.base.expires.Sub(issued) > 30*time.Second || !e.h.verified || !e.r.verified {
		return empty, errStage2aReservationAuthority
	}
	h, hd, err := stage2aDecodeHDescriptorV3(e.hEnvelope, e.base.enrolledAdminKey)
	r := e.r.ref
	if err != nil || h.HInventory != e.h.ref || h.HostID != e.base.hostID || h.HInventory.Domain != "H-code" ||
		h.HInventory.ReaderUID != uint32(e.base.hqUID) || h.HInventory.ReaderGID != uint32(e.base.hqUID) ||
		h.HInventory.MachineUID != uint32(e.base.machineUID) || !stage2aPrefixedDigest.MatchString(r.InventoryDigest) ||
		!stage2aPrefixedDigest.MatchString(hd) || strings.EqualFold(h.HInventory.Snapshot.Path, r.Snapshot.Path) ||
		r.Domain != "R-runtime" || r.InstallationID != req.start.InstallationID || r.MachineUID != h.HInventory.MachineUID ||
		r.ReaderUID != uint32(e.base.runner.UID) || r.ReaderGID != uint32(e.base.runner.GID) ||
		r.OwnerPlanDigest != "sha256:"+req.start.PlanDigest || h.HInventory.ReaderGID == r.ReaderGID ||
		!matchesHQStage2aRuntimeNames(r) || stage2aCheckReservationRInventoryV3(e) != nil {
		return empty, errStage2aReservationAuthority
	}
	base.Assignment.Schema = stage2aAssignmentSchemaV3
	base.MeasurementBinding.Contract, base.MeasurementBinding.SchemaVersion = "machine/v3", 3
	return stage2aCheckedReservationHRV3{base: base, descriptorDigest: hd, r: r}, nil
}

func prepareStage2aReservationV3(req stage2aReservationRequest, e stage2aReservationEvidenceV3, issued time.Time) (stage2aReservationPayloadV3, error) {
	common, err := prepareStage2aReservationHREvidenceV3(req, e, issued)
	if err != nil || stage2aCheckReservationREvidence(e) != nil {
		return stage2aReservationPayloadV3{}, errStage2aReservationAuthority
	}
	base, hd, r := common.base, common.descriptorDigest, common.r
	return stage2aReservationPayloadV3{Contract: "machine/v3", Kind: base.Kind, SchemaVersion: 3, HostID: base.HostID,
		IssuedAt: base.IssuedAt, ExpiresAt: base.ExpiresAt, InstalledPlanReceiptSHA256: base.InstalledPlanReceiptSHA256,
		Assignment: stage2aReservationAssignmentV3{base.Assignment, hd, r.InventoryDigest}, MemberEndpoint: base.MemberEndpoint,
		MeasurementBinding:       stage2aMeasurementBindingV3{base.MeasurementBinding, hd, r, e.rComponents, e.broker, e.adapter},
		AdmissionChallengeSHA256: base.AdmissionChallengeSHA256}, nil
}

// The complete canonical envelope SHA, not the payload or purpose digest, is
// the reservation identifier carried by Q and its EOF acknowledgement.
func verifyStage2aReservationV3(raw []byte, envelopeSHA string, expected stage2aReservationPayloadV3,
	key ed25519.PublicKey, now time.Time) error {
	payload, _, err := verifyStage2aV3Envelope(raw, stage2aReservationPurposeV3, key)
	var decoded stage2aReservationPayloadV3
	if err != nil || stage2aReservationSHA256(raw) != envelopeSHA || stage2aDecodeExact(payload, &decoded) != nil || !reflect.DeepEqual(decoded, expected) {
		return errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(expected)
	issued, issuedErr := time.Parse(time.RFC3339Nano, expected.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, expected.ExpiresAt)
	if err != nil || !bytes.Equal(payload, canonical) || issuedErr != nil || expiryErr != nil || now.Before(issued) ||
		!now.Before(expires) || expires.Sub(issued) > 30*time.Second {
		return errStage2aReservationAuthority
	}
	return nil
}

func issueStage2aReservationV3(req stage2aReservationRequest, e stage2aReservationEvidenceV3, machineGID uint32,
	issued time.Time, sign func([]byte) ([]byte, error)) (stage2aReservation, error) {
	if !stage2aInstallSealNoIP() || stage2aRecheckVerifiedDomainV3(e.h) != nil || stage2aRecheckVerifiedDomainV3(e.r) != nil {
		return stage2aReservation{}, errStage2aReservationAuthority
	}
	prepared, err := prepareStage2aReservationV3(req, e, issued)
	if err != nil {
		return stage2aReservation{}, err
	}
	payload, err := marshalStage2aReservationJCS(prepared)
	if err != nil {
		return stage2aReservation{}, err
	}
	raw, _, err := signStage2aVerifiedEnvelopeV3(stage2aVerifiedSigningPayloadV3{verified: true, purpose: stage2aReservationPurposeV3,
		payload: payload, machineUID: uint32(e.base.machineUID), machineGID: machineGID}, e.base.enrolledAdminKey, sign)
	if err != nil {
		return stage2aReservation{}, err
	}
	digest := stage2aReservationSHA256(raw)
	if err := verifyStage2aReservationV3(raw, digest, prepared, e.base.enrolledAdminKey, issued); err != nil {
		return stage2aReservation{}, err
	}
	return stage2aReservation{envelope: raw, sha256: digest}, nil
}

// Reserve under the existing A-owned one-use claim and installation lock.
// The authority loader runs after locking so retirement, replacement, and
// changed component evidence cannot race the signature or reuse a start ID.
func reserveStage2aAdminStartV3(store stage2aAdminClaimStore, req stage2aReservationRequest,
	load func(stage2aReservationRequest) (stage2aReservationEvidenceV3, error), sign func([]byte) ([]byte, error),
	now func() time.Time) (stage2aReservation, error) {
	var empty stage2aReservation
	if load == nil || sign == nil || now == nil || !stage2aInstallSealNoIP() {
		return empty, errStage2aReservationAuthority
	}
	var e stage2aReservationEvidenceV3
	var issued time.Time
	var got stage2aReservation
	err := stage2aAdminSpend(store, req, func() error {
		var err error
		e, err = load(req)
		if err != nil || uint32(e.base.machineUID) != store.uid {
			return errStage2aReservationAuthority
		}
		dir, err := store.open()
		if err != nil {
			return err
		}
		defer dir.Close()
		if err := requireUnspentStage2aReservation(dir, stage2aActiveClaimName(req.start.InstallationID)); err != nil {
			return err
		}
		issued = now()
		_, err = prepareStage2aReservationV3(req, e, issued)
		return err
	}, func(dir *os.File) error {
		if err := spendStage2aAdminName(dir, stage2aActiveClaimName(req.start.InstallationID), store.uid, store.gid); err != nil {
			return err
		}
		var err error
		got, err = issueStage2aReservationV3(req, e, store.gid, issued, sign)
		if err != nil {
			return err
		}
		name := ".stage2a-admin-envelope-" + soulStartClaimName(req.start.InstallationID, req.start.StartID)
		return commitStage2aReservation(dir, name, got.envelope)
	})
	if err != nil {
		return empty, err
	}
	if !now().Before(e.base.expires) {
		return empty, errStage2aReservationExpired
	}
	return got, nil
}

// Use the independently pinned A key and the fixed descriptor path. A
// reopens H's sealed inventory rather than trusting the signed inode claim.
func loadStage2aReservationHV3(p stage2aInstalledPolicy, key ed25519.PublicKey) (stage2aVerifiedDomainRefV3, []byte, error) {
	result, _, err := loadStage2aInstalledHV3(p.Binding.HostID, p.MachineUID, p.HQUID, p.HQUID, key)
	return result.verifiedH, result.envelope, err
}

func loadStage2aInstalledHV3(hostID string, machineUID, hqUID, readerGID int,
	key ed25519.PublicKey) (stage2aCooperativeHDescriptorV3, stage2aHServiceDescriptorPayloadV3, error) {
	var empty stage2aCooperativeHDescriptorV3
	var descriptor stage2aHServiceDescriptorPayloadV3
	pin, err := readStage2aRolePin()
	if err != nil || !key.Equal(pin) {
		return empty, descriptor, errStage2aReservationAuthority
	}
	if _, err := stage2aInstalledDirectoryIdentity(hqStage2aMetadataDir, machineUID, readerGID, 0750); err != nil {
		return empty, descriptor, err
	}
	witness, raw, err := stage2aV3SidecarAt(hqStage2aDescriptor, uint32(machineUID), uint32(readerGID))
	if err != nil {
		return empty, descriptor, err
	}
	descriptor, descriptorDigest, err := stage2aDecodeHDescriptorV3(raw, key)
	if err != nil || descriptor.HostID != hostID {
		return empty, descriptor, errStage2aReservationAuthority
	}
	h := descriptor.HInventory
	namespace, snapshot, sidecar, err := stage2aDomainNamesV3("H-code", descriptor.HQInstallationID)
	if err != nil || h.Domain != "H-code" || h.InstallationID != descriptor.HQInstallationID || h.OwnerPlanDigest != descriptor.OwnerPlanDigest ||
		h.MachineUID != uint32(machineUID) || h.ReaderUID != uint32(hqUID) || h.ReaderGID != uint32(readerGID) ||
		h.Snapshot.Path != filepath.Join(namespace, snapshot) || h.Sidecar.Path != filepath.Join(namespace, sidecar) {
		return empty, descriptor, errStage2aReservationAuthority
	}
	checked, err := stage2aObserveInstalledDomainV3(h.Snapshot.Path, h.Sidecar.Path, h.MachineUID, h.ReaderUID, h.ReaderGID, h.OwnerPlanDigest, h.ReviewedSourceInventoryDigest)
	if err != nil || checked.ref != h {
		return empty, descriptor, errStage2aReservationAuthority
	}
	return stage2aCooperativeHDescriptorV3{verifiedH: checked, envelope: raw, descriptorDigest: descriptorDigest, witness: witness}, descriptor, nil
}

// The installed runtime loader has authenticated the retained R owner plan
// and receipt. Ordinary callers supply independently verified vendor adapter
// qualifications. Candidate callers bind their separate Q approval.
func loadStage2aReservationEvidenceV3(req stage2aReservationRequest, runtime stage2aInstalledRuntimeV3, key ed25519.PublicKey,
	adapter stage2aReservationAdapterV3,
	qualifiedCode []string) (stage2aReservationEvidenceV3, error) {
	var empty stage2aReservationEvidenceV3
	p, r := runtime.Policy, runtime.VerifiedR
	_, snapshots := p.stores()
	base, err := p.inputs(req, snapshots, key)
	if err != nil || !r.verified || stage2aRecheckVerifiedDomainV3(r) != nil {
		return empty, errStage2aReservationAuthority
	}
	// p.Receipt is A's compacted copy. The outgoing receipt digest binds the
	// exact root-applied file, including its canonical stored representation.
	rootReceipt := filepath.Join("/private"+DarwinReceiptsDir, p.Binding.PlanID+".json")
	base.installedReceipt, err = stage2aReadRootFile(rootReceipt, 256<<10, 0644)
	if err != nil || !stage2aInstalledReceiptMatchesRoot(p.Receipt, base.installedReceipt) {
		return empty, errStage2aReservationAuthority
	}
	h, hEnvelope, err := loadStage2aReservationHV3(p, key)
	if err != nil {
		return empty, err
	}
	_, providerSHA, err := stage2aProviderConfig(p.BridgeQualification)
	if err != nil || p.BridgeExecutable.Path != SoulBridgeBinary || verifyHarnessExecutable(SoulBridgeBinary, p.BridgeExecutable.SHA256) != nil {
		return empty, errStage2aReservationAuthority
	}
	selected := make([]stage2aHReleaseComponentV3, 0, len(runtime.Plan.Components))
	for _, c := range runtime.Plan.Components {
		wire := stage2aHReleaseComponentV3{ComponentID: c.ComponentID, SourceRepository: c.SourceRepository, SourceCommit: c.SourceCommit,
			ReleaseArtifactSHA256: c.ReleaseArtifactSHA256, ReleaseManifestSHA256: c.ReleaseManifestSHA256}
		if c.SourceTag != "" {
			tag := c.SourceTag
			wire.SourceTag = &tag
		}
		selected = append(selected, wire)
	}
	return stage2aReservationEvidenceV3{base: base, h: h, r: r, hEnvelope: hEnvelope, rInventory: runtime.Inventory, rComponents: selected,
		broker:  stage2aReservationBrokerV3{Path: p.BridgeExecutable.Path, SHA256: "sha256:" + p.BridgeExecutable.SHA256, ProviderConfigSHA256: "sha256:" + providerSHA},
		adapter: adapter, adapterCode: slices.Clone(qualifiedCode)}, nil
}
