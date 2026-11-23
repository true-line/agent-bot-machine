package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// This is a separate authority from soul-protected-launch-install. A
// cooperative request cannot select, reuse, or weaken a protected policy.
const SoulCooperativeLaunchInstallPurpose = "soul-cooperative-launch-install"
const soulCooperativeInstallSchema = "agent-bot-machine/soul-cooperative-launch-install/v1"
const soulCooperativeReservationPurpose = "agent-bot/soul-cooperative-reservation/v1"

var errSoulCooperativeAuthority = errors.New("cooperative Soul launch authority unavailable or mismatched")

// SoulCooperativeLaunchPolicy is the exact owner-reviewable input for one
// cooperative installation. The installed receipt, frozen byte observations,
// live pairing, and durable spent claim must be supplied by A at use time;
// this structure alone grants no launch permission.
type SoulCooperativeLaunchPolicy struct {
	Schema            string     `json:"schema"`
	Purpose           string     `json:"purpose"`
	Profile           string     `json:"profile_in_force"`
	HostID            string     `json:"host_id"`
	HQUID             int        `json:"hq_uid"`
	HQEpoch           string     `json:"hq_epoch"`
	MachinePublicKey  string     `json:"machine_public_key_base64url"`
	SourcePackagePath string     `json:"source_package_path"`
	Runner            SoulRunner `json:"runner"`
	ArtifactSHA256    string     `json:"soul_artifact_sha256"`
	DefinitionSHA256  string     `json:"definition_sha256"`
	NodePath          string     `json:"node_path"`
	NodeSHA256        string     `json:"node_sha256"`
	Entry             string     `json:"entry"`
	LauncherPath      string     `json:"launcher_path"`
	LauncherSHA256    string     `json:"launcher_sha256"`
	ApprovedUntil     string     `json:"approved_until"`
}

// ParseSoulCooperativeLaunchPolicy accepts one bounded JSON object, refusing
// duplicate, unknown and missing fields before an owner may review it.
func ParseSoulCooperativeLaunchPolicy(raw []byte) (SoulCooperativeLaunchPolicy, error) {
	var policy SoulCooperativeLaunchPolicy
	if len(raw) == 0 || len(raw) > 8192 || strictCooperativeObject(raw) != nil {
		return policy, errSoulCooperativeAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil || decoder.Decode(new(any)) != io.EOF || policy.validate() != nil {
		return SoulCooperativeLaunchPolicy{}, errSoulCooperativeAuthority
	}
	return policy, nil
}

func strictCooperativeObject(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errSoulCooperativeAuthority
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return errSoulCooperativeAuthority
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return errSoulCooperativeAuthority
		}
		// The nested runner must also refuse duplicate JSON keys.
		if name == "runner" && strictCooperativeRunner(value) != nil {
			return errSoulCooperativeAuthority
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return errSoulCooperativeAuthority
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errSoulCooperativeAuthority
	}
	return nil
}

func strictCooperativeRunner(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errSoulCooperativeAuthority
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return errSoulCooperativeAuthority
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return errSoulCooperativeAuthority
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return errSoulCooperativeAuthority
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errSoulCooperativeAuthority
	}
	return nil
}

func cooperativeAbsolute(p string) bool {
	return strings.HasPrefix(p, "/") && p != "/" && path.Clean(p) == p &&
		len(p) <= 1024 && !strings.ContainsAny(p, "\x00\n\r")
}

func (p SoulCooperativeLaunchPolicy) validate() error {
	key, err := base64.RawURLEncoding.Strict().DecodeString(p.MachinePublicKey)
	expiry, timeErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if p.Schema != soulCooperativeInstallSchema || p.Purpose != SoulCooperativeLaunchInstallPurpose ||
		p.Profile != "managed-cooperative" || !soulInstallationID.MatchString(p.HostID) ||
		p.HQUID < 300 || p.HQUID > 399 || !soulHQEpoch.MatchString(p.HQEpoch) ||
		err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != p.MachinePublicKey ||
		!soulIdentity.MatchString(p.Runner.SoulID) || !soulInstallationID.MatchString(p.Runner.InstallationID) ||
		p.Runner.Account != soulRunnerName(p.Runner.InstallationID) || p.Runner.UID < 300 || p.Runner.UID > 399 ||
		p.Runner.GID != p.Runner.UID || p.Runner.UID == p.HQUID ||
		!cooperativeAbsolute(p.SourcePackagePath) || p.SourcePackagePath == p.Runner.PackageRoot ||
		!cooperativeAbsolute(p.Runner.PackageRoot) || p.Runner.PackageRoot != cooperativeArtifactPath(p.Runner.InstallationID) ||
		!soulDigest.MatchString(p.Runner.PackageSHA256) ||
		!soulDigest.MatchString(p.ArtifactSHA256) || !soulDigest.MatchString(p.DefinitionSHA256) ||
		!cooperativeAbsolute(p.NodePath) || !soulDigest.MatchString(p.NodeSHA256) ||
		p.Entry == "" || p.Entry == "." || len(p.Entry) > 1024 || strings.HasPrefix(p.Entry, "/") || path.Clean(p.Entry) != p.Entry ||
		strings.HasPrefix(p.Entry, "../") || p.Entry == ".." || strings.ContainsAny(p.Entry, "\x00\n\r") ||
		!cooperativeAbsolute(p.LauncherPath) || !soulDigest.MatchString(p.LauncherSHA256) ||
		timeErr != nil || expiry.IsZero() {
		return errSoulCooperativeAuthority
	}
	return nil
}

// SoulCooperativeReserveRequest carries selectors only. It cannot supply an
// executable, UID, argument, profile downgrade, or package replacement.
type SoulCooperativeReserveRequest struct {
	Profile        string `json:"profile"`
	HostID         string `json:"host_id"`
	PlanDigest     string `json:"plan_digest"`
	InstallationID string `json:"installation_id"`
	StartID        string `json:"start_id"`
	HQEpoch        string `json:"hq_epoch"`
	PackagePath    string `json:"package_path"`
}

func ParseSoulCooperativeReserveRequest(raw []byte) (SoulCooperativeReserveRequest, error) {
	var q SoulCooperativeReserveRequest
	if len(raw) == 0 || len(raw) > 2048 || strictCooperativeObject(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&q) != nil || decoder.Decode(new(any)) != io.EOF ||
		q.Profile != "managed-cooperative" || !soulInstallationID.MatchString(q.HostID) ||
		!cooperativeAbsolute(q.PackagePath) ||
		!(SoulRunRequest{PlanDigest: q.PlanDigest, InstallationID: q.InstallationID,
			StartID: q.StartID, HQEpoch: q.HQEpoch}).valid() {
		return SoulCooperativeReserveRequest{}, errSoulCooperativeAuthority
	}
	return q, nil
}

type SoulCooperativeReservation struct {
	Purpose                string                  `json:"purpose"`
	Profile                string                  `json:"profile_in_force"`
	HostID                 string                  `json:"host_id"`
	PlanID                 string                  `json:"plan_id"`
	PlanDigest             string                  `json:"plan_digest"`
	InstalledReceiptSHA256 string                  `json:"installed_receipt_sha256"`
	InstallationID         string                  `json:"installation_id"`
	SoulID                 string                  `json:"soul_id"`
	StartID                string                  `json:"start_id"`
	HQEpoch                string                  `json:"hq_epoch"`
	RunnerUID              int                     `json:"runner_uid"`
	RunnerGID              int                     `json:"runner_gid"`
	SourcePackagePath      string                  `json:"source_package_path"`
	PackageRoot            string                  `json:"package_root"`
	PackageSHA256          string                  `json:"package_sha256"`
	SoulArtifactSHA256     string                  `json:"soul_artifact_sha256"`
	DefinitionSHA256       string                  `json:"definition_sha256"`
	NodePath               string                  `json:"node_path"`
	NodeSHA256             string                  `json:"node_sha256"`
	Entry                  string                  `json:"entry"`
	LauncherPath           string                  `json:"launcher_path"`
	LauncherSHA256         string                  `json:"launcher_sha256"`
	Endpoint               SoulCooperativeEndpoint `json:"endpoint"`
	IssuedAt               string                  `json:"issued_at"`
	ExpiresAt              string                  `json:"expires_at"`
}

type SoulCooperativeEndpoint struct {
	Directory  string `json:"directory"`
	SocketPath string `json:"socket_path"`
	OwnerUID   int    `json:"owner_uid"`
	GroupGID   int    `json:"group_gid"`
	DirMode    int    `json:"dir_mode"`
	SocketMode int    `json:"socket_mode"`
	PeerUID    int    `json:"peer_uid"`
}

func cooperativeEndpoint(p SoulCooperativeLaunchPolicy, startID string) (SoulCooperativeEndpoint, error) {
	directory := path.Join(launchRuntimeDir, "c", soulEndpointInstallationSlot(p.Runner.InstallationID))
	socket := path.Join(directory, soulEndpointStartSlot(p.Runner.InstallationID, startID)+".sock")
	if len(socket) > 103 {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	return SoulCooperativeEndpoint{Directory: directory, SocketPath: socket,
		OwnerUID: p.HQUID, GroupGID: p.Runner.GID, DirMode: 02750, SocketMode: 0660,
		PeerUID: p.Runner.UID}, nil
}

type SoulCooperativeSignedReservation struct {
	Purpose            string `json:"purpose"`
	PayloadBase64URL   string `json:"payload_base64url"`
	PayloadSHA256      string `json:"payload_sha256"`
	SignatureBase64URL string `json:"signature_base64url"`
}

// SoulCooperativeInstalledAuthority is produced only by an A-side loader
// after comparing the policy with the applied root receipt and approved plan.
// It is deliberately a different type from the owner-reviewable request.
type SoulCooperativeInstalledAuthority struct {
	Policy                   SoulCooperativeLaunchPolicy
	PlanID                   string
	PlanDigest               string
	ReceiptSHA256            string
	ObservedPackageSHA256    string
	ObservedArtifactSHA256   string
	ObservedDefinitionSHA256 string
	ObservedNodeSHA256       string
	ObservedLauncherSHA256   string
}

// PrepareSoulCooperativeReservation is the narrow A-side signing boundary.
// Its caller must independently load an applied owner-approved policy and
// receipt, check frozen bytes and live paired epoch, and pass a durable spend
// operation. A successful spend is terminal even if delivery is lost.
func PrepareSoulCooperativeReservation(in SoulCooperativeInstalledAuthority, q SoulCooperativeReserveRequest,
	now time.Time, sign func([]byte) ([]byte, error), spend func(string, string) error,
) (SoulCooperativeSignedReservation, error) {
	var empty SoulCooperativeSignedReservation
	p := in.Policy
	if p.validate() != nil || q.Profile != "managed-cooperative" || q.HostID != p.HostID ||
		q.PlanDigest != in.PlanDigest || !ValidApproval(in.PlanID, in.PlanDigest) ||
		q.InstallationID != p.Runner.InstallationID || q.HQEpoch != p.HQEpoch ||
		q.PackagePath != p.SourcePackagePath ||
		in.ObservedPackageSHA256 != p.Runner.PackageSHA256 ||
		in.ObservedArtifactSHA256 != p.ArtifactSHA256 ||
		in.ObservedDefinitionSHA256 != p.DefinitionSHA256 ||
		in.ObservedNodeSHA256 != p.NodeSHA256 ||
		in.ObservedLauncherSHA256 != p.LauncherSHA256 ||
		!soulStartID.MatchString(q.StartID) || !soulDigest.MatchString(in.ReceiptSHA256) ||
		sign == nil || spend == nil {
		return empty, errSoulCooperativeAuthority
	}
	expiry, _ := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if !now.Before(expiry) {
		return empty, errSoulCooperativeAuthority
	}
	lease := now.Add(30 * time.Second)
	if expiry.Before(lease) {
		lease = expiry
	}
	endpoint, err := cooperativeEndpoint(p, q.StartID)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	reserved := SoulCooperativeReservation{
		Purpose: soulCooperativeReservationPurpose, Profile: "managed-cooperative", HostID: p.HostID,
		PlanID: in.PlanID, PlanDigest: in.PlanDigest, InstalledReceiptSHA256: in.ReceiptSHA256,
		InstallationID: p.Runner.InstallationID, SoulID: p.Runner.SoulID, StartID: q.StartID, HQEpoch: q.HQEpoch,
		RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID,
		SourcePackagePath: p.SourcePackagePath, PackageRoot: p.Runner.PackageRoot,
		PackageSHA256: p.Runner.PackageSHA256, SoulArtifactSHA256: p.ArtifactSHA256,
		DefinitionSHA256: p.DefinitionSHA256, NodePath: p.NodePath, NodeSHA256: p.NodeSHA256,
		Entry: p.Entry, LauncherPath: p.LauncherPath, LauncherSHA256: p.LauncherSHA256,
		Endpoint: endpoint,
		IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: lease.UTC().Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(reserved)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	preimage := append([]byte(soulCooperativeReservationPurpose+"\x00"), canonical...)
	signature, err := sign(preimage)
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(p.MachinePublicKey)
	if err != nil || keyErr != nil || !ed25519.Verify(key, preimage, signature) {
		return empty, errSoulCooperativeAuthority
	}
	if err := spend(q.InstallationID, q.StartID); err != nil {
		return empty, errSoulCooperativeAuthority
	}
	sum := sha256.Sum256(canonical)
	return SoulCooperativeSignedReservation{
		Purpose: soulCooperativeReservationPurpose, PayloadBase64URL: base64.RawURLEncoding.EncodeToString(canonical),
		PayloadSHA256: fmt.Sprintf("%x", sum), SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}
