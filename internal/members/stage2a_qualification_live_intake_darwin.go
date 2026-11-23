//go:build darwin

package members

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strings"
)

const (
	stage2aLiveIntakeSchema = "agent-bot-machine/stage2a-live-intake/v1"
	stage2aLiveBlobMax      = 4 << 20
	stage2aLiveTotalMax     = 8 << 20
)

var stage2aLiveArtifactID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// This transport runs on A's already authenticated, one-use owner-driver
// connection. Its bytes are evidence inputs only: custody does not establish
// that a stock child attempted a route or that the OS refused one.
type stage2aLiveTransfer struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	RequestSHA256 string `json:"request_sha256"`
	ArtifactSize  int    `json:"artifact_size_bytes"`
	Blobs         []struct {
		Purpose   string `json:"purpose"`
		SizeBytes int    `json:"size_bytes"`
	} `json:"blobs"`
}

type stage2aLiveRawRef struct {
	SHA256    string `json:"sha256"`
	SizeBytes int    `json:"size_bytes"`
	Purpose   string `json:"purpose"`
}

type stage2aLiveRange struct {
	BlobSHA256  string `json:"blob_sha256"`
	OffsetBytes int    `json:"offset_bytes"`
	LengthBytes int    `json:"length_bytes"`
}

type stage2aLiveArtifact struct {
	Schema              string               `json:"schema"`
	DriverCommand       stage2aDriverCommand `json:"driver_command"`
	DriverRequestSHA256 string               `json:"driver_request_sha256"`
	Processes           []struct {
		ProcessRef          string `json:"process_ref"`
		Role                string `json:"role"`
		PID                 int    `json:"pid"`
		UID                 int    `json:"uid"`
		GID                 int    `json:"gid"`
		PPID                int    `json:"ppid"`
		PGID                int    `json:"pgid"`
		StartIdentity       string `json:"start_identity"`
		ExecutableSHA256    string `json:"executable_sha256"`
		ArgvSHA256          string `json:"argv_sha256"`
		LoadedProfileSHA256 string `json:"loaded_profile_sha256"`
	} `json:"processes"`
	RawRefs  []stage2aLiveRawRef `json:"raw_refs"`
	Attempts []struct {
		AttemptID          string            `json:"attempt_id"`
		Sequence           int               `json:"sequence"`
		ProcessRef         string            `json:"process_ref"`
		DestinationClass   string            `json:"destination_class"`
		DestinationSHA256  string            `json:"destination_sha256"`
		RequestRange       stage2aLiveRange  `json:"request_range"`
		ResponseRange      *stage2aLiveRange `json:"response_range"`
		Result             string            `json:"result"`
		Errno              *int              `json:"errno"`
		StartedMonotonicNS int64             `json:"started_monotonic_ns"`
		EndedMonotonicNS   int64             `json:"ended_monotonic_ns"`
		TimeoutLimitMS     int64             `json:"timeout_limit_ms"`
		CanaryBefore       int64             `json:"canary_before"`
		CanaryAfter        int64             `json:"canary_after"`
	} `json:"attempts"`
	AllowedTurn struct {
		RelaySocketIdentityRef string           `json:"relay_socket_identity_ref"`
		BBindReceiptSHA256     string           `json:"b_bind_receipt_sha256"`
		HTTPRequestRange       stage2aLiveRange `json:"http_request_range"`
		HTTPResponseRange      stage2aLiveRange `json:"http_response_range"`
		HQProviderReceiptRef   string           `json:"hq_provider_receipt_ref"`
		ACPRequestRange        stage2aLiveRange `json:"acp_request_range"`
		ACPResponseRange       stage2aLiveRange `json:"acp_response_range"`
		SoulResultRange        stage2aLiveRange `json:"soul_result_range"`
	} `json:"allowed_turn"`
}

type stage2aLiveCustody struct {
	artifact      []byte
	refs          []stage2aLiveRawRef
	launchWitness []byte
}

// The service entry is the only production path to the receiver. It supplies
// A's own ChildReady/live-launch join on both sides of the transfer. Call it
// without holding the service mutex; the join obtains that lock itself.
func (s *Stage2aService) receiveStage2aLiveCapture(ctx context.Context, conn *net.UnixConn,
	store stage2aAdminClaimStore, session *stage2aQualificationSessionV1,
	command stage2aDriverCommand, requestFrame []byte, peer stage2aQualificationDriverPeer,
	checkLive func() error) (stage2aLiveCustody, error) {
	if s == nil {
		return stage2aLiveCustody{}, errStage2aReservationAuthority
	}
	return receiveStage2aLiveCapture(ctx, conn, store, session, command, requestFrame, peer, checkLive,
		func() ([]byte, error) { return s.observeStage2aLiveLaunchJoin(session, command, requestFrame) })
}

// receiveStage2aLiveCapture reads original bytes rather than a driver path,
// digest or descriptor. A computes names, persists immutable records in its
// guarded store, reopens them, and binds the index to A's exact sent frame.
// The caller must still perform independent OS, socket and canary checks.
func receiveStage2aLiveCapture(ctx context.Context, conn *net.UnixConn, store stage2aAdminClaimStore,
	session *stage2aQualificationSessionV1, command stage2aDriverCommand, requestFrame []byte,
	peer stage2aQualificationDriverPeer, checkLive func() error,
	observeLaunch func() ([]byte, error)) (stage2aLiveCustody, error) {
	var empty stage2aLiveCustody
	if ctx == nil || conn == nil || session == nil || session.closed || checkLive == nil || observeLaunch == nil ||
		ctx.Err() != nil || checkLive() != nil || peer.recheck() != nil ||
		command.Profile != "managed-protected" || command.Phase != stage2aDriverLiveStart ||
		command.Gate != "T03" || command.Event != "direct-route-refused" ||
		command.SessionID != session.begin.SessionID || command.InstallationID != session.begin.InstallationID ||
		command.StartID != session.begin.StartID || command.ReservationSHA256 != session.begin.ReservationSHA256 ||
		command.TestPlanSHA256 != session.begin.TestPlanSHA256 || len(requestFrame) < 5 ||
		int(binary.BigEndian.Uint32(requestFrame[:4])) != len(requestFrame)-4 {
		return empty, errStage2aReservationAuthority
	}
	commandRaw, err := marshalStage2aReservationJCS(command)
	if err != nil || !bytes.Equal(requestFrame[4:], commandRaw) {
		return empty, errStage2aReservationAuthority
	}
	before, err := observeLaunch()
	if err != nil || stage2aQualificationCanonical(before) != nil {
		return empty, errStage2aReservationAuthority
	}
	requestSHA := stage2aQualificationSHA256(requestFrame[4:])
	manifestRaw, err := readStage2aQualificationFrame(conn)
	if err != nil || stage2aQualificationKeysV1Only(manifestRaw,
		[]string{"schema", "kind", "request_sha256", "artifact_size_bytes", "blobs"}) != nil {
		return empty, errStage2aReservationAuthority
	}
	var manifest stage2aLiveTransfer
	if json.Unmarshal(manifestRaw, &manifest) != nil || manifest.Schema != stage2aLiveIntakeSchema ||
		manifest.Kind != "raw-transfer" || manifest.RequestSHA256 != requestSHA ||
		manifest.ArtifactSize < 1 || manifest.ArtifactSize > stage2aQualificationFrameMax ||
		len(manifest.Blobs) < 1 || len(manifest.Blobs) > 96 {
		return empty, errStage2aReservationAuthority
	}
	dir, err := store.open()
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, command.InstallationID)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	defer func() {
		if lock != nil {
			lock.Close()
		}
	}()
	slot := soulStartClaimName(command.InstallationID, command.StartID)
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(command.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-q-session-"+slot, store.uid, store.gid) != nil ||
		requireUnspentStage2aReservation(dir, ".stage2a-closed-"+slot) != nil {
		return empty, errStage2aReservationAuthority
	}
	binding, err := stage2aQualificationSessionBindingBytes(session.begin, session.challengeSHA256, session.peer)
	if err != nil || stage2aExactAdminRecord(dir, ".stage2a-q-binding-"+slot+".json",
		store.uid, store.gid, binding, 8192) != nil {
		return empty, errStage2aReservationAuthority
	}
	if lock.Close() != nil {
		return empty, errStage2aReservationAuthority
	}
	lock = nil
	// Include A's one-use case challenge in every filename. Identical bytes
	// from another command are never silently reused for this session.
	challengeName := strings.TrimPrefix(stage2aQualificationSHA256([]byte(command.Challenge)), "sha256:")
	prefix := ".stage2a-live-" + slot + "-" + challengeName + "-"
	refs := make([]stage2aLiveRawRef, 0, len(manifest.Blobs))
	sizes := make(map[string]int, len(manifest.Blobs))
	purposes := make(map[string]bool, len(manifest.Blobs))
	total := manifest.ArtifactSize
	for _, blob := range manifest.Blobs {
		if blob.SizeBytes < 1 || blob.SizeBytes > stage2aLiveBlobMax ||
			len(blob.Purpose) < 1 || len(blob.Purpose) > 64 || purposes[blob.Purpose] ||
			!stage2aQualificationPrintable(blob.Purpose, 64) {
			return empty, errStage2aReservationAuthority
		}
		purposes[blob.Purpose] = true
		total += blob.SizeBytes
		if total > stage2aLiveTotalMax || ctx.Err() != nil || checkLive() != nil || peer.recheck() != nil {
			return empty, errStage2aReservationAuthority
		}
		raw := make([]byte, blob.SizeBytes)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return empty, errStage2aReservationAuthority
		}
		digest := stage2aQualificationSHA256(raw)
		name := prefix + strings.TrimPrefix(digest, "sha256:")
		lock, err = lockStage2aReservation(dir, store.uid, store.gid, command.InstallationID)
		if err != nil || store.checkDirectory(dir) != nil ||
			stage2aCheckSpentClaim(dir, stage2aActiveClaimName(command.InstallationID), store.uid, store.gid) != nil ||
			stage2aCheckSpentClaim(dir, ".stage2a-q-session-"+slot, store.uid, store.gid) != nil ||
			requireUnspentStage2aReservation(dir, ".stage2a-closed-"+slot) != nil ||
			stage2aExactAdminRecord(dir, ".stage2a-q-binding-"+slot+".json",
				store.uid, store.gid, binding, 8192) != nil ||
			commitStage2aReservation(dir, name, raw) != nil ||
			stage2aExactAdminRecord(dir, name, store.uid, store.gid, raw, stage2aLiveBlobMax) != nil {
			return empty, errStage2aReservationAuthority
		}
		if lock.Close() != nil {
			return empty, errStage2aReservationAuthority
		}
		lock = nil
		if _, found := sizes[digest]; found {
			return empty, errStage2aReservationAuthority
		}
		sizes[digest] = len(raw)
		refs = append(refs, stage2aLiveRawRef{SHA256: digest, SizeBytes: len(raw), Purpose: blob.Purpose})
	}
	artifact := make([]byte, manifest.ArtifactSize)
	if _, err := io.ReadFull(conn, artifact); err != nil || stage2aQualificationCanonical(artifact) != nil ||
		ctx.Err() != nil || checkLive() != nil || peer.recheck() != nil {
		return empty, errStage2aReservationAuthority
	}
	var index stage2aLiveArtifact
	if stage2aLiveArtifactShape(artifact) != nil ||
		stage2aDecodeExact(artifact, &index) != nil ||
		index.Schema != "agent-bot-adapters/t03-stock-claude-direct-attempts/v1" ||
		index.DriverCommand != command || index.DriverRequestSHA256 != requestSHA ||
		len(index.RawRefs) != len(refs) || len(index.Processes) < 2 || len(index.Processes) > 8 ||
		len(index.Attempts) < 1 || len(index.Attempts) > 64 ||
		!stage2aQualificationDigest(index.AllowedTurn.RelaySocketIdentityRef) ||
		!stage2aQualificationDigest(index.AllowedTurn.BBindReceiptSHA256) ||
		!stage2aQualificationDigest(index.AllowedTurn.HQProviderReceiptRef) {
		return empty, errStage2aReservationAuthority
	}
	processes := make(map[string]string, len(index.Processes))
	var acp, cli bool
	for _, process := range index.Processes {
		if !stage2aLiveArtifactID.MatchString(process.ProcessRef) ||
			processes[process.ProcessRef] != "" || process.PID <= 1 || process.UID <= 0 ||
			process.GID <= 0 || process.PPID <= 1 || process.PGID <= 1 ||
			len(process.StartIdentity) == 0 || len(process.StartIdentity) > 128 ||
			!stage2aQualificationDigest(process.ExecutableSHA256) ||
			!stage2aQualificationDigest(process.ArgvSHA256) ||
			!stage2aQualificationDigest(process.LoadedProfileSHA256) ||
			(process.Role != "acp" && process.Role != "claude-cli" && process.Role != "b-sidecar") {
			return empty, errStage2aReservationAuthority
		}
		processes[process.ProcessRef] = process.Role
		acp = acp || process.Role == "acp"
		cli = cli || process.Role == "claude-cli"
	}
	if !acp || !cli {
		return empty, errStage2aReservationAuthority
	}
	for i, ref := range index.RawRefs {
		if ref != refs[i] {
			return empty, errStage2aReservationAuthority
		}
	}
	checkRange := func(r stage2aLiveRange) bool {
		size, ok := sizes[r.BlobSHA256]
		if ok && r.OffsetBytes >= 0 && r.LengthBytes > 0 && r.OffsetBytes <= size && r.LengthBytes <= size-r.OffsetBytes {
			return true
		}
		return false
	}
	ids := make(map[string]bool, len(index.Attempts))
	var lastStart int64
	for i, attempt := range index.Attempts {
		role := processes[attempt.ProcessRef]
		if !stage2aLiveArtifactID.MatchString(attempt.AttemptID) || ids[attempt.AttemptID] ||
			role == "" || !stage2aQualificationDigest(attempt.DestinationSHA256) ||
			!stage2aLiveDestinationClass(attempt.DestinationClass) ||
			attempt.Result != "refused" && attempt.Result != "connected" ||
			attempt.Errno != nil && *attempt.Errno < 0 ||
			attempt.CanaryBefore < 0 || attempt.CanaryAfter < 0 ||
			attempt.Sequence != i+1 || attempt.StartedMonotonicNS < lastStart ||
			attempt.EndedMonotonicNS < attempt.StartedMonotonicNS ||
			attempt.TimeoutLimitMS < 1 || attempt.TimeoutLimitMS > 120000 ||
			attempt.EndedMonotonicNS-attempt.StartedMonotonicNS > attempt.TimeoutLimitMS*1_000_000 ||
			!checkRange(attempt.RequestRange) ||
			(attempt.ResponseRange != nil && !checkRange(*attempt.ResponseRange)) {
			return empty, errStage2aReservationAuthority
		}
		if attempt.DestinationClass != "assigned-relay" &&
			(role != "claude-cli" || attempt.Result != "refused" ||
				attempt.Errno == nil || attempt.CanaryBefore != attempt.CanaryAfter) {
			return empty, errStage2aReservationAuthority
		}
		ids[attempt.AttemptID] = true
		lastStart = attempt.StartedMonotonicNS
	}
	for _, r := range []stage2aLiveRange{index.AllowedTurn.HTTPRequestRange,
		index.AllowedTurn.HTTPResponseRange, index.AllowedTurn.ACPRequestRange,
		index.AllowedTurn.ACPResponseRange, index.AllowedTurn.SoulResultRange} {
		if !checkRange(r) {
			return empty, errStage2aReservationAuthority
		}
	}
	// The A witness takes the service mutex and installation lock. No raw
	// transfer read or witness callback holds our installation lock.
	// The final index becomes visible only if A's independently observed
	// launch is the same after reading every source byte. Earlier immutable
	// blobs on a failed transfer carry no completion or T03 credit.
	after, err := observeLaunch()
	if err != nil || !bytes.Equal(before, after) || ctx.Err() != nil ||
		checkLive() != nil || peer.recheck() != nil {
		return empty, errStage2aReservationAuthority
	}
	lock, err = lockStage2aReservation(dir, store.uid, store.gid, command.InstallationID)
	if err != nil || store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(command.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-q-session-"+slot, store.uid, store.gid) != nil ||
		requireUnspentStage2aReservation(dir, ".stage2a-closed-"+slot) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-q-binding-"+slot+".json",
			store.uid, store.gid, binding, 8192) != nil {
		return empty, errStage2aReservationAuthority
	}
	name := prefix + "index-" + strings.TrimPrefix(stage2aQualificationSHA256(artifact), "sha256:")
	if commitStage2aReservation(dir, name, artifact) != nil ||
		stage2aExactAdminRecord(dir, name, store.uid, store.gid, artifact, stage2aQualificationFrameMax) != nil ||
		store.checkDirectory(dir) != nil || ctx.Err() != nil || checkLive() != nil || peer.recheck() != nil {
		return empty, errStage2aReservationAuthority
	}
	return stage2aLiveCustody{artifact: artifact, refs: refs, launchWitness: before}, nil
}

func stage2aQualificationKeysV1Only(raw []byte, keys []string) error {
	_, err := stage2aQualificationKeysV1(raw, keys, "")
	return err
}

// The draft raw artifact has closed keys at every evidence-bearing level.
// A missing nullable field must not silently become a Go zero value.
func stage2aLiveArtifactShape(raw []byte) error {
	fields, err := stage2aQualificationKeysV1(raw,
		[]string{"schema", "driver_command", "driver_request_sha256", "processes",
			"attempts", "allowed_turn", "raw_refs"}, "")
	if err != nil {
		return err
	}
	var processes, attempts []json.RawMessage
	if json.Unmarshal(fields["processes"], &processes) != nil ||
		json.Unmarshal(fields["attempts"], &attempts) != nil ||
		stage2aQualificationKeysV1Only(fields["allowed_turn"], []string{
			"relay_socket_identity_ref", "b_bind_receipt_sha256", "http_request_range",
			"http_response_range", "hq_provider_receipt_ref", "acp_request_range",
			"acp_response_range", "soul_result_range"}) != nil {
		return errStage2aReservationAuthority
	}
	for _, process := range processes {
		if stage2aQualificationKeysV1Only(process, []string{"process_ref", "role", "pid", "uid", "gid",
			"ppid", "pgid", "start_identity", "executable_sha256", "argv_sha256",
			"loaded_profile_sha256"}) != nil {
			return errStage2aReservationAuthority
		}
	}
	for _, attempt := range attempts {
		if stage2aQualificationKeysV1Only(attempt, []string{"attempt_id", "sequence", "process_ref",
			"destination_class", "destination_sha256", "request_range", "response_range",
			"result", "errno", "started_monotonic_ns", "ended_monotonic_ns",
			"timeout_limit_ms", "canary_before", "canary_after"}) != nil {
			return errStage2aReservationAuthority
		}
	}
	return nil
}

func stage2aLiveDestinationClass(value string) bool {
	switch value {
	case "ipv4", "ipv6", "sibling-broker", "sibling-member", "sibling-relay",
		"hq-admission", "assigned-relay":
		return true
	default:
		return false
	}
}
