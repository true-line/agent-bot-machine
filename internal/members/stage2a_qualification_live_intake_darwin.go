//go:build darwin

package members

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
)

const (
	stage2aLiveIntakeSchema = "agent-bot-machine/stage2a-live-intake/v1"
	stage2aLiveBlobMax      = 4 << 20
	stage2aLiveTotalMax     = 8 << 20
)

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
	RawRefs             []stage2aLiveRawRef  `json:"raw_refs"`
	Attempts            []struct {
		AttemptID          string            `json:"attempt_id"`
		Sequence           int               `json:"sequence"`
		ProcessRef         string            `json:"process_ref"`
		RequestRange       stage2aLiveRange  `json:"request_range"`
		ResponseRange      *stage2aLiveRange `json:"response_range"`
		StartedMonotonicNS int64             `json:"started_monotonic_ns"`
		EndedMonotonicNS   int64             `json:"ended_monotonic_ns"`
		TimeoutLimitMS     int64             `json:"timeout_limit_ms"`
	} `json:"attempts"`
	AllowedTurn struct {
		HTTPRequestRange  stage2aLiveRange `json:"http_request_range"`
		HTTPResponseRange stage2aLiveRange `json:"http_response_range"`
		ACPRequestRange   stage2aLiveRange `json:"acp_request_range"`
		ACPResponseRange  stage2aLiveRange `json:"acp_response_range"`
		SoulResultRange   stage2aLiveRange `json:"soul_result_range"`
	} `json:"allowed_turn"`
}

type stage2aLiveCustody struct {
	artifact      []byte
	refs          []stage2aLiveRawRef
	launchWitness []byte
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
	defer lock.Close()
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
		if commitStage2aReservation(dir, name, raw) != nil ||
			stage2aExactAdminRecord(dir, name, store.uid, store.gid, raw, stage2aLiveBlobMax) != nil {
			return empty, errStage2aReservationAuthority
		}
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
	if stage2aQualificationKeysV1Only(artifact, []string{"schema", "driver_command", "driver_request_sha256",
		"processes", "attempts", "allowed_turn", "raw_refs"}) != nil ||
		json.Unmarshal(artifact, &index) != nil ||
		index.Schema != "agent-bot-adapters/t03-stock-claude-direct-attempts/v1" ||
		index.DriverCommand != command || index.DriverRequestSHA256 != requestSHA ||
		len(index.RawRefs) != len(refs) || len(index.Attempts) < 1 || len(index.Attempts) > 64 {
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
		if attempt.AttemptID == "" || ids[attempt.AttemptID] || attempt.ProcessRef == "" ||
			attempt.Sequence != i+1 || attempt.StartedMonotonicNS < lastStart ||
			attempt.EndedMonotonicNS < attempt.StartedMonotonicNS || attempt.TimeoutLimitMS < 1 ||
			!checkRange(attempt.RequestRange) ||
			(attempt.ResponseRange != nil && !checkRange(*attempt.ResponseRange)) {
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
	// The final index becomes visible only if A's independently observed
	// launch is the same after reading every source byte. Earlier immutable
	// blobs on a failed transfer carry no completion or T03 credit.
	after, err := observeLaunch()
	if err != nil || !bytes.Equal(before, after) || ctx.Err() != nil ||
		checkLive() != nil || peer.recheck() != nil {
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
