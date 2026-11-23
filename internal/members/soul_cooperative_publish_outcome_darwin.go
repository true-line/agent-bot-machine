//go:build darwin

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
	"os"
	"path/filepath"
	"strconv"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/sys/unix"
)

const soulCooperativePublishOutcomePurposeV3 = "agent-bot/soul-cooperative-publish-outcome/v3"
const soulCooperativeOutcomeSidecarSchema = "agent-bot-machine/soul-cooperative-published-handoff/v1"

type soulCooperativeRequestIdentity struct {
	Device      string `json:"device"`
	Inode       string `json:"inode"`
	BirthtimeNS string `json:"birthtime_ns"`
	OwnerUID    int    `json:"owner_uid"`
	GroupGID    int    `json:"group_gid"`
	Mode        uint32 `json:"mode"`
}

type soulCooperativePublishOutcomePayloadV3 struct {
	Contract               string `json:"contract"`
	Kind                   string `json:"kind"`
	SchemaVersion          int    `json:"schema_version"`
	ReservationSHA256      string `json:"reservation_sha256"`
	BridgeAssignmentSHA256 string `json:"bridge_assignment_sha256"`
	OrderSHA256            string `json:"order_sha256"`
	RequestSHA256          string `json:"request_sha256"`
	RequestDevice          string `json:"request_device"`
	RequestInode           string `json:"request_inode"`
	RequestBirthtimeNS     string `json:"request_birthtime_ns"`
	InstallationID         string `json:"installation_id"`
	StartID                string `json:"start_id"`
	LaunchID               string `json:"launch_id"`
	PublishedAt            string `json:"published_at"`
	ExpiresAt              string `json:"expires_at"`
	PublicationMode        string `json:"publication_mode"`
}

type soulCooperativePublishedHandoff struct {
	Schema                               string                         `json:"schema"`
	ReservationSHA256                    string                         `json:"reservation_sha256"`
	RequestIdentity                      soulCooperativeRequestIdentity `json:"request_identity"`
	PublishOutcomeEnvelopeBase64URL      string                         `json:"publish_outcome_envelope_base64url"`
	BridgeAssignmentEnvelopeBase64URL    string                         `json:"bridge_assignment_envelope_base64url"`
	MemberSetAssignmentEnvelopeBase64URL string                         `json:"member_set_assignment_envelope_base64url"`
}

func observedCooperativeRequestIdentity(paths soulCooperativeLaunchPaths, machineUID, runnerGID int,
	request []byte) (soulCooperativeRequestIdentity, error) {
	var empty soulCooperativeRequestIdentity
	dir, err := openStage2aAdminDirectory(paths.requestDir, uint32(machineUID))
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(paths.request), stage2aFileOpenFlags, 0)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0640 || st.Uid != uint32(machineUID) ||
		st.Gid != uint32(runnerGID) || st.Nlink != 1 || st.Size != int64(len(request)) ||
		st.Dev <= 0 || st.Ino == 0 || st.Btim.Sec <= 0 ||
		checkDarwinACLs([]string{paths.request}) != nil {
		return empty, errSoulCooperativeAuthority
	}
	// Dup prevents os.File.Close from owning the checked descriptor.
	dup, err := unix.Dup(fd)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(dup), paths.request)
	defer f.Close()
	body := make([]byte, len(request))
	if _, err := io.ReadFull(f, body); err != nil || !bytes.Equal(body, request) {
		return empty, errSoulCooperativeAuthority
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !stage2aSameNode(st, after) {
		return empty, errSoulCooperativeAuthority
	}
	birth := st.Btim.Sec*1_000_000_000 + st.Btim.Nsec
	if birth <= 0 {
		return empty, errSoulCooperativeAuthority
	}
	return soulCooperativeRequestIdentity{Device: strconv.FormatUint(uint64(uint32(st.Dev)), 10),
		Inode: strconv.FormatUint(st.Ino, 10), BirthtimeNS: strconv.FormatInt(birth, 10),
		OwnerUID: machineUID, GroupGID: runnerGID, Mode: 0640}, nil
}

func publishSoulCooperativeOutcomeV3(paths soulCooperativeLaunchPaths,
	p SoulCooperativeLaunchPolicy, q SoulCooperativeReserveRequest,
	reservationSHA, bridgeSHA string, request, bridgeEnvelope, memberEnvelope []byte,
	issued time.Time, key ed25519.PublicKey, sign func([]byte) ([]byte, error)) error {
	if len(key) != ed25519.PublicKeySize || sign == nil ||
		!stage2aPrefixedDigest.MatchString(reservationSHA) ||
		!stage2aPrefixedDigest.MatchString(bridgeSHA) ||
		len(bridgeEnvelope) == 0 || len(memberEnvelope) == 0 {
		return errSoulCooperativeAuthority
	}
	identity, err := observedCooperativeRequestIdentity(paths, p.MachineUID, p.Runner.GID, request)
	if err != nil {
		return err
	}
	published := time.Now().UTC()
	expires := issued.Add(30 * time.Second)
	if !published.Before(expires) {
		return errSoulCooperativeAuthority
	}
	// The A-private pending claim was already committed and fsynced with these
	// exact request bytes before the watched rename. Its digest is the order.
	orderSHA := fmt.Sprintf("sha256:%x", sha256.Sum256(request))
	payload := soulCooperativePublishOutcomePayloadV3{Contract: "machine/v3",
		Kind: "soul-cooperative-publish-outcome", SchemaVersion: 3,
		ReservationSHA256: reservationSHA, BridgeAssignmentSHA256: bridgeSHA,
		OrderSHA256: orderSHA, RequestSHA256: orderSHA,
		RequestDevice: identity.Device, RequestInode: identity.Inode,
		RequestBirthtimeNS: identity.BirthtimeNS, InstallationID: q.InstallationID,
		StartID: q.StartID, LaunchID: q.LaunchID,
		PublishedAt: published.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano),
		PublicationMode: "direct"}
	envelope, err := signStage2aEnvelope(payload, 3, soulCooperativePublishOutcomePurposeV3, key, sign)
	if err != nil || len(envelope) > 8192 {
		return errSoulCooperativeAuthority
	}
	sidecar := soulCooperativePublishedHandoff{Schema: soulCooperativeOutcomeSidecarSchema,
		ReservationSHA256: reservationSHA, RequestIdentity: identity,
		PublishOutcomeEnvelopeBase64URL:      base64.RawURLEncoding.EncodeToString(envelope),
		BridgeAssignmentEnvelopeBase64URL:    base64.RawURLEncoding.EncodeToString(bridgeEnvelope),
		MemberSetAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(memberEnvelope)}
	raw, err := json.Marshal(sidecar)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > 32<<10 {
		return errSoulCooperativeAuthority
	}
	if _, err := os.Lstat(paths.outcome); !errors.Is(err, os.ErrNotExist) {
		return errSoulCooperativeAuthority
	}
	f, err := os.CreateTemp(paths.stagingDir, ".outcome-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0440); err == nil {
		_, err = f.Write(canonical)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := unix.RenamexNp(f.Name(), paths.outcome, unix.RENAME_EXCL); err != nil {
		return err
	}
	if err := syncUpgradeDir(paths.stagingDir); err != nil {
		return err
	}
	return syncUpgradeDir(paths.requestDir)
}
