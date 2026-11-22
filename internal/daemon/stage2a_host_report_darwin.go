//go:build darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"time"

	"github.com/qwts/managed-machine/internal/qualification"
)

// signStage2aHostReportV3 is the A-local keyd transport after the Stage 2a
// service has authenticated a completed physical run. It is not an HQ verb:
// the caller must supply only the report assembled from that completed run.
// policyAt must load and verify the installed owner policy and revision ledger
// for its exact argument time; it is called again after keyd returns.
func signStage2aHostReportV3(ctx context.Context, adminHome string, machine ed25519.PrivateKey,
	report, executionCompletionEnvelope []byte, hostID, signerID string,
	policyAt func(time.Time) (qualification.VerifiedPolicy, error), provider deviceProvider) ([]byte, error) {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || len(machine) != ed25519.PrivateKeySize ||
		len(report) == 0 || len(report) > qualification.MaxReportBytes ||
		len(executionCompletionEnvelope) == 0 || len(executionCompletionEnvelope) > qualification.MaxReportBytes ||
		hostID == "" || signerID == "" || policyAt == nil || provider == nil {
		return nil, errHQDevice
	}
	dir := stateDir(adminHome)
	unlock, err := lockDevicePairing(dir)
	if err != nil {
		return nil, errHQDevice
	}
	defer unlock()
	pair, err := currentDevicePairing(dir)
	pinned, pinErr := loadPublic(filepath.Join(dir, "daemon.pub"))
	if err != nil || pinErr != nil || !pinned.Equal(machine.Public()) ||
		!exactKey(pair.HQEpoch) || !devicePairAllows(pair, pair.AgentDaemonUID, pair.AgentDaemon) {
		return nil, errHQDevice
	}
	before := time.Now()
	if qualification.VerifyExecutionCompletionBeforeSignV3(report, executionCompletionEnvelope,
		machine.Public().(ed25519.PublicKey), before) != nil {
		return nil, errHQDevice
	}
	policy, err := policyAt(before)
	if err != nil || qualification.CheckDesignatedHostSignerV3(policy, hostID, signerID, before) != nil {
		return nil, errHQDevice
	}
	revision, policyDigest, err := policy.RevisionDigest()
	if err != nil {
		return nil, errHQDevice
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, errHQDevice
	}
	delegation := deviceDelegation{
		Epoch: pair.HQEpoch, Machine: base64.StdEncoding.EncodeToString(machine.Public().(ed25519.PublicKey)),
		HQ: base64.StdEncoding.EncodeToString(pair.AgentDaemon), UID: pair.AgentDaemonUID,
		Nonce: nonce, Timestamp: before.Unix(), Option: "qualification-host-report-v3",
		ReportBase64URL: base64.RawURLEncoding.EncodeToString(report), HostID: hostID, SignerID: signerID,
	}
	delegation.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(machine, delegation.transcript()))
	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	envelope, err := provider(callCtx, adminHome, delegation)
	if err != nil {
		return nil, errHQDevice
	}
	after := time.Now()
	current, currentErr := currentDevicePairing(dir)
	if currentErr != nil || current.HQEpoch != pair.HQEpoch ||
		!devicePairAllows(current, pair.AgentDaemonUID, pair.AgentDaemon) {
		return nil, errHQDevice
	}
	policy, err = policyAt(after)
	if err != nil || qualification.CheckDesignatedHostSignerV3(policy, hostID, signerID, after) != nil {
		return nil, errHQDevice
	}
	newRevision, newDigest, err := policy.RevisionDigest()
	if err != nil || newRevision != revision || newDigest != policyDigest {
		return nil, errHQDevice
	}
	verified, err := qualification.VerifyHostReportV3(envelope, policy, after)
	if err != nil || !bytes.Equal(verified, report) {
		return nil, errHQDevice
	}
	return envelope, nil
}
