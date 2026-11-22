//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// A started claim is spent even if its caller crashes before launching. This
// private record is not a signed reservation or permission to run a Soul.
// The production caller must first establish the installed root receipt,
// owner policy, immutable package closure, and live dedicated HQ pairing.
type soulStartClaim struct {
	Schema           string `json:"schema"`
	PlanID           string `json:"plan_id"`
	PlanDigest       string `json:"plan_digest"`
	InstallationID   string `json:"installation_id"`
	StartID          string `json:"start_id"`
	LaunchID         string `json:"launch_id"`
	RuntimeID        string `json:"runtime_id"`
	HQEpoch          string `json:"hq_epoch"`
	AssignmentSHA256 string `json:"assignment_sha256"`
	StartedAt        string `json:"started_at"`
	ExpiresAt        string `json:"expires_at"`
	State            string `json:"state"`
}

const soulStartClaimsDir = "/private/var/db/managed-machine/soul-starts/claims"

func soulStartClaimName(installationID, startID string) string {
	key := sha256.Sum256([]byte("agent-bot-soul-start-claim/v1\x00" + installationID + "\x00" + startID))
	return fmt.Sprintf("%x.json", key)
}

func soulStartClaimPath(installationID, startID string) string {
	return filepath.Join(soulStartClaimsDir, soulStartClaimName(installationID, startID))
}

// prepareSoulStartClaim binds the exact canonical assignment to a durable
// single-use name. The installed bytes and live request are rechecked here,
// but their root receipt and pairing still require an independent caller.
func prepareSoulStartClaim(assignment SoulStartAssignment, installedID string, installedCanonical []byte,
	runner SoulRunner, bridge SoulBridge, hqUID, machineUID int,
	live SoulRunRequest, launchID, runtimeID string, now time.Time) (soulStartClaim, error) {
	if CheckSoulStartAssignment(assignment, installedID, installedCanonical,
		runner, bridge, hqUID, machineUID, live, launchID, runtimeID, now) != nil {
		return soulStartClaim{}, errors.New("Soul start claim differs from installed and live state")
	}
	assignmentBytes, err := json.Marshal(assignment)
	if err != nil {
		return soulStartClaim{}, err
	}
	return soulStartClaim{
		Schema: "agent-bot-machine/soul-start-claim/v1", PlanID: assignment.PlanID,
		PlanDigest: assignment.PlanDigest, InstallationID: assignment.InstallationID,
		StartID: assignment.StartID, LaunchID: assignment.LaunchID,
		RuntimeID: assignment.RuntimeID, HQEpoch: assignment.HQEpoch,
		AssignmentSHA256: fmt.Sprintf("%x", sha256.Sum256(assignmentBytes)),
		StartedAt:        now.UTC().Format(time.RFC3339Nano), ExpiresAt: assignment.ExpiresAt,
		State: "started",
	}, nil
}

func (c soulStartClaim) valid(path string) bool {
	if c.Schema != "agent-bot-machine/soul-start-claim/v1" || c.State != "started" ||
		!ValidApproval(c.PlanID, c.PlanDigest) || !soulInstallationID.MatchString(c.InstallationID) ||
		!soulStartID.MatchString(c.StartID) || !soulLaunchID.MatchString(c.LaunchID) ||
		!soulInstallationID.MatchString(c.RuntimeID) || !soulHQEpoch.MatchString(c.HQEpoch) ||
		!soulDigest.MatchString(c.AssignmentSHA256) || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || filepath.Base(path) != soulStartClaimName(c.InstallationID, c.StartID) {
		return false
	}
	started, e1 := time.Parse(time.RFC3339Nano, c.StartedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	return e1 == nil && e2 == nil && expires.After(started) && expires.Sub(started) <= 30*time.Second &&
		c.StartedAt == started.UTC().Format(time.RFC3339Nano) &&
		c.ExpiresAt == expires.UTC().Format(time.RFC3339Nano)
}

// claimSoulStartOnceFile publishes a complete, immutable spent record with
// exclusive rename and parent-directory sync. A sync error may leave the
// name occupied, which must still be treated as spent on retry.
func claimSoulStartOnceFile(path string, claim soulStartClaim) error {
	if !claim.valid(path) {
		return errors.New("invalid Soul start claim")
	}
	raw, err := json.Marshal(claim)
	if err != nil {
		return err
	}
	return writeUpgradeFile(path, append(raw, '\n'), 0600, true)
}

// claimSoulStartOnce is deliberately unreachable from a daemon or launcher
// until the installed authority and active-installation lock are implemented.
// The root-only directory must be created by a separate owner-reviewed grant.
func claimSoulStartOnce(claim soulStartClaim) error {
	if os.Geteuid() != 0 {
		return errors.New("Soul start claims require Machine administrator custody")
	}
	if err := trustedPath(OSHost{}, soulStartClaimsDir, true); err != nil {
		return err
	}
	if err := checkDarwinACLs(pathAncestry(soulStartClaimsDir)); err != nil {
		return err
	}
	st, err := os.Lstat(soulStartClaimsDir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("Soul start claim directory is not private to Machine")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != 0 {
		return errors.New("Soul start claim directory changed owner")
	}
	return claimSoulStartOnceFile(soulStartClaimPath(claim.InstallationID, claim.StartID), claim)
}
