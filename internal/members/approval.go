package members

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/plan"
)

// ApprovalTTL is how long an approval allows an apply.
const ApprovalTTL = 10 * time.Minute

const approvalTime = "2006-01-02T15:04:05Z"

// Approval is the owner's consent to one plan digest. agent-machine writes
// it in its own state directory when it accepts a signed approve-members
// request; the root apply reads it. It holds no secret.
type Approval struct {
	PlanID     string `json:"plan_id"`
	PlanDigest string `json:"plan_digest"`
	ApprovedAt string `json:"approved_at"`
	ExpiresAt  string `json:"expires_at"`
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrApprovalMalformed is a plan ID or digest that is not in its fixed form.
var ErrApprovalMalformed = errors.New("plan_id or plan_digest is malformed")

// ValidApproval reports whether the two identifiers have their fixed forms.
// The plan ID becomes a file name, so nothing else may reach the disk.
func ValidApproval(planID, digest string) bool {
	return plan.ValidID(planID) && digestPattern.MatchString(digest)
}

// ApprovalsDir is where approvals live under a daemon state directory.
func ApprovalsDir(state string) string {
	return filepath.Join(state, "members", "approvals")
}

// ApprovalPath is the approval file for one plan.
func ApprovalPath(state, planID string) string {
	return filepath.Join(ApprovalsDir(state), planID+".json")
}

// RecordApproval writes the approval for planID, replacing an earlier one,
// and removes approvals that have expired. The directory is private to the
// account that runs it.
func RecordApproval(state, planID, digest string, now time.Time) (Approval, error) {
	if !ValidApproval(planID, digest) {
		return Approval{}, ErrApprovalMalformed
	}
	dir := ApprovalsDir(state)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Approval{}, err
	}
	pruneApprovals(dir, now)
	a := Approval{
		PlanID:     planID,
		PlanDigest: digest,
		ApprovedAt: now.UTC().Format(approvalTime),
		ExpiresAt:  now.Add(ApprovalTTL).UTC().Format(approvalTime),
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return Approval{}, err
	}
	tmp, err := os.CreateTemp(dir, ".approval-*")
	if err != nil {
		return Approval{}, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return Approval{}, err
	}
	if err := tmp.Close(); err != nil {
		return Approval{}, err
	}
	if err := os.Rename(tmp.Name(), ApprovalPath(state, planID)); err != nil {
		return Approval{}, err
	}
	return a, nil
}

// pruneApprovals removes expired and unreadable approval files, so the
// directory holds at most the approvals of the last ten minutes.
func pruneApprovals(dir string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var a Approval
		expires, perr := time.Time{}, error(nil)
		if err := json.Unmarshal(raw, &a); err == nil {
			expires, perr = time.Parse(approvalTime, a.ExpiresAt)
		} else {
			perr = err
		}
		if perr != nil || !now.Before(expires) {
			_ = os.Remove(path)
		}
	}
}
