package daemon

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
)

// approveMembers records the owner's approval of one member accounts plan
// in the daemon state directory and returns it. It reads no plan and runs
// nothing: the plan is private to the account that made it, and the root
// apply is what compares its own rebuilt digest with the one recorded here.
// Member accounts are Linux only, so every other host refuses first.
func approveMembers(goos, dir, planID, digest string, now time.Time) ([]byte, string, string) {
	if goos != "linux" {
		return nil, diag.MembersUnsupported, "member accounts are Linux only"
	}
	approval, err := members.RecordApproval(dir, planID, digest, now)
	if errors.Is(err, members.ErrApprovalMalformed) {
		return nil, diag.DaemonUndeclared, err.Error()
	}
	if err != nil {
		return nil, diag.DaemonPlanFailed, "approval could not be recorded"
	}
	body, err := json.Marshal(approval)
	if err != nil {
		return nil, diag.DaemonPlanFailed, "approval could not be encoded"
	}
	return body, "", ""
}
