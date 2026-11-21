package members

import (
	"errors"
	"fmt"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

// A failed or interrupted apply consumes its receipt. A fresh plan covers only
// what remains. The prefix or HQ cannot turn a broad or unpaired approval into
// authority to create accounts.
func runHarnessAccountApply(s Saved, a Approval, platform, owner string, h Host, deps Deps, paired func(Approval, func() error) error) cli.Result {
	p := s.Plan
	if platform != PlatformDarwin || p.Purpose != HarnessAccountsPurpose || a.Purpose != HarnessAccountsPurpose || len(p.Steps) == 0 || s.PlanDigest != a.PlanDigest || !digestPattern.MatchString(a.PairCommitment) || !digestPattern.MatchString(a.MachineFingerprint) {
		return failure(diag.MembersNotApproved, "harness account provisioning requires the matching paired owner approval")
	}
	var r Root = OSRoot{}
	if deps.Root != nil {
		r = deps.Root()
	}
	refused := func(err error) cli.Result {
		return failure(diag.MembersNotApproved, "harness account apply refused: %v", err)
	}
	if err := paired(a, nil); err != nil {
		return refused(err)
	}
	if err := checkDarwinHarnessAccounts(s, owner, p.Steps[0].UID, h); err != nil {
		return refused(err)
	}
	if err := Precheck(p, r); err != nil {
		return refused(err)
	}

	// Revocation takes the exclusive pairing lock. Claim and mutate in
	// separate shared lock intervals so a completed revocation stops the next step.
	receipt := Receipt{PlanID: s.PlanID, PlanDigest: s.PlanDigest, Owner: owner, HQAccount: p.HQAccount, Dir: p.Dir, Members: p.Members, Changes: p.Changes(), Result: "started"}
	err := paired(a, func() error {
		expires, err := time.Parse(approvalTime, a.ExpiresAt)
		now := deps.Time().UTC()
		if err != nil || !now.Before(expires) {
			return errors.New("harness owner approval expired before the receipt was claimed")
		}
		receipt.StartedAt = now.Format(approvalTime)
		claimed, err := r.Claim(s.PlanID, encodeReceipt(receipt))
		if err != nil {
			return err
		}
		if !claimed {
			return errors.New("this approval was already used; replan any remaining work")
		}
		return nil
	})
	if err != nil {
		return refused(err)
	}

	failedAt := "verification"
	for _, step := range p.Steps {
		if step.Action == ActionNone {
			continue
		}
		err = paired(a, func() error { return applyReviewedHarnessStep(p, step, h, r) })
		if err != nil {
			failedAt = step.Kind + " " + step.Target
			break
		}
	}
	if err == nil {
		err = paired(a, func() error {
			after, err := Build(Input{HarnessAccounts: true, Platform: platform, HQAccount: p.HQAccount, Members: p.Members, Dir: p.Dir, Invoker: owner}, h)
			if err != nil {
				return err
			}
			if after.Changes() != 0 || len(after.Steps) != len(p.Steps) {
				return errors.New("reviewed harness account changes are incomplete")
			}
			for i, step := range after.Steps {
				if step.UID != p.Steps[i].UID || step.GID != p.Steps[i].GID {
					return errors.New("reviewed account identity changed")
				}
			}
			return Precheck(after, r)
		})
	}
	receipt.Result = "applied"
	if err != nil {
		receipt.Result, receipt.FailedAt = "failed", failedAt
	}
	receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
	if err = errors.Join(err, r.Finish(s.PlanID, encodeReceipt(receipt))); err != nil {
		return failure(diag.MembersApplyFailed, "harness provisioning stopped; replan remaining work: %v", err)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("plan_id", s.PlanID).Set("plan_digest", s.PlanDigest).Set("changes", p.Changes()).Set("applied", true).Set("receipt", ReceiptPath(s.PlanID))}}
}

func applyReviewedHarnessStep(p Plan, s Step, h Host, r Root) error {
	if s.Kind == KindDirectory && s.Action == ActionCreate {
		ops, ok := r.(interface {
			CreateReviewedBrokerDirectory(string, string, string, uint32, int, int) error
		})
		if !ok {
			return errors.New("protected broker directories unavailable")
		}
		if s.Target == DarwinBrokerDir {
			return ops.CreateReviewedBrokerDirectory(s.Target, s.Owner, s.Group, 0755, 0, 0)
		}
		for _, member := range p.Steps {
			if member.Kind == KindAccount && member.Target == s.Group {
				return ops.CreateReviewedBrokerDirectory(s.Target, s.Owner, s.Group, 02750, p.Steps[0].UID, member.GID)
			}
		}
		return errors.New("broker directory has no reviewed private group")
	}
	ops, ok := r.(interface {
		CreateReviewedHarness(string, int) error
		RepairReviewedHarnessHome(string, int, uint32) error
	})
	if !ok || s.Kind != KindAccount {
		return errors.New("unsupported protected harness operation")
	}
	switch s.Action {
	case ActionCreate:
		return ops.CreateReviewedHarness(s.Target, s.UID)
	case ActionRepair:
		entry, ok, err := h.Lstat(darwinHarnessHome(s.Target))
		if err != nil {
			return err
		}
		if !ok || !entry.Dir || entry.Owner != s.Target || entry.Group != s.Target || s.Detail != accountHomeRepairDetail(darwinHarnessHome(s.Target), entry.Mode&07777) {
			return errors.New("reviewed home mode or ownership changed")
		}
		return ops.RepairReviewedHarnessHome(s.Target, s.UID, entry.Mode&07777)
	default:
		return fmt.Errorf("unexpected protected account action %s", s.Action)
	}
}
