package members

import (
	"errors"
	"fmt"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

func runSoulRunnerAccountApply(s Saved, a Approval, owner string, h Host, deps Deps, paired func(Approval, func() error) error) cli.Result {
	p := s.Plan
	if p.Purpose != SoulRunnerAccountsPurpose || len(p.Steps) == 0 || a.Purpose != SoulRunnerAccountsPurpose || s.PlanDigest != a.PlanDigest ||
		!digestPattern.MatchString(a.PairCommitment) || !digestPattern.MatchString(a.MachineFingerprint) {
		return failure(diag.MembersNotApproved, "Soul runner accounts require their own paired owner approval")
	}
	var root Root = OSRoot{}
	if deps.Root != nil {
		root = deps.Root()
	}
	refused := func(err error) cli.Result {
		return failure(diag.MembersNotApproved, "Soul runner account apply refused: %v", err)
	}
	if err := paired(a, nil); err != nil {
		return refused(err)
	}
	if err := checkDarwinSoulRunnerAccounts(s, owner, p.Steps[0].UID, h); err != nil {
		return refused(err)
	}
	if err := Precheck(p, root); err != nil {
		return refused(err)
	}
	receipt := Receipt{PlanID: s.PlanID, PlanDigest: s.PlanDigest, Owner: owner, HQAccount: p.HQAccount,
		Dir: p.Dir, Members: p.Members, Changes: p.Changes(), Result: "started"}
	err := paired(a, func() error {
		expires, err := time.Parse(approvalTime, a.ExpiresAt)
		now := deps.Time().UTC()
		if err != nil || !now.Before(expires) {
			return errors.New("Soul runner approval expired before the receipt was claimed")
		}
		receipt.StartedAt = now.Format(approvalTime)
		claimed, err := root.Claim(s.PlanID, encodeReceipt(receipt))
		if err != nil {
			return err
		}
		if !claimed {
			return errors.New("Soul runner approval was already used; replan remaining work")
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
		err = paired(a, func() error { return applyReviewedSoulRunnerStep(step, h, root) })
		if err != nil {
			failedAt = step.Kind + " " + step.Target
			break
		}
	}
	if err == nil {
		err = paired(a, func() error {
			after, err := Build(Input{SoulRunnerAccounts: s.SoulRunnerAccounts, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, h)
			if err != nil {
				return err
			}
			if after.Changes() != 0 || len(after.Steps) != len(p.Steps) {
				return errors.New("reviewed Soul runner accounts are incomplete")
			}
			for i := range after.Steps {
				if after.Steps[i].UID != p.Steps[i].UID || after.Steps[i].GID != p.Steps[i].GID {
					return errors.New("reviewed Soul runner identity changed")
				}
			}
			return Precheck(after, root)
		})
	}
	receipt.Result = "applied"
	if err != nil {
		receipt.Result, receipt.FailedAt = "failed", failedAt
	}
	receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
	if err = errors.Join(err, root.Finish(s.PlanID, encodeReceipt(receipt))); err != nil {
		return failure(diag.MembersApplyFailed, "Soul runner provisioning stopped; replan remaining work: %v", err)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("plan_id", s.PlanID).Set("plan_digest", s.PlanDigest).
		Set("changes", p.Changes()).Set("applied", true).Set("receipt", ReceiptPath(s.PlanID))}}
}

func applyReviewedSoulRunnerStep(s Step, h Host, root Root) error {
	ops, ok := root.(interface {
		CreateReviewedSoulRunner(string, int) error
		RepairReviewedSoulRunnerHome(string, int, uint32) error
	})
	if !ok || s.Kind != KindAccount || !accountName.MatchString(s.Target) || s.UID < 300 || s.UID > 399 || s.GID != s.UID {
		return errors.New("unsupported protected Soul runner operation")
	}
	switch s.Action {
	case ActionCreate:
		return ops.CreateReviewedSoulRunner(s.Target, s.UID)
	case ActionRepair:
		e, exists, err := h.Lstat(darwinSoulRunnerHome(s.Target))
		if err != nil {
			return err
		}
		if !exists || !e.Dir || e.Owner != s.Target || e.Group != s.Target || s.Detail != accountHomeRepairDetail(darwinSoulRunnerHome(s.Target), e.Mode&07777) {
			return errors.New("reviewed Soul runner home changed")
		}
		return ops.RepairReviewedSoulRunnerHome(s.Target, s.UID, e.Mode&07777)
	default:
		return fmt.Errorf("unexpected Soul runner account action %s", s.Action)
	}
}
