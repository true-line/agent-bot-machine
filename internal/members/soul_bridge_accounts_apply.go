package members

import (
	"errors"
	"fmt"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

func runSoulBridgeAccountApply(s Saved, a Approval, owner string, h Host, deps Deps, paired func(Approval, func() error) error) cli.Result {
	p := s.Plan
	if p.Purpose != SoulBridgeAccountsPurpose || len(p.Steps) == 0 || a.Purpose != SoulBridgeAccountsPurpose || s.PlanDigest != a.PlanDigest ||
		!digestPattern.MatchString(a.PairCommitment) || !digestPattern.MatchString(a.MachineFingerprint) {
		return failure(diag.MembersNotApproved, "Soul bridge accounts require their own paired owner approval")
	}
	var root Root = OSRoot{}
	if deps.Root != nil {
		root = deps.Root()
	}
	refused := func(err error) cli.Result {
		return failure(diag.MembersNotApproved, "Soul bridge account apply refused: %v", err)
	}
	authorize := harnessAuthority(a, upgradePairGuard(paired), deps.Time)
	if err := authorize(nil); err != nil {
		return refused(err)
	}
	if err := checkDarwinSoulBridgeAccounts(s, owner, p.Steps[0].UID, h); err != nil {
		return refused(err)
	}
	if err := Precheck(p, root); err != nil {
		return refused(err)
	}
	receipt := Receipt{PlanID: s.PlanID, PlanDigest: s.PlanDigest, Owner: owner, HQAccount: p.HQAccount,
		Dir: p.Dir, Members: p.Members, Changes: p.Changes(), Result: "started"}
	err := authorize(func() error {
		receipt.StartedAt = deps.Time().UTC().Format(approvalTime)
		claimed, err := root.Claim(s.PlanID, encodeReceipt(receipt))
		if err != nil {
			return err
		}
		if !claimed {
			return errors.New("Soul bridge approval was already used; replan remaining work")
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
		err = authorize(func() error { return applyReviewedSoulBridgeStep(step, h, root) })
		if err != nil {
			failedAt = step.Kind + " " + step.Target
			break
		}
	}
	if err == nil {
		err = authorize(func() error {
			after, err := Build(Input{SoulBridgeAccounts: s.SoulBridgeAccounts, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, h)
			if err != nil {
				return err
			}
			if after.Changes() != 0 || len(after.Steps) != len(p.Steps) {
				return errors.New("reviewed Soul bridge accounts are incomplete")
			}
			for i := range after.Steps {
				if after.Steps[i].UID != p.Steps[i].UID || after.Steps[i].GID != p.Steps[i].GID {
					return errors.New("reviewed Soul bridge identity changed")
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
		return failure(diag.MembersApplyFailed, "Soul bridge provisioning stopped; replan remaining work: %v", err)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("plan_id", s.PlanID).Set("plan_digest", s.PlanDigest).
		Set("changes", p.Changes()).Set("applied", true).Set("receipt", ReceiptPath(s.PlanID))}}
}

func applyReviewedSoulBridgeStep(s Step, h Host, root Root) error {
	ops, ok := root.(interface {
		CreateReviewedSoulBridge(string, int) error
		RepairReviewedSoulBridgeHome(string, int, uint32) error
	})
	if !ok || s.Kind != KindAccount || !accountName.MatchString(s.Target) || s.UID < 300 || s.UID > 399 || s.GID != s.UID {
		return errors.New("unsupported protected Soul bridge operation")
	}
	switch s.Action {
	case ActionCreate:
		return ops.CreateReviewedSoulBridge(s.Target, s.UID)
	case ActionRepair:
		e, exists, err := h.Lstat(darwinSoulBridgeHome(s.Target))
		if err != nil {
			return err
		}
		if !exists || !e.Dir || e.Owner != s.Target || e.Group != s.Target || s.Detail != accountHomeRepairDetail(darwinSoulBridgeHome(s.Target), e.Mode&07777) {
			return errors.New("reviewed Soul bridge home changed")
		}
		return ops.RepairReviewedSoulBridgeHome(s.Target, s.UID, e.Mode&07777)
	default:
		return fmt.Errorf("unexpected Soul bridge account action %s", s.Action)
	}
}
