package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
)

const UpgradePurpose = "hq-service-upgrade"
const upgradeAction = "upgrade"
const upgradeJournalName = ".hq-service-upgrade.json"

type priorServicePlan struct {
	ID   string `json:"plan_id"`
	Plan Plan   `json:"plan"`
}
type launchUpgrade struct {
	PreviousID     string       `json:"previous_plan_id"`
	PreviousDigest string       `json:"previous_plan_digest"`
	Previous       launchRecord `json:"previous"`
	Next           launchRecord `json:"next"`
}

type upgradeObservation struct {
	acl    func([]string) error
	loaded func(HQService, string) (bool, string, error)
}

func receiptForUpgrade(h Host, id, digest, owner string, acl func([]string) error) error {
	if !ValidApproval(id, digest) {
		return errors.New("invalid prior plan reference")
	}
	// /var is an OS symlink on Darwin; verify the protected physical hierarchy.
	path := filepath.Join("/private"+DarwinReceiptsDir, id+".json")
	if err := trustedPath(h, path, false); err != nil {
		return err
	}
	if err := acl(pathAncestry(path)); err != nil {
		return err
	}
	data, ok, err := h.ReadFile(path)
	var r Receipt
	if err != nil || !ok || json.Unmarshal([]byte(data), &r) != nil || r.Result != "applied" || r.FinishedAt == "" || r.FailedAt != "" || r.Owner != owner || r.HQAccount != DarwinHQAccount || r.Dir != DarwinDir || len(r.Members) != 0 || r.PlanID != id || r.PlanDigest != digest {
		return errors.New("previous service requires its matching completed root apply receipt")
	}
	return nil
}

func upgradeDirectory(dir *launchDirectory, allowCreate bool) bool {
	return dir != nil && dir.Path == launchRuntimeDir && dir.Owner == "root" && dir.Group == "wheel" && dir.Mode == "0755" && (dir.Action == ActionNone || allowCreate && dir.Action == ActionCreate)
}

func priorLaunchRecord(p Plan, owner string) (launchRecord, error) {
	var rec launchRecord
	invalid := errors.New("prior applied plan must identify the dedicated HQ role and exact service")
	if p.Version != PlanVersion || p.Dir != DarwinDir || p.HQAccount != DarwinHQAccount || len(p.Members) != 0 || len(p.Steps) != 2 {
		return rec, invalid
	}
	a, s := p.Steps[0], p.Steps[1]
	if a.Kind != KindHQAccount || a.Target != DarwinHQAccount || a.Group != DarwinHQAccount || a.Mode != "0700" || (a.Action != ActionNone && a.Action != ActionCreate) || s.Kind != KindService || s.Target != launchLabel || s.Owner != owner {
		return rec, invalid
	}
	switch s.Action {
	case ActionCreate, ActionWrite:
		if json.Unmarshal([]byte(s.Content), &rec) != nil {
			return rec, invalid
		}
	case upgradeAction:
		var old launchUpgrade
		if json.Unmarshal([]byte(s.Content), &old) != nil {
			return rec, invalid
		}
		rec = old.Next
	default:
		return rec, invalid
	}
	return rec, nil
}

func appendServiceUpgrade(p *Plan, in Input, h Host, next launchRecord) error {
	observe := in.upgradeObservation
	if observe == nil {
		observe = &upgradeObservation{checkDarwinACLs, inspectUpgradeJob}
	}
	if !upgradeDirectory(next.RuntimeDir, false) || len(p.Steps) != 1 || p.Steps[0].Action != ActionNone {
		return errors.New("upgrade requires an existing dedicated role and its version 2 control directory")
	}
	prev := in.UpgradeFrom
	digest, err := prev.Plan.Digest()
	if err != nil {
		return err
	}
	// This is the candidate receipt reference. The prefix account can verify the
	// saved plan and live service, but only root can read the applied receipt.
	if !ValidApproval(prev.ID, digest) {
		return errors.New("invalid prior plan reference")
	}
	old, err := priorLaunchRecord(prev.Plan, in.Invoker)
	if err != nil {
		return err
	}
	if !upgradeDirectory(old.RuntimeDir, true) || old.OwnerUID != next.OwnerUID || old.OwnerUID <= 0 || old.Service.Node != next.Service.Node || old.Service.NodeSHA256 != next.Service.NodeSHA256 || old.Service.ArtifactSHA256 == next.Service.ArtifactSHA256 || old.Service.ReleaseDir == next.Service.ReleaseDir || old.Service.Archive == next.Service.Archive {
		return errors.New("upgrade must retain the approved owner, runtime and Node while switching to a distinct release")
	}
	cap, err := verifyDarwinRelease(old.Service, h)
	if err != nil {
		return err
	}
	if cap != launchControlV2 || old.Plist != renderLaunchPlist(old.Service, old.OwnerUID, in.Invoker, cap) {
		return errors.New("prior plan does not match its verified version 2 release")
	}
	if err := observe.acl(pathAncestry(launchPlist)); err != nil {
		return err
	}
	actual, ok, err := h.ReadFile(launchPlist)
	if err != nil || !ok || actual != old.Plist {
		return errors.New("installed HQ plist does not match its prior applied plan")
	}
	active, pid, err := observe.loaded(old.Service, in.Invoker)
	n, parseErr := strconv.Atoi(pid)
	if err != nil {
		return err
	}
	if !active || parseErr != nil || n <= 0 {
		return errors.New("upgrade requires the exact prior HQ job to be running")
	}
	raw, err := json.Marshal(launchUpgrade{prev.ID, digest, old, next})
	if err != nil {
		return err
	}
	p.Steps = append(p.Steps, Step{Kind: KindService, Target: launchLabel, Owner: in.Invoker, Action: upgradeAction, Content: string(raw), Detail: fmt.Sprintf("verify the prior root receipt for plan %s before replacing the running HQ, verify the new owner-control service, and restore the reviewed prior release if activation fails", prev.ID)})
	return nil
}

type upgradeSigner struct {
	Available  bool   `json:"available"`
	Backend    string `json:"backend"`
	Storage    string `json:"key_storage"`
	Thumbprint string `json:"thumbprint"`
	Generation int    `json:"generation"`
}

type upgradeReceiptEvidence struct {
	Approval Approval      `json:"approval"`
	Signer   upgradeSigner `json:"signer"`
}

type upgradePairGuard func(Approval, func() error) error
