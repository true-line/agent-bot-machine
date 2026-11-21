package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

func decodeSoulBridgeAccounts(raw []byte) ([]SoulBridgeAccount, error) {
	if len(raw) == 0 || len(raw) > 32768 {
		return nil, errors.New("Soul bridge request exceeds the review limit")
	}
	var request struct {
		Bridges []SoulBridgeAccount `json:"bridges"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&request); err != nil {
		return nil, errors.New("invalid Soul bridge request")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing Soul bridge request")
	}
	bridges, _, err := validateSoulBridgeAccounts(request.Bridges)
	return bridges, err
}

func saveSoulBridgePlan(deps Deps, p Plan, bridges []SoulBridgeAccount) cli.Result {
	digest, err := p.Digest()
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot digest Soul bridge plan: %v", err)
	}
	now := deps.Time()
	id, err := deps.PlanID(now)
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot make Soul bridge plan ID: %v", err)
	}
	state, err := deps.ResolveStateDir("darwin")
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate owner plan store: %v", err)
	}
	s := Saved{SoulBridgeAccounts: bridges, PlanID: id, PlanDigest: digest, CreatedAt: now.UTC().Format(approvalTime), Plan: p}
	if err := save(filepath.Join(state, "members", "plans"), s); err != nil {
		return failure(diag.MembersPlanFailed, "cannot save Soul bridge plan: %v", err)
	}
	row := output.New().Set("plan_id", id).Set("plan_digest", digest).Set("purpose", SoulBridgeAccountsPurpose).
		Set("members", p.Members).Set("changes", p.Changes()).Set("applied", false).
		Set("advice", "The paired HQ must obtain the owner's exact proof before the administrator applies this plan; it creates no launch rule.")
	records := []*output.Record{row}
	for _, step := range p.Steps {
		records = append(records, output.New().Set("kind", step.Kind).Set("target", step.Target).Set("action", step.Action).
			Set("uid", step.UID).Set("gid", step.GID).Set("detail", step.Detail))
	}
	return cli.Result{Records: records}
}
