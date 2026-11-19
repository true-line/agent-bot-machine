package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/qwts/managed-machine/internal/plan"
	"github.com/qwts/managed-machine/internal/statedir"
)

// FirstHQPlan loads the prefix owner's saved plan from the same location sudo
// apply uses. Only a freshly rebuilt, matching, dedicated HQ creation plan is
// eligible for approval before HQ enrollment.
func FirstHQPlan(home, invoker, id string, h Host) (string, string, error) {
	if !plan.ValidID(id) {
		return "", "", errors.New("invalid first-HQ plan id")
	}
	state, err := statedir.Path(PlatformDarwin, func(key string) string {
		if key == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		return "", "", err
	}
	raw, ok, err := h.ReadFile(filepath.Join(state, "members", "plans", id+".json"))
	if err != nil {
		return "", "", err
	}
	var saved Saved
	if !ok || json.Unmarshal([]byte(raw), &saved) != nil || saved.PlanID != id || !ValidApproval(id, saved.PlanDigest) {
		return "", "", errors.New("cannot read the prefix owner's saved plan; run managed-machine members plan first")
	}
	p := saved.Plan
	if p.HQAccount != DarwinHQAccount || p.Dir != DarwinDir || len(p.Members) != 0 {
		return "", "", errors.New("first-HQ approval requires only the dedicated macOS HQ account and optional verified HQ service")
	}
	digest, err := p.Digest()
	if err != nil || digest != saved.PlanDigest {
		return "", "", errors.New("saved first-HQ plan digest does not match its contents")
	}
	rebuilt, err := Build(Input{HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: invoker, HQService: saved.HQService}, h)
	if err != nil {
		return "", "", fmt.Errorf("cannot rebuild the first-HQ plan: %w", err)
	}
	if len(rebuilt.Steps) == 0 || rebuilt.Steps[0].Kind != KindHQAccount || rebuilt.Steps[0].Target != DarwinHQAccount || rebuilt.Steps[0].Action != ActionCreate {
		return "", "", errors.New("first-HQ approval requires the dedicated HQ role to be absent")
	}
	switch {
	case len(rebuilt.Steps) == 1 && saved.HQService == nil:
	case len(rebuilt.Steps) == 2 && saved.HQService != nil && rebuilt.Steps[1].Kind == KindService && rebuilt.Steps[1].Target == launchLabel:
	default:
		return "", "", errors.New("first-HQ plan contains unrelated steps")
	}
	current, err := rebuilt.Digest()
	if err != nil || current != digest {
		return "", "", errors.New("the saved first-HQ plan differs from the current host; make a new plan")
	}
	canonical, err := rebuilt.Canonical()
	return string(canonical), digest, err
}
