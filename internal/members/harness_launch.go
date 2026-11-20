package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	HarnessInstall  = "harness-launch-install"
	HarnessRetire   = "harness-launch-retire"
	HarnessLauncher = launchRuntimeDir + "/harness-launch"
	HarnessSandbox  = launchRuntimeDir + "/harness-egress.sb"
	HarnessPolicy   = launchRuntimeDir + "/harness-launch-policy.json"
	HarnessRule     = "/private/etc/sudoers.d/agent-bot-hq-harness-launch"
)

type HarnessArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type HarnessAdapter struct {
	ID         string   `json:"adapter_id"`
	Account    string   `json:"account"`
	UID        int      `json:"uid"`
	Executable string   `json:"executable"`
	SHA256     string   `json:"sha256"`
	Args       []string `json:"args"`
}
type HarnessPolicyRecord struct {
	Schema          string           `json:"schema"`
	Action          string           `json:"action"`
	HQUID           int              `json:"hq_uid"`
	Launcher        HarnessArtifact  `json:"launcher"`
	Sandbox         HarnessArtifact  `json:"sandbox"`
	Adapters        []HarnessAdapter `json:"adapters"`
	InstalledID     string           `json:"installed_plan_id"`
	InstalledDigest string           `json:"installed_plan_digest"`
}

func harnessJSON(value any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(value)
	return buf.String(), err
}
func HarnessPurpose(action string) string {
	switch action {
	case "install":
		return HarnessInstall
	case "retire":
		return HarnessRetire
	}
	return ""
}

var harnessBinaryPath = regexp.MustCompile(`^/[A-Za-z0-9._+ /-]+$`)

func (p HarnessPolicyRecord) accounts() ([]string, error) {
	invalid := errors.New("invalid reviewed Darwin harness launch policy")
	if p.Schema != "agent-bot-harness-launch/v1" || HarnessPurpose(p.Action) == "" || p.HQUID < 300 || p.HQUID > 399 ||
		p.Launcher.Path != HarnessLauncher || p.Sandbox.Path != HarnessSandbox || !digestPattern.MatchString(p.Launcher.SHA256) || !digestPattern.MatchString(p.Sandbox.SHA256) ||
		len(p.Adapters) < 1 || len(p.Adapters) > 16 {
		return nil, invalid
	}
	if p.Action == "install" {
		if p.InstalledID != "" || p.InstalledDigest != "" {
			return nil, invalid
		}
	} else if !ValidApproval(p.InstalledID, p.InstalledDigest) {
		return nil, invalid
	}
	names := map[string]int{}
	ids := map[int]string{}
	var accounts []string
	prev := ""
	for _, a := range p.Adapters {
		if !adapterID.MatchString(a.ID) || a.ID <= prev || !accountName.MatchString(a.Account) || a.Account == "root" || a.Account == "admin" || a.Account == DarwinHQAccount || a.UID == p.HQUID || a.UID < 300 || a.UID > 399 ||
			!harnessBinaryPath.MatchString(a.Executable) || path.Clean(a.Executable) != a.Executable || len(a.Executable) > 1024 || !digestPattern.MatchString(a.SHA256) || a.Args == nil || len(a.Args) > 32 {
			return nil, invalid
		}
		for _, arg := range a.Args {
			if len(arg) > 1024 || !utf8.ValidString(arg) || strings.IndexFunc(arg, unicode.IsControl) >= 0 {
				return nil, invalid
			}
		}
		if name, ok := ids[a.UID]; ok && name != a.Account {
			return nil, invalid
		}
		if uid, ok := names[a.Account]; ok {
			if uid != a.UID {
				return nil, invalid
			}
		} else {
			accounts = append(accounts, a.Account)
		}
		names[a.Account] = a.UID
		ids[a.UID] = a.Account
		prev = a.ID
	}
	sort.Strings(accounts)
	return accounts, nil
}
func (r HarnessPolicyRecord) plan() (Plan, error) {
	accounts, err := r.accounts()
	if err != nil {
		return Plan{}, err
	}
	if r.Action == "retire" {
		prior, err := r.installation().render(accounts)
		if err != nil {
			return Plan{}, err
		}
		sum, err := prior.Digest()
		if err != nil || sum != r.InstalledDigest {
			return Plan{}, errors.New("retirement mapping differs from the referenced installation digest")
		}
	}
	return r.render(accounts)
}

// The original install plan is fully determined by the reviewed retirement.
func (r HarnessPolicyRecord) installation() HarnessPolicyRecord {
	r.Action = "install"
	r.InstalledID = ""
	r.InstalledDigest = ""
	return r
}

func (r HarnessPolicyRecord) render(accounts []string) (Plan, error) {
	data, err := harnessJSON(r)
	if err != nil {
		return Plan{}, err
	}
	var rule strings.Builder
	rule.WriteString("# Managed by managed-machine harness launch v1.\n")
	for _, account := range accounts {
		fmt.Fprintf(&rule, "%s ALL = (%s) NOPASSWD: NOSETENV: sha256:%s %s harness-run\n", DarwinHQAccount, account, r.Launcher.SHA256, strings.ReplaceAll(HarnessLauncher, " ", "\\ "))
	}
	action := ActionCreate
	if r.Action == "retire" {
		action = ActionRemove
	}
	p := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinBrokerDir, Members: accounts, Steps: []Step{
		{Kind: KindFile, Target: HarnessPolicy, Action: action, Owner: "root", Group: "wheel", Mode: "0644", Content: data},
		{Kind: KindFile, Target: HarnessRule, Action: action, Owner: "root", Group: "wheel", Mode: "0440", Content: rule.String()},
	}}
	raw, err := p.Canonical()
	if err != nil || len(raw) > 32*1024 {
		return Plan{}, errors.New("harness launch plan exceeds the signed review limit")
	}
	return p, nil
}

// CanonicalForReview returns the bytes served by the paired read-only route.
// A saved launch request and its rendered file steps must describe one grant.
// Reading a review does not authorize installation or retirement.
func (s Saved) CanonicalForReview() ([]byte, error) {
	raw, err := s.Plan.Canonical()
	if err != nil {
		return nil, err
	}
	if s.HarnessLaunch == nil {
		for _, step := range s.Plan.Steps {
			if step.Target == HarnessPolicy || step.Target == HarnessRule {
				return nil, errors.New("saved harness launch files require their exact request")
			}
		}
		return raw, nil
	}
	if s.HQService != nil || s.HarnessLaunch.InstalledID == s.PlanID {
		return nil, errors.New("invalid saved harness launch request")
	}
	plan, err := s.HarnessLaunch.plan()
	if err != nil {
		return nil, err
	}
	expected, err := plan.Canonical()
	if err != nil || !bytes.Equal(raw, expected) {
		return nil, errors.New("saved harness launch request differs from its canonical plan")
	}
	return raw, nil
}
