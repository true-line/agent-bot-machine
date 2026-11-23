package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
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

type installedHarness struct {
	ID     string              `json:"plan_id"`
	Digest string              `json:"plan_digest"`
	Policy HarnessPolicyRecord `json:"policy"`
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

func buildHarnessLaunch(in Input, h Host) (Plan, error) {
	r := in.HarnessLaunch
	if in.Platform != PlatformDarwin || in.HQService != nil || in.HQAccount != DarwinHQAccount || in.Dir != DarwinBrokerDir {
		return Plan{}, errors.New("harness launch requires its own dedicated Darwin plan")
	}
	p, err := r.plan()
	if err != nil {
		return Plan{}, err
	}
	if !slices.Equal(p.Members, in.Members) {
		return Plan{}, errors.New("reviewed harness accounts differ from the plan")
	}
	in.HarnessLaunch = nil
	roles, err := Build(in, h)
	if err != nil {
		return Plan{}, err
	}
	if roles.Changes() != 0 {
		return Plan{}, errors.New("provision and verify the dedicated roles and broker directories before reviewing a launch grant")
	}
	for _, a := range append(slices.Clone(r.Adapters), HarnessAdapter{Account: DarwinHQAccount, UID: r.HQUID}) {
		role, ok, e := h.Account(a.Account)
		if e != nil {
			return Plan{}, e
		}
		if !ok || role.UID != a.UID || role.GID != a.UID {
			return Plan{}, errors.New("reviewed harness or HQ role changed")
		}
	}
	if err := inspectHarnessLaunch(*r); err != nil {
		return Plan{}, err
	}
	return p, nil
}

func harnessInput(raw []byte) ([]HarnessAdapter, error) {
	if len(raw) > 32768 || !utf8.Valid(raw) {
		return nil, errors.New("invalid bounded harness adapter list")
	}
	var in struct {
		Adapters []struct {
			ID         string   `json:"adapter_id"`
			Account    string   `json:"account"`
			Executable string   `json:"executable"`
			SHA256     string   `json:"sha256"`
			Args       []string `json:"args"`
		} `json:"adapters"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return nil, err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("trailing harness launch input")
	}
	out := make([]HarnessAdapter, 0, len(in.Adapters))
	for _, a := range in.Adapters {
		out = append(out, HarnessAdapter{ID: a.ID, Account: a.Account, Executable: a.Executable, SHA256: a.SHA256, Args: a.Args})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// A saved harness plan may contain its typed request, its fixed file steps,
// or both. All of these forms are review-only.
func (s Saved) isHarnessLaunchPlan() bool {
	if s.HarnessLaunch != nil {
		return true
	}
	for _, step := range s.Plan.Steps {
		if step.Target == HarnessPolicy || step.Target == HarnessRule {
			return true
		}
	}
	return false
}

// CheckDarwinHarnessLaunch rechecks the exact grant, registered role and
// installed artifacts when issuing a challenge and when accepting the proof.
func CheckDarwinHarnessLaunch(s Saved, purpose, owner string, uid int) error {
	return checkDarwinHarnessLaunch(s, purpose, owner, uid, OSHost{})
}

func checkDarwinHarnessLaunch(s Saved, purpose, owner string, uid int, h Host) error {
	if _, err := savedHarnessPlan(s, purpose, owner, uid, h); err != nil {
		return err
	}
	if purpose == HarnessInstall {
		// Planning reports an identical installed policy as no work and refuses
		// a different one. Neither can use this pending install challenge.
		_, present, err := h.Lstat(HarnessPolicy)
		if err != nil {
			return err
		}
		if present {
			return errors.New("a harness launch policy already occupies the install target")
		}
	}
	return nil
}

func savedHarnessPlan(s Saved, purpose, owner string, uid int, h Host) (Plan, error) {
	r := s.HarnessLaunch
	if r == nil || HarnessPurpose(r.Action) != purpose || r.HQUID != uid || !ValidApproval(s.PlanID, s.PlanDigest) {
		return Plan{}, errors.New("saved plan is not for this harness launch action and HQ identity")
	}
	raw, err := s.CanonicalForReview()
	if err != nil {
		return Plan{}, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != s.PlanDigest {
		return Plan{}, errors.New("saved harness plan differs from the signed digest")
	}
	p, err := Build(Input{Platform: PlatformDarwin, HQAccount: s.Plan.HQAccount, Dir: s.Plan.Dir, Members: s.Plan.Members, Invoker: owner, HarnessLaunch: r}, h)
	if err != nil {
		return Plan{}, err
	}
	current, err := p.Canonical()
	if err != nil || !bytes.Equal(raw, current) {
		return Plan{}, errors.New("harness launch plan changed")
	}
	return p, nil
}

// PairedPlanFrameBytes is the maximum size of a signed paired daemon frame.
const PairedPlanFrameBytes = 64 << 10

// EncodePairedPlanReview checks the escaped wire body, leaving room for the
// fixed signed response fields and the bounded request nonce.
func EncodePairedPlanReview(id, digest string, canonical []byte) ([]byte, error) {
	body, err := json.Marshal(struct {
		ID        string `json:"plan_id"`
		Digest    string `json:"plan_digest"`
		Canonical string `json:"plan_canonical"`
	}{id, digest, string(canonical)})
	if err != nil || len(body) > PairedPlanFrameBytes-1024 {
		return nil, errors.New("paired plan review exceeds the signed response limit")
	}
	return body, nil
}

// CanonicalForReview returns the bytes served by the paired read-only route.
// A saved launch request and its rendered file steps must describe one grant.
// Reading a review does not authorize installation or retirement.
func (s Saved) CanonicalForReview() ([]byte, error) {
	raw, err := s.Plan.Canonical()
	if err != nil {
		return nil, err
	}
	if s.SoulCooperativeLaunch != nil || s.Plan.Purpose == SoulCooperativeLaunchInstallPurpose || s.Plan.SoulCooperativeLaunch != nil {
		if s.SoulCooperativeLaunch == nil || s.Plan.SoulCooperativeLaunch == nil ||
			s.Plan.Purpose != SoulCooperativeLaunchInstallPurpose || s.SoulProtectedLaunch != nil ||
			s.SoulProtectedRetire != nil || s.SoulRunnerAccounts != nil || s.SoulBridgeAccounts != nil ||
			s.HarnessLaunch != nil || s.QualificationRun != nil || s.HQService != nil || s.UpgradeFrom != nil ||
			s.SoulCooperativeLaunch.validate() != nil {
			return nil, errors.New("invalid saved cooperative Soul launch request")
		}
		a, errA := json.Marshal(s.SoulCooperativeLaunch)
		b, errB := json.Marshal(s.Plan.SoulCooperativeLaunch)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			return nil, errors.New("cooperative Soul launch request differs from canonical plan")
		}
		return raw, nil
	}
	if s.SoulProtectedRetire != nil || s.Plan.Purpose == SoulProtectedLaunchRetirePurpose || s.Plan.SoulProtectedRetire != nil {
		if s.SoulProtectedRetire == nil || s.Plan.SoulProtectedRetire == nil ||
			s.Plan.Purpose != SoulProtectedLaunchRetirePurpose || s.SoulProtectedLaunch != nil ||
			s.SoulRunnerAccounts != nil || s.SoulBridgeAccounts != nil || s.HarnessLaunch != nil ||
			s.QualificationRun != nil || s.HQService != nil || s.UpgradeFrom != nil {
			return nil, errors.New("invalid saved protected Soul retirement")
		}
		a, errA := json.Marshal(s.SoulProtectedRetire)
		b, errB := json.Marshal(s.Plan.SoulProtectedRetire)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			return nil, errors.New("protected Soul retirement differs from canonical plan")
		}
		return raw, nil
	}
	if s.SoulProtectedLaunch != nil || s.Plan.Purpose == SoulProtectedLaunchInstallPurpose || s.Plan.SoulProtectedLaunch != nil {
		if s.SoulProtectedLaunch == nil || s.Plan.SoulProtectedLaunch == nil ||
			s.Plan.Purpose != SoulProtectedLaunchInstallPurpose || s.SoulRunnerAccounts != nil ||
			s.SoulBridgeAccounts != nil || s.HarnessLaunch != nil || s.QualificationRun != nil ||
			s.HQService != nil || s.UpgradeFrom != nil {
			return nil, errors.New("invalid saved protected Soul launch request")
		}
		a, errA := json.Marshal(s.SoulProtectedLaunch)
		b, errB := json.Marshal(s.Plan.SoulProtectedLaunch)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			return nil, errors.New("protected Soul launch request differs from canonical plan")
		}
		return raw, nil
	}
	if s.SoulBridgeAccounts != nil || s.Plan.Purpose == SoulBridgeAccountsPurpose || s.Plan.SoulBridges != nil {
		if s.SoulBridgeAccounts == nil || s.SoulRunnerAccounts != nil || s.HarnessLaunch != nil ||
			s.HQService != nil || s.UpgradeFrom != nil || s.QualificationRun != nil ||
			s.Plan.Purpose != SoulBridgeAccountsPurpose || s.Plan.SoulRunners != nil {
			return nil, errors.New("invalid saved Soul bridge account request")
		}
		bridges, accounts, err := validateSoulBridgeAccounts(s.SoulBridgeAccounts)
		if err != nil || !slices.Equal(bridges, s.Plan.SoulBridges) || !slices.Equal(accounts, s.Plan.Members) {
			return nil, errors.New("Soul bridge request differs from the canonical plan")
		}
		return raw, nil
	}
	if s.SoulRunnerAccounts != nil || s.Plan.Purpose == SoulRunnerAccountsPurpose || s.Plan.SoulRunners != nil {
		if s.SoulRunnerAccounts == nil || s.SoulBridgeAccounts != nil || s.HarnessLaunch != nil || s.HQService != nil || s.UpgradeFrom != nil || s.QualificationRun != nil || s.Plan.Purpose != SoulRunnerAccountsPurpose {
			return nil, errors.New("invalid saved Soul runner account request")
		}
		runners, accounts, err := validateSoulRunnerAccounts(s.SoulRunnerAccounts)
		if err != nil || !slices.Equal(runners, s.Plan.SoulRunners) || !slices.Equal(accounts, s.Plan.Members) {
			return nil, errors.New("Soul runner request differs from the canonical plan")
		}
		return raw, nil
	}
	if s.QualificationRun != nil {
		if s.HarnessLaunch != nil || s.HQService != nil || s.UpgradeFrom != nil || s.Plan.Purpose != HarnessQualificationPurpose || len(s.Plan.Steps) != 1 || s.Plan.Steps[0].Kind != "qualification-run" || s.Plan.Steps[0].Action != ActionNone || !qualificationDigest.MatchString(s.QualificationRun.RequestSHA256) || s.QualificationRun.MemberState != "disposable" || !s.QualificationRun.OneUse {
			return nil, errors.New("invalid saved qualification review plan")
		}
		if err := validateQualificationRequest(s.QualificationRun.Request); err != nil {
			return nil, err
		}
		want, err := json.Marshal(s.QualificationRun)
		if err != nil || string(want) != s.Plan.Steps[0].Content {
			return nil, errors.New("saved qualification inputs differ from their canonical plan")
		}
		if !sameQualificationGates(s.QualificationRun.Gates) {
			return nil, errors.New("saved qualification gates differ from the fixed plan")
		}
		expected, expectedErr := qualificationPlan(s.QualificationRun)
		if expectedErr != nil {
			return nil, expectedErr
		}
		expectedBytes, expectedErr := expected.Canonical()
		if expectedErr != nil || !bytes.Equal(raw, expectedBytes) {
			return nil, errors.New("saved qualification plan differs from its canonical review request")
		}
		return raw, nil
	}
	if s.Plan.Purpose == HarnessQualificationPurpose {
		return nil, errors.New("saved qualification plan requires its exact request")
	}
	if s.HarnessLaunch == nil {
		if s.isHarnessLaunchPlan() {
			return nil, errors.New("saved harness launch files require their exact request")
		}
		return raw, nil
	}
	if s.HQService != nil || s.UpgradeFrom != nil || s.HarnessLaunch.InstalledID == s.PlanID {
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

func sameQualificationGates(gates []qualificationGate) bool {
	want := fixedQualificationGates()
	if len(gates) != len(want) {
		return false
	}
	for i := range want {
		if gates[i] != want[i] {
			return false
		}
	}
	return true
}
