package members

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/target"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func validQualificationRequest() QualificationRequest {
	var r QualificationRequest
	r.SchemaVersion = 1
	r.Adapter.ID, r.Adapter.Version = "codex", "1.2.3"
	r.Adapter.PackagePath, r.Adapter.PackageSHA = "/tmp/package.tar", strings.Repeat("a", 64)
	r.Adapter.Launch.Executable, r.Adapter.Launch.ExecutableSHA = "/tmp/codex", strings.Repeat("b", 64)
	r.Adapter.Launch.Argv = []string{}
	r.Adapter.Launch.CodeInputs = []qualificationCodeInput{{Path: "/tmp/code-manifest.json", SHA256: strings.Repeat("c", 64)}}
	r.Adapter.Launch.Driver = qualificationFile{Path: "/tmp/driver.js", SHA256: strings.Repeat("d", 64)}
	r.Adapter.Harness.Name, r.Adapter.Harness.Version = "codex", "1.2.3"
	r.Adapter.Harness.BinaryPath, r.Adapter.Harness.BinarySHA = "/tmp/harness", strings.Repeat("e", 64)
	r.Target.Account, r.Target.UID = "_codex", 325
	r.Host.ID, r.Host.Model, r.Host.OS, r.Host.OSVersion, r.Host.OSBuild, r.Host.Architecture = "mac-test-1", "Mac mini", "darwin", "15.1", "24B83", "arm64"
	r.Host.EnforcementPolicySHA = strings.Repeat("f", 64)
	r.DefinitionRevision, r.SuiteRevision = strings.Repeat("1", 40), strings.Repeat("2", 40)
	r.Runner.ID, r.Runner.Version, r.Runner.BinaryPath, r.Runner.BinarySHA = "soul-conformance", "0.1.0", "/tmp/runner", strings.Repeat("3", 64)
	r.TestProvider.ID, r.TestProvider.ConfigPath, r.TestProvider.ConfigSHA = "fixture", "/tmp/provider.json", strings.Repeat("4", 64)
	return r
}

func TestQualificationRequestStrictShape(t *testing.T) {
	raw, err := json.Marshal(validQualificationRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeQualificationRequest(raw); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for name, changed := range map[string]string{
		"duplicate key": strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"case alias":    strings.Replace(string(raw), `"schema_version":1`, `"Schema_Version":1`, 1),
		"unknown field": strings.Replace(string(raw), `"schema_version":1`, `"unknown":true,"schema_version":1`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeQualificationRequest([]byte(changed)); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestQualificationCandidateQRunnerReviewsPendingSource(t *testing.T) {
	r := validQualificationRequest()
	r.SchemaVersion = 2
	r.Candidate = &qualificationCandidatePlan{
		HostUUID:       "A0000000-0000-0000-0000-000000000001",
		InstallationID: "inst_0000000000000001", InstalledPlanDigest: strings.Repeat("a", 64),
		RuntimeInventorySHA: strings.Repeat("b", 64), ComponentID: "adapter",
		Manifest: qualificationFile{"/private/tmp/manifest.json", strings.Repeat("c", 64)},
		TestPlan: qualificationFile{"/private/tmp/gate-plan.json", strings.Repeat("d", 64)},
	}
	r.Runner.BinaryPath = path.Join(stage2aQualificationQHome, "qualification-runner.mjs")
	r.Runner.SourcePath = "/private/var/db/managed-machine/pending-q/runner.mjs"
	if err := validateQualificationRequest(r); err != nil {
		t.Fatalf("reviewed pending Q source refused: %v", err)
	}
	f, staged := qualificationRunnerReviewFile(r)
	if !staged || f.Path != r.Runner.SourcePath || f.SHA256 != r.Runner.BinarySHA {
		t.Fatal("planner tried to hash the uncreated Q destination")
	}
	for name, change := range map[string]func(*QualificationRequest){
		"missing pending source":    func(v *QualificationRequest) { v.Runner.SourcePath = "" },
		"source in Q home":          func(v *QualificationRequest) { v.Runner.SourcePath = stage2aQualificationQHome + "/source.mjs" },
		"source equals destination": func(v *QualificationRequest) { v.Runner.SourcePath = v.Runner.BinaryPath },
		"alternate destination":     func(v *QualificationRequest) { v.Runner.BinaryPath = "/private/tmp/other.mjs" },
		"legacy source":             func(v *QualificationRequest) { v.SchemaVersion = 1; v.Candidate = nil },
	} {
		bad := r
		change(&bad)
		if err := validateQualificationRequest(bad); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestQualificationRequestAcceptsEmptyArgvAndRequiresSingleClosure(t *testing.T) {
	r := validQualificationRequest()
	if err := validateQualificationRequest(r); err != nil {
		t.Fatalf("empty argv should be valid: %v", err)
	}
	r.Adapter.Launch.CodeInputs = nil
	r.Adapter.Launch.CodeInputs = []qualificationCodeInput{}
	r.Adapter.Launch.CodeInputManifest = qualificationFile{Path: "/tmp/tree.manifest", SHA256: strings.Repeat("a", 64)}
	if err := validateQualificationRequest(r); err != nil {
		t.Fatalf("manifest should represent a large code closure: %v", err)
	}
	r.Adapter.Launch.CodeInputs = []qualificationCodeInput{{Path: "/tmp/a", SHA256: strings.Repeat("b", 64)}}
	if err := validateQualificationRequest(r); err == nil {
		t.Fatal("accepted both a file list and manifest")
	}
}

func TestQualificationRequiresCanonicalExecutables(t *testing.T) {
	for _, bad := range []string{"./candidate", "/a/../candidate"} {
		r := validQualificationRequest()
		r.Adapter.Launch.Executable = bad
		if err := validateQualificationRequest(r); err == nil {
			t.Fatal("accepted launch executable", bad)
		}
		r = validQualificationRequest()
		r.Adapter.Harness.BinaryPath = bad
		if err := validateQualificationRequest(r); err == nil {
			t.Fatal("accepted harness executable", bad)
		}
	}
}

func TestQualificationRechecksProvisionedRole(t *testing.T) {
	h := emptyHost()
	const name = "_codex"
	const uid = 325
	account := Account{Name: name, Group: name, UID: uid, GID: uid, Home: darwinHarnessHome(name), Shell: DarwinNoLoginShell, DarwinRole: darwinHarnessRoleName}
	h.entries[account.Home] = Entry{Dir: true, Owner: name, Group: name, Mode: 0700}
	h.accounts[name] = account
	if err := checkQualificationRole(name, uid, h); err != nil {
		t.Fatal(err)
	}
	if err := checkQualificationRole(name, uid+1, h); err == nil {
		t.Fatal("accepted changed UID")
	}
	for _, change := range []func(*Account){
		func(a *Account) { a.Groups = []string{"admin"} },
		func(a *Account) { a.Shell = "/bin/zsh" },
	} {
		changed := account
		change(&changed)
		h.accounts[name] = changed
		if err := checkQualificationRole(name, uid, h); err == nil {
			t.Fatal("accepted changed account properties")
		}
	}
	h.accounts[name] = account
	h.entries[account.Home] = Entry{Dir: true, Owner: name, Group: name, Mode: 0755}
	if err := checkQualificationRole(name, uid, h); err == nil {
		t.Fatal("accepted a home needing repair")
	}
}

func TestQualificationPlanReviewBindsWholeFixedPlan(t *testing.T) {
	r := validQualificationRequest()
	run := &QualificationRun{RequestSHA256: strings.Repeat("a", 64), Request: r, MemberState: "disposable", OneUse: true, Gates: []qualificationGate{
		{ID: "T01", Profile: "managed-protected"}, {ID: "T02", Profile: "managed-protected"}, {ID: "T03", Profile: "managed-protected"}, {ID: "T21", Profile: "managed-cooperative"},
	}}
	content, _ := json.Marshal(run)
	p := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinBrokerDir, Members: []string{}, Purpose: HarnessQualificationPurpose,
		Steps: []Step{{Kind: "qualification-run", Target: r.Adapter.ID, Action: ActionNone, Content: string(content), Detail: "Review only: declared host identity, fixed conformance gates, pinned runner and test provider, disposable member state; no install or launch authorization."}}}
	s := Saved{QualificationRun: run, Plan: p}
	if _, err := s.CanonicalForReview(); err != nil {
		t.Fatalf("valid review plan rejected: %v", err)
	}
	p.Dir = DarwinDir
	s.Plan = p
	if _, err := s.CanonicalForReview(); err == nil {
		t.Fatal("accepted changed outer plan field")
	}
}

func TestQualificationPlanApplyRefusesBeforeApprovalOrChanges(t *testing.T) {
	w := newWorld(bare())
	p := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinBrokerDir, Members: []string{}, Purpose: HarnessQualificationPurpose,
		Steps: []Step{{Kind: "qualification-run", Target: "codex", Action: ActionNone}}}
	raw, err := json.Marshal(Saved{PlanID: applyID, Plan: p, QualificationRun: &QualificationRun{}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join("/home/owner", "Library", "Application Support", "managed-machine", "members", "plans", applyID+".json")
	w.h.files[file] = string(raw)
	res := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", applyID})
	wantRefused(t, w, res, diag.MembersNotApproved)
	if !strings.Contains(res.Diagnostic.Message, "non-applicable") {
		t.Fatalf("unexpected refusal: %s", res.Diagnostic.Message)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestQualificationArtifactHashSupportsRealLargeBinaryWithoutChangingHQArchiveBound(t *testing.T) {
	const size = maxReleaseBytes + 1
	name := filepath.Join(t.TempDir(), "candidate")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.CopyN(h, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if err := verifyQualificationFile(qualificationFile{Path: name, SHA256: digest}); err != nil {
		t.Fatalf("qualification input above existing 256 MiB archive bound rejected: %v", err)
	}
	if _, err := openPinnedFile(name, digest); err == nil {
		t.Fatal("changed the existing HQ archive bound")
	}
	if pinned, err := openPinnedFileLimit(name, digest, 2<<30); err != nil {
		t.Fatalf("large selected executable rejected: %v", err)
	} else {
		pinned.Close()
	}
}

func TestQualificationFieldsRejectControlsAndDuplicateCodePaths(t *testing.T) {
	r := validQualificationRequest()
	r.Adapter.ID = "bad\x1b"
	if err := validateQualificationRequest(r); err == nil {
		t.Fatal("accepted control in displayed ID")
	}
	r = validQualificationRequest()
	r.Adapter.Launch.CodeInputs = append(r.Adapter.Launch.CodeInputs, r.Adapter.Launch.CodeInputs[0])
	if err := validateQualificationRequest(r); err == nil {
		t.Fatal("accepted duplicate code input path")
	}
}

func TestCandidateQualificationPlanRequiresExactHostAndInputs(t *testing.T) {
	request := validQualificationRequest()
	request.SchemaVersion = 2
	if err := validateQualificationRequest(request); err == nil {
		t.Fatal("candidate request lacking its exact reviewed inputs was accepted")
	}
	request.Candidate = &qualificationCandidatePlan{
		HostUUID:            "A0000000-0000-0000-0000-000000000001",
		InstallationID:      "inst_0000000000000001",
		InstalledPlanDigest: strings.Repeat("a", 64),
		RuntimeInventorySHA: strings.Repeat("b", 64),
		ComponentID:         "adapter",
		Manifest:            qualificationFile{"/private/tmp/manifest.json", strings.Repeat("c", 64)},
		TestPlan:            qualificationFile{"/private/tmp/gate-plan.json", strings.Repeat("d", 64)},
	}
	if err := validateQualificationRequest(request); err != nil {
		t.Fatalf("exact candidate inputs refused: %v", err)
	}
	run := &QualificationRun{RequestSHA256: strings.Repeat("e", 64), Request: request,
		MemberState: "disposable", OneUse: true, Gates: fixedQualificationGates()}
	before, err := qualificationPlan(run)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := before.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	run.Request.Candidate.TestPlan.SHA256 = strings.Repeat("f", 64)
	after, err := qualificationPlan(run)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := after.Canonical()
	if err != nil || string(changed) == string(canonical) {
		t.Fatal("changing the test plan did not change the owner review")
	}
	request.SchemaVersion = 1
	if err := validateQualificationRequest(request); err == nil {
		t.Fatal("schema-1 request accepted candidate authority")
	}
}
