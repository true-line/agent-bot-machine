package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// HarnessQualificationPurpose is a read-only review purpose. It never grants
// permission to install or launch a harness.
const HarnessQualificationPurpose = "harness-qualification-run"

var qualificationDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var qualificationRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)

type qualificationFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type qualificationCodeInput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// QualificationRequest is local planner input, not a qualification report or
// authorization. Paths and digests identify the exact files reviewed.
type QualificationRequest struct {
	Candidate     *qualificationCandidatePlan `json:"candidate,omitempty"`
	SchemaVersion int                         `json:"schema_version"`
	Adapter       struct {
		ID          string `json:"id"`
		Version     string `json:"version"`
		PackagePath string `json:"package_path"`
		PackageSHA  string `json:"package_sha256"`
		Launch      struct {
			Executable        string                   `json:"executable"`
			ExecutableSHA     string                   `json:"executable_sha256"`
			Argv              []string                 `json:"argv"`
			CodeInputs        []qualificationCodeInput `json:"code_inputs"`
			CodeInputManifest qualificationFile        `json:"code_inputs_manifest"`
			Driver            qualificationFile        `json:"driver"`
		} `json:"launch"`
		Harness struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			BinaryPath string `json:"binary_path"`
			BinarySHA  string `json:"binary_sha256"`
		} `json:"harness"`
	} `json:"adapter"`
	Target struct {
		Account string `json:"account"`
		UID     int    `json:"uid"`
	} `json:"target"`
	Host struct {
		ID                   string `json:"id"`
		Model                string `json:"model"`
		OS                   string `json:"os"`
		OSVersion            string `json:"os_version"`
		OSBuild              string `json:"os_build"`
		Architecture         string `json:"architecture"`
		EnforcementPolicySHA string `json:"enforcement_policy_sha256"`
	} `json:"host"`
	DefinitionRevision string `json:"definition_revision"`
	SuiteRevision      string `json:"suite_revision"`
	Runner             struct {
		ID         string `json:"id"`
		Version    string `json:"version"`
		BinaryPath string `json:"binary_path"`
		BinarySHA  string `json:"binary_sha256"`
		SourcePath string `json:"source_path,omitempty"`
	} `json:"runner"`
	TestProvider struct {
		ID         string `json:"id"`
		ConfigPath string `json:"configuration_path"`
		ConfigSHA  string `json:"configuration_sha256"`
	} `json:"test_provider"`
}

// Schema 2 authorizes only a candidate qualification. These selectors and
// bytes are included in the exact saved plan covered by paired owner proof.
type qualificationCandidatePlan struct {
	HostUUID            string            `json:"host_uuid"`
	InstallationID      string            `json:"installation_id"`
	InstalledPlanDigest string            `json:"installed_plan_digest"`
	RuntimeInventorySHA string            `json:"runtime_inventory_sha256"`
	ComponentID         string            `json:"component_id"`
	Manifest            qualificationFile `json:"manifest"`
	TestPlan            qualificationFile `json:"test_plan"`
}

var qualificationCandidateComponent = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var qualificationPhysicalUUID = regexp.MustCompile(`^[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}$`)

func qualificationCandidateFiles(r QualificationRequest) []qualificationFile {
	if r.Candidate == nil {
		return nil
	}
	return []qualificationFile{r.Candidate.Manifest, r.Candidate.TestPlan}
}

// Schema-v2 Q plans review both the intended protected destination and the
// root-owned pending source. Q's destination is created only at owner apply.
func qualificationRunnerReviewFile(r QualificationRequest) (qualificationFile, bool) {
	if r.Runner.SourcePath != "" {
		return qualificationFile{r.Runner.SourcePath, r.Runner.BinarySHA}, true
	}
	return qualificationFile{r.Runner.BinaryPath, r.Runner.BinarySHA}, false
}

func verifyQualificationRunnerReviewFile(r QualificationRequest) error {
	f, staged := qualificationRunnerReviewFile(r)
	if staged {
		return verifyQualificationPendingQSource(f)
	}
	return verifyQualificationFile(f)
}

type qualificationGate struct {
	ID      string `json:"id"`
	Profile string `json:"profile"`
}

type QualificationRun struct {
	RequestSHA256 string               `json:"request_sha256"`
	Request       QualificationRequest `json:"request"`
	MemberState   string               `json:"member_state"`
	OneUse        bool                 `json:"one_use"`
	Gates         []qualificationGate  `json:"gates"`
}

func decodeQualificationRequest(raw []byte) (QualificationRequest, error) {
	var r QualificationRequest
	if len(raw) == 0 || len(raw) > 4*1024*1024 {
		return r, errors.New("qualification request must be between 1 byte and 4 MiB")
	}
	if !json.Valid(raw) {
		return r, errors.New("qualification request is not valid JSON")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return r, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, fmt.Errorf("invalid qualification request: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return r, errors.New("qualification request must contain exactly one JSON object")
	}
	if err := validateQualificationRequest(r); err != nil {
		return r, err
	}
	return r, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func() error
	value = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if key != strings.ToLower(key) {
					return fmt.Errorf("qualification request key %q must use its canonical lowercase spelling", key)
				}
				if seen[key] {
					return fmt.Errorf("duplicate qualification request key %q", key)
				}
				seen[key] = true
				if err := value(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := value(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("qualification request must contain exactly one JSON value")
	}
	return nil
}

func validateQualificationRequest(r QualificationRequest) error {
	textFields := []string{r.Adapter.ID, r.Adapter.Version, r.Adapter.Harness.Name, r.Adapter.Harness.Version,
		r.Target.Account, r.Host.ID, r.Host.Model, r.Host.OS, r.Host.OSVersion, r.Host.OSBuild, r.Host.Architecture, r.Runner.ID, r.Runner.Version, r.TestProvider.ID}
	if (r.SchemaVersion != 1 && r.SchemaVersion != 2) ||
		(r.SchemaVersion == 2) != (r.Candidate != nil) || r.DefinitionRevision == "" || !qualificationRevision.MatchString(r.DefinitionRevision) || !qualificationRevision.MatchString(r.SuiteRevision) || r.Target.UID < 300 || r.Target.UID > 399 || r.Host.OS != "darwin" || r.Host.Architecture != "arm64" || !qualificationDigest.MatchString(r.Host.EnforcementPolicySHA) {
		return errors.New("qualification request needs schema_version 1 or candidate schema_version 2 and lowercase 40-character definition and suite revisions")
	}
	if candidate := r.Candidate; candidate != nil {
		if !qualificationPhysicalUUID.MatchString(candidate.HostUUID) ||
			!soulInstallationID.MatchString(candidate.InstallationID) ||
			!qualificationDigest.MatchString(candidate.InstalledPlanDigest) ||
			!qualificationDigest.MatchString(candidate.RuntimeInventorySHA) ||
			!qualificationCandidateComponent.MatchString(candidate.ComponentID) {
			return errors.New("candidate qualification needs the exact designated host, installed plan and sealed runtime")
		}
	}
	qDestination := path.Join(stage2aQualificationQHome, "qualification-runner.mjs")
	needsPending := r.SchemaVersion == 2 && r.Runner.BinaryPath == qDestination
	if needsPending != (r.Runner.SourcePath != "") ||
		(needsPending && (r.Runner.SourcePath == r.Runner.BinaryPath ||
			strings.HasPrefix(r.Runner.SourcePath, stage2aQualificationQHome+"/"))) {
		return errors.New("candidate Q runner requires a separate reviewed pending source")
	}
	for _, s := range textFields {
		if strings.TrimSpace(s) == "" || hasASCIIControl(s) || len(s) > 256 {
			return errors.New("qualification identity fields must be nonempty single-line values of at most 256 bytes")
		}
	}
	files := []qualificationFile{
		{r.Adapter.PackagePath, r.Adapter.PackageSHA},
		{r.Adapter.Launch.Executable, r.Adapter.Launch.ExecutableSHA},
		{r.Adapter.Harness.BinaryPath, r.Adapter.Harness.BinarySHA},
		{r.Runner.BinaryPath, r.Runner.BinarySHA},
		{r.TestProvider.ConfigPath, r.TestProvider.ConfigSHA},
	}
	if needsPending {
		files = append(files, qualificationFile{r.Runner.SourcePath, r.Runner.BinarySHA})
	}
	files = append(files, qualificationCandidateFiles(r)...)
	for label, artifact := range map[string]qualificationFile{"code input manifest": r.Adapter.Launch.CodeInputManifest, "driver": r.Adapter.Launch.Driver} {
		if (artifact.Path == "") != (artifact.SHA256 == "") {
			return fmt.Errorf("%s must provide both path and digest", label)
		}
	}
	for _, f := range r.Adapter.Launch.CodeInputs {
		files = append(files, qualificationFile{Path: f.Path, SHA256: f.SHA256})
	}
	if r.Adapter.Launch.CodeInputManifest.Path != "" {
		files = append(files, r.Adapter.Launch.CodeInputManifest)
	}
	if r.Adapter.Launch.Driver.Path != "" {
		files = append(files, r.Adapter.Launch.Driver)
	}
	for _, f := range files {
		if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || hasASCIIControl(f.Path) || !qualificationDigest.MatchString(f.SHA256) {
			return errors.New("every qualification artifact needs a clean absolute path and lowercase SHA-256 digest")
		}
	}
	if r.Adapter.Launch.Argv == nil || r.Adapter.Launch.CodeInputs == nil || len(r.Adapter.Launch.Argv) > 128 || (len(r.Adapter.Launch.CodeInputs) == 0) == (r.Adapter.Launch.CodeInputManifest.Path == "") || len(r.Adapter.Launch.CodeInputs) > 2048 {
		return errors.New("qualification request needs exact harness digest, an argv array, and either code inputs or a code-input manifest")
	}
	for _, arg := range r.Adapter.Launch.Argv {
		if hasASCIIControl(arg) || len(arg) > 4096 {
			return errors.New("launch arguments must not contain NUL and must be at most 4096 bytes")
		}
	}
	seen := map[string]bool{}
	for _, item := range r.Adapter.Launch.CodeInputs {
		if seen[item.Path] {
			return fmt.Errorf("duplicate code input path %s", item.Path)
		}
		seen[item.Path] = true
	}
	if r.Adapter.Launch.CodeInputManifest.Path != "" {
		if seen[r.Adapter.Launch.CodeInputManifest.Path] {
			return fmt.Errorf("duplicate code input path %s", r.Adapter.Launch.CodeInputManifest.Path)
		}
		seen[r.Adapter.Launch.CodeInputManifest.Path] = true
	}
	return nil
}

func qualificationRunPlan(raw []byte, r QualificationRequest, h Host) (Plan, *QualificationRun, error) {
	if err := checkQualificationRole(r.Target.Account, r.Target.UID, h); err != nil {
		return Plan{}, nil, err
	}
	if err := verifyQualificationRunnerReviewFile(r); err != nil {
		return Plan{}, nil, err
	}
	files := []qualificationFile{{r.Adapter.PackagePath, r.Adapter.PackageSHA},
		{r.TestProvider.ConfigPath, r.TestProvider.ConfigSHA}}
	for _, f := range append(files, qualificationCandidateFiles(r)...) {
		if err := verifyQualificationFile(f); err != nil {
			return Plan{}, nil, err
		}
	}
	for _, f := range r.Adapter.Launch.CodeInputs {
		if err := verifyQualificationFile(qualificationFile{Path: f.Path, SHA256: f.SHA256}); err != nil {
			return Plan{}, nil, err
		}
	}
	if r.Adapter.Launch.CodeInputManifest.Path != "" {
		if err := verifyQualificationFile(r.Adapter.Launch.CodeInputManifest); err != nil {
			return Plan{}, nil, err
		}
	}
	if r.Adapter.Launch.Driver.Path != "" {
		if err := verifyQualificationFile(r.Adapter.Launch.Driver); err != nil {
			return Plan{}, nil, err
		}
	}
	for _, executable := range []qualificationFile{{r.Adapter.Launch.Executable, r.Adapter.Launch.ExecutableSHA}, {r.Adapter.Harness.BinaryPath, r.Adapter.Harness.BinarySHA}} {
		if err := verifyQualificationExecutable(executable.Path, executable.SHA256); err != nil {
			return Plan{}, nil, err
		}
	}
	sum := sha256.Sum256(raw)
	run := &QualificationRun{RequestSHA256: hex.EncodeToString(sum[:]), Request: r, MemberState: "disposable", OneUse: true, Gates: fixedQualificationGates()}
	p, err := qualificationPlan(run)
	if err != nil {
		return Plan{}, nil, err
	}
	canonical, err := p.Canonical()
	if err != nil || len(canonical) > 28*1024 {
		return Plan{}, nil, errors.New("qualification plan exceeds the bounded review size")
	}
	return p, run, nil
}

// Qualification cannot repair a changed role. Require the ordinary account
// planner to confirm the existing role and its private home need no changes.
func checkQualificationRole(name string, uid int, h Host) error {
	uids := make(map[int]string)
	step, err := platformAccountStep(PlatformDarwin, name, h, uids)
	if err != nil {
		return err
	}
	if uid < 300 || uid > 399 || step.Action != ActionNone || uids[uid] != name {
		return errors.New("qualification target must be the named existing dedicated harness role with its exact UID")
	}
	return nil
}

func verifyQualificationFile(f qualificationFile) error {
	info, err := os.Lstat(f.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("qualification artifact %s must be an existing regular non-symlink file", f.Path)
	}
	file, err := os.Open(f.Path)
	if err != nil {
		return fmt.Errorf("cannot read qualification artifact %s: %w", f.Path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() < 0 || opened.Size() > 2<<30 {
		return fmt.Errorf("qualification artifact changed or is not a bounded regular file: %s", f.Path)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, (2<<30)+1))
	if err != nil {
		return fmt.Errorf("cannot hash qualification artifact %s: %w", f.Path, err)
	}
	if n != opened.Size() || n > 2<<30 {
		return fmt.Errorf("qualification artifact size changed or exceeds 2 GiB: %s", f.Path)
	}
	if hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("qualification artifact digest mismatch: %s", f.Path)
	}
	return nil
}

func fixedQualificationGates() []qualificationGate {
	return []qualificationGate{{ID: "T01", Profile: "managed-protected"}, {ID: "T02", Profile: "managed-protected"}, {ID: "T03", Profile: "managed-protected"}, {ID: "T21", Profile: "managed-cooperative"}}
}

func qualificationPlan(run *QualificationRun) (Plan, error) {
	body, err := json.Marshal(run)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinBrokerDir, Members: []string{}, Purpose: HarnessQualificationPurpose,
		Steps: []Step{{Kind: "qualification-run", Target: run.Request.Adapter.ID, Action: ActionNone, Content: string(body), Detail: "Review only: declared host identity, fixed conformance gates, pinned runner and test provider, disposable member state; no install or launch authorization."}}}
	return p, nil
}

func hasASCIIControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
