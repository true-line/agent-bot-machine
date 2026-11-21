package qualification

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

var reportID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var reportVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$`)

type reportReference struct {
	URI    string `json:"uri"`
	SHA256 string `json:"sha256"`
}

type reportFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type reportDocument struct {
	SchemaVersion int `json:"schema_version"`
	Adapter       struct {
		ID            string `json:"id"`
		Version       string `json:"version"`
		PackageSHA256 string `json:"package_sha256"`
	} `json:"adapter"`
	Launch struct {
		Executable       string       `json:"executable"`
		ExecutableSHA256 string       `json:"executable_sha256"`
		Argv             []string     `json:"argv"`
		CodeInputs       []reportFile `json:"code_inputs"`
	} `json:"launch"`
	Harness struct {
		Name         string `json:"name"`
		Version      string `json:"version"`
		BinaryPath   string `json:"binary_path"`
		BinarySHA256 string `json:"binary_sha256"`
	} `json:"harness"`
	Runner struct {
		BinaryPath   string `json:"binary_path"`
		BinarySHA256 string `json:"binary_sha256"`
	} `json:"runner"`
	SoulStart struct {
		Initiator          string          `json:"initiator"`
		HQLaunchReceipt    reportReference `json:"hq_launch_receipt"`
		MachineObservation reportReference `json:"machine_observation"`
	} `json:"soul_start"`
	Host struct {
		OS           string            `json:"os"`
		OSVersion    string            `json:"os_version"`
		Architecture string            `json:"architecture"`
		Profile      string            `json:"profile"`
		Evidence     []reportReference `json:"evidence"`
		ID           string            `json:"id"`
	} `json:"host"`
	ProfileInForce  string   `json:"profile_in_force"`
	Renders         []string `json:"renders"`
	CostBound       string   `json:"cost_bound"`
	EvaluationCells []struct {
		Role     string          `json:"role"`
		Model    string          `json:"model"`
		Provider string          `json:"provider"`
		Revision string          `json:"revision"`
		Evidence reportReference `json:"evidence"`
	} `json:"evaluation_cells"`
	SuiteRevision string `json:"suite_revision"`
	RunID         string `json:"run_id"`
	Outcome       string `json:"outcome"`
	Checks        map[string]struct {
		Outcome  string            `json:"outcome"`
		Evidence []reportReference `json:"evidence"`
	} `json:"checks"`
	Gates map[string]struct {
		Outcome  string          `json:"outcome"`
		Evidence reportReference `json:"evidence"`
	} `json:"gates"`
	RecordedAt string `json:"recorded_at"`
}

func reportPath(p string) bool {
	if len(p) < 2 || len(p) > 4096 || !path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func reportRef(r reportReference) bool {
	if len(r.URI) == 0 || len(r.URI) > 1024 || !validSHA(r.SHA256) {
		return false
	}
	for _, c := range r.URI {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// reportShape checks the full signed report shape. A signature over empty
// adapter or evidence objects cannot become qualification evidence.
func reportShape(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var r reportDocument
	if d.Decode(&r) != nil || d.Decode(new(any)) == nil || r.SchemaVersion != 1 ||
		!reportID.MatchString(r.Adapter.ID) || !reportVersion.MatchString(r.Adapter.Version) || !validSHA(r.Adapter.PackageSHA256) ||
		!reportPath(r.Launch.Executable) || !validSHA(r.Launch.ExecutableSHA256) || r.Launch.Argv == nil || len(r.Launch.Argv) > 128 || r.Launch.CodeInputs == nil ||
		!reportID.MatchString(r.Harness.Name) || r.Harness.Version == "" || !reportPath(r.Harness.BinaryPath) || !validSHA(r.Harness.BinarySHA256) ||
		!reportPath(r.Runner.BinaryPath) || !validSHA(r.Runner.BinarySHA256) ||
		r.SoulStart.Initiator != "hq" || !reportRef(r.SoulStart.HQLaunchReceipt) || !reportRef(r.SoulStart.MachineObservation) ||
		r.Host.OS != "darwin" || r.Host.OSVersion == "" || r.Host.Architecture == "" || r.Host.Profile == "" || !reportID.MatchString(r.Host.ID) || len(r.Host.Evidence) == 0 ||
		(r.ProfileInForce != "managed-protected" && r.ProfileInForce != "managed-cooperative") || r.Renders == nil ||
		(r.CostBound != "exact" && r.CostBound != "estimate" && r.CostBound != "none") || len(r.EvaluationCells) == 0 ||
		!validHex(r.SuiteRevision, 40) || !reportID.MatchString(r.RunID) || r.Outcome != "pass" || len(r.Checks) != 7 || len(r.Gates) == 0 || len(r.Gates) > 3 {
		return ErrUnqualified
	}
	for _, arg := range r.Launch.Argv {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return ErrUnqualified
		}
	}
	seen := map[string]bool{}
	for _, f := range r.Launch.CodeInputs {
		if !reportPath(f.Path) || !validSHA(f.SHA256) || seen[f.Path] {
			return ErrUnqualified
		}
		seen[f.Path] = true
	}
	for _, e := range r.Host.Evidence {
		if !reportRef(e) {
			return ErrUnqualified
		}
	}
	for _, render := range r.Renders {
		if !reportID.MatchString(render) {
			return ErrUnqualified
		}
	}
	for _, cell := range r.EvaluationCells {
		if cell.Role == "" || cell.Model == "" || cell.Provider == "" || cell.Revision == "" || !reportRef(cell.Evidence) {
			return ErrUnqualified
		}
	}
	for _, name := range []string{"egress", "credentials", "state_redirect", "safe_interrupt_resume", "session_reuse", "cost_bound", "render_coverage"} {
		check, ok := r.Checks[name]
		if !ok || len(check.Evidence) == 0 ||
			(check.Outcome != "pass" && check.Outcome != "fail" && check.Outcome != "unenforced" && check.Outcome != "not-run") ||
			(r.ProfileInForce == "managed-protected" && check.Outcome != "pass") {
			return ErrUnqualified
		}
		for _, e := range check.Evidence {
			if !reportRef(e) {
				return ErrUnqualified
			}
		}
	}
	for name, gate := range r.Gates {
		if gate.Outcome != "pass" || !reportRef(gate.Evidence) ||
			(name != "T01" && name != "T02" && name != "T03" && name != "T21") ||
			(r.ProfileInForce == "managed-protected" && name == "T21") ||
			(r.ProfileInForce == "managed-cooperative" && name != "T21") {
			return ErrUnqualified
		}
	}
	if r.ProfileInForce == "managed-cooperative" && len(r.Gates) != 1 {
		return ErrUnqualified
	}
	if _, err := parseTime(r.RecordedAt); err != nil {
		return ErrUnqualified
	}
	return nil
}
