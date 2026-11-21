package members

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
)

// SoulRunner is an owner-reviewed mapping for one installed Soul. It is
// deliberately separate from a harness credential account: package-controlled
// entry-point code must never run with HQ's or a harness credential's UID.
// No launch rule is emitted from this record until its protected installer and
// HQ endpoint handoff are available.
type SoulRunner struct {
	SoulID         string `json:"soul_id"`
	InstallationID string `json:"installation_id"`
	Account        string `json:"account"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
	PackageRoot    string `json:"package_root"`
	PackageSHA256  string `json:"package_sha256"`
}

var soulInstallationID = regexp.MustCompile(`^inst_[0-9a-f]{16}$`)
var soulIdentity = regexp.MustCompile(`^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
var soulDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateSoulRunners closes both namespace collisions. Every installation
// has one dedicated kernel principal; two installations cannot share either
// an account name or a UID/GID, even when their Soul IDs match. A caller also
// supplies the already-reviewed harness accounts to reject role reuse.
func ValidateSoulRunners(runners []SoulRunner, hqUID int, harnesses []HarnessAdapter) error {
	invalid := errors.New("invalid reviewed Soul-runner mapping")
	if len(runners) == 0 || len(runners) > 64 || hqUID < 300 || hqUID > 399 {
		return invalid
	}
	accounts := map[string]bool{DarwinHQAccount: true}
	uids := map[int]bool{hqUID: true}
	for _, h := range harnesses {
		accounts[h.Account], uids[h.UID] = true, true
	}
	ids := map[string]bool{}
	previous := ""
	for _, r := range runners {
		if !soulIdentity.MatchString(r.SoulID) || !soulInstallationID.MatchString(r.InstallationID) ||
			!accountName.MatchString(r.Account) || r.Account == "root" || r.Account == "admin" ||
			r.UID < 300 || r.UID > 399 || r.GID != r.UID ||
			!strings.HasPrefix(r.PackageRoot, "/") || path.Clean(r.PackageRoot) != r.PackageRoot ||
			len(r.PackageRoot) > 1024 || strings.ContainsAny(r.PackageRoot, "\x00\n\r") ||
			!soulDigest.MatchString(r.PackageSHA256) ||
			accounts[r.Account] || uids[r.UID] || ids[r.InstallationID] || r.InstallationID <= previous {
			return invalid
		}
		accounts[r.Account], uids[r.UID], ids[r.InstallationID] = true, true, true
		previous = r.InstallationID
	}
	return nil
}

// SoulRunRequest is the only variable input to a future fixed launcher. The
// reviewed policy selects account, UID, package, executable and arguments.
// HQ must authenticate each start and its own epoch before invoking the rule.
type SoulRunRequest struct {
	PlanDigest     string `json:"plan_digest"`
	InstallationID string `json:"installation_id"`
	StartID        string `json:"start_id"`
	HQEpoch        string `json:"hq_epoch"`
}

var soulStartID = regexp.MustCompile(`^st_[0-9a-f]{24}$`)

// Protected launch cannot use the legacy device epoch.
var soulHQEpoch = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (r SoulRunRequest) valid() bool {
	return soulDigest.MatchString(r.PlanDigest) && soulInstallationID.MatchString(r.InstallationID) &&
		soulStartID.MatchString(r.StartID) && soulHQEpoch.MatchString(r.HQEpoch)
}

// ReadSoulRunRequest consumes exactly one private, bounded JSON header and
// leaves any buffered ACP bytes with the returned reader. Duplicate or unknown
// keys are refused; no attacker-controlled input enters a refusal message.
func ReadSoulRunRequest(input io.Reader) (SoulRunRequest, *bufio.Reader, error) {
	invalid := errors.New("invalid Soul start request")
	reader := bufio.NewReaderSize(input, 4096)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 2048 {
		return SoulRunRequest{}, nil, invalid
	}
	var request SoulRunRequest
	fields := map[string]*string{
		"plan_digest": &request.PlanDigest, "installation_id": &request.InstallationID,
		"start_id": &request.StartID, "hq_epoch": &request.HQEpoch,
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return SoulRunRequest{}, nil, invalid
	}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		target := fields[name]
		if err != nil || !ok || target == nil || decoder.Decode(target) != nil {
			return SoulRunRequest{}, nil, invalid
		}
		delete(fields, name)
	}
	end, err := decoder.Token()
	if len(fields) != 0 || err != nil || end != json.Delim('}') {
		return SoulRunRequest{}, nil, invalid
	}
	if _, err := decoder.Token(); err != io.EOF || !request.valid() {
		return SoulRunRequest{}, nil, invalid
	}
	return request, reader, nil
}

// SelectSoulRunner never takes a path, account, UID or command from a start
// request. The installed record is the sole source of those values.
func SelectSoulRunner(runners []SoulRunner, installedDigest string, r SoulRunRequest, uid int) (SoulRunner, error) {
	if !r.valid() || r.PlanDigest != installedDigest {
		return SoulRunner{}, errors.New("invalid Soul start request")
	}
	var selected SoulRunner
	for _, runner := range runners {
		if runner.InstallationID != r.InstallationID {
			continue
		}
		if selected.InstallationID != "" || runner.UID != uid || runner.GID != uid {
			return SoulRunner{}, errors.New("Soul start has no reviewed runner principal")
		}
		selected = runner
	}
	if selected.InstallationID == "" {
		return SoulRunner{}, errors.New("Soul start has no reviewed runner principal")
	}
	return selected, nil
}
