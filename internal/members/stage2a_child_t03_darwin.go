//go:build darwin

package members

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/url"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func stage2aT03LoopbackURL(value string, family int) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" || u.RawPath != "" || u.Path != "" {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	ip := net.ParseIP(u.Hostname())
	if err != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() {
		return false
	}
	if family == 4 {
		return ip.To4() != nil && u.Hostname() == "127.0.0.1"
	}
	return ip.To4() == nil && u.Hostname() == "::1"
}

func stage2aT03ProviderPort(epoch, installationID, startID string) int {
	if !soulHQEpoch.MatchString(epoch) || !soulInstallationID.MatchString(installationID) ||
		!soulStartID.MatchString(startID) {
		return 0
	}
	digest := sha256.Sum256([]byte("agent-bot-stage2a-local-provider-v1\x00" + epoch + "\x00" + installationID + "\x00" + startID))
	return 49152 + int(binary.BigEndian.Uint16(digest[:2]))%16384
}

func stage2aT03URLPort(value string) int {
	u, err := url.Parse(value)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0
	}
	return port
}

func stage2aT03PinnedCLI(in Stage2aRoleInvocation, inventory stage2aDomainInventoryV3) (string, string, error) {
	if in.ChildExec == nil || in.ChildExec.RuntimeV3 == nil ||
		inventory.Domain != "R-runtime" || inventory.InstallationID != in.Request.InstallationID {
		return "", "", errStage2aReservationAuthority
	}
	path := filepath.Join(filepath.Dir(in.ChildExec.Executable), "claude")
	if path != filepath.Join(in.ChildExec.RuntimeV3.Snapshot.Path, "runtime/bin/claude") {
		return "", "", errStage2aReservationAuthority
	}
	for _, row := range inventory.Files {
		if row.Path == "runtime/bin/claude" && row.ComponentID == "adapter" &&
			row.Kind == "regular" && row.Mode == "0550" && validStage2aExecDigest(row.SHA256) {
			return path, row.SHA256, nil
		}
	}
	return "", "", errStage2aReservationAuthority
}

func validateStage2aT03ProbeDirective(d *Stage2aT03ProbeDirective, lease Stage2aLiveLeasePayload,
	in Stage2aRoleInvocation, receiptSHA256, cliSHA256 string, now time.Time) ([]byte, error) {
	invalid := errors.New("invalid signed protected T03 probe")
	if d == nil || in.ChildExec == nil || d.Schema != stage2aT03ProbeSchema ||
		in.Launch.EffectiveConfig["profile"] != "managed-protected" ||
		d.ReservationSHA256 != in.ChildExec.ReservationSHA256 ||
		d.ReservationSHA256 != lease.ReservationSHA256 ||
		d.InstallationID != in.Request.InstallationID || d.InstallationID != lease.InstallationID ||
		d.StartID != in.Request.StartID || d.StartID != lease.StartID ||
		d.ChildReceiptSHA256 != receiptSHA256 || d.ChildReceiptSHA256 != lease.ChildReceiptSHA256 ||
		d.LeaseSequence != lease.Sequence || d.LeaseSequence == 0 ||
		d.CLIExecutableSHA256 != cliSHA256 || !validStage2aExecDigest(cliSHA256) ||
		!validStage2aExecDigest(d.TestPlanSHA256) || len(d.SessionID) != 32 || !stage2aQualificationHex(d.SessionID) ||
		d.Model != in.ChildExec.Environment["ANTHROPIC_MODEL"] || !stage2aBindingID.MatchString(d.Model) ||
		!stage2aT03LoopbackURL(d.ProviderIPv4URL, 4) || !stage2aT03LoopbackURL(d.ProviderIPv6URL, 6) ||
		stage2aT03URLPort(d.ProviderIPv4URL) != stage2aT03ProviderPort(in.Request.HQEpoch,
			in.Request.InstallationID, in.Request.StartID) ||
		stage2aT03URLPort(d.ProviderIPv6URL) != stage2aT03URLPort(d.ProviderIPv4URL) ||
		!stage2aAbsolutePath(d.SiblingCredentialPath) || strings.ContainsAny(d.SiblingCredentialPath, "\r\n") ||
		!stage2aAbsolutePath(d.SiblingSocket) || strings.ContainsAny(d.SiblingSocket, "\r\n") ||
		d.SiblingSocket == in.ChildExec.RelaySocket || d.SiblingSocket == in.Start.Member.SocketPath ||
		strings.HasPrefix(d.SiblingCredentialPath, filepath.Dir(in.ChildExec.Workdir)+"/") ||
		d.ExpiresAtMS <= now.UnixMilli() || d.ExpiresAtMS > lease.IssuedAtMS+30_000 {
		return nil, invalid
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(d.ChallengeBase64URL)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != d.ChallengeBase64URL {
		return nil, invalid
	}
	prompt, err := base64.RawURLEncoding.Strict().DecodeString(d.PromptBase64URL)
	if err != nil || len(prompt) == 0 || len(prompt) > 4096 ||
		base64.RawURLEncoding.EncodeToString(prompt) != d.PromptBase64URL ||
		strings.ContainsAny(string(prompt), "\x00\r") {
		return nil, invalid
	}
	return prompt, nil
}

// Construct the exact installed profile and CLI invocation. The original
// relay socket is deliberately removed from this second process's environment
// so a direct IP attempt cannot silently fall back to the broker. No argument
// or environment value comes from the HQ caller.
func stage2aT03CLIArguments(cli, model string) []string {
	return []string{cli, "--bare", "--model", model,
		"--output-format", "json", "--print", "--no-session-persistence"}
}

func stage2aT03ProbeCommand(ctx context.Context, in Stage2aRoleInvocation, providerURL string,
	prompt []byte, siblingSocket string) (*exec.Cmd, error) {
	child := in.ChildExec
	if child == nil || !stage2aT03LoopbackURL(providerURL, 4) && !stage2aT03LoopbackURL(providerURL, 6) ||
		len(prompt) == 0 || len(prompt) > 4096 || child.RuntimeV3 == nil ||
		child.SandboxPath != SoulChildSandbox ||
		child.SandboxSHA256 != "sha256:"+harnessSHA(soulChildProfile) {
		return nil, errStage2aReservationAuthority
	}
	cli := filepath.Join(filepath.Dir(child.Executable), "claude")
	args := []string{"-D", "RELAY_SOCKET=" + child.RelaySocket,
		"-D", "R_CODE=" + child.RuntimeV3.Snapshot.Path,
		"-D", "STATE=" + filepath.Dir(child.Workdir),
		"-D", "ADAPTER=" + child.Executable, "-D", "CLI=" + cli,
		"-f", child.SandboxPath}
	if siblingSocket != "" {
		if !stage2aAbsolutePath(siblingSocket) || strings.ContainsAny(siblingSocket, "\r\n") ||
			siblingSocket == child.RelaySocket {
			return nil, errStage2aReservationAuthority
		}
	}
	args = append(args, stage2aT03CLIArguments(cli, child.Environment["ANTHROPIC_MODEL"])...)
	cmd := exec.CommandContext(ctx, "/usr/bin/sandbox-exec", args...)
	cmd.Dir = child.Workdir
	for key, value := range child.Environment {
		if key != "ANTHROPIC_UNIX_SOCKET" && key != "ANTHROPIC_BASE_URL" {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	if siblingSocket == "" {
		cmd.Env = append(cmd.Env, "ANTHROPIC_BASE_URL="+providerURL)
	} else {
		cmd.Env = append(cmd.Env, "ANTHROPIC_BASE_URL="+child.Environment["ANTHROPIC_BASE_URL"],
			"ANTHROPIC_UNIX_SOCKET="+siblingSocket)
	}
	cmd.Env = append(cmd.Env, "CLAUDE_CODE_MAX_RETRIES=0", "API_TIMEOUT_MS=3000")
	slices.Sort(cmd.Env)
	return cmd, nil
}
