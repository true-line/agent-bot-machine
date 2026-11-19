package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/members"
	"github.com/qwts/managed-machine/internal/output"
	"github.com/qwts/managed-machine/internal/plan"
)

const firstHQAction = "first-hq-provision"

// Only the binding is persisted. The canonical plan is regenerated at export
// and import, including release verification for the optional HQ service.
type firstHQChallenge struct {
	Action  string `json:"action"`
	Machine string `json:"machine_key"`
	ID      string `json:"plan_id"`
	Digest  string `json:"plan_digest"`
	Nonce   string `json:"nonce"`
	Expires int64  `json:"expires_at"`
}

func (c firstHQChallenge) valid() bool {
	return c.Action == firstHQAction && exactKey(c.Machine) && members.ValidApproval(c.ID, c.Digest) && exactKey(c.Nonce) && c.Expires > 0
}

func (c firstHQChallenge) message() []byte {
	return []byte(strings.Join([]string{"agent-bot-machine-owner/v1", c.Action, c.Machine, c.ID, c.Digest, c.Nonce, strconv.FormatInt(c.Expires, 10), ""}, "\n"))
}

func firstHQ(deps Deps, args []string) (result cli.Result) {
	if len(args) < 2 || !plan.ValidID(args[1]) {
		return cli.Result{Diagnostic: command.UsageErr("first-hq takes export or cancel PLAN_ID, or approve PLAN_ID --proof-file PATH")}
	}
	action, id := args[0], args[1]
	switch {
	case (action == "export" || action == "cancel") && len(args) == 2:
	case action == "approve" && len(args) == 4 && args[2] == "--proof-file" && args[3] != "":
	default:
		return cli.Result{Diagnostic: command.UsageErr("first-hq takes export or cancel PLAN_ID, or approve PLAN_ID --proof-file PATH")}
	}
	goos := deps.GOOS
	if goos == "" {
		goos = hostOS()
	}
	if goos != "darwin" {
		return ownerPairRefused("first-HQ provisioning requires macOS")
	}
	caller, err := deps.caller()
	if err != nil {
		return ownerPairRefused(err.Error())
	}
	if why := caller.Refuse(); why != "" {
		return ownerPairRefused(why)
	}
	if caller.PrefixOwner == "" || !caller.DarwinAdmin {
		return ownerPairRefused("first-HQ provisioning requires the Homebrew prefix owner's macOS admin account")
	}
	var proof string
	if action == "approve" {
		proof, err = readFirstHQProof(args[3])
		if err != nil {
			return ownerPairRefused(err.Error())
		}
	}
	root, err := deps.root()
	if err != nil {
		return serviceFailed(err)
	}
	if action != "cancel" {
		if err := prepareMachineLifecycle(root); err != nil {
			return serviceFailed(err)
		}
	}
	dir := stateDir(root)
	// Refuse foreign or linked private state before taking the same lock
	// that protects the owner pin and HQ enrollment.
	for _, path := range []string{filepath.Dir(dir), dir, filepath.Join(dir, "peers")} {
		if err := verifyPrivateDir(path); err != nil {
			return serviceFailed(err)
		}
	}
	unlock, err := lockOwnerPairing(dir)
	if err != nil {
		return serviceFailed(err)
	}
	defer func() {
		if err := unlock(); err != nil && result.Diagnostic == nil {
			result = serviceFailed(fmt.Errorf("close owner enrollment lock: %w", err))
		}
	}()
	state, err := readOwnerPairState(dir)
	if err != nil {
		return serviceFailed(err)
	}
	if state == nil {
		return ownerPairRefused("independently pin the owner's public key before first-HQ provisioning")
	}
	c := state.FirstHQ
	if action == "cancel" {
		if c == nil || c.ID != id {
			return ownerPairRefused("no pending first-HQ challenge for this plan")
		}
		state.FirstHQ = nil
		if err := state.save(dir); err != nil {
			return serviceFailed(err)
		}
		return cli.Result{Records: []*output.Record{output.New().Set("state", "canceled").Set("plan_id", id)}}
	}
	if state.HQ != "" || state.Pending != nil {
		return ownerPairRefused("first-HQ provisioning is unavailable after HQ enrollment has begun")
	}
	for _, suffix := range pairingSuffixes {
		_, err := os.Lstat(filepath.Join(dir, "peers", "agent-daemon"+suffix))
		if err == nil {
			return ownerPairRefused("existing HQ enrollment or revocation prevents first-HQ provisioning")
		}
		if !errors.Is(err, os.ErrNotExist) {
			return serviceFailed(err)
		}
	}
	machine, err := loadPublic(filepath.Join(dir, "daemon.pub"))
	if err != nil {
		return ownerPairRefused("cannot read the installed Machine service public key")
	}
	machineHex := hex.EncodeToString(machine)
	h := deps.MembersHost
	if h == nil {
		h = members.OSHost{}
	}
	canonical, digest, err := members.FirstHQPlan(caller.RegisteredHome, caller.Username, id, h)
	if err != nil {
		return ownerPairRefused(err.Error())
	}
	if action == "export" {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return serviceFailed(err)
		}
		c = &firstHQChallenge{firstHQAction, machineHex, id, digest, hex.EncodeToString(nonce[:]), deps.Time().Unix() + ownerChallengeTTL}
		state.FirstHQ = c
		if err := state.save(dir); err != nil {
			return serviceFailed(err)
		}
		return cli.Result{Records: []*output.Record{output.New().Set("action", c.Action).Set("machine_key", c.Machine).Set("plan_id", c.ID).Set("plan_digest", c.Digest).Set("nonce", c.Nonce).Set("expires_at", c.Expires).Set("plan_canonical", canonical)}}
	}
	now := deps.Time()
	if c == nil || c.ID != id || c.Digest != digest || c.Machine != machineHex || c.Expires <= now.Unix() || c.Expires > now.Unix()+ownerChallengeTTL {
		return ownerPairRefused("missing, expired or mismatched first-HQ challenge")
	}
	if err := verifyOwnerProof(state.Owner, proof, c.message()); err != nil {
		return ownerPairRefused(err.Error())
	}
	// Consume and fsync before making approval visible. A crash or an
	// approval write failure requires a new export and owner presence.
	state.FirstHQ = nil
	if err := state.save(dir); err != nil {
		return serviceFailed(err)
	}
	approval, err := members.RecordApproval(dir, id, digest, now)
	if err != nil {
		return serviceFailed(err)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("state", "approved").Set("plan_id", id).Set("plan_digest", digest).Set("expires_at", approval.ExpiresAt)}}
}

func readFirstHQProof(path string) (string, error) {
	f, err := openFirstHQProof(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024 {
		return "", errors.New("first-HQ proof must be a regular JSON file of at most 1024 bytes")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil {
		return "", err
	}
	if len(data) > 1024 {
		return "", errors.New("first-HQ proof exceeds 1024 bytes")
	}
	return string(data), nil
}
