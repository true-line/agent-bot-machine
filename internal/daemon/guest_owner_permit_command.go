package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/output"
)

// The host administrator invokes this one-shot command only after the
// owner's reviewed VM/key/plan packet has identified the exact guest. It
// observes the live named VM again through the pinned local Tart executable;
// the challenge's own guest signature is never an independent observation.
func guestOwnerPermitCommand(deps Deps, args []string) (result cli.Result) {
	usage := command.UsageErr("guest-owner-permit takes CHALLENGE_FILE VM_NAME VM_MAC GUEST_BUILD TARTCTL_SHA256 TART_APP_SHA256; use --human for the exact permit JSON line")
	if len(args) != 6 {
		return cli.Result{Diagnostic: usage}
	}
	goos := deps.GOOS
	if goos == "" {
		goos = hostOS()
	}
	if goos != "darwin" {
		return ownerPairRefused("guest owner permit requires the paired macOS administrator")
	}
	caller, err := deps.caller()
	if err != nil {
		return ownerPairRefused("cannot identify the Machine administrator")
	}
	if why := caller.Refuse(); why != "" {
		return ownerPairRefused(why)
	}
	if caller.PrefixOwner == "" || !caller.DarwinAdmin || caller.UID < 501 {
		return ownerPairRefused("guest owner permit requires the paired Homebrew administrator")
	}
	if !exactKey(args[4]) || !exactKey(args[5]) || !guestVMNamePattern.MatchString(args[1]) ||
		!guestMACPattern.MatchString(args[2]) || !guestBuildPattern.MatchString(args[3]) {
		return cli.Result{Diagnostic: usage}
	}
	raw, err := readAdminGuestChallenge(args[0], caller)
	if err != nil {
		return ownerPairRefused("guest challenge is not a private administrator file")
	}
	root, err := deps.root()
	if err != nil {
		return serviceFailed(err)
	}
	dir := stateDir(root)
	unlock, err := lockOwnerPairing(dir)
	if err != nil {
		return serviceFailed(err)
	}
	defer func() {
		if err := unlock(); err != nil && result.Diagnostic == nil {
			result = serviceFailed(err)
		}
	}()
	state, err := readOwnerPairState(dir)
	if err != nil || state == nil || state.HQ == "" || state.Pending != nil {
		return ownerPairRefused("guest permit requires an existing, stable owner-approved pairing")
	}
	key, err := pairedChannelKey(dir, ChannelDir(), defaultLegacySharedDir(root),
		defaultKeyStore(filepath.Join(dir, "daemon.key")))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return ownerPairRefused("paired Machine signing identity is unavailable")
	}
	defer zeroBytes(key)
	// Reject a stale, unsigned, or changed challenge before invoking Tart.
	if _, challenge, _, err := parseGuestOwnerChallenge(raw, deps.Time()); err != nil || challenge.OwnerKey != state.Owner {
		return ownerPairRefused("guest challenge or current owner pin differs")
	}
	if deps.ObserveGuest == nil {
		return ownerPairRefused("direct Tart observer is unavailable")
	}
	observed, err := deps.ObserveGuest(context.Background(), caller, args[1], args[2], args[3], args[4], args[5])
	if err != nil {
		return ownerPairRefused("Tart could not independently attest the live guest key, VM and build")
	}
	permit, err := issueGuestOwnerPermit(key, state.Owner, raw, observed, deps.Time())
	if err != nil {
		return ownerPairRefused("guest challenge expired or did not match the independently observed VM key")
	}
	encoded, err := json.Marshal(permit)
	if err != nil {
		return serviceFailed(errors.New("guest permit encoding failed"))
	}
	return cli.Result{Human: string(encoded) + "\n", Records: []*output.Record{
		output.New().Set("state", "issued").Set("permit", string(encoded)),
	}}
}
