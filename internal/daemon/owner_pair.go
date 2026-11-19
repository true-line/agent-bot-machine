package daemon

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

const ownerPairFile = "owner-pair.json"
const ownerChallengeTTL = 120

type ownerPairOptions struct {
	pin, proof                  string
	pinSet, challenge, proofSet bool
}

type ownerPairChallenge struct {
	UID     int    `json:"hq_uid,omitempty"`
	Action  string `json:"action"`
	Machine string `json:"machine_key"`
	HQ      string `json:"hq_key"`
	Nonce   string `json:"nonce"`
	Expires int64  `json:"expires_at"`
}

func (c ownerPairChallenge) message() []byte {
	parts := []string{"agent-bot-machine-owner/v1", c.Action, c.Machine, c.HQ}
	if c.Action == "machine-pair-ordinary" {
		parts = append(parts, strconv.Itoa(c.UID))
	}
	return []byte(strings.Join(append(parts, c.Nonce, strconv.FormatInt(c.Expires, 10), ""), "\n"))
}

type ownerPairState struct {
	Recovery   *recoveryChallenge  `json:"service_recovery,omitempty"`
	Owner      string              `json:"owner"`
	Machine    string              `json:"machine,omitempty"`
	HQ         string              `json:"hq,omitempty"`
	HQEpoch    string              `json:"hq_epoch,omitempty"`
	UID        int                 `json:"uid,omitempty"`
	Pending    *ownerPairChallenge `json:"pending,omitempty"`
	PendingUID int                 `json:"pending_uid,omitempty"`
	FirstHQ    *firstHQChallenge   `json:"first_hq,omitempty"`
}

func ownerKey(s string) (*ecdsa.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, errors.New("invalid owner public key encoding")
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
}

func exactKey(s string) bool {
	key, err := hex.DecodeString(s)
	return err == nil && len(key) == 32 && hex.EncodeToString(key) == s
}

func readOwnerPairState(dir string) (*ownerPairState, error) {
	path := filepath.Join(dir, ownerPairFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return nil, errors.New("owner pairing record must be an admin-private regular file")
	}
	if err := verifyDirOwner(path, info); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s ownerPairState
	if err = json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if _, err := ownerKey(s.Owner); err != nil {
		return nil, err
	}
	if (s.HQEpoch != "" && (!exactKey(s.HQEpoch) || s.HQ == "")) || (s.HQ == "" && (s.UID != 0 || s.Machine != "")) || (s.HQ != "" && (!exactKey(s.HQ) || !exactKey(s.Machine) || s.UID <= 0)) {
		return nil, errors.New("invalid enrolled HQ identity")
	}
	if c := s.Pending; c != nil && (s.PendingUID <= 0 || !(c.Action == "machine-pair" && c.UID == 0 || c.Action == "machine-pair-ordinary" && c.UID == s.PendingUID) || !exactKey(c.Machine) || !exactKey(c.HQ) || !exactKey(c.Nonce)) {
		return nil, errors.New("invalid pending owner challenge")
	}
	if c := s.Recovery; c != nil && (!c.valid() || c.Machine != s.Machine || c.HQ != s.HQ || c.Owner != s.Owner || c.UID != s.UID) {
		return nil, errors.New("invalid pending service recovery")
	}
	if s.FirstHQ != nil && !s.FirstHQ.valid() {
		return nil, errors.New("invalid pending first-HQ challenge")
	}
	return &s, nil
}

// Owner pin, outstanding nonce and live key/UID change together. Readers see
// the entire old record or its replacement. Admin enrollment and protected
// service recovery share this lock, with separate challenge purposes.
func (s *ownerPairState) save(dir string) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".owner-pair-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = stripDarwinACL(f.Name()); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, ownerPairFile)); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func ownerPairRefused(msg string) cli.Result {
	d := diag.New(diag.DaemonCallerRefused, msg)
	return cli.Result{Diagnostic: &d}
}

// This first pin is an explicit trust decision by the prefix owner. No key
// observed in a challenge reply can initialize or replace it.
func pinPairOwner(dir, pub string, existing *ownerPairState) error {
	if _, err := ownerKey(pub); err != nil {
		return err
	}
	if existing != nil {
		if existing.Owner != pub {
			return errors.New("an owner key is already pinned; rotation requires a separately approved transition")
		}
		return nil
	}
	for _, suffix := range pairingSuffixes {
		_, err := os.Lstat(filepath.Join(dir, "peers", "agent-daemon"+suffix))
		if err == nil {
			return errors.New("an existing HQ enrollment requires a separate transition; the owner pin has not changed")
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return (&ownerPairState{Owner: pub}).save(dir)
}

func ownerPair(root string, caller Caller, state *ownerPairState, options ownerPairOptions, enrollment, fingerprint, userName string) cli.Result {
	dir := stateDir(root)
	if options.pinSet {
		if err := pinPairOwner(dir, options.pin, state); err != nil {
			return ownerPairRefused(err.Error())
		}
		return cli.Result{Records: []*output.Record{output.New().Set("state", "owner-key-pinned")}}
	}
	if state == nil {
		return ownerPairRefused("the prefix owner must independently pin the owner client's public key first")
	}
	if !options.challenge && !options.proofSet {
		return ownerPairRefused("HQ enrollment requires a fresh --owner-challenge and --owner-proof")
	}
	if userName == "" {
		userName = "_agent-bot-hq"
	}
	account, err := lookupUser(userName)
	if err != nil || account.Username != userName {
		return ownerPairRefused("cannot resolve the selected local HQ account")
	}
	uid, err := strconv.Atoi(account.Uid)
	ordinary := userName != "_agent-bot-hq"
	if err != nil || uid <= 0 || uid == caller.UID || ordinary && !ordinaryHQAccount(account) {
		return ownerPairRefused("selected account is ineligible for HQ pairing")
	}
	hq, err := parseEnrollKey(enrollment, fingerprint)
	if err != nil {
		return ownerPairRefused(err.Error())
	}
	machine, err := loadPublic(filepath.Join(dir, "daemon.pub"))
	if err != nil {
		return ownerPairRefused("the installed Machine service must have its daemon public key before enrollment")
	}
	if machine.Equal(hq) {
		return ownerPairRefused("Machine and HQ must use distinct public keys")
	}
	machineHex, hqHex := hex.EncodeToString(machine), hex.EncodeToString(hq)
	now := time.Now().Unix()
	if options.challenge {
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return serviceFailed(err)
		}
		c := &ownerPairChallenge{Action: "machine-pair", Machine: machineHex, HQ: hqHex, Nonce: hex.EncodeToString(nonce[:]), Expires: now + ownerChallengeTTL}
		if ordinary {
			c.Action = "machine-pair-ordinary"
			c.UID = uid
		}
		state.FirstHQ, state.Recovery = nil, nil
		state.Pending, state.PendingUID = c, uid
		if err = state.save(dir); err != nil {
			return serviceFailed(err)
		}
		record := output.New().Set("action", c.Action).Set("machine_key", c.Machine).Set("hq_key", c.HQ).Set("nonce", c.Nonce).Set("expires_at", c.Expires)
		if ordinary {
			record.Set("hq_uid", uid)
		}
		return cli.Result{Records: []*output.Record{record}}
	}
	c := state.Pending
	if c == nil || (c.Action == "machine-pair-ordinary") != ordinary || ordinary && c.UID != uid || state.PendingUID != uid || c.Machine != machineHex || c.HQ != hqHex || c.Expires <= now || c.Expires > now+ownerChallengeTTL {
		return ownerPairRefused("missing, expired or mismatched owner pairing challenge")
	}
	if err = verifyOwnerProof(state.Owner, options.proof, c.message()); err != nil {
		return ownerPairRefused(err.Error())
	}
	terminal, err := loadClientKey(filepath.Join(dir, "peers"), "terminal")
	if err != nil {
		return serviceFailed(err)
	}
	if hq.Equal(terminal) {
		return ownerPairRefused("HQ and terminal must use distinct public keys")
	}
	if _, err = os.Lstat(filepath.Join(dir, "peers", "agent-daemon.revoked")); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ownerPairRefused("HQ enrollment is revoked or its revocation state cannot be read")
	}
	state.FirstHQ, state.Recovery = nil, nil
	state.Machine, state.HQ, state.UID, state.HQEpoch = machineHex, hqHex, uid, c.Nonce
	state.Pending, state.PendingUID = nil, 0
	if err = state.save(dir); err != nil {
		return serviceFailed(err)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("service", "agent-machine").Set("client", "agent-daemon").Set("state", "paired").Set("uid", uid)}}
}

func verifyOwnerProof(pin, proof string, message []byte) error {
	var reply struct {
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	}
	parse := json.NewDecoder(strings.NewReader(proof))
	parse.DisallowUnknownFields()
	if len(proof) > 1024 || parse.Decode(&reply) != nil || parse.Decode(new(any)) != io.EOF || reply.PublicKey != pin {
		return errors.New("owner pairing proof does not name the independently pinned public key")
	}
	pub, err := ownerKey(pin)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(reply.Signature)
	digest := sha256.Sum256(message)
	if err != nil || base64.StdEncoding.EncodeToString(sig) != reply.Signature || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("invalid owner pairing signature")
	}
	return nil
}

// A protected pairing supersedes legacy staged keys. Honour a revocation
// marker written by an older administrator tool even after the transition.
func (s *ownerPairState) liveKey(peers string) (ed25519.PublicKey, error) {
	_, err := os.Lstat(filepath.Join(peers, "agent-daemon.revoked"))
	if err == nil || s.HQ == "" {
		return nil, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read HQ revocation: %w", err)
	}
	machine, err := loadPublic(filepath.Join(filepath.Dir(peers), "daemon.pub"))
	if err != nil || hex.EncodeToString(machine) != s.Machine {
		return nil, errors.New("the Machine key changed since the owner approved pairing")
	}
	raw, err := hex.DecodeString(s.HQ)
	return ed25519.PublicKey(raw), err
}
