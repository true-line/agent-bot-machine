package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/members"
)

// A guest permit is only for an independently observed, disposable Tart VM.
// The ordinary owner helper still pins its locally installed Machine. The
// guest-only helper verifies this permit under that local pin and the guest's
// separately signed, one-use paired challenge.
const guestOwnerPermitDomain = "agent-bot-machine-owner/guest-permit/v1"

var (
	errGuestOwnerPermit = errors.New("guest owner permit refused")
	guestVMNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	guestMACPattern     = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	guestBuildPattern   = regexp.MustCompile(`^[0-9]{2}[A-Z][0-9]{1,5}$`)
)

type GuestTartObservation struct {
	VMName     string
	MAC        string
	Build      string
	WrapperSHA string
	AppSHA     string
	Machine    ed25519.PublicKey
}

type guestOwnerPermit struct {
	Version         int    `json:"version"`
	HostMachineKey  string `json:"host_machine_key"`
	GuestMachineKey string `json:"guest_machine_key"`
	GuestVMName     string `json:"guest_vm_name"`
	GuestVMMAC      string `json:"guest_vm_mac"`
	GuestBuild      string `json:"guest_build"`
	TartWrapperSHA  string `json:"tart_wrapper_sha256"`
	TartAppSHA      string `json:"tart_app_sha256"`
	Action          string `json:"action"`
	HQKey           string `json:"hq_key"`
	OwnerKey        string `json:"owner_key"`
	PlanID          string `json:"plan_id"`
	PlanDigest      string `json:"plan_digest"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	ChallengeNonce  string `json:"challenge_nonce"`
	IssuedAt        int64  `json:"issued_at"`
	ExpiresAt       int64  `json:"expires_at"`
	PermitNonce     string `json:"permit_nonce"`
	Signature       string `json:"signature"`
}

func (p guestOwnerPermit) signedBytes() []byte {
	return []byte(strings.Join([]string{guestOwnerPermitDomain, strconv.Itoa(p.Version),
		p.HostMachineKey, p.GuestMachineKey, p.GuestVMName, p.GuestVMMAC,
		p.GuestBuild, p.TartWrapperSHA, p.TartAppSHA, p.Action, p.HQKey, p.OwnerKey, p.PlanID, p.PlanDigest,
		p.ChallengeSHA256, p.ChallengeNonce, strconv.FormatInt(p.IssuedAt, 10),
		strconv.FormatInt(p.ExpiresAt, 10), p.PermitNonce, ""}, "\n"))
}

type guestOwnerChallenge struct {
	Action        string `json:"action"`
	MachineKey    string `json:"machine_key"`
	HQKey         string `json:"hq_key"`
	OwnerKey      string `json:"owner_key"`
	PlanID        string `json:"plan_id"`
	PlanDigest    string `json:"plan_digest"`
	Nonce         string `json:"nonce"`
	ExpiresAt     int64  `json:"expires_at"`
	PlanCanonical string `json:"plan_canonical"`
}

func guestOwnerPermitAction(action string) bool {
	switch action {
	case members.UpgradePurpose, members.HarnessAccountsPurpose, members.HarnessInstall, members.HarnessRetire,
		members.HarnessQualificationPurpose, members.SoulRunnerAccountsPurpose,
		members.SoulBridgeAccountsPurpose, members.SoulProtectedLaunchInstallPurpose,
		members.SoulProtectedLaunchRetirePurpose, members.SoulCooperativeLaunchInstallPurpose:
		return true
	default:
		return false
	}
}

func parseGuestOwnerChallenge(raw []byte, now time.Time) (Response, guestOwnerChallenge, []byte, error) {
	var frame Response
	var body guestOwnerChallenge
	if len(raw) == 0 || len(raw) > 64*1024+1 {
		return frame, body, nil, errGuestOwnerPermit
	}
	line := bytes.TrimSuffix(raw, []byte("\n"))
	if bytes.ContainsAny(line, "\r\n") || len(line) > 64*1024 || json.Unmarshal(line, &frame) != nil {
		return frame, body, nil, errGuestOwnerPermit
	}
	canonical, err := json.Marshal(frame)
	if err != nil || !bytes.Equal(canonical, line) || !frame.OK || frame.State != "challenged" ||
		frame.Diagnostic != "" || frame.Message != "" || frame.Timestamp < now.Unix()-120 ||
		frame.Timestamp > now.Unix()+30 || frame.Nonce == "" || frame.RequestNonce == "" {
		return frame, body, nil, errGuestOwnerPermit
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(frame.Body, &fields) != nil || len(fields) != 9 || json.Unmarshal(frame.Body, &body) != nil {
		return frame, body, nil, errGuestOwnerPermit
	}
	bodyCanonical, err := json.Marshal(fields)
	if err != nil || !bytes.Equal(bodyCanonical, frame.Body) || !guestOwnerPermitAction(body.Action) ||
		!exactKey(body.MachineKey) || !exactKey(body.HQKey) || !exactKey(body.Nonce) ||
		!members.ValidApproval(body.PlanID, body.PlanDigest) ||
		body.ExpiresAt <= now.Unix() || body.ExpiresAt > now.Unix()+120 ||
		frame.Timestamp >= body.ExpiresAt || len(body.PlanCanonical) > 48*1024 {
		return frame, body, nil, errGuestOwnerPermit
	}
	if _, err := ownerKey(body.OwnerKey); err != nil {
		return frame, body, nil, errGuestOwnerPermit
	}
	digest := sha256.Sum256([]byte(body.PlanCanonical))
	var plan map[string]json.RawMessage
	var purpose string
	if !strings.HasSuffix(body.PlanCanonical, "\n") ||
		json.Unmarshal([]byte(body.PlanCanonical), &plan) != nil ||
		json.Unmarshal(plan["purpose"], &purpose) != nil || purpose != body.Action {
		return frame, body, nil, errGuestOwnerPermit
	}
	guestKey, err := hex.DecodeString(body.MachineKey)
	if err != nil || hex.EncodeToString(digest[:]) != body.PlanDigest ||
		!VerifyResponse(ed25519.PublicKey(guestKey), frame) {
		return frame, body, nil, errGuestOwnerPermit
	}
	return frame, body, line, nil
}

func issueGuestOwnerPermit(host ed25519.PrivateKey, pinnedOwner string, rawChallenge []byte,
	observed GuestTartObservation, now time.Time) (guestOwnerPermit, error) {
	var permit guestOwnerPermit
	if len(host) != ed25519.PrivateKeySize || !guestVMNamePattern.MatchString(observed.VMName) ||
		!guestMACPattern.MatchString(observed.MAC) || !guestBuildPattern.MatchString(observed.Build) ||
		!exactKey(observed.WrapperSHA) || !exactKey(observed.AppSHA) ||
		len(observed.Machine) != ed25519.PublicKeySize {
		return permit, errGuestOwnerPermit
	}
	_, challenge, line, err := parseGuestOwnerChallenge(rawChallenge, now)
	if err != nil || challenge.OwnerKey != pinnedOwner ||
		challenge.MachineKey != hex.EncodeToString(observed.Machine) {
		return permit, errGuestOwnerPermit
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return permit, fmt.Errorf("guest permit nonce: %w", err)
	}
	challengeHash := sha256.Sum256(line)
	permit = guestOwnerPermit{
		Version: 1, HostMachineKey: hex.EncodeToString(host.Public().(ed25519.PublicKey)),
		GuestMachineKey: challenge.MachineKey, GuestVMName: observed.VMName,
		GuestVMMAC: observed.MAC, GuestBuild: observed.Build,
		TartWrapperSHA: observed.WrapperSHA, TartAppSHA: observed.AppSHA,
		Action: challenge.Action, HQKey: challenge.HQKey, OwnerKey: challenge.OwnerKey,
		PlanID: challenge.PlanID, PlanDigest: challenge.PlanDigest,
		ChallengeSHA256: hex.EncodeToString(challengeHash[:]), ChallengeNonce: challenge.Nonce,
		IssuedAt: now.Unix(), ExpiresAt: challenge.ExpiresAt,
		PermitNonce: hex.EncodeToString(nonce[:]),
	}
	permit.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(host, permit.signedBytes()))
	return permit, nil
}
