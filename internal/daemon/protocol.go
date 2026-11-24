package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
	"github.com/qwts/managed-machine/internal/plan"
)

const maxMessage = members.PairedPlanFrameBytes
const timestampSkew = 5 * time.Minute

// Request is one signed command. Fields the catalog did not declare are
// rejected by DisallowUnknownFields before a signature is considered.
type Request struct {
	Verb                             string `json:"verb"`
	Name                             string `json:"name,omitempty"`
	Option                           string `json:"option,omitempty"`
	Target                           string `json:"target,omitempty"`
	DeviceSession                    string `json:"session,omitempty"`
	HQEpoch                          string `json:"hq_epoch,omitempty"`
	ReceiptBody                      string `json:"receipt_body,omitempty"`
	ReceiptJTI                       string `json:"receipt_jti,omitempty"`
	ReceiptKID                       string `json:"receipt_kid,omitempty"`
	ReceiptSignature                 string `json:"receipt_signature,omitempty"`
	Stage2aRequest                   string `json:"stage2a_request,omitempty"`
	stage2aReserve                   members.Stage2aReserveRequest
	stage2aCooperativeReserve        members.SoulCooperativeStartRequestV3
	stage2aCooperativeProvider       members.SoulCooperativeProviderRequestV3
	stage2aCooperativeLookup         members.Stage2aLookupRequest
	stage2aCooperativeLive           members.SoulCooperativeLiveRequestV3
	stage2aCooperativeQBegin         members.SoulCooperativeLiveRequestV3
	stage2aCooperativeQFinish        members.Stage2aDirectQFinishRequestV3
	stage2aCooperativeQWitnessBegin  members.Stage2aDirectQWitnessBeginRequestV3
	stage2aCooperativeQWitnessFinish members.Stage2aDirectQWitnessFinishRequestV3
	stage2aCooperativeAbort          members.Stage2aStopRequest
	stage2aCooperativeAttach         members.SoulCooperativeAttachRequestV3
	stage2aCooperativeStop           members.Stage2aStopRequest
	stage2aCooperativeProjection     members.Stage2aStopRequest
	stage2aCooperativeRecovery       members.Stage2aStopRequest
	stage2aExec                      stage2aExecRequest
	stage2aChildReady                members.Stage2aChildReadyRequest
	stage2aVerifyB                   members.Stage2aVerifyBRequest
	stage2aPrepareB                  members.Stage2aPrepareBRequest
	stage2aStop                      members.Stage2aStopRequest
	stage2aFinalizeB                 members.Stage2aFinalizeBRequest
	stage2aT03Ready                  members.Stage2aT03ReadyRequest
	stage2aT03Complete               members.Stage2aT03CompleteRequest
	stage2aT03Positive               members.Stage2aT03ArmRequest
	stage2aT03SiblingWitness         members.Stage2aT03SiblingCredentialWitnessRequest
	stage2aLive                      members.Stage2aLiveRequest
	stage2aProvider                  members.Stage2aProviderRequest
	stage2aLookup                    members.Stage2aLookupRequest
	stage2aHelloStart                members.Stage2aHelloStartRequest
	stage2aHelloFinalize             members.Stage2aHelloFinalizeRequest
	stage2aHelloAbort                members.Stage2aStopRequest
	stage2aPeerRole                  members.Stage2aPeerRequest
	stage2aEpoch                     string
	peerUID                          int
	peerPID                          int
	ChallengeNonce                   string           `json:"challenge_nonce,omitempty"`
	OwnerSignature                   string           `json:"owner_signature,omitempty"`
	PlanID                           string           `json:"plan_id,omitempty"`
	PlanDigest                       string           `json:"plan_digest,omitempty"`
	Soul                             string           `json:"soul,omitempty"`
	Harness                          string           `json:"harness,omitempty"`
	SessionID                        string           `json:"session_id,omitempty"`
	CatalogKey                       *CatalogKey      `json:"catalog_key,omitempty"`
	Floor                            *CatalogFloor    `json:"floor,omitempty"`
	Envelope                         *CatalogEnvelope `json:"envelope,omitempty"`
	Timestamp                        int64            `json:"timestamp"`
	Nonce                            string           `json:"nonce"`
	PublicKey                        string           `json:"public_key"`
	Signature                        string           `json:"signature"`
}

// Response is signed by the daemon. Signature is over the other fields.
type Response struct {
	OK           bool            `json:"ok"`
	Diagnostic   string          `json:"diagnostic,omitempty"`
	Message      string          `json:"message,omitempty"`
	State        string          `json:"state,omitempty"`
	Body         json.RawMessage `json:"body,omitempty"`
	Timestamp    int64           `json:"timestamp"`
	Nonce        string          `json:"nonce"`
	RequestNonce string          `json:"request_nonce"`
	Signature    string          `json:"signature"`
}

// Pairing is the live client public keys. Live is the first client. Extra
// holds any further live clients. A staged key does not replace Live until
// Confirm. File loading puts terminal in Live and agent-daemon in Extra
// when both are present.
type Pairing struct {
	Live     ed25519.PublicKey
	Staged   ed25519.PublicKey
	Extra    []ed25519.PublicKey
	Terminal ed25519.PublicKey
	// AgentDaemon is HQ's key. When AgentDaemonBound is set the gate
	// accepts it only from AgentDaemonUID, the HQ account.
	AgentDaemon           ed25519.PublicKey
	AgentDaemonUID        int
	AgentDaemonBound      bool
	OwnerPresenceRequired bool
	HQEpoch               string
}

// Stage records a replacement key and keeps Live authoritative.
func (p *Pairing) Stage(next ed25519.PublicKey) {
	p.Staged = append(ed25519.PublicKey(nil), next...)
}

// Confirm makes the staged key live. It does nothing when nothing is staged.
func (p *Pairing) Confirm() {
	if len(p.Staged) == ed25519.PublicKeySize {
		p.Live = p.Staged
		p.Staged = nil
	}
}

func (p Pairing) isTerminal(key ed25519.PublicKey) bool {
	return len(p.Terminal) == ed25519.PublicKeySize && p.Terminal.Equal(key)
}

func (p Pairing) allows(key ed25519.PublicKey) bool {
	if len(p.Live) == ed25519.PublicKeySize && ed25519.PublicKey(p.Live).Equal(key) {
		return true
	}
	for _, live := range p.Extra {
		if len(live) == ed25519.PublicKeySize && live.Equal(key) {
			return true
		}
	}
	return false
}

// Gate verifies peer identity, signature, time, and nonce. A local process
// identity (getpeereid / SO_PEERCRED) is necessary and never sufficient:
// the pairing key authorizes the request. The caller UID does not have to
// match the daemon account — agent-daemon and the Terminal thin client
// run in the user account.
type Gate struct {
	Pairing Pairing
	// Dir is the daemon state directory. When set, verify reads the pairing
	// files before authorizing so a revocation or a confirmed replacement
	// takes effect without a restart.
	Dir     string
	PeerUID int
	Now     func() time.Time
	seen    map[string]struct{}
}

func (g *Gate) verify(peerUID int, raw []byte) (Request, string, string) {
	var req Request
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, diag.DaemonTampered, "request was not a single known object"
	}
	if peerUID < 0 {
		return req, diag.DaemonPeerRefused, "caller is not a local process"
	}
	if req.Signature == "" || req.PublicKey == "" {
		return req, diag.DaemonUnsigned, "request is not signed"
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return req, diag.DaemonUnknownKey, "request key is not a known pairing"
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), canonical(req), sig) {
		return req, diag.DaemonTampered, "request signature does not match"
	}
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	when := time.Unix(req.Timestamp, 0)
	if when.Before(now.Add(-timestampSkew)) || when.After(now.Add(timestampSkew)) {
		return req, diag.DaemonStale, "request timestamp is outside the allowed window"
	}
	if req.Nonce == "" {
		return req, diag.DaemonReplay, "request nonce is missing"
	}
	if g.seen == nil {
		g.seen = map[string]struct{}{}
	}
	if _, ok := g.seen[req.Nonce]; ok {
		return req, diag.DaemonReplay, "request nonce was already used"
	}
	g.seen[req.Nonce] = struct{}{}
	if !knownVerb(req.Verb) {
		return req, diag.DaemonVerbUnknown, "verb is not one of status, receipts, plan, apply, update, catalog, members-plans, hq-service-recovery, hq-service-upgrade, harness-account-provision, soul-runner-provision, soul-bridge-provision, harness-launch-install, harness-launch-retire, hq-device, approve-members, bootstrap"
	}
	if id, msg := catalogFields(req, raw); id != "" {
		return req, id, msg
	}
	if id, msg := deviceFields(req, raw); id != "" {
		return req, id, msg
	}
	if id, msg := membersFields(req, raw); id != "" {
		return req, id, msg
	}
	if id, msg := stage2aFields(&req, raw); id != "" {
		return req, id, msg
	}
	if g.Dir != "" {
		readPairing := loadPairing
		if req.Verb == deviceVerb || isStage2aVerb(req.Verb) {
			readPairing = currentDevicePairing
		}
		pairing, err := readPairing(g.Dir)
		if err != nil {
			return req, diag.DaemonUnknownKey, "pairing state could not be read: " + err.Error()
		}
		g.Pairing = pairing
	}
	if pairedServiceVerb(req.Verb) && (!g.Pairing.OwnerPresenceRequired || runtime.GOOS != "darwin") {
		return req, diag.DaemonPeerRefused, "service approval requires the protected macOS pairing"
	}
	if req.Verb == deviceVerb && !devicePairAllows(g.Pairing, peerUID, ed25519.PublicKey(pub)) {
		return req, diag.DaemonPeerRefused, "HQ device custody requires the approved HQ pairing"
	}
	if req.Verb == membersPlansVerb || pairedServiceVerb(req.Verb) || isStage2aVerb(req.Verb) {
		p := g.Pairing
		if !p.AgentDaemonBound || p.AgentDaemonUID != peerUID || !p.AgentDaemon.Equal(ed25519.PublicKey(pub)) || !dedicatedMembersPlanPeer(peerUID) {
			return req, diag.DaemonPeerRefused, "this command requires the enrolled HQ service account"
		}
	}
	if isStage2aVerb(req.Verb) {
		if runtime.GOOS != "darwin" || !devicePairAllows(g.Pairing, peerUID, ed25519.PublicKey(pub)) ||
			g.Pairing.HQEpoch == "" || req.Verb == stage2aReserveVerb && req.stage2aReserve.HQEpoch != g.Pairing.HQEpoch {
			return req, diag.DaemonPeerRefused, "Stage 2a requires the current protected HQ pairing epoch"
		}
		req.stage2aEpoch = g.Pairing.HQEpoch
	}
	if g.Pairing.OwnerPresenceRequired && req.Verb != "status" && req.Verb != "receipts" && req.Verb != membersPlansVerb && !pairedServiceVerb(req.Verb) && req.Verb != deviceVerb && !isStage2aVerb(req.Verb) {
		return req, diag.DaemonPeerRefused, "this command requires its own owner presence proof"
	}
	if req.Verb == "bootstrap" {
		if g.Dir == "" {
			return req, diag.DaemonPeerRefused, "bootstrap needs daemon state"
		}
		if err := adoptTerminal(g.Dir, ed25519.PublicKey(pub), peerUID); err != nil {
			return req, diag.DaemonPeerRefused, err.Error()
		}
		return req, "", ""
	}
	if !g.Pairing.allows(ed25519.PublicKey(pub)) {
		return req, diag.DaemonUnknownKey, "request key is not the live pairing"
	}
	if p := g.Pairing; p.AgentDaemonBound && len(p.AgentDaemon) == ed25519.PublicKeySize &&
		p.AgentDaemon.Equal(ed25519.PublicKey(pub)) && peerUID != p.AgentDaemonUID {
		return req, diag.DaemonPeerRefused, fmt.Sprintf("the agent-daemon key is accepted only from the HQ account (uid %d)", p.AgentDaemonUID)
	}
	if g.Pairing.isTerminal(ed25519.PublicKey(pub)) && !terminalVerb(req.Verb) {
		return req, diag.DaemonUnknownKey, "the terminal client key is only for update, status, and receipts"
	}
	req.peerUID = peerUID
	return req, "", ""
}

// Legacy enrollment may bind agent-daemon to a custom account. Check the
// current system role independently for this dedicated-account operation.
func dedicatedMembersPlanPeer(uid int) bool {
	var role string
	switch runtime.GOOS {
	case "darwin":
		role = members.DarwinHQAccount
	case "linux":
		role = members.DefaultHQAccount
	default:
		return false
	}
	if uid <= 0 || uid == os.Geteuid() {
		return false
	}
	account, err := lookupUser(role)
	return err == nil && account.Username == role && account.Uid == strconv.Itoa(uid)
}

func terminalVerb(verb string) bool {
	switch verb {
	case "status", "receipts", "update":
		return true
	default:
		return false
	}
}

func knownVerb(verb string) bool {
	switch verb {
	case "status", "receipts", "plan", "apply", "update", "catalog", membersPlansVerb, recoveryVerb, upgradeVerb, harnessAccountsVerb, soulRunnerAccountsVerb, soulBridgeAccountsVerb, harnessInstallVerb, harnessRetireVerb, harnessQualificationVerb, members.SoulProtectedLaunchInstallPurpose, members.SoulProtectedLaunchRetirePurpose, members.SoulCooperativeLaunchInstallPurpose, stage2aCooperativeRecoveryVerb, deviceVerb, approveMembersVerb, stage2aReserveVerb, stage2aExecVerb, stage2aVerifyBVerb, stage2aLookupVerb, stage2aListVerb, stage2aPrepareBVerb, stage2aStopVerb, stage2aLiveVerb, stage2aT03PositiveVerb, stage2aT03ReadyVerb, stage2aT03CompleteVerb, stage2aT03SiblingWitnessVerb, stage2aFinalizeBVerb, stage2aProviderVerb, stage2aChildReadyVerb, stage2aHelloStartVerb, stage2aHelloFinalizeVerb, stage2aHelloAbortVerb, stage2aPeerRoleVerb, stage2aCooperativeReserveVerb, stage2aCooperativeReserveResultVerb, stage2aCooperativeAttachVerb, stage2aCooperativeStopVerb, stage2aCooperativeProjectionVerb, stage2aCooperativeProviderVerb, stage2aCooperativeLookupVerb, stage2aCooperativeLiveVerb, stage2aCooperativeAbortVerb, stage2aCooperativeQBeginVerb, stage2aCooperativeQFinishVerb, stage2aCooperativeQWitnessBeginVerb, stage2aCooperativeQWitnessFinishVerb, "bootstrap":
		return true
	default:
		return false
	}
}

// catalogFields refuses catalog_key, floor, or envelope on any other verb,
// including a JSON null value, and refuses non-catalog fields on the catalog
// verb. The signature already covers those fields when they are present.
func catalogFields(req Request, raw []byte) (string, string) {
	present := req.CatalogKey != nil || req.Floor != nil || req.Envelope != nil || hasRawCatalogKey(raw)
	if req.Verb != "catalog" {
		if present {
			return diag.DaemonUndeclared, "catalog fields are not declared on this verb"
		}
		return "", ""
	}
	if req.Name != "" || req.Option != "" || req.Target != "" || req.PlanID != "" || req.PlanDigest != "" || req.Soul != "" || req.Harness != "" || req.SessionID != "" {
		return diag.DaemonUndeclared, "catalog accepts only catalog_key, floor, and envelope"
	}
	if req.CatalogKey == nil {
		return diag.DaemonUnsigned, ErrCatalogNoKey.Error()
	}
	return "", ""
}

func hasRawCatalogKey(raw []byte) bool {
	return hasRawField(raw, "catalog_key", "floor", "envelope")
}

func hasRawField(raw []byte, keys ...string) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false
	}
	for _, k := range keys {
		if _, ok := fields[k]; ok {
			return true
		}
	}
	return false
}

// approveMembersVerb records the owner's approval of one member accounts
// plan (docs/plans/member-accounts.md). It runs nothing.
const approveMembersVerb = "approve-members"

// membersFields refuses plan_digest on any other verb, including an empty
// or null value, and refuses everything but plan_id and plan_digest on
// approve-members. Both identifiers must have their fixed forms.
func membersFields(req Request, raw []byte) (string, string) {
	if pairedServiceVerb(req.Verb) {
		if !validRecoveryRequest(req, raw) {
			return diag.DaemonUndeclared, "invalid " + req.Verb + " request"
		}
		return "", ""
	}
	if req.ChallengeNonce != "" || req.OwnerSignature != "" || hasRawField(raw, "challenge_nonce", "owner_signature") {
		return diag.DaemonUndeclared, "recovery proof fields are not declared on this verb"
	}

	if req.Verb == membersPlansVerb {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return diag.DaemonUndeclared, "invalid members-plans request"
		}
		for k := range fields {
			switch k {
			case "verb", "option", "plan_id", "nonce", "timestamp", "public_key", "signature":
			default:
				return diag.DaemonUndeclared, "unexpected members-plans field"
			}
		}
		_, hasID := fields["plan_id"]
		if (req.Option != "list" && req.Option != "get") || ((hasID || req.Option == "get") && !plan.ValidID(req.PlanID)) ||
			len(req.Nonce) > 128 || strings.ContainsAny(req.Nonce, "\r\n") {
			return diag.DaemonUndeclared, "members-plans requires list with an optional cursor, or get with a plan ID"
		}
		return "", ""
	}

	if req.Verb != approveMembersVerb {
		if req.PlanDigest != "" || hasRawField(raw, "plan_digest") {
			return diag.DaemonUndeclared, "plan_digest is not declared on this verb"
		}
		return "", ""
	}
	if req.Name != "" || req.Option != "" || req.Target != "" || req.Soul != "" || req.Harness != "" || req.SessionID != "" {
		return diag.DaemonUndeclared, "approve-members accepts only plan_id and plan_digest"
	}
	if !members.ValidApproval(req.PlanID, req.PlanDigest) {
		return diag.DaemonUndeclared, "approve-members needs a plan id and a sha-256 plan digest"
	}
	return "", ""
}

func canonical(r Request) []byte {
	parts := []string{
		r.Verb, r.Name, r.Option, r.Target, r.PlanID, r.Soul, r.Harness, r.SessionID,
		strconv.FormatInt(r.Timestamp, 10), r.Nonce,
	}
	if r.CatalogKey != nil || r.Floor != nil || r.Envelope != nil {
		parts = append(parts, catalogCanonical(r))
	}
	if r.PlanDigest != "" {
		parts = append(parts, "plan_digest", r.PlanDigest)
	}
	if r.ChallengeNonce != "" {
		parts = append(parts, "challenge_nonce", r.ChallengeNonce)
	}
	if r.OwnerSignature != "" {
		parts = append(parts, "owner_signature", r.OwnerSignature)
	}
	if isStage2aVerb(r.Verb) || r.Verb == stage2aCooperativeRecoveryVerb {
		parts = append(parts, "stage2a_request", r.Stage2aRequest)
	}
	if r.Verb == deviceVerb && r.Option != "identity" {
		parts = append(parts, "hq_epoch", r.HQEpoch)
	}
	if r.Verb == deviceVerb && r.Option == "whoami" {
		parts = append(parts, "session", r.DeviceSession)
	}
	if r.Verb == deviceVerb && (r.Option == "bind-enrollment" || r.Option == "bind-access") {
		parts = append(parts, "receipt_body", r.ReceiptBody, "receipt_jti", r.ReceiptJTI, "receipt_kid", r.ReceiptKID, "receipt_signature", r.ReceiptSignature)
	}
	return []byte(strings.Join(parts, "\n"))
}

func catalogCanonical(r Request) string {
	var key, floor, env string
	if r.CatalogKey != nil {
		key = r.CatalogKey.PublicKey + "\n" + r.CatalogKey.KeyID
	}
	if r.Floor != nil {
		floor = r.Floor.KeyID + "\n" + strconv.FormatInt(r.Floor.MinVersion, 10)
	}
	if r.Envelope != nil {
		env = strings.Join([]string{
			r.Envelope.Format,
			r.Envelope.KeyID,
			strconv.FormatInt(r.Envelope.Version, 10),
			strconv.FormatInt(r.Envelope.IssuedAt, 10),
			r.Envelope.Catalog,
			r.Envelope.Sig,
		}, "\n")
	}
	return strings.Join([]string{key, floor, env}, "\n")
}

// Sign fills PublicKey and Signature using the agent-daemon private key.
func Sign(priv ed25519.PrivateKey, r *Request) error {
	pub := priv.Public().(ed25519.PublicKey)
	r.PublicKey = base64.StdEncoding.EncodeToString(pub)
	sig := ed25519.Sign(priv, canonical(*r))
	r.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

func signResponse(priv ed25519.PrivateKey, res *Response) {
	res.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, responsePayload(*res)))
}

func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func refused(id, message string) Response {
	return Response{OK: false, Diagnostic: id, Message: message}
}

func formatLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > maxMessage {
		return nil, fmt.Errorf("message exceeds %d bytes", maxMessage)
	}
	return append(b, '\n'), nil
}
