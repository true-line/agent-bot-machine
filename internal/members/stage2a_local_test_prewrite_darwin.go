//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"time"
)

// The three envelope hashes bind B's member assignment and authority to the
// particular outer start. None may be selected by HQ at prewrite time.
type stage2aLocalTestSelectors struct {
	AssignmentEnvelopeSHA256 string `json:"assignment_envelope_sha256"`
	AuthorityEnvelopeSHA256  string `json:"authority_envelope_sha256"`
	InstallationID           string `json:"installation_id"`
	LaunchID                 string `json:"launch_id"`
	MemberSelectorsSHA256    string `json:"member_selectors_sha256"`
	PlanDigest               string `json:"plan_digest"`
	PlanID                   string `json:"plan_id"`
	ReservationDigest        string `json:"reservation_digest"`
	StartID                  string `json:"start_id"`
}

func (s stage2aLocalTestSelectors) valid() bool {
	return stage2aPrefixedDigest.MatchString(s.AssignmentEnvelopeSHA256) &&
		stage2aPrefixedDigest.MatchString(s.AuthorityEnvelopeSHA256) &&
		stage2aPrefixedDigest.MatchString(s.MemberSelectorsSHA256) &&
		stage2aPrefixedDigest.MatchString(s.ReservationDigest) &&
		soulInstallationID.MatchString(s.InstallationID) && soulLaunchID.MatchString(s.LaunchID) &&
		soulStartID.MatchString(s.StartID) && stage2aBindingID.MatchString(s.PlanID) &&
		soulDigest.MatchString(s.PlanDigest)
}

type stage2aLocalTestIngressAuthorization struct {
	Schema              string                    `json:"schema"`
	Kind                string                    `json:"kind"`
	Selectors           stage2aLocalTestSelectors `json:"selectors"`
	IngressCoreSHA256   string                    `json:"ingress_core_sha256"`
	ProviderClaimSHA256 string                    `json:"provider_claim_sha256"`
	IssuedAt            string                    `json:"issued_at"`
	ExpiresAt           string                    `json:"expires_at"`
}

// B's exact observed ingress record is supplied alongside A's signed hash.
// A must compare the record with the prepared wire before it spends or signs
// prewrite acceptance; a hash alone does not prove matching peer or body.
type stage2aLocalTestIngressCore struct {
	Schema                 string                    `json:"schema"`
	Kind                   string                    `json:"kind"`
	Selectors              stage2aLocalTestSelectors `json:"selectors"`
	AttemptID              string                    `json:"attempt_id"`
	BindReceiptSHA256      string                    `json:"bind_receipt_sha256"`
	BodyProfile            string                    `json:"body_profile"`
	DigestKind             string                    `json:"digest_kind"`
	ObservedBodySHA256     string                    `json:"observed_body_sha256"`
	ObservedBriefSHA256    string                    `json:"observed_brief_sha256"`
	ObservedHeadersSHA256  string                    `json:"observed_headers_sha256"`
	OwnerPromptSHA256      string                    `json:"owner_prompt_sha256"`
	Peer                   Stage2aT03RelayPeer       `json:"peer"`
	PeerSHA256             string                    `json:"peer_sha256"`
	StaticProjectionSHA256 string                    `json:"static_projection_sha256"`
	TargetReceivedAt       string                    `json:"target_received_at"`
}

func parseStage2aLocalTestIngressCore(raw []byte) (stage2aLocalTestIngressCore, error) {
	var core stage2aLocalTestIngressCore
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &core) != nil ||
		core.Schema != "stage2a-observed-body-local-test-ingress/v1" ||
		core.Kind != "observed-body-local-test-ingress" || !core.Selectors.valid() ||
		!stage2aBindingID.MatchString(core.AttemptID) ||
		core.BodyProfile != "stage2a-stock-observed-local-test/v1" ||
		core.DigestKind != "observed-stock-body/v1" || !core.Peer.valid() {
		return stage2aLocalTestIngressCore{}, errStage2aReservationAuthority
	}
	for _, digest := range []string{core.BindReceiptSHA256, core.ObservedBodySHA256,
		core.ObservedBriefSHA256, core.ObservedHeadersSHA256, core.OwnerPromptSHA256,
		core.PeerSHA256, core.StaticProjectionSHA256} {
		if !stage2aPrefixedDigest.MatchString(digest) {
			return stage2aLocalTestIngressCore{}, errStage2aReservationAuthority
		}
	}
	peer, err := stage2aT03PeerCanonical(core.Peer)
	if err != nil || stage2aReservationSHA256(peer) != core.PeerSHA256 {
		return stage2aLocalTestIngressCore{}, errStage2aReservationAuthority
	}
	if _, err := time.Parse(time.RFC3339Nano, core.TargetReceivedAt); err != nil {
		return stage2aLocalTestIngressCore{}, errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(core)
	if err != nil || !bytes.Equal(canonical, raw) {
		return stage2aLocalTestIngressCore{}, errStage2aReservationAuthority
	}
	return core, nil
}

func joinStage2aLocalTestIngressPrewrite(ingress stage2aLocalTestIngressCore,
	core stage2aLocalTestPrewriteCore) error {
	if ingress.Selectors != core.Selectors || ingress.BindReceiptSHA256 != core.BindReceiptSHA256 ||
		ingress.ObservedBodySHA256 != core.ObservedBodySHA256 ||
		ingress.ObservedHeadersSHA256 != core.ObservedHeadersSHA256 ||
		ingress.OwnerPromptSHA256 != core.OwnerPromptSHA256 ||
		ingress.StaticProjectionSHA256 != core.StaticProjectionSHA256 ||
		ingress.Peer != core.Peer || ingress.PeerSHA256 != core.PeerSHA256 {
		return errStage2aReservationAuthority
	}
	return nil
}

// This is the complete B prepared-wire core. The digest of its canonical
// bytes commits the observed body and headers, live peer, response bytes and
// HTTP status without putting any response body in the A-signed proof.
type stage2aLocalTestPrewriteCore struct {
	Schema                      string                    `json:"schema"`
	Selectors                   stage2aLocalTestSelectors `json:"selectors"`
	BindReceiptSHA256           string                    `json:"bind_receipt_sha256"`
	AuthorizationEnvelopeSHA256 string                    `json:"authorization_envelope_sha256"`
	IngressCoreSHA256           string                    `json:"ingress_core_sha256"`
	ObservedBodySHA256          string                    `json:"observed_body_sha256"`
	ObservedHeadersSHA256       string                    `json:"observed_headers_sha256"`
	StaticProjectionSHA256      string                    `json:"static_projection_sha256"`
	OwnerPromptSHA256           string                    `json:"owner_prompt_sha256"`
	Peer                        Stage2aT03RelayPeer       `json:"peer"`
	PeerSHA256                  string                    `json:"peer_sha256"`
	ResponseWireSHA256          string                    `json:"response_wire_sha256"`
	ResponseWireBytes           int                       `json:"response_wire_bytes"`
	HTTPStatus                  int                       `json:"http_status"`
}

func (c stage2aLocalTestPrewriteCore) canonical() ([]byte, error) {
	if c.Schema != "stage2a-observed-body-local-test-prewrite/v1" ||
		!c.Selectors.valid() || !c.Peer.valid() || c.ResponseWireBytes <= 0 ||
		c.ResponseWireBytes > 1<<20 || c.HTTPStatus != 200 {
		return nil, errStage2aReservationAuthority
	}
	for _, digest := range []string{c.BindReceiptSHA256, c.AuthorizationEnvelopeSHA256,
		c.IngressCoreSHA256, c.ObservedBodySHA256, c.ObservedHeadersSHA256,
		c.StaticProjectionSHA256, c.OwnerPromptSHA256, c.PeerSHA256,
		c.ResponseWireSHA256} {
		if !stage2aPrefixedDigest.MatchString(digest) {
			return nil, errStage2aReservationAuthority
		}
	}
	peer, err := stage2aT03PeerCanonical(c.Peer)
	if err != nil || stage2aReservationSHA256(peer) != c.PeerSHA256 {
		return nil, errStage2aReservationAuthority
	}
	return marshalStage2aReservationJCS(c)
}

type stage2aLocalTestPrewriteProof struct {
	Schema                      string                    `json:"schema"`
	Kind                        string                    `json:"kind"`
	SchemaVersion               int                       `json:"schema_version"`
	Selectors                   stage2aLocalTestSelectors `json:"selectors"`
	HQEpoch                     string                    `json:"hq_epoch"`
	AuthorizationEnvelopeSHA256 string                    `json:"authorization_envelope_sha256"`
	PrewriteCoreSHA256          string                    `json:"prewrite_core_sha256"`
	PrewriteReceipt             string                    `json:"prewrite_receipt"`
	IssuedAt                    string                    `json:"issued_at"`
	ExpiresAt                   string                    `json:"expires_at"`
}

// prepareStage2aLocalTestPrewriteProof is a shape and join check only. The
// caller must first check live peer, stop, current epoch, observed pins and
// Provider spend, then durably accept this exact core before signing it.
func prepareStage2aLocalTestPrewriteProof(core stage2aLocalTestPrewriteCore,
	ingressCore, authorizationEnvelope []byte, enrolledKey ed25519.PublicKey, epoch, receipt string,
	authorityExpiry, now time.Time) ([]byte, error) {
	if !soulHQEpoch.MatchString(epoch) || !stage2aLowerHex64(receipt) ||
		len(authorizationEnvelope) == 0 || authorityExpiry.IsZero() || !now.Before(authorityExpiry) {
		return nil, errStage2aReservationAuthority
	}
	authRaw, err := verifyStage2aLocalTestEnvelope(authorizationEnvelope,
		stage2aLocalTestIngressPurpose, enrolledKey)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	var auth stage2aLocalTestIngressAuthorization
	if stage2aDecodeExact(authRaw, &auth) != nil || !auth.Selectors.valid() ||
		!stage2aPrefixedDigest.MatchString(auth.IngressCoreSHA256) ||
		!stage2aPrefixedDigest.MatchString(auth.ProviderClaimSHA256) {
		return nil, errStage2aReservationAuthority
	}
	ingress, err := parseStage2aLocalTestIngressCore(ingressCore)
	if err != nil || stage2aReservationSHA256(ingressCore) != auth.IngressCoreSHA256 ||
		joinStage2aLocalTestIngressPrewrite(ingress, core) != nil {
		return nil, errStage2aReservationAuthority
	}
	authIssued, err1 := time.Parse(time.RFC3339Nano, auth.IssuedAt)
	authExpires, err2 := time.Parse(time.RFC3339Nano, auth.ExpiresAt)
	targetReceived, err3 := time.Parse(time.RFC3339Nano, ingress.TargetReceivedAt)
	if err1 != nil || err2 != nil || err3 != nil || targetReceived.After(authIssued) ||
		now.Before(authIssued) || !now.Before(authExpires) ||
		!authIssued.Before(authExpires) || authExpires.After(authorityExpiry) ||
		authExpires.Sub(authIssued) > 30*time.Second ||
		core.Selectors != auth.Selectors || core.IngressCoreSHA256 != auth.IngressCoreSHA256 ||
		core.AuthorizationEnvelopeSHA256 != stage2aReservationSHA256(authorizationEnvelope) {
		return nil, errStage2aReservationAuthority
	}
	coreRaw, err := core.canonical()
	if err != nil {
		return nil, err
	}
	proof := stage2aLocalTestPrewriteProof{
		Schema: "agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1",
		Kind:   "observed-body-local-test-prewrite-acceptance", SchemaVersion: 1,
		Selectors: core.Selectors,
		HQEpoch:   epoch, AuthorizationEnvelopeSHA256: core.AuthorizationEnvelopeSHA256,
		PrewriteCoreSHA256: stage2aReservationSHA256(coreRaw), PrewriteReceipt: receipt,
		IssuedAt:  now.UTC().Format(time.RFC3339Nano),
		ExpiresAt: authExpires.UTC().Format(time.RFC3339Nano),
	}
	return marshalStage2aReservationJCS(proof)
}

type stage2aLocalTestPrewriteReply struct {
	PrewriteReceipt                string `json:"prewrite_receipt"`
	PrewriteProofEnvelopeBase64URL string `json:"prewrite_proof_envelope_base64url"`
	PrewriteProofEnvelopeSHA256    string `json:"prewrite_proof_envelope_sha256"`
}

// The caller rechecks the installed plan, current epoch, stop, live roles,
// Provider spend and B peer before invoking this gate. authorityExpiry is the
// minimum signed reservation/B-policy expiry. The gate takes the installation
// lock to serialize its durable claim with other A-side transitions.
// The exclusive durable record is committed before A signs or returns proof.
// A failed signature leaves the name occupied and cannot authorize a retry.
func commitAndSignStage2aLocalTestPrewrite(store stage2aAdminClaimStore, dir *os.File,
	core stage2aLocalTestPrewriteCore, ingressCore, authorizationEnvelope []byte,
	enrolledKey ed25519.PublicKey, epoch, receipt string, authorityExpiry, now time.Time,
	sign func([]byte) ([]byte, error)) (stage2aLocalTestPrewriteReply, error) {
	var reply stage2aLocalTestPrewriteReply
	if dir == nil || store.checkDirectory(dir) != nil || store.uid < 400 || store.gid == 0 ||
		store.uid != uint32(os.Getuid()) || store.uid != uint32(os.Geteuid()) ||
		store.gid != uint32(os.Getgid()) || store.gid != uint32(os.Getegid()) || sign == nil {
		return reply, errStage2aReservationAuthority
	}
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, core.Selectors.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil {
		return reply, errStage2aReservationAuthority
	}
	payload, err := prepareStage2aLocalTestPrewriteProof(core, ingressCore, authorizationEnvelope,
		enrolledKey, epoch, receipt, authorityExpiry, now)
	if err != nil {
		return reply, err
	}
	name := ".stage2a-local-test-prewrite-" + soulStartClaimName(
		core.Selectors.InstallationID, core.Selectors.StartID) + ".json"
	if err := commitStage2aReservation(dir, name, payload); err != nil {
		return reply, err
	}
	envelope, err := signStage2aVerifiedLocalTestEnvelope(stage2aVerifiedSigningPayloadV3{
		verified: true, purpose: stage2aLocalTestPrewritePurpose, payload: payload,
		machineUID: store.uid, machineGID: store.gid,
	}, enrolledKey, sign)
	if err != nil {
		return reply, err
	}
	return stage2aLocalTestPrewriteReply{
		PrewriteReceipt:                receipt,
		PrewriteProofEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		PrewriteProofEnvelopeSHA256:    stage2aReservationSHA256(envelope),
	}, nil
}

// B checks this proof against its own prepared-wire core immediately before
// the first response byte. A bare receipt returned by HQ has no authority.
func verifyStage2aLocalTestPrewriteProof(envelope []byte, enrolledKey ed25519.PublicKey,
	core stage2aLocalTestPrewriteCore, authorizationEnvelopeSHA256, epoch string,
	authorizationIssued, authorityExpiry, now time.Time) (string, error) {
	raw, err := verifyStage2aLocalTestEnvelope(envelope, stage2aLocalTestPrewritePurpose, enrolledKey)
	if err != nil {
		return "", errStage2aReservationAuthority
	}
	var proof stage2aLocalTestPrewriteProof
	if stage2aDecodeExact(raw, &proof) != nil || !proof.Selectors.valid() ||
		!soulHQEpoch.MatchString(proof.HQEpoch) || !stage2aLowerHex64(proof.PrewriteReceipt) ||
		!stage2aPrefixedDigest.MatchString(proof.PrewriteCoreSHA256) ||
		!stage2aPrefixedDigest.MatchString(proof.AuthorizationEnvelopeSHA256) ||
		proof.Selectors != core.Selectors || proof.HQEpoch != epoch ||
		proof.AuthorizationEnvelopeSHA256 != authorizationEnvelopeSHA256 ||
		core.AuthorizationEnvelopeSHA256 != authorizationEnvelopeSHA256 {
		return "", errStage2aReservationAuthority
	}
	issued, err1 := time.Parse(time.RFC3339Nano, proof.IssuedAt)
	expires, err2 := time.Parse(time.RFC3339Nano, proof.ExpiresAt)
	if err1 != nil || err2 != nil || authorizationIssued.IsZero() || authorityExpiry.IsZero() ||
		issued.Before(authorizationIssued) || now.Before(issued) || !now.Before(expires) || !issued.Before(expires) ||
		expires.After(authorityExpiry) || expires.Sub(issued) > 30*time.Second {
		return "", errStage2aReservationAuthority
	}
	coreRaw, err := core.canonical()
	if err != nil || proof.PrewriteCoreSHA256 != stage2aReservationSHA256(coreRaw) {
		return "", errStage2aReservationAuthority
	}
	return proof.PrewriteReceipt, nil
}

// B and H must use this full check at the write boundary. It joins the
// signed ingress authorization to B's own canonical ingress core and to the
// immutable prepared-wire core before trusting the signed prewrite proof.
func verifyStage2aLocalTestPrewriteProofWithIngress(envelope []byte,
	enrolledKey ed25519.PublicKey, core stage2aLocalTestPrewriteCore,
	ingressCore, authorizationEnvelope []byte, epoch string, authorityExpiry,
	now time.Time) (string, error) {
	authRaw, err := verifyStage2aLocalTestEnvelope(authorizationEnvelope,
		stage2aLocalTestIngressPurpose, enrolledKey)
	if err != nil {
		return "", errStage2aReservationAuthority
	}
	var auth stage2aLocalTestIngressAuthorization
	if stage2aDecodeExact(authRaw, &auth) != nil || !auth.Selectors.valid() ||
		!stage2aPrefixedDigest.MatchString(auth.ProviderClaimSHA256) {
		return "", errStage2aReservationAuthority
	}
	ingress, err := parseStage2aLocalTestIngressCore(ingressCore)
	if err != nil || auth.Selectors != ingress.Selectors ||
		stage2aReservationSHA256(ingressCore) != auth.IngressCoreSHA256 ||
		joinStage2aLocalTestIngressPrewrite(ingress, core) != nil ||
		core.AuthorizationEnvelopeSHA256 != stage2aReservationSHA256(authorizationEnvelope) ||
		core.IngressCoreSHA256 != auth.IngressCoreSHA256 {
		return "", errStage2aReservationAuthority
	}
	issued, e1 := time.Parse(time.RFC3339Nano, auth.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, auth.ExpiresAt)
	targetReceived, e3 := time.Parse(time.RFC3339Nano, ingress.TargetReceivedAt)
	if e1 != nil || e2 != nil || e3 != nil || targetReceived.After(issued) ||
		now.Before(issued) || !now.Before(expires) || !issued.Before(expires) ||
		expires.After(authorityExpiry) || expires.Sub(issued) > 30*time.Second {
		return "", errStage2aReservationAuthority
	}
	return verifyStage2aLocalTestPrewriteProof(envelope, enrolledKey, core,
		stage2aReservationSHA256(authorizationEnvelope), epoch, issued, expires, now)
}

func parseStage2aLocalTestPrewriteCore(raw []byte) (stage2aLocalTestPrewriteCore, error) {
	var core stage2aLocalTestPrewriteCore
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &core) != nil {
		return stage2aLocalTestPrewriteCore{}, errStage2aReservationAuthority
	}
	canonical, err := core.canonical()
	if err != nil || string(canonical) != string(raw) {
		return stage2aLocalTestPrewriteCore{}, errStage2aReservationAuthority
	}
	return core, nil
}

// The envelope's payload is JSON; decoding happens only after signature and
// canonicality verification. It is kept local to Machine until Contracts
// freezes the wire schema and B/H implement the same checks.
func decodeStage2aLocalTestPrewriteProof(raw []byte) (stage2aLocalTestPrewriteProof, error) {
	var proof stage2aLocalTestPrewriteProof
	if json.Unmarshal(raw, &proof) != nil || stage2aLocalTestCanonicalPayload(raw, stage2aLocalTestPrewritePurpose) != nil {
		return stage2aLocalTestPrewriteProof{}, errStage2aReservationAuthority
	}
	return proof, nil
}
