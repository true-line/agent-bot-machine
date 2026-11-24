package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
)

const stage2aReserveVerb = "stage2a-reserve"
const stage2aExecVerb = "stage2a-exec"
const stage2aVerifyBVerb = "stage2a-verify-b"
const stage2aLookupVerb = "stage2a-lookup"
const stage2aListVerb = "stage2a-list"
const stage2aPrepareBVerb = "stage2a-prepare-b"
const stage2aStopVerb = "stage2a-stop"
const stage2aFinalizeBVerb = "stage2a-finalize-b"
const stage2aLiveVerb = "stage2a-live"
const stage2aT03PositiveVerb = "stage2a-t03-positive"
const stage2aT03PrewriteVerb = "stage2a-t03-prewrite-peer"
const stage2aT03ReadyVerb = "stage2a-t03-ready"
const stage2aT03CompleteVerb = "stage2a-t03-complete"
const stage2aT03SiblingWitnessVerb = "stage2a-t03-sibling-credential-witness"
const stage2aT03DirectChildWitnessVerb = "stage2a-t03-child-credential-witness"
const stage2aProviderVerb = "stage2a-provider"
const stage2aChildReadyVerb = "stage2a-child-ready"
const stage2aHelloStartVerb = "stage2a-hello-start"
const stage2aHelloFinalizeVerb = "stage2a-hello-finalize"
const stage2aHelloAbortVerb = "stage2a-hello-abort"
const stage2aPeerRoleVerb = "stage2a-peer-role"
const stage2aCooperativeReserveVerb = "stage2a-cooperative-reserve-v3"
const stage2aCooperativeReserveResultVerb = "stage2a-cooperative-reserve-result-v3"
const stage2aCooperativeAttachVerb = "stage2a-cooperative-attach-v3"
const stage2aCooperativeStopVerb = "stage2a-cooperative-stop-v3"
const stage2aCooperativeProjectionVerb = "stage2a-cooperative-launch-inputs-v3"
const stage2aCooperativeProviderVerb = "stage2a-cooperative-provider-v3"
const stage2aCooperativeLookupVerb = "stage2a-cooperative-lookup-v3"
const stage2aCooperativeLiveVerb = "stage2a-cooperative-live-v3"
const stage2aCooperativeAbortVerb = "stage2a-cooperative-abort-v3"
const stage2aCooperativeRecoveryVerb = "stage2a-cooperative-recovery-v3"
const stage2aCooperativeQBeginVerb = "stage2a-cooperative-q-begin-v3"
const stage2aCooperativeQFinishVerb = "stage2a-cooperative-q-finish-v3"
const stage2aCooperativeQWitnessBeginVerb = "stage2a-cooperative-q-witness-begin-v3"
const stage2aCooperativeQWitnessFinishVerb = "stage2a-cooperative-q-witness-finish-v3"

var stage2aExecDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type stage2aExecRequest struct {
	ReservationSHA256 string `json:"reservation_sha256"`
	Role              string `json:"role"`
	Nonce             string `json:"nonce"`
	PID               int    `json:"pid"`
}

func isStage2aVerb(verb string) bool {
	return verb == stage2aReserveVerb || verb == stage2aExecVerb || verb == stage2aT03PositiveVerb || verb == stage2aT03PrewriteVerb ||
		verb == stage2aT03ReadyVerb || verb == stage2aT03CompleteVerb || verb == stage2aT03SiblingWitnessVerb ||
		verb == stage2aVerifyBVerb || verb == stage2aLookupVerb || verb == stage2aListVerb || verb == stage2aPrepareBVerb || verb == stage2aStopVerb || verb == stage2aFinalizeBVerb || verb == stage2aLiveVerb || verb == stage2aProviderVerb || verb == stage2aChildReadyVerb ||
		verb == stage2aHelloStartVerb || verb == stage2aHelloFinalizeVerb || verb == stage2aHelloAbortVerb ||
		verb == stage2aPeerRoleVerb || verb == stage2aCooperativeReserveVerb ||
		verb == stage2aCooperativeAttachVerb || verb == stage2aCooperativeStopVerb ||
		verb == stage2aCooperativeProjectionVerb || verb == stage2aCooperativeProviderVerb ||
		verb == stage2aCooperativeLookupVerb || verb == stage2aCooperativeLiveVerb ||
		verb == stage2aCooperativeAbortVerb || verb == stage2aCooperativeReserveResultVerb ||
		verb == stage2aCooperativeQBeginVerb || verb == stage2aCooperativeQFinishVerb ||
		verb == stage2aCooperativeQWitnessBeginVerb || verb == stage2aCooperativeQWitnessFinishVerb
}

func stage2aFields(req *Request, raw []byte) (string, string) {
	if req.Verb == stage2aCooperativeRecoveryVerb {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(req.Stage2aRequest)
		if err != nil || len(decoded) == 0 || len(decoded) > 2048 ||
			base64.RawURLEncoding.EncodeToString(decoded) != req.Stage2aRequest {
			return diag.DaemonUndeclared, "invalid cooperative recovery selectors"
		}
		q, err := members.ParseStage2aStopRequest(decoded)
		if err != nil || q.PlanID != req.PlanID || q.PlanDigest != req.PlanDigest {
			return diag.DaemonUndeclared, "cooperative recovery selectors mismatch"
		}
		req.stage2aCooperativeRecovery = q
		return "", ""
	}
	if !isStage2aVerb(req.Verb) {
		if req.Stage2aRequest != "" || hasRawField(raw, "stage2a_request") {
			return diag.DaemonUndeclared, "Stage 2a request is not declared on this verb"
		}
		return "", ""
	}
	fields, ok := deviceObject(raw)
	if !ok || !deviceKeys(fields, "verb", "stage2a_request", "nonce", "timestamp", "public_key", "signature") ||
		len(req.Stage2aRequest) == 0 || len(req.Stage2aRequest) > base64.RawURLEncoding.EncodedLen(8192) {
		return diag.DaemonUndeclared, "invalid Stage 2a request fields"
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(req.Stage2aRequest)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != req.Stage2aRequest {
		return diag.DaemonUndeclared, "invalid Stage 2a request"
	}
	if req.Verb == stage2aListVerb {
		if string(decoded) != "{}" {
			return diag.DaemonUndeclared, "invalid Stage 2a installed list request"
		}
		return "", ""
	}
	if req.Verb == stage2aReserveVerb {
		parsed, err := members.ParseStage2aReserveRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a reserve request"
		}
		req.stage2aReserve = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeReserveVerb || req.Verb == stage2aCooperativeReserveResultVerb {
		parsed, err := members.ParseSoulCooperativeStartRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative Soul reserve request"
		}
		req.stage2aCooperativeReserve = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeAttachVerb {
		parsed, err := members.ParseSoulCooperativeAttachRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative Soul attach request"
		}
		req.stage2aCooperativeAttach = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeStopVerb {
		parsed, err := members.ParseStage2aStopRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative Soul stop request"
		}
		req.stage2aCooperativeStop = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeProjectionVerb {
		parsed, err := members.ParseStage2aStopRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative launch-input request"
		}
		req.stage2aCooperativeProjection = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeProviderVerb {
		parsed, err := members.ParseSoulCooperativeProviderRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative provider request"
		}
		req.stage2aCooperativeProvider = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeLookupVerb {
		parsed, err := members.ParseStage2aLookupRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative installed lookup"
		}
		req.stage2aCooperativeLookup = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeLiveVerb {
		parsed, err := members.ParseSoulCooperativeLiveRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative liveness request"
		}
		req.stage2aCooperativeLive = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeQBeginVerb {
		parsed, err := members.ParseSoulCooperativeLiveRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative Q begin request"
		}
		req.stage2aCooperativeQBegin = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeQFinishVerb {
		parsed, err := members.ParseStage2aDirectQFinishRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative Q finish request"
		}
		req.stage2aCooperativeQFinish = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeQWitnessBeginVerb {
		parsed, err := members.ParseStage2aDirectQWitnessBeginRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative Q witness begin"
		}
		req.stage2aCooperativeQWitnessBegin = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeQWitnessFinishVerb {
		parsed, err := members.ParseStage2aDirectQWitnessFinishRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative Q witness finish"
		}
		req.stage2aCooperativeQWitnessFinish = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeAbortVerb {
		parsed, err := members.ParseStage2aStopRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative preattach abort request"
		}
		req.stage2aCooperativeAbort = parsed
		return "", ""
	}
	if req.Verb == stage2aLookupVerb {
		parsed, err := members.ParseStage2aLookupRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a installed lookup"
		}
		req.stage2aLookup = parsed
		return "", ""
	}
	if req.Verb == stage2aVerifyBVerb {
		parsed, err := members.ParseStage2aVerifyBRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a B verification request"
		}
		req.stage2aVerifyB = parsed
		return "", ""
	}
	if req.Verb == stage2aPrepareBVerb {
		parsed, err := members.ParseStage2aPrepareBRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a B preparation"
		}
		req.stage2aPrepareB = parsed
		return "", ""
	}
	if req.Verb == stage2aStopVerb {
		parsed, err := members.ParseStage2aStopRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a stop request"
		}
		req.stage2aStop = parsed
		return "", ""
	}
	if req.Verb == stage2aT03PositiveVerb {
		parsed, err := members.ParseStage2aT03ArmRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid protected T03 positive receipt"
		}
		req.stage2aT03Positive = parsed
		return "", ""
	}
	if req.Verb == stage2aT03PrewriteVerb {
		parsed, err := members.ParseStage2aT03PrewriteRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid protected T03 broker prewrite"
		}
		req.stage2aT03Prewrite = parsed
		return "", ""
	}
	if req.Verb == stage2aT03ReadyVerb {
		parsed, err := members.ParseStage2aT03ReadyRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid protected T03 ready record"
		}
		req.stage2aT03Ready = parsed
		return "", ""
	}
	if req.Verb == stage2aT03CompleteVerb {
		parsed, err := members.ParseStage2aT03CompleteRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid protected T03 completion record"
		}
		req.stage2aT03Complete = parsed
		return "", ""
	}
	if req.Verb == stage2aT03SiblingWitnessVerb {
		parsed, err := members.ParseStage2aT03SiblingCredentialWitnessRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid protected T03 sibling credential witness"
		}
		req.stage2aT03SiblingWitness = parsed
		return "", ""
	}
	if req.Verb == stage2aLiveVerb {
		parsed, err := members.ParseStage2aLiveRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a Live request"
		}
		req.stage2aLive = parsed
		return "", ""
	}
	if req.Verb == stage2aFinalizeBVerb {
		parsed, err := members.ParseStage2aFinalizeBRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a B finalization"
		}
		req.stage2aFinalizeB = parsed
		return "", ""
	}
	if req.Verb == stage2aProviderVerb {
		parsed, err := members.ParseStage2aProviderRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a provider request"
		}
		req.stage2aProvider = parsed
		return "", ""
	}
	if req.Verb == stage2aChildReadyVerb {
		parsed, err := members.ParseStage2aChildReadyRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a child readiness"
		}
		req.stage2aChildReady = parsed
		return "", ""
	}
	if req.Verb == stage2aHelloStartVerb {
		parsed, err := members.ParseStage2aHelloStartRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a Hello start"
		}
		req.stage2aHelloStart = parsed
		return "", ""
	}
	if req.Verb == stage2aHelloFinalizeVerb {
		parsed, err := members.ParseStage2aHelloFinalizeRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a Hello finalization"
		}
		req.stage2aHelloFinalize = parsed
		return "", ""
	}
	if req.Verb == stage2aHelloAbortVerb {
		parsed, err := members.ParseStage2aStopRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a Hello abort"
		}
		req.stage2aHelloAbort = parsed
		return "", ""
	}
	if req.Verb == stage2aPeerRoleVerb {
		parsed, err := members.ParseStage2aPeerRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a peer role"
		}
		req.stage2aPeerRole = parsed
		return "", ""
	}
	body, ok := deviceObject(decoded)
	var parsed stage2aExecRequest
	if !ok || !deviceKeys(body, "reservation_sha256", "role", "nonce", "pid") || json.Unmarshal(decoded, &parsed) != nil ||
		!stage2aExecDigest.MatchString(parsed.ReservationSHA256) || parsed.PID <= 1 || parsed.PID > 1<<31-1 ||
		(parsed.Role != "runner" && parsed.Role != "bridge" && parsed.Role != "child") {
		return diag.DaemonUndeclared, "invalid Stage 2a exec request"
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(parsed.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != parsed.Nonce {
		return diag.DaemonUndeclared, "invalid Stage 2a exec nonce"
	}
	req.stage2aExec = parsed
	return "", ""
}

func stage2aWitnessVerb(verb string) bool {
	return verb == stage2aCooperativeQWitnessBeginVerb || verb == stage2aCooperativeQWitnessFinishVerb
}

func lockStage2aPairing(dir string, req Request) (func() error, error) {
	unlock, err := lockDevicePairing(dir)
	if err != nil {
		return nil, err
	}
	pairing, err := currentDevicePairing(dir)
	key, decodeErr := base64.StdEncoding.Strict().DecodeString(req.PublicKey)
	if err != nil || decodeErr != nil || req.stage2aEpoch == "" || req.stage2aEpoch != pairing.HQEpoch ||
		!devicePairAllows(pairing, req.peerUID, ed25519.PublicKey(key)) || !dedicatedMembersPlanPeer(req.peerUID) {
		_ = unlock()
		return nil, errors.New("Stage 2a pairing no longer matches")
	}
	return unlock, nil
}
