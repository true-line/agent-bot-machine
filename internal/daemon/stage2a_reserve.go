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
const stage2aProviderVerb = "stage2a-provider"
const stage2aChildReadyVerb = "stage2a-child-ready"
const stage2aCaptureSelectorVerb = "stage2a-capture-selector"
const stage2aControlProbeVerb = "stage2a-control-probe-upload"
const stage2aHelloStartVerb = "stage2a-hello-start"
const stage2aHelloFinalizeVerb = "stage2a-hello-finalize"
const stage2aHelloAbortVerb = "stage2a-hello-abort"
const stage2aPeerRoleVerb = "stage2a-peer-role"
const stage2aMemberSetAssignVerb = "stage2a-member-set-assign"
const stage2aMemberProvisionalMapVerb = "stage2a-member-provisional-map"
const stage2aMemberChildGrantVerb = "stage2a-member-child-grant"
const stage2aMemberChildObserveVerb = "stage2a-member-child-observe"
const stage2aMemberLiveVerb = "stage2a-member-live"

const stage2aMemberReadyVerb = "stage2a-member-ready"

const stage2aCooperativeReserveVerb = "stage2a-cooperative-reserve-v3"
const stage2aCooperativeReserveResultVerb = "stage2a-cooperative-reserve-result-v3"
const stage2aCooperativeAttachVerb = "stage2a-cooperative-attach-v3"
const stage2aCooperativeStopVerb = "stage2a-cooperative-stop-v3"
const stage2aCooperativeProjectionVerb = "stage2a-cooperative-launch-inputs-v3"
const stage2aCooperativeLookupVerb = "stage2a-cooperative-lookup-v3"
const stage2aCooperativeLiveVerb = "stage2a-cooperative-live-v3"
const stage2aCooperativeAbortVerb = "stage2a-cooperative-abort-v3"
const stage2aCooperativeBExecVerb = "stage2a-cooperative-b-exec-v3"
const stage2aCooperativeBVerifyVerb = "stage2a-cooperative-b-verify-v3"
const stage2aCooperativeBObserveVerb = "stage2a-cooperative-b-observe-v3"
const stage2aCooperativeMemberPolicyVerb = "stage2a-cooperative-member-policy-v3"
const stage2aCooperativeChildExecVerb = "stage2a-cooperative-child-exec-v3"
const stage2aCooperativeProvisionalMapVerb = "stage2a-cooperative-provisional-map-v3"
const stage2aCooperativeChildObserveVerb = "stage2a-cooperative-child-observe-v3"
const stage2aCooperativeMemberReadyVerb = "stage2a-cooperative-member-ready-v3"
const stage2aCooperativeBLiveVerb = "stage2a-cooperative-b-live-v3"
const stage2aCooperativeMemberLiveVerb = "stage2a-cooperative-member-live-v3"
const stage2aCooperativeRelayPeerVerb = "stage2a-cooperative-relay-peer-v3"
const stage2aCooperativeRelayIngressVerb = "stage2a-cooperative-relay-ingress-v3"

var stage2aExecDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type stage2aExecRequest struct {
	ReservationSHA256 string `json:"reservation_sha256"`
	Role              string `json:"role"`
	Nonce             string `json:"nonce"`
	PID               int    `json:"pid"`
}

func isStage2aVerb(verb string) bool {
	return verb == stage2aReserveVerb || verb == stage2aExecVerb ||
		verb == stage2aVerifyBVerb || verb == stage2aLookupVerb || verb == stage2aListVerb || verb == stage2aPrepareBVerb || verb == stage2aStopVerb || verb == stage2aFinalizeBVerb || verb == stage2aLiveVerb || verb == stage2aProviderVerb || verb == stage2aChildReadyVerb || verb == stage2aCaptureSelectorVerb || verb == stage2aControlProbeVerb ||
		verb == stage2aHelloStartVerb || verb == stage2aHelloFinalizeVerb || verb == stage2aHelloAbortVerb ||
		verb == stage2aPeerRoleVerb || verb == stage2aMemberSetAssignVerb ||
		verb == stage2aMemberProvisionalMapVerb || verb == stage2aMemberChildGrantVerb ||
		verb == stage2aMemberChildObserveVerb || verb == stage2aMemberLiveVerb ||
		verb == stage2aMemberReadyVerb ||
		verb == stage2aCooperativeReserveVerb || verb == stage2aCooperativeReserveResultVerb ||
		verb == stage2aCooperativeAttachVerb || verb == stage2aCooperativeStopVerb ||
		verb == stage2aCooperativeProjectionVerb || verb == stage2aCooperativeLookupVerb ||
		verb == stage2aCooperativeLiveVerb || verb == stage2aCooperativeAbortVerb ||
		verb == stage2aCooperativeBExecVerb || verb == stage2aCooperativeBVerifyVerb ||
		verb == stage2aCooperativeBObserveVerb || verb == stage2aCooperativeMemberPolicyVerb ||
		verb == stage2aCooperativeChildExecVerb || verb == stage2aCooperativeProvisionalMapVerb ||
		verb == stage2aCooperativeChildObserveVerb || verb == stage2aCooperativeMemberReadyVerb ||
		verb == stage2aCooperativeBLiveVerb || verb == stage2aCooperativeMemberLiveVerb ||
		verb == stage2aCooperativeRelayPeerVerb || verb == stage2aCooperativeRelayIngressVerb

}

func stage2aFields(req *Request, raw []byte) (string, string) {
	if !isStage2aVerb(req.Verb) {
		if req.Stage2aRequest != "" || hasRawField(raw, "stage2a_request") {
			return diag.DaemonUndeclared, "Stage 2a request is not declared on this verb"
		}
		return "", ""
	}
	maxRequest := 8192
	if req.Verb == stage2aControlProbeVerb {
		maxRequest = 16 << 10
	}
	fields, ok := deviceObject(raw)
	if !ok || !deviceKeys(fields, "verb", "stage2a_request", "nonce", "timestamp", "public_key", "signature") ||
		len(req.Stage2aRequest) == 0 || len(req.Stage2aRequest) > base64.RawURLEncoding.EncodedLen(maxRequest) {
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
	if req.Verb == stage2aCooperativeReserveVerb || req.Verb == stage2aCooperativeReserveResultVerb {
		parsed, err := members.ParseSoulCooperativeStartRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative reserve request"
		}
		req.stage2aCooperativeReserve = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeAttachVerb {
		parsed, err := members.ParseSoulCooperativeAttachRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative attach request"
		}
		req.stage2aCooperativeAttach = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeStopVerb || req.Verb == stage2aCooperativeProjectionVerb || req.Verb == stage2aCooperativeAbortVerb {
		parsed, err := members.ParseStage2aStopRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative selectors"
		}
		req.stage2aCooperativeStop = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeLookupVerb {
		parsed, err := members.ParseStage2aLookupRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative lookup request"
		}
		req.stage2aCooperativeLookup = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeLiveVerb {
		parsed, err := members.ParseSoulCooperativeLiveRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative live request"
		}
		req.stage2aCooperativeLive = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeBExecVerb {
		parsed, err := members.ParseSoulCooperativeBExecRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative B exec request"
		}
		req.stage2aCooperativeBExec = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeBVerifyVerb {
		parsed, err := members.ParseSoulCooperativeBVerifyRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative B verify request"
		}
		req.stage2aCooperativeBVerify = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeBObserveVerb {
		parsed, err := members.ParseSoulCooperativeBObserveRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative B observation request"
		}
		req.stage2aCooperativeBObserve = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeMemberPolicyVerb {
		parsed, err := members.ParseSoulCooperativeMemberPolicyRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative member policy request"
		}
		req.stage2aCooperativeMemberPolicy = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeChildExecVerb {
		parsed, err := members.ParseSoulCooperativeChildExecRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative child exec request"
		}
		req.stage2aCooperativeChildExec = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeProvisionalMapVerb {
		parsed, err := members.ParseSoulCooperativeProvisionalMapRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative provisional map"
		}
		req.stage2aCooperativeProvisionalMap = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeChildObserveVerb {
		parsed, err := members.ParseSoulCooperativeChildObserveRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative child observation"
		}
		req.stage2aCooperativeChildObserve = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeMemberReadyVerb {
		parsed, err := members.ParseSoulCooperativeMemberReadyRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative member Ready request"
		}
		req.stage2aCooperativeMemberReady = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeBLiveVerb {
		parsed, err := members.ParseSoulCooperativeBLiveRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative B live request"
		}
		req.stage2aCooperativeBLive = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeMemberLiveVerb {
		parsed, err := members.ParseSoulCooperativeMemberLiveRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative member live request"
		}
		req.stage2aCooperativeMemberLive = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeRelayIngressVerb {
		parsed, err := members.ParseSoulCooperativeRelayIngressRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative relay ingress request"
		}
		req.stage2aCooperativeRelayIngress = parsed
		return "", ""
	}
	if req.Verb == stage2aCooperativeRelayPeerVerb {
		parsed, err := members.ParseSoulCooperativeRelayPeerRequestV3(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid cooperative relay peer request"
		}
		req.stage2aCooperativeRelayPeer = parsed
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
	if req.Verb == stage2aCaptureSelectorVerb {
		parsed, err := members.ParseStage2aCaptureSelectorRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a capture selector request"
		}
		req.stage2aCaptureSelector = parsed
		return "", ""
	}
	if req.Verb == stage2aControlProbeVerb {
		parsed, err := members.ParseStage2aProtectedControlProbeUpload(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a protected control probe upload"
		}
		req.stage2aControlProbe = parsed
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
	if req.Verb == stage2aMemberSetAssignVerb {
		parsed, err := members.ParseStage2aMemberSetAssignmentRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a member-set assignment request"
		}
		req.stage2aMemberSetAssign = parsed
		return "", ""
	}
	if req.Verb == stage2aMemberProvisionalMapVerb {
		parsed, err := members.ParseStage2aMemberProvisionalMapRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a provisional member map"
		}
		req.stage2aMemberProvisionalMap = parsed
		return "", ""
	}
	if req.Verb == stage2aMemberChildGrantVerb {
		parsed, err := members.ParseStage2aMemberChildGrantRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a member child grant"
		}
		req.stage2aMemberChildGrant = parsed
		return "", ""
	}
	if req.Verb == stage2aMemberChildObserveVerb {
		parsed, err := members.ParseStage2aMemberChildObservationRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a member child observation"
		}
		req.stage2aMemberChildObserve = parsed
		return "", ""
	}
	if req.Verb == stage2aMemberLiveVerb {
		parsed, err := members.ParseStage2aMemberLiveRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a member live request"
		}
		req.stage2aMemberLive = parsed
		return "", ""
	}
	if req.Verb == stage2aMemberReadyVerb {
		parsed, err := members.ParseStage2aMemberReadyRequest(decoded)
		if err != nil {
			return diag.DaemonUndeclared, "invalid Stage 2a member Ready request"
		}
		req.stage2aMemberReady = parsed
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
