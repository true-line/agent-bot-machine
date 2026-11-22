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
const stage2aHelloStartVerb = "stage2a-hello-start"
const stage2aHelloFinalizeVerb = "stage2a-hello-finalize"
const stage2aHelloAbortVerb = "stage2a-hello-abort"
const stage2aPeerRoleVerb = "stage2a-peer-role"

var stage2aExecDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type stage2aExecRequest struct {
	ReservationSHA256 string `json:"reservation_sha256"`
	Role              string `json:"role"`
	Nonce             string `json:"nonce"`
	PID               int    `json:"pid"`
}

func isStage2aVerb(verb string) bool {
	return verb == stage2aReserveVerb || verb == stage2aExecVerb ||
		verb == stage2aVerifyBVerb || verb == stage2aLookupVerb || verb == stage2aListVerb || verb == stage2aPrepareBVerb || verb == stage2aStopVerb || verb == stage2aFinalizeBVerb || verb == stage2aLiveVerb || verb == stage2aProviderVerb || verb == stage2aChildReadyVerb ||
		verb == stage2aHelloStartVerb || verb == stage2aHelloFinalizeVerb || verb == stage2aHelloAbortVerb ||
		verb == stage2aPeerRoleVerb
}

func stage2aFields(req *Request, raw []byte) (string, string) {
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
