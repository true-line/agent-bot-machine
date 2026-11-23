//go:build darwin

package daemon

import (
	"crypto/ed25519"
	"encoding/json"
	"log"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
)

func stage2aHandler(key ed25519.PrivateKey) func(Request) Response {
	service := members.NewStage2aService(key)
	return func(req Request) Response {
		var body any
		var err error
		state := "reserved"
		switch req.Verb {
		case stage2aListVerb:
			state = "listed"
			body, err = service.List(req.peerUID, req.stage2aEpoch)
		case stage2aLookupVerb:
			state = "found"
			body, err = service.Lookup(req.peerUID, req.stage2aEpoch, req.stage2aLookup)
		case stage2aReserveVerb:
			body, err = service.Reserve(req.peerUID, req.stage2aEpoch, req.stage2aReserve)
		case stage2aExecVerb:
			state = "granted"
			q := req.stage2aExec
			body, err = service.Exec(req.peerUID, req.stage2aEpoch, q.ReservationSHA256, q.Role, q.Nonce, q.PID)
		case stage2aVerifyBVerb:
			state = "verified"
			body, err = service.VerifyB(req.peerUID, req.stage2aEpoch, req.stage2aVerifyB)
		case stage2aPrepareBVerb:
			state = "prepared"
			body, err = service.PrepareB(req.peerUID, req.stage2aEpoch, req.stage2aPrepareB)
		case stage2aStopVerb:
			state = "stopped"
			body, err = service.Stop(req.peerUID, req.stage2aEpoch, req.stage2aStop)
		case stage2aFinalizeBVerb:
			state = "finalized"
			body, err = service.FinalizeB(req.peerUID, req.stage2aEpoch, req.stage2aFinalizeB)
		case stage2aLiveVerb:
			state = "live"
			body, err = service.Live(req.peerUID, req.stage2aEpoch, req.stage2aLive)
		case stage2aProviderVerb:
			state = "provided"
			body, err = service.Provider(req.peerUID, req.stage2aEpoch, req.stage2aProvider)
		case stage2aChildReadyVerb:
			state = "child-ready"
			body, err = service.ChildReady(req.peerUID, req.stage2aEpoch, req.stage2aChildReady)
		case stage2aCaptureSelectorVerb:
			state = "capture-selected"
			body, err = service.CaptureSelector(req.peerUID, req.stage2aEpoch, req.stage2aCaptureSelector)
		case stage2aControlProbeVerb:
			state = "control-probe-stored"
			body, err = service.StoreProtectedControlProbe(req.peerUID, req.stage2aEpoch, req.stage2aControlProbe)
		case stage2aHelloStartVerb:
			state = "hello-started"
			body, err = service.HelloStart(req.peerUID, req.stage2aEpoch, req.stage2aHelloStart)
		case stage2aHelloFinalizeVerb:
			state = "hello-finalized"
			body, err = service.HelloFinalize(req.peerUID, req.stage2aEpoch, req.stage2aHelloFinalize)
		case stage2aHelloAbortVerb:
			state = "hello-aborted"
			err = service.AbortHello(req.peerUID, req.stage2aEpoch, req.stage2aHelloAbort)
			body = struct {
				Aborted bool `json:"aborted"`
			}{Aborted: err == nil}
		case stage2aPeerRoleVerb:
			state = "peer-verified"
			body, err = service.PeerRole(req.peerUID, req.stage2aEpoch, req.stage2aPeerRole)
		case stage2aMemberSetAssignVerb:
			state = "member-set-assigned"
			body, err = service.MemberSetAssign(req.peerUID, req.stage2aEpoch, req.stage2aMemberSetAssign)
		case stage2aMemberProvisionalMapVerb:
			state = "member-map-withheld"
			body, err = service.MemberProvisionalMap(req.peerUID, req.stage2aEpoch, req.stage2aMemberProvisionalMap)
		case stage2aMemberChildGrantVerb:
			state = "member-child-granted"
			body, err = service.MemberChildGrant(req.peerUID, req.stage2aEpoch, req.stage2aMemberChildGrant)
		case stage2aMemberChildObserveVerb:
			state = "member-children-observed"
			body, err = service.MemberChildObserve(req.peerUID, req.stage2aEpoch, req.stage2aMemberChildObserve)
		case stage2aMemberLiveVerb:
			state = "member-live"
			body, err = service.MemberLive(req.peerUID, req.stage2aEpoch, req.stage2aMemberLive)
		case stage2aMemberReadyVerb:
			state = "member-ready"
			body, err = service.MemberReady(req.peerUID, req.stage2aEpoch, req.stage2aMemberReady)
		default:
			return refused(diag.DaemonUnimplemented, "unsupported Stage 2a verb")
		}
		if err != nil {
			log.Printf("Stage 2a local %s refused: %v", req.Verb, err)
			return refused(diag.DaemonUnimplemented, "Stage 2a installed authority unavailable or mismatched")
		}
		raw, err := json.Marshal(body)
		if err != nil || len(raw) > maxMessage-1024 {
			return refused(diag.DaemonUnimplemented, "Stage 2a response exceeds transport limit")
		}
		return Response{OK: true, State: state, Body: raw}
	}
}
