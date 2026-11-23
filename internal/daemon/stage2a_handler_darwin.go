//go:build darwin

package daemon

import (
	"crypto/ed25519"
	"encoding/json"
	"log"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
)

func stage2aHandler(key ed25519.PrivateKey, dir, account string) func(Request) Response {
	service := members.NewStage2aService(key)
	paired := func(commitment string, run func() error) error {
		return CheckHQUpgradePair(dir, account, commitment, run)
	}
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
		case stage2aCooperativeReserveVerb:
			state = "cooperative-reserved"
			body, err = service.ReserveCooperativeV3(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeReserve, func(digest string) (members.Saved, error) {
					return findUniqueCooperativeHPlan(account, digest)
				}, paired)
		case stage2aCooperativeReserveResultVerb:
			state = "cooperative-reserve-result"
			body, err = service.CooperativeReserveResultV3(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeReserve.SoulCooperativeReserveRequest, paired)
		case stage2aCooperativeAttachVerb:
			state = "cooperative-attached"
			body, err = service.AttachCooperativeVerified(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeAttach, paired)
		case stage2aCooperativeStopVerb:
			state = "cooperative-stopped"
			body, err = service.StopCooperativeVerified(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeStop, paired)
		case stage2aCooperativeProjectionVerb:
			state = "cooperative-launch-inputs"
			body, err = service.CooperativeLaunchProjection(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeStop, paired)
		case stage2aCooperativeLookupVerb:
			state = "cooperative-found"
			body, err = service.LookupCooperativeInstalled(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeLookup, paired)
		case stage2aCooperativeLiveVerb:
			state = "cooperative-live"
			body, err = service.CooperativeLiveV3(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeLive, paired)
		case stage2aCooperativeBExecVerb:
			state = "cooperative-b-granted"
			body, err = service.CooperativeBExec(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeBExec, paired)
		case stage2aCooperativeBVerifyVerb:
			state = "cooperative-b-verified"
			body, err = service.CooperativeVerifyB(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeBVerify, paired)
		case stage2aCooperativeBObserveVerb:
			state = "cooperative-b-observed"
			body, err = service.CooperativeObserveB(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeBObserve, paired)
		case stage2aCooperativeMemberPolicyVerb:
			state = "cooperative-member-policy"
			body, err = service.CooperativeMemberPolicy(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeMemberPolicy, paired)
		case stage2aCooperativeChildExecVerb:
			state = "cooperative-child-granted"
			body, err = service.CooperativeChildExec(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeChildExec, paired)
		case stage2aCooperativeProvisionalMapVerb:
			state = "cooperative-provisional-map"
			body, err = service.CooperativeProvisionalMap(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeProvisionalMap, paired)
		case stage2aCooperativeChildObserveVerb:
			state = "cooperative-child-observed"
			body, err = service.CooperativeChildObserve(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeChildObserve, paired)
		case stage2aCooperativeMemberReadyVerb:
			state = "cooperative-member-ready"
			body, err = service.CooperativeMemberReady(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeMemberReady, paired)
		case stage2aCooperativeBLiveVerb:
			state = "cooperative-b-live"
			body, err = service.CooperativeBLive(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeBLive, paired)
		case stage2aCooperativeMemberLiveVerb:
			state = "cooperative-member-live"
			body, err = service.CooperativeMemberLive(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeMemberLive, paired)
		case stage2aCooperativeRelayIngressVerb:
			state = "cooperative-relay-ingress"
			body, err = service.CooperativeRelayIngress(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeRelayIngress, paired)
		case stage2aCooperativeRelayPeerVerb:
			state = "cooperative-relay-peer"
			body, err = service.CooperativeRelayPeer(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeRelayPeer, paired)
		case stage2aCooperativeAbortVerb:
			state = "cooperative-aborted"
			body, err = service.AbortCooperativePreAttach(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeStop, paired)
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
