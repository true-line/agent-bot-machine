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
	return stage2aHandlerWithService(members.NewStage2aCandidateService(key, CheckHQUpgradePair), dir, account)
}

func stage2aServiceHandlers(key ed25519.PrivateKey, dir, account string) (
	func(Request) Response, cooperativeRecoveryApply) {
	service := members.NewStage2aCandidateService(key, CheckHQUpgradePair)
	return stage2aHandlerWithService(service, dir, account),
		func(recovery Request, paired func(string, func() error) error) Response {
			body, err := service.ReconcileCooperativeAfterRestart(recovery.peerUID,
				recovery.stage2aEpoch, recovery.stage2aCooperativeRecovery, paired)
			if err != nil {
				return refused(diag.DaemonUnimplemented, "cooperative recovery cutoff refused")
			}
			raw, err := json.Marshal(body)
			if err != nil || len(raw) > maxMessage-1024 {
				return refused(diag.DaemonUnimplemented, "cooperative recovery cutoff exceeds transport limit")
			}
			return Response{OK: true, State: "cooperative-recovered", Body: raw}
		}
}

func stage2aHandlerWithService(service *members.Stage2aService, dir, account string) func(Request) Response {
	paired := func(commitment string, run func() error) error {
		return CheckHQUpgradePair(dir, account, commitment, run)
	}
	return func(req Request) Response {
		var body any
		var err error
		state := "reserved"
		switch req.Verb {
		case stage2aLocalTestQIssueVerb:
			state = "local-test-q-issued"
			body, err = service.IssueLocalTestQApproval(req.peerUID, req.stage2aEpoch, req.stage2aLocalTestQPlanID)
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
				req.stage2aCooperativeProjection, paired)
		case stage2aCooperativeProviderVerb:
			state = "cooperative-provided"
			body, err = service.CooperativeProviderV3(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeProvider, paired)
		case stage2aCooperativeLookupVerb:
			state = "cooperative-found"
			body, err = service.LookupCooperativeInstalled(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeLookup, paired)
		case stage2aCooperativeLiveVerb:
			state = "cooperative-live"
			body, err = service.CooperativeLiveV3(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeLive, paired)
		case stage2aCooperativeQBeginVerb:
			state = "cooperative-q-pre"
			body, err = service.BeginDirectQualificationV3(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeQBegin, paired)
		case stage2aCooperativeQFinishVerb:
			state = "cooperative-q-captured"
			body, err = service.FinishDirectQualificationV3(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeQFinish, paired)
		case stage2aCooperativeQWitnessBeginVerb:
			state = "cooperative-q-witness-challenge"
			body, err = service.BeginDirectQualificationWitnessV3(req.peerUID, req.peerPID,
				req.stage2aEpoch, req.stage2aCooperativeQWitnessBegin, paired)
		case stage2aCooperativeQWitnessFinishVerb:
			state = "cooperative-q-witnessed"
			body, err = service.FinishDirectQualificationWitnessV3(req.peerUID, req.peerPID,
				req.stage2aEpoch, req.stage2aCooperativeQWitnessFinish, paired)
		case stage2aCooperativeAbortVerb:
			state = "cooperative-aborted"
			body, err = service.AbortCooperativePreAttach(req.peerUID, req.stage2aEpoch,
				req.stage2aCooperativeAbort, paired)
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
		case stage2aT03PositiveVerb:
			state = "t03-positive-recorded"
			var digest string
			digest, err = service.Stage2aT03AcceptPositive(req.peerUID, req.stage2aEpoch, req.stage2aT03Positive)
			if err == nil {
				service.StartProtectedT03(req.peerUID, req.stage2aEpoch, req.stage2aT03Positive.Stage2aStopRequest,
					func(run func() error) error {
						unlock, err := lockStage2aPairing(dir, req)
						if err != nil {
							return err
						}
						defer unlock()
						return run()
					})
			}
			body = struct {
				SHA256 string `json:"sha256"`
			}{digest}
		case stage2aT03PrewriteVerb:
			state = "t03-prewrite-peer-observed"
			var receipt string
			receipt, err = service.Stage2aT03AcceptPrewrite(req.peerUID, req.stage2aEpoch, req.stage2aT03Prewrite)
			body = struct {
				PrewriteReceipt string `json:"prewrite_receipt"`
			}{receipt}
		case stage2aT03ReadyVerb:
			state = "t03-ready-observed"
			err = service.Stage2aT03AcceptReady(req.peerUID, req.stage2aEpoch, req.stage2aT03Ready)
			body = struct {
				Accepted bool `json:"accepted"`
			}{err == nil}
		case stage2aT03CompleteVerb:
			state = "t03-completion-recorded"
			var digest string
			digest, err = service.Stage2aT03AcceptComplete(req.peerUID, req.stage2aEpoch, req.stage2aT03Complete)
			body = struct {
				SHA256 string `json:"sha256"`
			}{digest}
		case stage2aT03SiblingWitnessVerb:
			state = "t03-sibling-credential-witnessed"
			var digest string
			var sequence uint64
			digest, sequence, err = service.Stage2aT03AcceptSiblingWitness(req.peerUID, req.stage2aEpoch,
				req.stage2aT03SiblingWitness)
			body = struct {
				Accepted       bool   `json:"accepted"`
				MetadataSHA256 string `json:"metadata_sha256"`
				LeaseSequence  uint64 `json:"lease_sequence"`
			}{err == nil, digest, sequence}
		case stage2aT03DirectChildWitnessVerb:
			state = "t03-sibling-credential-observed"
			var digest string
			var sequence uint64
			digest, sequence, err = service.Stage2aT03ObserveDirectChildWitness(req.peerUID, req.peerPID,
				req.stage2aT03SiblingWitness)
			body = struct {
				Accepted       bool   `json:"accepted"`
				MetadataSHA256 string `json:"metadata_sha256"`
				LeaseSequence  uint64 `json:"lease_sequence"`
			}{err == nil, digest, sequence}
		case stage2aLiveVerb:
			state = "live"
			body, err = service.Live(req.peerUID, req.stage2aEpoch, req.stage2aLive)
		case stage2aProviderVerb:
			state = "provided"
			body, err = service.Provider(req.peerUID, req.stage2aEpoch, req.stage2aProvider)
		case stage2aChildReadyVerb:
			state = "child-ready"
			body, err = service.ChildReady(req.peerUID, req.stage2aEpoch, req.stage2aChildReady)
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
