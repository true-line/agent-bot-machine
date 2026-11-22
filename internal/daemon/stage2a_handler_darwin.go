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
