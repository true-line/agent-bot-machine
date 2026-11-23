package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
)

// Serve accepts one JSON line per connection, checks the peer and the
// signature, and writes one signed JSON line back. It returns when ctx is
// cancelled.
func Serve(ctx context.Context, ln net.Listener, g *Gate, priv ed25519.PrivateKey, peer func(net.Conn) (int, error), hooks Hooks) error {
	const maxInFlight = 32
	slots := make(chan struct{}, maxInFlight)
	var workers sync.WaitGroup
	var ordinaryHooks sync.Mutex
	defer workers.Wait()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				handleConnScoped(conn, g, priv, peer, hooks, &ordinaryHooks)
			}()
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
	}
}

func handleConn(conn net.Conn, g *Gate, priv ed25519.PrivateKey, peer func(net.Conn) (int, error), hooks Hooks) {
	handleConnScoped(conn, g, priv, peer, hooks, nil)
}

// The daemon admits bounded concurrent Stage 2a calls so a slow Q exchange
// cannot starve short child/runner lease renewals. Other hooks retain their
// historical serial execution. Gate.verify serializes pairing and nonce state.
func handleConnScoped(conn net.Conn, g *Gate, priv ed25519.PrivateKey, peer func(net.Conn) (int, error), hooks Hooks,
	ordinaryHooks *sync.Mutex) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(io.LimitReader(conn, maxMessage))
	line, err := reader.ReadBytes('\n')
	uid := -1
	if peer != nil && err == nil {
		uid, err = peer(conn)
	}
	var res Response
	var requestNonce string
	if err != nil {
		res = refused(diag.DaemonTampered, err.Error())
	} else {
		req, id, msg := g.verify(uid, line)
		requestNonce = req.Nonce
		if id != "" {
			res = refused(id, msg)
		} else if req.Verb == "bootstrap" {
			res = bootstrapReply(priv)
		} else if isStage2aVerb(req.Verb) && hooks.Stage2a != nil {
			unlock, err := lockStage2aPairing(g.Dir, req)
			if err != nil {
				res = refused(diag.DaemonPeerRefused, "Stage 2a requires the current protected HQ pairing")
			} else {
				defer unlock()
				if req.Verb == stage2aReserveVerb {
					// HQ allows ten seconds after sending a reservation request.
					// Keep the initial read budget distinct from A's local
					// qualification and response budget.
					_ = conn.SetWriteDeadline(time.Now().Add(9 * time.Second))
				}
				res = hooks.reply(req)
			}
		} else {
			if ordinaryHooks != nil {
				ordinaryHooks.Lock()
				defer ordinaryHooks.Unlock()
			}
			res = hooks.reply(req)
			if req.Verb == deviceVerb && res.OK {
				unlock, err := lockDeviceDelivery(g.Dir, req, res.Body)
				if err != nil {
					res = deviceUnavailable()
				} else {
					defer unlock()
				}
			}
		}
	}
	res.RequestNonce = requestNonce
	res.Timestamp = time.Now().Unix()
	nonce, nerr := newNonce()
	if nerr == nil {
		res.Nonce = nonce
	}
	if priv != nil {
		signResponse(priv, &res)
	}
	body, merr := formatLine(res)
	if merr == nil {
		_, _ = conn.Write(body)
	}
}

// Hooks supplies the read-only bodies for status and receipts and the
// catalog plan and apply actions. A nil function keeps the previous
// placeholder for status and refuses the other verbs.
type Hooks struct {
	Status   func() (string, []byte, error)
	Receipts func() ([]byte, error)
	Plan     func(name, option, target string) (string, string)
	Apply    func(planID, name, option, target, soul, harness, session string) string
	Update   func(name, soul, harness, session string) (string, string)
	Catalog  func(req Request) (string, string, string)
	// MembersPlans lists or fetches fixed saved plans from the prefix owner's store.
	MembersPlans    func(option, id string) ([]byte, error)
	ServiceRecovery func(Request) Response
	HQDevice        func(Request) Response
	Stage2a         func(Request) Response
	// ApproveMembers records the approval of a member accounts plan and
	// returns the approval as the response body. It runs nothing.
	ApproveMembers func(planID, digest string) ([]byte, string, string)
	OnReceipt      func()
}

func (h Hooks) reply(req Request) Response {
	switch req.Verb {
	case "status":
		if h.Status == nil {
			return Response{OK: true, State: "idle"}
		}
		state, body, err := h.Status()
		if err != nil {
			return refused(diag.DaemonStatusFailed, "status could not be read")
		}
		return Response{OK: true, State: state, Body: body}
	case "receipts":
		if h.Receipts == nil {
			return refused(diag.DaemonUnimplemented, "receipts is not served yet")
		}
		body, err := h.Receipts()
		if err != nil {
			return refused(diag.DaemonStatusFailed, "receipts could not be read")
		}
		return Response{OK: true, State: "listed", Body: body}
	case "plan":
		if h.Plan == nil {
			return refused(diag.DaemonUnimplemented, "plan is not served yet")
		}
		id, diagID := h.Plan(req.Name, req.Option, req.Target)
		if diagID != "" {
			return refused(diagID, "selection is not a pinned catalog item")
		}
		return Response{OK: true, State: "saved", Message: id}
	case "apply":
		if h.Apply == nil {
			return refused(diag.DaemonUnimplemented, "apply is not served yet")
		}
		if diagID := h.Apply(req.PlanID, req.Name, req.Option, req.Target, req.Soul, req.Harness, req.SessionID); diagID != "" {
			return refused(diagID, "saved plan was not applied")
		}
		if h.OnReceipt != nil {
			h.OnReceipt()
		}
		return Response{OK: true, State: "applied", Message: req.PlanID}
	case "update":
		if h.Update == nil {
			return refused(diag.DaemonUnimplemented, "update is not served yet")
		}
		ids, diagID := h.Update(req.Name, req.Soul, req.Harness, req.SessionID)
		if diagID != "" {
			return refused(diagID, "flavor was not updated")
		}
		if h.OnReceipt != nil {
			h.OnReceipt()
		}
		return Response{OK: true, State: "updated", Message: ids}
	case "catalog":
		if h.Catalog == nil {
			return refused(diag.DaemonUnimplemented, "catalog is not served yet")
		}
		state, message, diagID := h.Catalog(req)
		if diagID != "" {
			return refused(diagID, message)
		}
		return Response{OK: true, State: state, Message: message}
	case deviceVerb:
		if h.HQDevice == nil {
			return deviceUnavailable()
		}
		return h.HQDevice(req)
	case stage2aReserveVerb, stage2aExecVerb, stage2aVerifyBVerb, stage2aLookupVerb, stage2aListVerb, stage2aPrepareBVerb, stage2aStopVerb, stage2aFinalizeBVerb, stage2aLiveVerb, stage2aProviderVerb, stage2aChildReadyVerb, stage2aCaptureSelectorVerb, stage2aControlProbeVerb, stage2aHelloStartVerb, stage2aHelloFinalizeVerb, stage2aHelloAbortVerb, stage2aPeerRoleVerb, stage2aMemberSetAssignVerb, stage2aMemberProvisionalMapVerb, stage2aMemberChildGrantVerb, stage2aMemberChildObserveVerb, stage2aMemberLiveVerb, stage2aMemberReadyVerb, stage2aMemberRuntimeVerb:
		if h.Stage2a == nil {
			return refused(diag.DaemonUnimplemented, "Stage 2a reserve authority is unavailable")
		}
		return h.Stage2a(req)
	case recoveryVerb, upgradeVerb, harnessAccountsVerb, soulRunnerAccountsVerb, soulBridgeAccountsVerb, harnessInstallVerb, harnessRetireVerb, harnessQualificationVerb, members.SoulProtectedLaunchInstallPurpose, members.SoulProtectedLaunchRetirePurpose:
		if h.ServiceRecovery == nil {
			return refused(diag.DaemonUnimplemented, "service recovery is unavailable")
		}
		return h.ServiceRecovery(req)
	case membersPlansVerb:
		if h.MembersPlans == nil {
			return refused(diag.DaemonUnimplemented, "members-plans is not available")
		}
		body, err := h.MembersPlans(req.Option, req.PlanID)
		if err != nil {
			return refused(diag.MembersPlanFailed, "the requested members plans could not be read")
		}
		state := "listed"
		if req.Option == "get" {
			state = "found"
		}
		return Response{OK: true, State: state, Body: body}
	case approveMembersVerb:
		if h.ApproveMembers == nil {
			return refused(diag.DaemonUnimplemented, "approve-members is not served yet")
		}
		body, diagID, message := h.ApproveMembers(req.PlanID, req.PlanDigest)
		if diagID != "" {
			return refused(diagID, message)
		}
		return Response{OK: true, State: "approved", Message: req.PlanID, Body: body}
	default:
		return refused(diag.DaemonUnimplemented, req.Verb+" is not served yet")
	}
}

func bootstrapReply(priv ed25519.PrivateKey) Response {
	if priv == nil {
		return refused(diag.DaemonStatusFailed, "daemon key is missing")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return refused(diag.DaemonStatusFailed, "daemon key is not ed25519")
	}
	body, err := json.Marshal(struct {
		PublicKey string `json:"public_key"`
	}{PublicKey: hex.EncodeToString(pub)})
	if err != nil {
		return refused(diag.DaemonStatusFailed, "daemon public key could not be encoded")
	}
	return Response{OK: true, State: "enrolled", Body: body}
}

func responsePayload(res Response) []byte {
	return []byte(strings.Join([]string{
		strconv.FormatBool(res.OK), res.Diagnostic, res.Message, res.State, string(res.Body),
		strconv.FormatInt(res.Timestamp, 10), res.Nonce, res.RequestNonce,
	}, "\n"))
}

// VerifyResponse checks the daemon's signature over a response.
func VerifyResponse(pub ed25519.PublicKey, res Response) bool {
	sig, err := base64.StdEncoding.DecodeString(res.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, responsePayload(res), sig)
}
