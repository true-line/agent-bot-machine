//go:build darwin

package members

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const stage2aDirectQPrePurposeV3 = "agent-bot/stage2a-direct-q-pre/v3"
const stage2aDirectQCapturePurposeV3 = "agent-bot/stage2a-direct-q-capture/v3"
const stage2aDirectHQRefusalSchemaV1 = "agent-bot-hq/stage2a-direct-q-protected-claim-refusal/v1"

type stage2aDirectQPreV3 struct {
	Contract             string `json:"contract"`
	Kind                 string `json:"kind"`
	SchemaVersion        int    `json:"schema_version"`
	InstallationID       string `json:"installation_id"`
	StartID              string `json:"start_id"`
	LaunchID             string `json:"launch_id"`
	HQEpoch              string `json:"hq_epoch"`
	ReservationSHA256    string `json:"reservation_sha256"`
	AttachSHA256         string `json:"attach_sha256"`
	SessionID            string `json:"session_id"`
	QChallengeSHA256     string `json:"q_challenge_sha256"`
	TestPlanSHA256       string `json:"test_plan_sha256"`
	PreObservationSHA256 string `json:"pre_observation_sha256"`
	CaseNonceBase64URL   string `json:"case_nonce_base64url"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

type stage2aDirectQRunV3 struct {
	session     *stage2aQualificationSessionV1
	wait        func() error
	finishing   bool
	pre         stage2aDirectQPreV3
	preEnvelope []byte
	preSHA256   string
	install     stage2aQualificationQInstall
	request     QualificationRequest
	owner       string
}

func (s *Stage2aService) directQCheckV3(uid int, epoch string,
	q SoulCooperativeLiveRequestV3, live *soulCooperativeLiveV3,
	run *stage2aDirectQRunV3) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.directQCurrentV3(uid, epoch, q)
	if err != nil || current != live || live.directQ != run {
		return errSoulCooperativeAuthority
	}
	return nil
}

type Stage2aDirectQFinishRequestV3 struct {
	SoulCooperativeLiveRequestV3
	PreResponseSHA256         string `json:"pre_response_sha256"`
	HQRefusalReceiptBase64URL string `json:"hq_refusal_receipt_base64url"`
	HQRefusalReceiptSHA256    string `json:"hq_refusal_receipt_sha256"`
}

func ParseStage2aDirectQFinishRequestV3(raw []byte) (Stage2aDirectQFinishRequestV3, error) {
	var q Stage2aDirectQFinishRequestV3
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.AttachSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.PreResponseSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.HQRefusalReceiptSHA256) {
		return Stage2aDirectQFinishRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}

type stage2aDirectHQRefusalV1 struct {
	Schema                        string `json:"schema"`
	Plugin                        string `json:"plugin"`
	Kind                          string `json:"kind"`
	Seq                           uint64 `json:"seq"`
	At                            int64  `json:"at"`
	Profile                       string `json:"profile"`
	InstallationID                string `json:"installation_id"`
	StartID                       string `json:"start_id"`
	LaunchID                      string `json:"launch_id"`
	HQEpoch                       string `json:"hq_epoch"`
	ReservationSHA256             string `json:"reservation_sha256"`
	AttachSHA256                  string `json:"attach_sha256"`
	SessionID                     string `json:"session_id"`
	QChallengeSHA256              string `json:"q_challenge_sha256"`
	TestPlanSHA256                string `json:"test_plan_sha256"`
	CaseNonceBase64URL            string `json:"case_nonce_base64url"`
	PreResponseSHA256             string `json:"pre_response_sha256"`
	RequestedProfile              string `json:"requested_profile"`
	RefusalCode                   string `json:"refusal_code"`
	CooperativeStartReceiptSeq    uint64 `json:"cooperative_start_receipt_seq"`
	CooperativeStartReceiptSHA256 string `json:"cooperative_start_receipt_sha256"`
}

func verifyStage2aDirectHQRefusalV1(q Stage2aDirectQFinishRequestV3,
	pre stage2aDirectQPreV3, now time.Time) ([]byte, stage2aDirectHQRefusalV1, error) {
	var empty stage2aDirectHQRefusalV1
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.HQRefusalReceiptBase64URL)
	if err != nil || len(raw) == 0 || len(raw) > 4096 ||
		base64.RawURLEncoding.EncodeToString(raw) != q.HQRefusalReceiptBase64URL ||
		stage2aQualificationSHA256(raw) != q.HQRefusalReceiptSHA256 ||
		stage2aStrictJSONBounded(raw, 4096, stage2aV3MaxJSONNodes) != nil {
		return nil, empty, errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, empty, errSoulCooperativeAuthority
	}
	var receipt stage2aDirectHQRefusalV1
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || d.Decode(new(any)) != io.EOF ||
		receipt.Schema != stage2aDirectHQRefusalSchemaV1 ||
		receipt.Plugin != "hq" || receipt.Kind != "hq.soul.protected-claim.refused" ||
		receipt.Profile != "managed-cooperative" || receipt.RequestedProfile != "managed-protected" ||
		receipt.RefusalCode != "profile_insufficient" ||
		receipt.InstallationID != pre.InstallationID || receipt.StartID != pre.StartID ||
		receipt.LaunchID != pre.LaunchID || receipt.HQEpoch != pre.HQEpoch ||
		receipt.ReservationSHA256 != pre.ReservationSHA256 ||
		receipt.AttachSHA256 != pre.AttachSHA256 ||
		receipt.SessionID != pre.SessionID ||
		receipt.QChallengeSHA256 != pre.QChallengeSHA256 ||
		receipt.TestPlanSHA256 != pre.TestPlanSHA256 ||
		receipt.CaseNonceBase64URL != pre.CaseNonceBase64URL ||
		receipt.PreResponseSHA256 != q.PreResponseSHA256 ||
		receipt.CooperativeStartReceiptSeq == 0 ||
		receipt.Seq <= receipt.CooperativeStartReceiptSeq ||
		!stage2aQualificationDigest(receipt.CooperativeStartReceiptSHA256) {
		return nil, empty, errSoulCooperativeAuthority
	}
	issued, e1 := time.Parse(time.RFC3339Nano, pre.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, pre.ExpiresAt)
	at := time.UnixMilli(receipt.At)
	if e1 != nil || e2 != nil || receipt.At <= 0 || at.Before(issued) ||
		!at.Before(expires) || at.After(now) || !now.Before(expires) {
		return nil, empty, errSoulCooperativeAuthority
	}
	return raw, receipt, nil
}

// Exact A-owned live state is checked before Q begins and again around each
// case phase. The caller holds Stage2aService.mu and a current paired-HQ lock.
func (s *Stage2aService) directQCurrentV3(uid int, epoch string,
	q SoulCooperativeLiveRequestV3) (*soulCooperativeLiveV3, error) {
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		!stage2aPrefixedDigest.MatchString(q.AttachSHA256) {
		return nil, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || live.attachSHA256 != q.AttachSHA256 ||
		live.installed.Policy.HQUID != uid || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.request.HQEpoch != epoch ||
		live.digest != q.ReservationSHA256 {
		return nil, errSoulCooperativeAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	installed, r, err := loadSoulCooperativeInstalledV3(key, uid, epoch, q.InstallationID)
	if err != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
		stage2aRecheckVerifiedDomainV3(r) != nil ||
		stage2aRecheckVerifiedDomainV3(live.h) != nil || r.ref != live.installed.RuntimeV3 {
		return nil, errSoulCooperativeAuthority
	}
	paths, err := cooperativeLaunchPaths(q.InstallationID)
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	pid, err := observeSoulCooperativeLaunchdPID(paths, q.InstallationID)
	if err != nil || pid != live.dispatcherPID {
		return nil, errSoulCooperativeAuthority
	}
	dispatcher, e1 := observeSoulKernelProcess(live.dispatcherPID)
	runner, e2 := observeSoulKernelProcess(live.runnerPID)
	if e1 != nil || e2 != nil || !sameSoulKernelProcess(live.dispatcher, dispatcher) ||
		!sameSoulKernelProcess(live.runner, runner) ||
		!cooperativeProcessPair(installed.Policy, dispatcher, runner) {
		return nil, errSoulCooperativeAuthority
	}
	store := installed.claimStore()
	dir, err := store.open()
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	defer dir.Close()
	if store.checkDirectory(dir) != nil ||
		cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
		stage2aCheckSpentClaim(dir, cooperativeAttachedName(q.InstallationID, q.StartID),
			store.uid, store.gid) != nil {
		return nil, errSoulCooperativeAuthority
	}
	return live, nil
}

func stage2aDirectQPreName(installationID, startID string) string {
	return ".cooperative-q-pre-" + soulStartClaimName(installationID, startID) + ".json"
}

func publishStage2aDirectQPreV3(store stage2aAdminClaimStore,
	live *soulCooperativeLiveV3, session *stage2aQualificationSessionV1,
	pre stage2aDirectQPreV3, envelope []byte) error {
	if session == nil || live == nil || pre.ReservationSHA256 != live.digest ||
		pre.SessionID != session.begin.SessionID || len(envelope) == 0 || len(envelope) > 8192 {
		return errSoulCooperativeAuthority
	}
	dir, err := store.open()
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, pre.InstallationID)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer lock.Close()
	bound := stage2aQualificationSessionResultV1{begin: session.begin,
		peer: session.peer, challengeSHA256: session.challengeSHA256}
	if store.checkDirectory(dir) != nil ||
		cooperativeActiveClaimMatches(dir, store, pre.InstallationID, pre.StartID) != nil ||
		checkStage2aDirectQBindingV3(dir, store, bound) != nil {
		return errSoulCooperativeAuthority
	}
	return commitStage2aReservation(dir, stage2aDirectQPreName(pre.InstallationID, pre.StartID), envelope)
}

// BeginDirectQualificationV3 spends the one-use Q claim and returns an
// A-signed, challenge-bound pre observation. HQ performs the fixed protected
// claim stimulus while this session remains live, then supplies its durable
// refusal receipt to Finish. This method never reports a T21 verdict.
func (s *Stage2aService) BeginDirectQualificationV3(uid int, epoch string,
	q SoulCooperativeLiveRequestV3,
	paired func(string, func() error) error) (Stage2aReserveReply, error) {
	s.mu.Lock()
	if paired == nil || len(s.key) != ed25519.PrivateKeySize {
		s.mu.Unlock()
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	live, err := s.directQCurrentV3(uid, epoch, q)
	if err != nil || live.directQ != nil {
		s.mu.Unlock()
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	run := &stage2aDirectQRunV3{}
	var ran bool
	err = paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		current, err := s.directQCurrentV3(uid, epoch, q)
		if err != nil || current != live ||
			claimStage2aDirectQSessionV3(live.installed.claimStore(), live,
				s.key.Public().(ed25519.PublicKey)) != nil {
			return errSoulCooperativeAuthority
		}
		live.directQ = run
		return nil
	})
	s.mu.Unlock()
	if err != nil || !ran {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	keep := false
	var session *stage2aQualificationSessionV1
	var wait func() error
	defer func() {
		if !keep {
			if session != nil {
				session.close()
			}
			if wait != nil {
				_ = wait()
			}
			s.mu.Lock()
			if live.directQ == run {
				live.directQ = nil
			}
			s.mu.Unlock()
		}
	}()
	checkLive := func() error { return s.directQCheckV3(uid, epoch, q, live, run) }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	session, wait, err = openStage2aDirectQualificationObserverV3(ctx,
		live, s.key.Public().(ed25519.PublicKey), checkLive)
	if err != nil || checkLive() != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	preRaw, err := session.observe(stage2aQualificationObserveV1{
		Gate: "T21", Phase: "pre", EventID: "direct-comms",
		Processes: []stage2aQualificationProcessRequestV1{
			{Role: "dispatcher", PID: live.dispatcherPID},
			{Role: "runner", PID: live.runnerPID}},
		Paths: []stage2aQualificationPathRequestV1{},
	})
	if err != nil || checkLive() != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	install, request, err := loadStage2aQualificationQAuthority(ctx)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	var receipt Receipt
	if json.Unmarshal(live.installed.RootReceipt, &receipt) != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	now := time.Now().UTC()
	expires, err := time.Parse(time.RFC3339Nano, session.begin.DeadlineAt)
	if err != nil || !now.Before(expires) {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	pre := stage2aDirectQPreV3{Contract: "machine/v3", Kind: "stage2a-direct-q-pre", SchemaVersion: 3,
		InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
		HQEpoch: epoch, ReservationSHA256: q.ReservationSHA256, AttachSHA256: q.AttachSHA256,
		SessionID: session.begin.SessionID, QChallengeSHA256: session.challengeSHA256,
		TestPlanSHA256:       session.begin.TestPlanSHA256,
		PreObservationSHA256: stage2aQualificationSHA256(preRaw),
		CaseNonceBase64URL:   base64.RawURLEncoding.EncodeToString(nonce[:]),
		IssuedAt:             now.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano)}
	envelope, err := signStage2aEnvelope(pre, 3, stage2aDirectQPrePurposeV3,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || len(envelope) > 8192 || session.conn.SetDeadline(expires) != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	s.mu.Lock()
	var reply Stage2aReserveReply
	ran = false
	err = paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		current, e := s.directQCurrentV3(uid, epoch, q)
		if e != nil || current != live || live.directQ != run ||
			publishStage2aDirectQPreV3(live.installed.claimStore(), live, session, pre, envelope) != nil {
			return errSoulCooperativeAuthority
		}
		run.session, run.wait, run.pre = session, wait, pre
		run.preEnvelope, run.preSHA256 = envelope, stage2aQualificationSHA256(envelope)
		run.install, run.request, run.owner = install, request, receipt.Owner
		reply = Stage2aReserveReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope), SHA256: run.preSHA256}
		return nil
	})
	s.mu.Unlock()
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	keep = true
	return reply, nil
}

// A failed begin or a daemon restart keeps the durable Q name spent. The
// pre receipt cannot be replayed into another process lifetime.
func (s *Stage2aService) closeDirectQualificationV3(live *soulCooperativeLiveV3) {
	if live != nil && live.directQ != nil {
		if live.directQ.session != nil {
			live.directQ.session.close()
		}
		if live.directQ.wait != nil {
			_ = live.directQ.wait()
		}
		live.directQ = nil
	}
}

func stage2aDirectQCapturePath(store stage2aAdminClaimStore, installationID, startID string) string {
	return filepath.Join(store.path, ".cooperative-q-capture-"+
		soulStartClaimName(installationID, startID)+".json")
}

func readStage2aDirectQPreV3(store stage2aAdminClaimStore, pre stage2aDirectQPreV3, envelope []byte) error {
	dir, err := store.open()
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer dir.Close()
	if store.checkDirectory(dir) != nil ||
		stage2aExactAdminRecord(dir, stage2aDirectQPreName(pre.InstallationID, pre.StartID),
			store.uid, store.gid, envelope, 8192) != nil {
		return errSoulCooperativeAuthority
	}
	return nil
}

// readOnlyDirectQPre is used by Finish after its paired caller provides the
// exact retained HQ refusal. No copied refusal text is accepted as authority.
func readOnlyDirectQPre(store stage2aAdminClaimStore, run *stage2aDirectQRunV3) error {
	if run == nil || stage2aQualificationSHA256(run.preEnvelope) != run.preSHA256 ||
		readStage2aDirectQPreV3(store, run.pre, run.preEnvelope) != nil {
		return errSoulCooperativeAuthority
	}
	return nil
}

type stage2aDirectQCaptureV3 struct {
	Contract               string `json:"contract"`
	Kind                   string `json:"kind"`
	SchemaVersion          int    `json:"schema_version"`
	Status                 string `json:"status"`
	HostCredit             bool   `json:"host_credit"`
	InstallationID         string `json:"installation_id"`
	StartID                string `json:"start_id"`
	LaunchID               string `json:"launch_id"`
	HQEpoch                string `json:"hq_epoch"`
	ReservationSHA256      string `json:"reservation_sha256"`
	AttachSHA256           string `json:"attach_sha256"`
	SessionID              string `json:"session_id"`
	TestPlanSHA256         string `json:"test_plan_sha256"`
	PreResponseSHA256      string `json:"pre_response_sha256"`
	HQRefusalReceiptSHA256 string `json:"hq_refusal_receipt_sha256"`
	PostObservationSHA256  string `json:"post_observation_sha256"`
	QWireSHA256            string `json:"q_wire_sha256"`
	QIndexSHA256           string `json:"q_index_sha256"`
	QEOFReceiptSHA256      string `json:"q_eof_receipt_sha256"`
	DispatcherPID          int    `json:"dispatcher_pid"`
	DispatcherStartSeconds int64  `json:"dispatcher_start_seconds"`
	DispatcherStartMicros  int32  `json:"dispatcher_start_micros"`
	RunnerPID              int    `json:"runner_pid"`
	RunnerStartSeconds     int64  `json:"runner_start_seconds"`
	RunnerStartMicros      int32  `json:"runner_start_micros"`
	MachineProtectedAbsent bool   `json:"machine_protected_authority_absent"`
	CompletedAt            string `json:"completed_at"`
}

func publishStage2aDirectQCaptureV3(store stage2aAdminClaimStore,
	live *soulCooperativeLiveV3, run *stage2aDirectQRunV3,
	artifacts stage2aQualificationPreSignArtifactsV1, envelope []byte) error {
	if live == nil || run == nil || len(envelope) == 0 || len(envelope) > 16<<10 ||
		!stage2aQualificationDigest(artifacts.EOFReceiptSHA256) {
		return errSoulCooperativeAuthority
	}
	dir, err := store.open()
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, live.request.InstallationID)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil ||
		cooperativeActiveClaimMatches(dir, store, live.request.InstallationID,
			live.request.StartID) != nil ||
		stage2aExactAdminRecord(dir, stage2aDirectQPreName(live.request.InstallationID,
			live.request.StartID), store.uid, store.gid, run.preEnvelope, 8192) != nil {
		return errSoulCooperativeAuthority
	}
	return commitStage2aReservation(dir, filepath.Base(stage2aDirectQCapturePath(store,
		live.request.InstallationID, live.request.StartID)), envelope)
}

// FinishDirectQualificationV3 accepts the exact durable HQ refusal only on
// the paired local channel. It completes Q's post observation and persists an
// A-signed capture, but never emits a qualification host report or host credit.
func (s *Stage2aService) FinishDirectQualificationV3(uid int, epoch string,
	q Stage2aDirectQFinishRequestV3,
	paired func(string, func() error) error) (Stage2aReserveReply, error) {
	s.mu.Lock()
	if paired == nil || len(s.key) != ed25519.PrivateKeySize {
		s.mu.Unlock()
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	live, err := s.directQCurrentV3(uid, epoch, q.SoulCooperativeLiveRequestV3)
	if err != nil || live.directQ == nil || live.directQ.session == nil ||
		live.directQ.finishing || live.directQ.preSHA256 != q.PreResponseSHA256 {
		s.mu.Unlock()
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	run := live.directQ
	var ran bool
	err = paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		current, e := s.directQCurrentV3(uid, epoch, q.SoulCooperativeLiveRequestV3)
		if e != nil || current != live || live.directQ != run ||
			readOnlyDirectQPre(live.installed.claimStore(), run) != nil {
			return errSoulCooperativeAuthority
		}
		run.finishing = true
		return nil
	})
	s.mu.Unlock()
	if err != nil || !ran {
		if run.finishing {
			run.session.close()
			_ = run.wait()
			s.mu.Lock()
			if live.directQ == run {
				live.directQ = nil
			}
			s.mu.Unlock()
		}
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	defer func() {
		s.mu.Lock()
		if live.directQ == run {
			live.directQ = nil
		}
		s.mu.Unlock()
		run.session.close()
		_ = run.wait()
	}()
	checkLive := func() error {
		return s.directQCheckV3(uid, epoch, q.SoulCooperativeLiveRequestV3, live, run)
	}
	if checkLive() != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	if _, _, err := verifyStage2aDirectHQRefusalV1(q, run.pre, time.Now().UTC()); err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	protectedPath, err := stage2aAuthorityPath(q.InstallationID)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	if _, err := os.Lstat(protectedPath); !os.IsNotExist(err) {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	postRaw, err := run.session.observe(stage2aQualificationObserveV1{
		Gate: "T21", Phase: "post", EventID: "direct-comms",
		Processes: []stage2aQualificationProcessRequestV1{
			{Role: "dispatcher", PID: live.dispatcherPID},
			{Role: "runner", PID: live.runnerPID}},
		Paths: []stage2aQualificationPathRequestV1{},
	})
	if err != nil || checkLive() != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	result, err := run.session.finish()
	if err != nil || run.wait() != nil || checkLive() != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	install, request, err := loadStage2aQualificationQAuthority(ctx)
	if err != nil || install.Review != run.install.Review ||
		request.SuiteRevision != run.request.SuiteRevision {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	s.mu.Lock()
	var reply Stage2aReserveReply
	ran = false
	err = paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		current, e := s.directQCurrentV3(uid, epoch, q.SoulCooperativeLiveRequestV3)
		if e != nil || current != live || live.directQ != run || !run.finishing ||
			readOnlyDirectQPre(live.installed.claimStore(), run) != nil {
			return errSoulCooperativeAuthority
		}
		artifacts, e := persistStage2aDirectQualificationPreSignV3(
			live.installed.claimStore(), live, result, install, request,
			run.owner, time.Now().UTC(), s.key.Public().(ed25519.PublicKey), s.sign)
		if e != nil {
			return errSoulCooperativeAuthority
		}
		capture := stage2aDirectQCaptureV3{Contract: "machine/v3", Kind: "stage2a-direct-q-capture",
			SchemaVersion: 3, Status: "unqualified", HostCredit: false,
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			HQEpoch: epoch, ReservationSHA256: q.ReservationSHA256, AttachSHA256: q.AttachSHA256,
			SessionID: run.pre.SessionID, TestPlanSHA256: run.pre.TestPlanSHA256,
			PreResponseSHA256:      q.PreResponseSHA256,
			HQRefusalReceiptSHA256: q.HQRefusalReceiptSHA256,
			PostObservationSHA256:  stage2aQualificationSHA256(postRaw),
			QWireSHA256:            artifacts.WireSHA256, QIndexSHA256: artifacts.IndexSHA256,
			QEOFReceiptSHA256: artifacts.EOFReceiptSHA256,
			DispatcherPID:     live.dispatcherPID, DispatcherStartSeconds: live.dispatcher.StartSeconds,
			DispatcherStartMicros: live.dispatcher.StartMicros,
			RunnerPID:             live.runnerPID, RunnerStartSeconds: live.runner.StartSeconds,
			RunnerStartMicros:      live.runner.StartMicros,
			MachineProtectedAbsent: true, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		envelope, e := signStage2aEnvelope(capture, 3, stage2aDirectQCapturePurposeV3,
			s.key.Public().(ed25519.PublicKey), s.sign)
		if e != nil || publishStage2aDirectQCaptureV3(live.installed.claimStore(),
			live, run, artifacts, envelope) != nil {
			return errSoulCooperativeAuthority
		}
		reply = Stage2aReserveReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			SHA256: stage2aQualificationSHA256(envelope)}
		return nil
	})
	s.mu.Unlock()
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
