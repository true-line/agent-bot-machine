//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const stage2aDirectQWitnessPurposeV3 = "agent-bot/stage2a-direct-q-witness/v3"

type stage2aDirectQWitnessChallengeReplyV3 struct {
	PreResponseSHA256  string `json:"pre_response_sha256"`
	ChallengeBase64URL string `json:"challenge_base64url"`
	SessionID          string `json:"session_id"`
	ReservationSHA256  string `json:"reservation_sha256"`
	AttachSHA256       string `json:"attach_sha256"`
	HQEpoch            string `json:"hq_epoch"`
	StartID            string `json:"start_id"`
	LaunchID           string `json:"launch_id"`
	InstallationID     string `json:"installation_id"`
}

type stage2aDirectQWitnessReplyV3 struct {
	WitnessSHA256 string `json:"witness_sha256"`
}

func stage2aDirectQWitnessChallengeName(install, start string) string {
	return ".cooperative-q-witness-challenge-" + soulStartClaimName(install, start) + ".json"
}

func stage2aDirectQWitnessName(install, start string) string {
	return ".cooperative-q-witness-" + soulStartClaimName(install, start) + ".json"
}

func stage2aDirectQHQRowName(install, start, kind string) string {
	return ".cooperative-q-hq-" + kind + "-" + soulStartClaimName(install, start) + ".json"
}

func stage2aDirectQRecord(store stage2aAdminClaimStore, install, start, name string,
	expected []byte, create bool) error {
	dir, err := store.open()
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, install)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil || cooperativeActiveClaimMatches(dir, store, install, start) != nil {
		return errSoulCooperativeAuthority
	}
	if create {
		return commitStage2aReservation(dir, name, expected)
	}
	return stage2aExactAdminRecord(dir, name, store.uid, store.gid, expected, 16<<10)
}

func (s *Stage2aService) BeginDirectQualificationWitnessV3(uid, peerPID int, epoch string,
	q Stage2aDirectQWitnessBeginRequestV3,
	paired func(string, func() error) error) (stage2aDirectQWitnessChallengeReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply stage2aDirectQWitnessChallengeReplyV3
	if paired == nil || len(s.key) != ed25519.PrivateKeySize {
		return reply, errSoulCooperativeAuthority
	}
	live, err := s.directQCurrentV3(uid, epoch, q.SoulCooperativeLiveRequestV3)
	if err != nil || live.directQ == nil || live.directQ.session == nil || live.directQ.witness != nil ||
		live.directQ.preSHA256 != q.PreResponseSHA256 {
		return reply, errSoulCooperativeAuthority
	}
	run := live.directQ
	var ran bool
	err = paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		if readOnlyDirectQPre(live.installed.claimStore(), run) != nil {
			return errSoulCooperativeAuthority
		}
		peer, e := observeStage2aDirectHQPeerV3(live, peerPID, s.key.Public().(ed25519.PublicKey))
		if e != nil {
			return errSoulCooperativeAuthority
		}
		expires, e := time.Parse(time.RFC3339Nano, run.pre.ExpiresAt)
		if e != nil || !time.Now().Before(expires) {
			return errSoulCooperativeAuthority
		}
		var nonce [32]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return errSoulCooperativeAuthority
		}
		reply = stage2aDirectQWitnessChallengeReplyV3{
			PreResponseSHA256: q.PreResponseSHA256, ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(nonce[:]),
			SessionID: run.pre.SessionID, ReservationSHA256: q.ReservationSHA256, AttachSHA256: q.AttachSHA256,
			HQEpoch: epoch, StartID: q.StartID, LaunchID: q.LaunchID, InstallationID: q.InstallationID}
		raw, e := marshalStage2aReservationJCS(reply)
		if e != nil || stage2aDirectQRecord(live.installed.claimStore(), q.InstallationID, q.StartID,
			stage2aDirectQWitnessChallengeName(q.InstallationID, q.StartID), raw, true) != nil {
			return errSoulCooperativeAuthority
		}
		run.witness = &stage2aDirectQWitnessV3{challenge: reply.ChallengeBase64URL, peer: peer}
		return nil
	})
	if err != nil || !ran {
		return stage2aDirectQWitnessChallengeReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}

type stage2aDirectHQStartReceiptV3 struct {
	Plugin            string `json:"plugin"`
	Kind              string `json:"kind"`
	Seq               uint64 `json:"seq"`
	At                int64  `json:"at"`
	Profile           string `json:"profile"`
	InstallationID    string `json:"installation_id"`
	StartID           string `json:"start_id"`
	HQEpoch           string `json:"hq_epoch"`
	ReservationSHA256 string `json:"reservation_sha256"`
	PID               int    `json:"pid"`
	RunnerUID         int    `json:"runner_uid"`
	RunnerGID         int    `json:"runner_gid"`
	State             string `json:"state"`
	Protected         bool   `json:"protected"`
}

func stage2aDirectQStartReceiptV3(q Stage2aDirectQWitnessFinishRequestV3,
	live *soulCooperativeLiveV3, pre stage2aDirectQPreV3, now time.Time) (stage2aDirectHQStartReceiptV3, error) {
	var empty stage2aDirectHQStartReceiptV3
	raw, e := base64.RawURLEncoding.Strict().DecodeString(q.CooperativeStartReceiptBase64URL)
	if e != nil || len(raw) == 0 || len(raw) > 4096 || base64.RawURLEncoding.EncodeToString(raw) != q.CooperativeStartReceiptBase64URL ||
		stage2aQualificationSHA256(raw) != q.CooperativeStartReceiptSHA256 || stage2aStrictJSONBounded(raw, 4096, stage2aV3MaxJSONNodes) != nil {
		return empty, errSoulCooperativeAuthority
	}
	canonical, e := jsoncanonicalizer.Transform(raw)
	if e != nil || !bytes.Equal(canonical, raw) {
		return empty, errSoulCooperativeAuthority
	}
	var start stage2aDirectHQStartReceiptV3
	if json.Unmarshal(raw, &start) != nil || start.Plugin != "hq" || start.Kind != "hq.soul.started" || start.Seq == 0 ||
		start.Profile != "managed-cooperative" || start.Protected || start.State != "running" ||
		start.InstallationID != pre.InstallationID || start.StartID != pre.StartID || start.HQEpoch != pre.HQEpoch ||
		start.ReservationSHA256 != pre.ReservationSHA256 || start.PID != live.runnerPID ||
		start.RunnerUID != live.installed.Policy.Runner.UID || start.RunnerGID != live.installed.Policy.Runner.GID ||
		start.At <= 0 || time.UnixMilli(start.At).After(now) {
		return empty, errSoulCooperativeAuthority
	}
	return start, nil
}

func (s *Stage2aService) FinishDirectQualificationWitnessV3(uid, peerPID int, epoch string,
	q Stage2aDirectQWitnessFinishRequestV3,
	paired func(string, func() error) error) (stage2aDirectQWitnessReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply stage2aDirectQWitnessReplyV3
	if paired == nil || len(s.key) != ed25519.PrivateKeySize {
		return reply, errSoulCooperativeAuthority
	}
	live, e := s.directQCurrentV3(uid, epoch, q.SoulCooperativeLiveRequestV3)
	if e != nil || live.directQ == nil || live.directQ.witness == nil || live.directQ.witness.accepted ||
		live.directQ.preSHA256 != q.PreResponseSHA256 || live.directQ.witness.challenge != q.ChallengeBase64URL {
		return reply, errSoulCooperativeAuthority
	}
	run := live.directQ
	var ran bool
	e = paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		peer, err := observeStage2aDirectHQPeerV3(live, peerPID, s.key.Public().(ed25519.PublicKey))
		if err != nil || !sameSoulKernelProcess(run.witness.peer, peer) ||
			readOnlyDirectQPre(live.installed.claimStore(), run) != nil {
			return errSoulCooperativeAuthority
		}
		challengeRaw, err := marshalStage2aReservationJCS(stage2aDirectQWitnessChallengeReplyV3{
			PreResponseSHA256: q.PreResponseSHA256, ChallengeBase64URL: q.ChallengeBase64URL,
			SessionID: run.pre.SessionID, ReservationSHA256: q.ReservationSHA256, AttachSHA256: q.AttachSHA256,
			HQEpoch: epoch, StartID: q.StartID, LaunchID: q.LaunchID, InstallationID: q.InstallationID})
		if err != nil || stage2aDirectQRecord(live.installed.claimStore(), q.InstallationID, q.StartID,
			stage2aDirectQWitnessChallengeName(q.InstallationID, q.StartID), challengeRaw, false) != nil {
			return errSoulCooperativeAuthority
		}
		start, err := stage2aDirectQStartReceiptV3(q, live, run.pre, time.Now().UTC())
		if err != nil {
			return errSoulCooperativeAuthority
		}
		refusalRaw, refusal, err := verifyStage2aDirectHQRefusalV1(q, run.pre, time.Now().UTC())
		if err != nil || refusal.CooperativeStartReceiptSeq != start.Seq ||
			refusal.CooperativeStartReceiptSHA256 != q.CooperativeStartReceiptSHA256 ||
			refusal.Seq <= start.Seq || refusal.At < start.At {
			return errSoulCooperativeAuthority
		}
		startRaw, err := base64.RawURLEncoding.Strict().DecodeString(q.CooperativeStartReceiptBase64URL)
		if err != nil || stage2aDirectQRecord(live.installed.claimStore(), q.InstallationID, q.StartID,
			stage2aDirectQHQRowName(q.InstallationID, q.StartID, "start"), startRaw, true) != nil ||
			stage2aDirectQRecord(live.installed.claimStore(), q.InstallationID, q.StartID,
				stage2aDirectQHQRowName(q.InstallationID, q.StartID, "refusal"), refusalRaw, true) != nil {
			return errSoulCooperativeAuthority
		}
		record := map[string]any{"contract": "machine/v3", "kind": "stage2a-direct-q-witness", "schema_version": 3,
			"pre_response_sha256": q.PreResponseSHA256, "challenge_base64url": q.ChallengeBase64URL,
			"reservation_sha256": q.ReservationSHA256, "attach_sha256": q.AttachSHA256,
			"session_id": run.pre.SessionID, "cooperative_start_receipt_sha256": q.CooperativeStartReceiptSHA256,
			"hq_refusal_receipt_sha256": q.HQRefusalReceiptSHA256,
			"hq_pid":                    peer.PID, "hq_start_seconds": peer.StartSeconds, "hq_start_micros": peer.StartMicros,
			"observed_at": time.Now().UTC().Format(time.RFC3339Nano)}
		envelope, err := signStage2aEnvelope(record, 3, stage2aDirectQWitnessPurposeV3,
			s.key.Public().(ed25519.PublicKey), s.sign)
		if err != nil || len(envelope) > 16<<10 || stage2aDirectQRecord(live.installed.claimStore(), q.InstallationID, q.StartID,
			stage2aDirectQWitnessName(q.InstallationID, q.StartID), envelope, true) != nil {
			return errSoulCooperativeAuthority
		}
		run.witness.envelope = envelope
		run.witness.sha256 = stage2aQualificationSHA256(envelope)
		run.witness.refusalSHA256 = q.HQRefusalReceiptSHA256
		run.witness.startRaw = startRaw
		run.witness.refusalRaw = refusalRaw
		run.witness.accepted = true
		reply.WitnessSHA256 = run.witness.sha256
		return nil
	})
	if e != nil || !ran || reply.WitnessSHA256 == "" {
		return stage2aDirectQWitnessReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
