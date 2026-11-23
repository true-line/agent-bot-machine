//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestStage2aDirectHQRefusalRequiresBoundDurableReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	digest := "sha256:" + strings.Repeat("a", 64)
	pre := stage2aDirectQPreV3{InstallationID: "inst_0000000000000001",
		StartID: "st_0123456789abcdef01234567", LaunchID: "ln_0123456789abcdef01234567",
		HQEpoch: strings.Repeat("f", 64), ReservationSHA256: digest, AttachSHA256: digest,
		SessionID: "qs_0123456789abcdef01234567", QChallengeSHA256: digest,
		TestPlanSHA256: digest, CaseNonceBase64URL: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		IssuedAt:  now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	q := Stage2aDirectQFinishRequestV3{PreResponseSHA256: digest}
	receipt := stage2aDirectHQRefusalV1{Schema: stage2aDirectHQRefusalSchemaV1,
		Plugin: "hq", Kind: "hq.soul.protected-claim.refused", Seq: 5, At: now.UnixMilli(),
		Profile: "managed-cooperative", InstallationID: pre.InstallationID,
		StartID: pre.StartID, LaunchID: pre.LaunchID, HQEpoch: pre.HQEpoch,
		ReservationSHA256: pre.ReservationSHA256, AttachSHA256: pre.AttachSHA256,
		SessionID: pre.SessionID, QChallengeSHA256: pre.QChallengeSHA256,
		TestPlanSHA256: pre.TestPlanSHA256, CaseNonceBase64URL: pre.CaseNonceBase64URL,
		PreResponseSHA256: q.PreResponseSHA256, RequestedProfile: "managed-protected",
		RefusalCode: "profile_insufficient", CooperativeStartReceiptSeq: 4,
		CooperativeStartReceiptSHA256: digest}
	encode := func(r stage2aDirectHQRefusalV1) {
		t.Helper()
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raw, err = jsoncanonicalizer.Transform(raw)
		if err != nil {
			t.Fatal(err)
		}
		q.HQRefusalReceiptBase64URL = base64.RawURLEncoding.EncodeToString(raw)
		q.HQRefusalReceiptSHA256 = stage2aQualificationSHA256(raw)
	}
	encode(receipt)
	if _, _, err := verifyStage2aDirectHQRefusalV1(q, pre, now); err != nil {
		t.Fatalf("bound HQ refusal rejected: %v", err)
	}
	for _, alter := range []struct {
		name   string
		change func(*stage2aDirectHQRefusalV1)
	}{
		{"other nonce", func(r *stage2aDirectHQRefusalV1) { r.CaseNonceBase64URL = "other" }},
		{"other pre", func(r *stage2aDirectHQRefusalV1) { r.PreResponseSHA256 = "other" }},
		{"earlier sequence", func(r *stage2aDirectHQRefusalV1) { r.Seq = 4 }},
		{"other refusal", func(r *stage2aDirectHQRefusalV1) { r.RefusalCode = "error" }},
		{"before pre", func(r *stage2aDirectHQRefusalV1) { r.At = now.Add(-2 * time.Second).UnixMilli() }},
		{"after deadline", func(r *stage2aDirectHQRefusalV1) { r.At = now.Add(time.Minute).UnixMilli() }},
	} {
		t.Run(alter.name, func(t *testing.T) {
			changed := receipt
			alter.change(&changed)
			encode(changed)
			if _, _, err := verifyStage2aDirectHQRefusalV1(q, pre, now); err == nil {
				t.Fatal("unbound HQ refusal accepted")
			}
		})
	}
}

func TestStage2aDirectQualificationBeginRequiresJoinedReviewedAuthority(t *testing.T) {
	request := validQualificationRequest()
	request.Candidate = &qualificationCandidatePlan{
		InstallationID: "inst_0000000000000001", RuntimeInventorySHA: strings.Repeat("8", 64),
		ComponentID: "codex", Manifest: qualificationFile{"/private/reviewed/manifest", strings.Repeat("c", 64)},
		TestPlan: qualificationFile{"/private/reviewed/t21-plan", strings.Repeat("d", 64)},
	}
	provider := Stage2aBridgeQualification{Model: "codex", RequestSHA256: "sha256:" + strings.Repeat("9", 64), ResponseText: "fixture"}
	_, providerSHA, err := stage2aProviderConfig(provider)
	if err != nil {
		t.Fatal(err)
	}
	const owner = "local-owner"
	planID, planDigest := "plan-20261122T141516Z-abcd", strings.Repeat("a", 64)
	install := stage2aQualificationQInstall{
		AdminUID: 501, AdminGID: 20, HQUID: 309, RunnerGID: request.Target.UID,
		UID: 451, GID: 451, Source: qualificationFile{"/private/var/db/managed-machine/qualification-q/qualification-runner.mjs", request.Runner.BinarySHA},
		PS:    qualificationFile{"/private/var/db/managed-machine/qualification-q/process-observer", strings.Repeat("e", 64)},
		Roots: []string{"/private/var/db/managed-machine"},
		Review: stage2aQualificationQReview{Owner: owner, PlanID: "plan-20261122T141516Z-1234",
			HostID: request.Host.ID, InstallationID: request.Candidate.InstallationID,
			InstalledPlanDigest: planDigest, TestPlan: request.Candidate.TestPlan,
			Provider: qualificationFile{request.TestProvider.ConfigPath, providerSHA}},
	}
	policy := SoulCooperativeLaunchPolicy{
		HostID: request.Host.ID, HQUID: install.HQUID, MachineUID: install.AdminUID, MachineGID: install.AdminGID,
		Runner: SoulRunner{InstallationID: install.Review.InstallationID, Account: request.Target.Account,
			UID: request.Target.UID, GID: install.RunnerGID},
		AdapterRelease: &soulCooperativeAdapterV3{ComponentID: request.Candidate.ComponentID,
			ReleaseManifestSHA256: "sha256:" + request.Candidate.Manifest.SHA256,
			PackageSHA256:         "sha256:" + request.Adapter.PackageSHA,
			ExecutablePath:        request.Adapter.Launch.Executable,
			ExecutableSHA256:      "sha256:" + request.Adapter.Launch.ExecutableSHA},
		LaunchInputs: &Stage2aLaunchInputRecords{ComponentDigests: map[string]string{
			"harness": "sha256:" + request.Adapter.Harness.BinarySHA},
			EffectiveConfig: map[string]any{"qualification_provider_config_sha256": "sha256:" + providerSHA}},
		QualificationProvider: &provider,
	}
	receiptRaw, err := json.Marshal(Receipt{Owner: owner, PlanID: planID, PlanDigest: planDigest})
	if err != nil {
		t.Fatal(err)
	}
	startID, launchID := "st_0123456789abcdef01234567", "ln_0123456789abcdef01234567"
	ref := stage2aDomainInventoryRefV3{InventoryDigest: "sha256:" + request.Candidate.RuntimeInventorySHA}
	live := &soulCooperativeLiveV3{
		request: SoulCooperativeReserveRequest{InstallationID: install.Review.InstallationID,
			StartID: startID, LaunchID: launchID, PlanDigest: planDigest,
			HQEpoch: strings.Repeat("f", 64), AdmissionChallengeSHA256: "sha256:" + strings.Repeat("1", 64)},
		installed:         soulCooperativeInstalledV3{Policy: policy, RuntimeV3: ref, RootReceipt: receiptRaw},
		hDescriptorDigest: "sha256:" + strings.Repeat("2", 64),
		envelope:          []byte("synthetic signed bytes"), attached: true,
	}
	live.digest = stage2aQualificationSHA256(live.envelope)
	now := time.Now().UTC().Truncate(time.Second)
	reservation := soulCooperativeReservationPayloadV3{
		Contract: "machine/v3", Kind: "soul-cooperative-reservation", SchemaVersion: 3,
		AdapterTransport: stage2aDirectComms, HostID: policy.HostID,
		IssuedAt:  now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(29 * time.Second).Format(time.RFC3339Nano),
		Assignment: soulCooperativeAssignmentV3{InstallationID: live.request.InstallationID,
			StartID: startID, LaunchID: launchID, PlanID: planID, PlanDigest: planDigest,
			HQEpoch: live.request.HQEpoch, SoulID: "agent_01234567-0123-4567-0123-456789abcdef",
			RunnerUID: policy.Runner.UID, RunnerGID: policy.Runner.GID,
			HQUID: policy.HQUID, MachineUID: policy.MachineUID},
		MeasurementBinding: soulCooperativeBindingV3{Stage2aMeasurementBinding: Stage2aMeasurementBinding{
			InstallationID: live.request.InstallationID, StartID: startID, LaunchID: launchID,
			PlanID: planID, InstalledPlanDigest: planDigest,
			SoulID: "agent_01234567-0123-4567-0123-456789abcdef",
			HostID: policy.HostID, HQEpoch: live.request.HQEpoch, ProfileInForce: "managed-cooperative"},
			RInventory: ref, HDescriptorDigest: live.hDescriptorDigest},
		AdmissionChallengeSHA256: live.request.AdmissionChallengeSHA256,
	}
	if got, err := stage2aDirectQualificationBeginV3(live, reservation, install, request, owner, now); err != nil ||
		got.Profile != "managed-cooperative" || got.ReservationSHA256 != live.digest || got.QUID != install.UID {
		t.Fatalf("reviewed direct Q begin refused: %+v, %v", got, err)
	}
	if _, err := stage2aDirectQualificationBeginV3(live, reservation, install, request, owner, now.Add(time.Minute)); err != nil {
		t.Fatalf("attached live Q begin refused after reservation lease: %v", err)
	}
	for _, change := range []struct {
		name string
		run  func() error
	}{
		{"protected profile", func() error {
			altered := reservation
			altered.MeasurementBinding.ProfileInForce = "managed-protected"
			_, err := stage2aDirectQualificationBeginV3(live, altered, install, request, owner, now)
			return err
		}},
		{"other transport", func() error {
			altered := reservation
			altered.AdapterTransport = "relay"
			_, err := stage2aDirectQualificationBeginV3(live, altered, install, request, owner, now)
			return err
		}},
		{"other R", func() error {
			altered := reservation
			altered.MeasurementBinding.RInventory.InventoryDigest = "sha256:" + strings.Repeat("3", 64)
			_, err := stage2aDirectQualificationBeginV3(live, altered, install, request, owner, now)
			return err
		}},
		{"other Q plan", func() error {
			altered := install
			altered.Review.TestPlan.SHA256 = strings.Repeat("4", 64)
			_, err := stage2aDirectQualificationBeginV3(live, reservation, altered, request, owner, now)
			return err
		}},
		{"invalid reservation lease", func() error {
			altered := reservation
			altered.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339Nano)
			_, err := stage2aDirectQualificationBeginV3(live, altered, install, request, owner, now)
			return err
		}},
		{"unattached", func() error {
			altered := *live
			altered.attached = false
			_, err := stage2aDirectQualificationBeginV3(&altered, reservation, install, request, owner, now)
			return err
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			if change.run() == nil {
				t.Fatal("unreviewed direct Q begin accepted")
			}
		})
	}
}

func TestStage2aDirectQualificationBindingCannotReplay(t *testing.T) {
	store, dir, q := cooperativeClaimFixture(t)
	var err error
	store.path, err = filepath.EvalSymlinks(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := spendSoulCooperativeStartIn(store, dir, q); err != nil {
		t.Fatal(err)
	}
	if err := spendStage2aAdminName(dir, cooperativeAttachedName(q.InstallationID, q.StartID), store.uid, store.gid); err != nil {
		t.Fatal(err)
	}
	live := &soulCooperativeLiveV3{request: q, attached: true, envelope: []byte("synthetic direct reservation")}
	live.digest = stage2aQualificationSHA256(live.envelope)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if err := claimStage2aDirectQSessionV3(store, live, key); err == nil {
		t.Fatal("Q session claimed without the exact A-owned signed journal")
	}
	if err := spendStage2aAdminName(dir, stage2aDirectQSessionName(q.InstallationID, q.StartID), store.uid, store.gid); err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0xbb}, 32)
	begin := stage2aQualificationBeginV1{
		InstallationID: q.InstallationID, StartID: q.StartID,
		ReservationSHA256: live.digest, SessionID: strings.Repeat("a", 32),
		ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(challenge),
		QUID:               650, QGID: 651, RequireArgvProof: true,
	}
	peer := stage2aQualificationPeerV1{
		pid: 42, uid: 650, gid: 651, reviewedArgvProof: true,
		executable: "/usr/local/bin/node",
		argv:       []string{"/usr/local/bin/node", "/opt/q/qualification-runner.mjs", "--once"},
		socketPath: "/private/tmp/q-session.sock", socketDev: 1, socketInode: 4242,
		socketBirthSeconds: 1795327200,
		kernel: soulKernelProcessSnapshot{PID: 42, ParentPID: 40, StartSeconds: 1795327200,
			RealUID: 650, EffectiveUID: 650, SavedUID: 650,
			RealGID: 651, PrimaryGroupGID: 651, SavedGID: 651},
	}
	session := &stage2aQualificationSessionV1{begin: begin,
		challengeSHA256: stage2aQualificationSHA256(challenge), peer: peer}
	if _, err := stage2aQualificationSessionBindingBytes(begin, session.challengeSHA256, peer); err != nil {
		t.Fatalf("synthetic Q peer invalid: %v", err)
	}
	if err := store.checkDirectory(dir); err != nil {
		t.Fatalf("store invalid: %v", err)
	}
	if err := cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID); err != nil {
		t.Fatalf("active claim invalid: %v", err)
	}
	if err := stage2aCheckSpentClaim(dir, stage2aDirectQSessionName(q.InstallationID, q.StartID), store.uid, store.gid); err != nil {
		t.Fatalf("Q claim invalid: %v", err)
	}
	opened, err := store.open()
	if err != nil {
		t.Fatalf("store reopened: %v", err)
	}
	lock, err := lockStage2aReservation(opened, store.uid, store.gid, q.InstallationID)
	if err != nil {
		t.Fatalf("claim lock: %v", err)
	}
	lock.Close()
	opened.Close()
	if err := bindStage2aDirectQSessionV3(store, live, session); err != nil {
		t.Fatalf("first exact direct Q binding refused: %v", err)
	}
	if err := bindStage2aDirectQSessionV3(store, live, session); err == nil {
		t.Fatal("second direct Q binding replaced the first")
	}
	result := stage2aQualificationSessionResultV1{begin: begin,
		challengeSHA256: session.challengeSHA256, peer: peer}
	if err := checkStage2aDirectQBindingV3(dir, store, result); err != nil {
		t.Fatalf("stored direct Q binding refused: %v", err)
	}
	result.begin.SessionID = strings.Repeat("c", 32)
	if err := checkStage2aDirectQBindingV3(dir, store, result); err == nil {
		t.Fatal("different Q session inherited the one-use binding")
	}
}
