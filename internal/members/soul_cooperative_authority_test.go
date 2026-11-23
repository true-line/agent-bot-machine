package members

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func cooperativeFixture(t *testing.T) (SoulCooperativeLaunchPolicy, SoulCooperativeReserveRequest, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	id := "installation-1"
	p := SoulCooperativeLaunchPolicy{
		Schema: soulCooperativeInstallSchema, Purpose: SoulCooperativeLaunchInstallPurpose,
		Profile: "managed-cooperative", HostID: "test-host", HQUID: 310,
		HQEpoch: strings.Repeat("a", 64), MachinePublicKey: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)),
		SourcePackagePath: "/var/agent-bot-hq/candidates/hello.soul",
		Runner: SoulRunner{SoulID: "agent_12345678-1234-1234-1234-123456789abc", InstallationID: id,
			Account: soulRunnerName(id), UID: 311, GID: 311, PackageRoot: cooperativeArtifactPath(id),
			PackageSHA256: strings.Repeat("b", 64)},
		ArtifactSHA256: strings.Repeat("c", 64), DefinitionSHA256: strings.Repeat("d", 64),
		NodePath: "/opt/agent-bot/node", NodeSHA256: strings.Repeat("e", 64),
		Entry: "Contents/opt/quickstart-adapter.mjs", LauncherPath: "/opt/agent-bot/soul-launcher",
		LauncherSHA256: strings.Repeat("f", 64), ApprovedUntil: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	q := SoulCooperativeReserveRequest{Profile: "managed-cooperative", HostID: p.HostID,
		InstallationID: id, StartID: "st_1234567890abcdef12345678",
		HQEpoch: p.HQEpoch, PackagePath: p.SourcePackagePath}
	h := &fakeHost{accounts: map[string]Account{
		DarwinHQAccount:  {Name: DarwinHQAccount, UID: p.HQUID, GID: p.HQUID},
		p.Runner.Account: {Name: p.Runner.Account, UID: p.Runner.UID, GID: p.Runner.GID},
	}}
	plan, err := Build(Input{SoulCooperativeLaunch: &p, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "owner"}, h)
	if err != nil {
		t.Fatal(err)
	}
	q.PlanDigest, err = plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return p, q, private, now
}

func installedCooperativeFixture(t *testing.T, p SoulCooperativeLaunchPolicy, q SoulCooperativeReserveRequest) SoulCooperativeInstalledAuthority {
	t.Helper()
	h := &fakeHost{accounts: map[string]Account{
		DarwinHQAccount:  {Name: DarwinHQAccount, UID: p.HQUID, GID: p.HQUID},
		p.Runner.Account: {Name: p.Runner.Account, UID: p.Runner.UID, GID: p.Runner.GID},
	}}
	plan, err := Build(Input{SoulCooperativeLaunch: &p, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "owner"}, h)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := plan.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{PlanID: "plan-20261122T120000Z-abcd", PlanDigest: q.PlanDigest,
		Owner: "owner", HQAccount: DarwinHQAccount, Dir: DarwinDir, Members: plan.Members,
		Changes: plan.Changes(), StartedAt: "2026-11-22T12:00:00Z",
		FinishedAt: "2026-11-22T12:00:01Z", Result: "applied"}
	receiptRaw := encodeReceipt(receipt)
	return SoulCooperativeInstalledAuthority{
		Policy: p, PlanID: receipt.PlanID, PlanDigest: q.PlanDigest,
		ReceiptSHA256: fmt.Sprintf("%x", sha256.Sum256(receiptRaw)),
		CanonicalPlan: canonical, RootReceipt: receiptRaw,
		ObservedPackageSHA256:  p.Runner.PackageSHA256,
		ObservedArtifactSHA256: p.ArtifactSHA256, ObservedDefinitionSHA256: p.DefinitionSHA256,
		ObservedNodeSHA256: p.NodeSHA256, ObservedLauncherSHA256: p.LauncherSHA256,
	}
}

func TestSoulCooperativeInstalledRecordCannotBeReplacedByDigestClaims(t *testing.T) {
	p, q, private, now := cooperativeFixture(t)
	base := installedCooperativeFixture(t, p, q)
	sign := func(body []byte) ([]byte, error) { return ed25519.Sign(private, body), nil }
	for name, edit := range map[string]func(*SoulCooperativeInstalledAuthority){
		"missing canonical plan": func(in *SoulCooperativeInstalledAuthority) { in.CanonicalPlan = nil },
		"altered plan bytes": func(in *SoulCooperativeInstalledAuthority) {
			in.CanonicalPlan = append([]byte(nil), in.CanonicalPlan...)
			in.CanonicalPlan[0] = '['
			in.PlanDigest = fmt.Sprintf("%x", sha256.Sum256(in.CanonicalPlan))
		},
		"missing root receipt": func(in *SoulCooperativeInstalledAuthority) { in.RootReceipt = nil },
		"failed receipt with matching digest": func(in *SoulCooperativeInstalledAuthority) {
			var receipt Receipt
			if err := json.Unmarshal(in.RootReceipt, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt.Result = "failed"
			in.RootReceipt = encodeReceipt(receipt)
			in.ReceiptSHA256 = fmt.Sprintf("%x", sha256.Sum256(in.RootReceipt))
		},
		"wrong owner with matching digest": func(in *SoulCooperativeInstalledAuthority) {
			var receipt Receipt
			if err := json.Unmarshal(in.RootReceipt, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt.Owner = ""
			in.RootReceipt = encodeReceipt(receipt)
			in.ReceiptSHA256 = fmt.Sprintf("%x", sha256.Sum256(in.RootReceipt))
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := base
			edit(&in)
			spent := false
			if _, err := PrepareSoulCooperativeReservation(in, q, now, sign,
				func(_, _ string) error { spent = true; return nil }); err == nil || spent {
				t.Fatal("unverified installed record reached durable spend")
			}
		})
	}
}

func TestSoulCooperativeReservationOneUseAndSignature(t *testing.T) {
	p, q, private, now := cooperativeFixture(t)
	policyRaw, _ := json.Marshal(p)
	parsedPolicy, err := ParseSoulCooperativeLaunchPolicy(policyRaw)
	if err != nil || parsedPolicy != p {
		t.Fatalf("parse reviewed policy: %v", err)
	}
	requestRaw, _ := json.Marshal(q)
	parsedRequest, err := ParseSoulCooperativeReserveRequest(requestRaw)
	if err != nil || parsedRequest != q {
		t.Fatalf("parse reserve request: %v", err)
	}
	spent := map[string]bool{}
	spend := func(installation, start string) error {
		key := installation + "/" + start
		if spent[key] {
			return errors.New("spent")
		}
		spent[key] = true
		return nil
	}
	sign := func(preimage []byte) ([]byte, error) { return ed25519.Sign(private, preimage), nil }
	in := installedCooperativeFixture(t, p, q)
	got, err := PrepareSoulCooperativeReservation(in, q, now, sign, spend)
	if err != nil || !spent[q.InstallationID+"/"+q.StartID] {
		t.Fatalf("prepare and spend: %v", err)
	}
	if got.Purpose != soulCooperativeReservationPurpose {
		t.Fatal("wrong signed purpose")
	}
	payload, err := base64.RawURLEncoding.DecodeString(got.PayloadBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(got.SignatureBase64URL)
	if err != nil || !ed25519.Verify(private.Public().(ed25519.PublicKey),
		append([]byte(got.Purpose+"\x00"), payload...), signature) {
		t.Fatal("Machine signature does not verify")
	}
	var reserved SoulCooperativeReservation
	if json.Unmarshal(payload, &reserved) != nil || reserved.Profile != "managed-cooperative" ||
		reserved.RunnerUID != p.Runner.UID || reserved.PackageSHA256 != p.Runner.PackageSHA256 ||
		reserved.SoulArtifactSHA256 != p.ArtifactSHA256 || reserved.SourcePackagePath != q.PackagePath ||
		reserved.Endpoint.OwnerUID != p.HQUID || reserved.Endpoint.PeerUID != p.Runner.UID ||
		reserved.Endpoint.SocketMode != 0660 {
		t.Fatal("signed payload lost reviewed binding")
	}
	if _, err := PrepareSoulCooperativeReservation(in, q, now, sign, spend); err == nil {
		t.Fatal("same installation/start was reissued")
	}
}

func TestSoulCooperativeReservationRefusals(t *testing.T) {
	p, q, private, now := cooperativeFixture(t)
	in := installedCooperativeFixture(t, p, q)
	sign := func(preimage []byte) ([]byte, error) { return ed25519.Sign(private, preimage), nil }
	goodSpend := func(string, string) error { return nil }
	for _, test := range []struct {
		name string
		edit func(*SoulCooperativeLaunchPolicy, *SoulCooperativeReserveRequest, *time.Time)
	}{
		{"protected request", func(_ *SoulCooperativeLaunchPolicy, q *SoulCooperativeReserveRequest, _ *time.Time) {
			q.Profile = "managed-protected"
		}},
		{"protected policy", func(p *SoulCooperativeLaunchPolicy, _ *SoulCooperativeReserveRequest, _ *time.Time) {
			p.Profile = "managed-protected"
		}},
		{"wrong host", func(_ *SoulCooperativeLaunchPolicy, q *SoulCooperativeReserveRequest, _ *time.Time) {
			q.HostID = "other-host"
		}},
		{"wrong source package", func(_ *SoulCooperativeLaunchPolicy, q *SoulCooperativeReserveRequest, _ *time.Time) {
			q.PackagePath = "/tmp/other.soul"
		}},
		{"wrong identity", func(p *SoulCooperativeLaunchPolicy, _ *SoulCooperativeReserveRequest, _ *time.Time) {
			p.Runner.UID = p.HQUID
		}},
		{"altered bundle", func(p *SoulCooperativeLaunchPolicy, _ *SoulCooperativeReserveRequest, _ *time.Time) {
			p.Runner.PackageSHA256 = "bad"
		}},
		{"expired approval", func(_ *SoulCooperativeLaunchPolicy, _ *SoulCooperativeReserveRequest, now *time.Time) {
			*now = now.Add(2 * time.Hour)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p1, q1, at := p, q, now
			test.edit(&p1, &q1, &at)
			called := false
			in1 := in
			in1.Policy = p1
			if _, err := PrepareSoulCooperativeReservation(in1, q1, at, sign,
				func(a, b string) error { called = true; return goodSpend(a, b) }); err == nil || called {
				t.Fatalf("invalid request reached durable spend: %v", err)
			}
		})
	}
	other := ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", ed25519.SeedSize)))
	if _, err := PrepareSoulCooperativeReservation(in, q, now,
		func(preimage []byte) ([]byte, error) { return ed25519.Sign(other, preimage), nil }, goodSpend); err == nil {
		t.Fatal("wrong Machine signer accepted")
	}
	altered := in
	altered.ObservedPackageSHA256 = strings.Repeat("3", 64)
	called := false
	if _, err := PrepareSoulCooperativeReservation(altered, q, now, sign,
		func(a, b string) error { called = true; return goodSpend(a, b) }); err == nil || called {
		t.Fatal("validly shaped altered package reached durable spend")
	}
}

func TestSoulCooperativeParsersRefuseAmbiguity(t *testing.T) {
	p, q, _, _ := cooperativeFixture(t)
	raw, _ := json.Marshal(p)
	if _, err := ParseSoulCooperativeLaunchPolicy(append(raw[:len(raw)-1], []byte(`,"profile_in_force":"managed-cooperative"}`)...)); err == nil {
		t.Fatal("duplicate policy field accepted")
	}
	if _, err := ParseSoulCooperativeLaunchPolicy(append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)); err == nil {
		t.Fatal("unknown policy field accepted")
	}
	request, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeReserveRequest(append(request[:len(request)-1], []byte(`,"profile":"managed-cooperative"}`)...)); err == nil {
		t.Fatal("duplicate request field accepted")
	}
}

func TestSoulCooperativePlanIsSeparateAndReviewable(t *testing.T) {
	p, _, _, _ := cooperativeFixture(t)
	h := &fakeHost{accounts: map[string]Account{
		DarwinHQAccount:  {Name: DarwinHQAccount, UID: p.HQUID, GID: p.HQUID},
		p.Runner.Account: {Name: p.Runner.Account, UID: p.Runner.UID, GID: p.Runner.GID},
	}}
	plan, err := Build(Input{SoulCooperativeLaunch: &p, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "owner"}, h)
	if err != nil || plan.Purpose != SoulCooperativeLaunchInstallPurpose ||
		plan.SoulProtectedLaunch != nil || len(plan.Steps) != 1 || plan.Steps[0].Kind != "soul-cooperative-launch" {
		t.Fatalf("separate cooperative review plan: %v, %+v", err, plan)
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	saved := Saved{SoulCooperativeLaunch: &p, PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: digest, Plan: plan}
	if _, err := saved.CanonicalForReview(); err != nil {
		t.Fatalf("review exact cooperative plan: %v", err)
	}
	altered := p
	altered.Profile = "managed-protected"
	saved.SoulCooperativeLaunch = &altered
	if _, err := saved.CanonicalForReview(); err == nil {
		t.Fatal("protected profile was accepted as cooperative review")
	}
}
