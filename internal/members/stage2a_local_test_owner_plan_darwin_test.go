//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func stage2aLocalTestOwnerPlanFixture(t *testing.T) (stage2aLocalTestOwnerPlan,
	Stage2aBridgeQualification, time.Time) {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	fixture := Stage2aBridgeQualification{Model: "fixture-model", HTTPHost: "fixture.invalid",
		MessagesQuery: "beta=true", ClientKeySHA256: digest, ResponseText: "fixture response"}
	header := stage2aLocalTestHeaderShape{
		Schema: "stage2a-observed-body-header-shape/v1", Host: fixture.HTTPHost,
		Forbidden:        []string{"authorization", "cookie", "proxy-authorization"},
		RequiredFixed:    map[string]string{"accept": "application/json"},
		RequiredVolatile: map[string]string{"content-length": "decimal-buffered-body-bytes/v1"},
	}
	ancillaryHeader := header
	ancillaryHeader.Schema = "stage2a-stock-ancillary-header-shape/v1"
	ancillaryHeaderRaw, err := marshalStage2aReservationJCS(ancillaryHeader)
	if err != nil {
		t.Fatal(err)
	}
	member := stage2aLocalTestOwnerMember{
		MemberID: "m_lead", Role: "lead", QualificationMode: "observed-body-local-test/v1",
		AdapterID: "fixture-adapter", AdapterVersion: "1.0.0",
		AdapterManifestRelpath: "Contents/opt/fixture.json", AdapterManifestSHA256: digest,
		CommandPath: "/fixture/bin/adapter", CommandSHA256: digest,
		AdjacentCLIPath: "/fixture/bin/stock-client", AdjacentCLISHA256: digest,
	}
	sibling := member
	sibling.MemberID, sibling.Role, sibling.QualificationMode = "m_sibling", "specialist", "disabled"
	plan := stage2aLocalTestOwnerPlan{
		Schema: stage2aLocalTestOwnerPlanSchema, Enabled: true,
		Revision: strings.Repeat("1", 40), SelectedMemberID: member.MemberID,
		Members: []stage2aLocalTestOwnerMember{member, sibling},
		Model:   fixture.Model, HTTPHost: fixture.HTTPHost, MessagesQuery: fixture.MessagesQuery,
		BodyProfile:       "stage2a-stock-observed-local-test/v1",
		OwnerPromptSHA256: digest, RFirstBriefSHA256: digest,
		StaticProjectionSHA256: digest, ClientKeySHA256: digest,
		HeaderShape: header,
		AncillaryProfile: stage2aLocalTestAncillaryProfile{
			Schema:       "stage2a-stock-ancillary-local-test-profile/v2",
			BodyProfile:  "stage2a-stock-ancillary-one-block/v1",
			MaxAncillary: 2, AncillaryHTTPStatus: 422,
			NormalizedBodySHA256: digest, FirstHeaderShape: ancillaryHeader,
			FirstHeadersSHA256:  stage2aReservationSHA256(ancillaryHeaderRaw),
			SecondHeaderShape:   ancillaryHeader,
			SecondHeadersSHA256: stage2aReservationSHA256(ancillaryHeaderRaw),
			Order:               []string{"first", "second"}, TargetAfter: []string{"first"},
		},
		ChildPathProfile:  "per-start-runner-home/v1",
		RunnerHomeLexical: darwinSoulRunnerHome(soulRunnerName("inst.fixture")),
	}
	approvedUntil := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	plan.ExpiresAt = approvedUntil.Add(-time.Hour).Format(time.RFC3339Nano)
	return plan, fixture, approvedUntil
}

func TestStage2aLocalTestDistinctQAndReceipt(t *testing.T) {
	plan, fixture, approvedUntil := stage2aLocalTestOwnerPlanFixture(t)
	planRaw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, ownerSHA, err := parseStage2aLocalTestOwnerPlan(planRaw, fixture, approvedUntil)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	installedDigest := strings.Repeat("3", 64)
	q := stage2aLocalTestQPlan{
		Schema: stage2aLocalTestQSchema, Purpose: stage2aLocalTestQPurpose,
		HostUUID: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", InstallationID: "inst.fixture",
		InstalledPlanID: "plan-20261124T120000Z-abcd", InstalledPlanDigest: installedDigest,
		OwnerPlanSHA256: ownerSHA, SourceRevision: plan.Revision,
		CandidateManifestSHA256: plan.Members[0].AdapterManifestSHA256,
		DriverPlanSHA256:        plan.OwnerPromptSHA256,
		AKeyID:                  stage2aReservationSHA256(key), ExpiresAt: plan.ExpiresAt,
	}
	qRaw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	_, qDigest, err := parseStage2aLocalTestQPlan(qRaw)
	if err != nil {
		t.Fatal(err)
	}
	approval := stage2aLocalTestQApprovalReference{PlanID: "plan-20261124T120001Z-abcd",
		PlanDigest: strings.TrimPrefix(qDigest, "sha256:"), PairCommitment: strings.Repeat("a", 64)}
	measured := stage2aLocalTestMeasuredLead{AdapterManifestSHA256: plan.Members[0].AdapterManifestSHA256,
		CommandSHA256:     plan.Members[0].CommandSHA256,
		AdjacentCLISHA256: plan.Members[0].AdjacentCLISHA256}
	create := func(p stage2aLocalTestOwnerPlan, oSHA string, q stage2aLocalTestQPlan, qSHA string,
		approval stage2aLocalTestQApprovalReference, measured stage2aLocalTestMeasuredLead) error {
		_, err := stage2aLocalTestInstallReceiptFor(p, oSHA, q, qSHA, approval, measured,
			q.InstalledPlanID, installedDigest, q.InstallationID, key)
		return err
	}
	if err := create(plan, ownerSHA, q, qDigest, approval, measured); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*stage2aLocalTestOwnerPlan, *stage2aLocalTestQPlan,
		*stage2aLocalTestQApprovalReference, *stage2aLocalTestMeasuredLead){
		"schema-2 Q purpose": func(_ *stage2aLocalTestOwnerPlan, q *stage2aLocalTestQPlan, _ *stage2aLocalTestQApprovalReference, _ *stage2aLocalTestMeasuredLead) {
			q.Purpose = HarnessQualificationPurpose
		},
		"unapproved owner pin": func(p *stage2aLocalTestOwnerPlan, _ *stage2aLocalTestQPlan, _ *stage2aLocalTestQApprovalReference, _ *stage2aLocalTestMeasuredLead) {
			p.StaticProjectionSHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"stale Q install digest": func(_ *stage2aLocalTestOwnerPlan, q *stage2aLocalTestQPlan, _ *stage2aLocalTestQApprovalReference, _ *stage2aLocalTestMeasuredLead) {
			q.InstalledPlanDigest = strings.Repeat("4", 64)
		},
		"changed installed CLI": func(_ *stage2aLocalTestOwnerPlan, _ *stage2aLocalTestQPlan, _ *stage2aLocalTestQApprovalReference, m *stage2aLocalTestMeasuredLead) {
			m.AdjacentCLISHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"unapproved Q reference": func(_ *stage2aLocalTestOwnerPlan, _ *stage2aLocalTestQPlan, a *stage2aLocalTestQApprovalReference, _ *stage2aLocalTestMeasuredLead) {
			a.PlanDigest = strings.Repeat("b", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, qq, a, m := plan, q, approval, measured
			change(&p, &qq, &a, &m)
			if err := create(p, ownerSHA, qq, qDigest, a, m); err == nil {
				t.Fatal("unapproved Q, policy, receipt or installed bytes accepted")
			}
		})
	}
	qUnknown := bytes.Replace(qRaw, []byte(`"purpose":"`), []byte(`"hq_pin":"x","purpose":"`), 1)
	if _, _, err := parseStage2aLocalTestQPlan(qUnknown); err == nil {
		t.Fatal("HQ-supplied Q pin accepted")
	}
}

func TestStage2aLocalTestOwnerPlanRefusals(t *testing.T) {
	plan, fixture, approvedUntil := stage2aLocalTestOwnerPlanFixture(t)
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	got, digest, err := parseStage2aLocalTestOwnerPlan(raw, fixture, approvedUntil)
	if err != nil || !got.Enabled || !stage2aPrefixedDigest.MatchString(digest) {
		t.Fatalf("reviewed local-test plan refused: %v", err)
	}
	if _, _, err := stage2aLocalTestOwnerPlanFromPolicy(nil, fixture, approvedUntil); err == nil {
		t.Fatal("absent local-test policy opened route")
	}
	if _, _, err := stage2aLocalTestOwnerPlanFromPolicy(json.RawMessage("null"), fixture, approvedUntil); err == nil {
		t.Fatal("null local-test policy opened route")
	}
	for name, edit := range map[string]func(*stage2aLocalTestOwnerPlan){
		"disabled":                func(p *stage2aLocalTestOwnerPlan) { p.Enabled = false },
		"changed model":           func(p *stage2aLocalTestOwnerPlan) { p.Model = "unapproved-model" },
		"changed selected member": func(p *stage2aLocalTestOwnerPlan) { p.SelectedMemberID = "m_sibling" },
		"enabled sibling":         func(p *stage2aLocalTestOwnerPlan) { p.Members[1].QualificationMode = "observed-body-local-test/v1" },
		"changed CLI digest": func(p *stage2aLocalTestOwnerPlan) {
			p.Members[0].AdjacentCLISHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"unreviewed header": func(p *stage2aLocalTestOwnerPlan) { p.HeaderShape.RequiredFixed["cookie"] = "secret" },
		"changed ancillary digest": func(p *stage2aLocalTestOwnerPlan) {
			p.AncillaryProfile.FirstHeadersSHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"expanded ancillary": func(p *stage2aLocalTestOwnerPlan) { p.AncillaryProfile.MaxAncillary = 3 },
		"expired after install": func(p *stage2aLocalTestOwnerPlan) {
			p.ExpiresAt = approvedUntil.Add(time.Hour).Format(time.RFC3339Nano)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutant := plan
			mutant.Members = append([]stage2aLocalTestOwnerMember(nil), plan.Members...)
			mutant.HeaderShape.RequiredFixed = map[string]string{"accept": "application/json"}
			edit(&mutant)
			encoded, err := json.Marshal(mutant)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := parseStage2aLocalTestOwnerPlan(encoded, fixture, approvedUntil); err == nil && name != "changed CLI digest" {
				t.Fatal("changed or unapproved local-test policy accepted")
			}
			// A changed but well-shaped CLI hash is rejected by the root
			// installed-file remeasurement and receipt join, not this parser.
		})
	}
	unknown := bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":true,"hq_supplied_pin":"x"`), 1)
	if bytes.Equal(unknown, raw) {
		t.Fatal("test fixture did not add unknown field")
	}
	if _, _, err := parseStage2aLocalTestOwnerPlan(unknown, fixture, approvedUntil); err == nil {
		t.Fatal("HQ-supplied pin field accepted")
	}
	duplicate := bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":true,"enabled":true`), 1)
	if _, _, err := parseStage2aLocalTestOwnerPlan(duplicate, fixture, approvedUntil); err == nil {
		t.Fatal("duplicate policy field accepted")
	}
}

func TestStage2aLocalTestDerivedChildPaths(t *testing.T) {
	plan, _, _ := stage2aLocalTestOwnerPlanFixture(t)
	installation := "inst.fixture"
	start := "st_" + strings.Repeat("1", 24)
	runner := soulRunnerName(installation)
	got, err := stage2aLocalTestPathsForStart(plan, runner, installation, start)
	if err != nil {
		t.Fatal(err)
	}
	if soulEndpointStartSlot(installation, start) != "70799e6441e7d13e10b2" {
		t.Fatal("per-start slot serialization changed")
	}
	root := darwinSoulRunnerHome(runner) + "/state/child-70799e6441e7d13e10b2"
	if got.CWDLexical != root+"/work" || got.HomeLexical != root+"/home" ||
		got.CWDEmitted != "/private"+root+"/work" ||
		!strings.HasPrefix(got.MemoryLexical, root+"/home/.claude/projects/-private-var-") ||
		!strings.HasSuffix(got.MemoryLexical, "/memory/") {
		t.Fatalf("unexpected per-start child paths: %+v", got)
	}
	for name, change := range map[string]func(*stage2aLocalTestOwnerPlan, *string, *string, *string){
		"sibling runner":         func(_ *stage2aLocalTestOwnerPlan, r, _, _ *string) { *r = soulRunnerName("inst.sibling") },
		"different installation": func(_ *stage2aLocalTestOwnerPlan, _, i, _ *string) { *i = "inst.sibling" },
		"wrong start":            func(_ *stage2aLocalTestOwnerPlan, _, _, s *string) { *s = "not-a-start" },
		"path alias": func(p *stage2aLocalTestOwnerPlan, _, _, _ *string) {
			p.RunnerHomeLexical = "/private" + p.RunnerHomeLexical
		},
		"stable shared path": func(p *stage2aLocalTestOwnerPlan, _, _, _ *string) { p.ChildPathProfile = "shared-home/v1" },
	} {
		t.Run(name, func(t *testing.T) {
			p, r, i, s := plan, runner, installation, start
			change(&p, &r, &i, &s)
			if _, err := stage2aLocalTestPathsForStart(p, r, i, s); err == nil {
				t.Fatal("alias or sibling child path accepted")
			}
		})
	}
}
