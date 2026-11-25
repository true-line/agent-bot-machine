package qualification

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type protectedSegmentFixtureV3 struct {
	root    string
	gate    gateManifestV3
	segment gateSegmentV3
	key     ed25519.PublicKey
	now     qFixtureV3
	refs    map[string]gateObjectRefV3
}

func TestSignedProtectedCohortBindingV3(t *testing.T) {
	ordinary, err := os.ReadFile("testdata/stage2a-hr-binding-v3-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		raw       []byte
		candidate bool
	}{{"ordinary", ordinary, false}, {"candidate", candidateContractBindingV3(t), true}} {
		t.Run(tc.name, func(t *testing.T) {
			readSigned := func(binding map[string]any) string {
				t.Helper()
				envelope := qSignFixtureV3(t, map[string]any{"measurement_binding": binding}, "fixture/cohort", 1, private)
				payload, err := qSignedRecordV3(envelope, "fixture/cohort", 1, public)
				if err != nil {
					t.Fatal(err)
				}
				var signed struct {
					Binding json.RawMessage `json:"measurement_binding"`
				}
				if err := json.Unmarshal(payload, &signed); err != nil {
					t.Fatal(err)
				}
				if tc.candidate {
					_, err = parseCandidateMeasurementBindingV3(signed.Binding)
				} else {
					_, err = parseHRMeasurementBindingV3(signed.Binding)
				}
				if err != nil {
					t.Fatalf("signed binding invalid: %v", err)
				}
				got, err := protectedCohortBindingV3(signed.Binding)
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			decode := func() map[string]any {
				var v map[string]any
				if err := json.Unmarshal(tc.raw, &v); err != nil {
					t.Fatal(err)
				}
				return v
			}
			want := readSigned(decode())
			changedStart := decode()
			changedStart["start_id"] = "st_aaaaaaaaaaaaaaaaaaaaaaaa"
			changedStart["launch_id"] = "ln_aaaaaaaaaaaaaaaaaaaaaaaa"
			changedStart["hq_epoch"] = strings.Repeat("a", 64)
			if !sameProtectedCohortV3(want, readSigned(changedStart)) {
				t.Fatal("new start in same cohort refused")
			}
			for name, mutate := range map[string]func(map[string]any){
				"H descriptor": func(v map[string]any) { v["h_service_descriptor_digest"] = digest([]byte("other H")) },
				"R inventory": func(v map[string]any) {
					v["r_inventory"].(map[string]any)["snapshot"].(map[string]any)["inode"] = "999999"
				},
				"R component": func(v map[string]any) {
					v["r_components"].([]any)[0].(map[string]any)["source_commit"] = strings.Repeat("a", 40)
				},
				"adapter": func(v map[string]any) {
					key := "adapter_release"
					if tc.candidate {
						key = "candidate_adapter"
					}
					v[key].(map[string]any)["executable_sha256"] = digest([]byte("other adapter"))
				},
				"broker": func(v map[string]any) {
					v["broker_executable"].(map[string]any)["sha256"] = digest([]byte("other broker"))
				},
			} {
				t.Run(name, func(t *testing.T) {
					changed := decode()
					mutate(changed)
					if sameProtectedCohortV3(want, readSigned(changed)) {
						t.Fatal("different signed cohort accepted")
					}
				})
			}
		})
	}
}

func qWriteBlobFixtureV3(t *testing.T, root, role string, raw []byte) gateObjectRefV3 {
	t.Helper()
	sha := digest(raw)
	name := strings.TrimPrefix(sha, "sha256:")
	dir := filepath.Join(root, "objects", "sha256", name[:2])
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return gateObjectRefV3{Role: role, URI: gateObjectPrefixV3 + "blob/" + name, SHA256: sha, SizeBytes: int64(len(raw)), Issuer: "machine-a"}
}

func makeProtectedSegmentFixtureV3(t *testing.T, stopIdle bool, attestationQDigestMatches bool, roleUIDs ...int) protectedSegmentFixtureV3 {
	return makeProtectedSegmentWithConfigV3(t, stopIdle, attestationQDigestMatches, nil, roleUIDs...)
}

func makeProtectedSegmentWithConfigV3(t *testing.T, stopIdle bool, attestationQDigestMatches bool, cfg *qAggregateConfigV3, roleUIDs ...int) protectedSegmentFixtureV3 {
	t.Helper()
	runnerUID, bridgeUID := 310, 311
	if len(roleUIDs) == 2 {
		runnerUID, bridgeUID = roleUIDs[0], roleUIDs[1]
	} else if len(roleUIDs) != 0 {
		t.Fatal("role UID fixture requires both R and B")
	}
	q := makeQFixtureV3(t, 1, true, true, runnerUID, bridgeUID)
	installation := "fixture-install"
	soul := "agent_12345678-1234-1234-1234-1234567890ab"
	start := "st_1234567890abcdef12345678"
	launch := "ln_1234567890abcdef12345678"
	plan := "plan-20261122T120000Z-abcd"
	planDigest := "1111111111111111111111111111111111111111111111111111111111111111"
	epoch := "2222222222222222222222222222222222222222222222222222222222222222"
	session := "1234567890abcdef1234567890abcdef"
	host := "fixture-host"
	if cfg != nil {
		purpose := qOrdinaryReservationPurposeV3
		var attempt map[string]any
		if cfg.candidate {
			purpose = qCandidateReservationPurposeV3
			attempt = map[string]any{"test_plan_sha256": digest([]byte("plan")), "suite_revision": strings.Repeat("1", 40)}
		}
		q = makeQFixtureWithConfigV3(t, 1, true, true, "machine/v3", 3, purpose, attempt, cfg, runnerUID, bridgeUID)
		installation = cfg.binding["installation_id"].(string)
		soul = cfg.binding["soul_id"].(string)
		start = cfg.binding["start_id"].(string)
		launch = cfg.binding["launch_id"].(string)
		plan = cfg.binding["plan_id"].(string)
		planDigest = cfg.binding["installed_plan_digest"].(string)
		epoch = cfg.binding["hq_epoch"].(string)
		session = cfg.session
		host = cfg.binding["host_id"].(string)
	}
	const suite = "1111111111111111111111111111111111111111"
	reservationPayload, _, err := qReservationRecordV3(q.reservation, q.key)
	if err != nil {
		t.Fatal(err)
	}
	reservationFields, err := strictObject(reservationPayload, 48<<10)
	if err != nil {
		t.Fatal(err)
	}
	bindingSHA := digest(reservationFields["measurement_binding"])
	finalization := qSignFixtureV3(t, map[string]any{
		"schema":             "agent-bot-machine/stage2a-finalization/v1",
		"reservation_sha256": digest(q.reservation), "installation_id": installation,
		"start_id": start, "launch_id": launch, "plan_id": plan, "plan_digest": planDigest,
		"hq_epoch": epoch, "bridge_pid": 813, "finalized_at": "2026-11-22T11:59:55Z",
		"bind_receipt_sha256": digest([]byte("B bind")), "relay_socket": map[string]any{"path": "/tmp/relay", "socket": map[string]any{}},
	}, "agent-bot/stage2a-finalization/v1", 1, q.private)
	stop := qSignFixtureV3(t, map[string]any{
		"schema":             "agent-bot-machine/stage2a-stop/v1",
		"reservation_sha256": digest(q.reservation), "installation_id": installation,
		"start_id": start, "launch_id": launch, "plan_id": plan, "plan_digest": planDigest,
		"hq_epoch": epoch, "runner_uid": runnerUID, "bridge_uid": bridgeUID, "runner_pid": 812, "bridge_pid": 813,
		"both_uids_idle": stopIdle, "stopped_at": "2026-11-22T12:00:03Z",
	}, "agent-bot/stage2a-stop/v1", 1, q.private)
	root := t.TempDir()
	objects := map[string][]byte{
		"reservation": q.reservation, "b_finalization": finalization, "stop": stop,
		"q_wire": q.wire, "q_index": q.index, "q_eof": q.eof,
		"owner_acp_to_hq":  []byte("fixture owner ACP capture"),
		"hq_acp_to_owner":  []byte("fixture HQ ACP capture"),
		"os_observation":   []byte("fixture OS observation"),
		"installed_inputs": []byte("fixture installed inventory"),
	}
	refs := make(map[string]gateObjectRefV3, len(objects))
	for role, raw := range objects {
		refs[role] = qWriteBlobFixtureV3(t, root, role, raw)
	}
	ownerPlan := digest([]byte("owner plan"))
	manifest := physicalSegmentV3{
		SchemaVersion: 1, Kind: "stage2a-physical-segment", Gate: "T01", Profile: "managed-protected",
		HostID: host, CohortID: "fixture-cohort", SuiteRevision: suite,
		OwnerPlanSHA256: ownerPlan, SegmentID: "fixture-segment", Purpose: "initial", ReportAnchor: true,
		TerminalState: "stopped", InstallationID: installation, SoulID: soul, StartID: start, LaunchID: launch,
		MeasurementBindingSHA256: bindingSHA, QSessionStatus: "completed", QSessionID: session,
		QChallengeSHA256: digest([]byte(strings.Repeat("B", 32))), Artifacts: refs,
	}
	// The Q challenge is 32 bytes of 0x42 ('B') in the Q fixture.
	manifestRaw := qJSONFixtureV3(t, manifest)
	manifestRef := qWriteBlobFixtureV3(t, root, "segment_manifest", manifestRaw)
	qWireSHA := refs["q_wire"].SHA256
	if !attestationQDigestMatches {
		qWireSHA = digest([]byte("other wire"))
	}
	attest := physicalSegmentAttestationV3{
		SchemaVersion: 1, Kind: "stage2a-physical-segment-attestation", Gate: manifest.Gate,
		Profile: manifest.Profile, HostID: manifest.HostID, CohortID: manifest.CohortID,
		SuiteRevision: manifest.SuiteRevision, OwnerPlanSHA256: ownerPlan, SegmentID: manifest.SegmentID,
		Purpose: manifest.Purpose, ReportAnchor: true, TerminalState: "stopped",
		InstallationID: installation, SoulID: soul, StartID: start, LaunchID: launch,
		MeasurementBindingSHA256: bindingSHA, QSessionStatus: "completed", QSessionID: session,
		QChallengeSHA256: manifest.QChallengeSHA256, SegmentManifestSHA256: digest(manifestRaw),
		ReservationSHA256: refs["reservation"].SHA256, BFinalizationSHA256: refs["b_finalization"].SHA256,
		StopSHA256: refs["stop"].SHA256, QWireSHA256: qWireSHA, QIndexSHA256: refs["q_index"].SHA256,
		QEOFSHA256: refs["q_eof"].SHA256, OwnerACPToHQSha256: refs["owner_acp_to_hq"].SHA256,
		HQACPToOwnerSHA256:    refs["hq_acp_to_owner"].SHA256,
		OSObservationSHA256:   refs["os_observation"].SHA256,
		InstalledInputsSHA256: refs["installed_inputs"].SHA256, SignedAt: "2026-11-22T12:00:05Z",
	}
	attestation := qSignFixtureV3(t, attest, physicalSegmentPurposeV3, 1, q.private)
	attestationRef := qWriteBlobFixtureV3(t, root, "segment_attestation", attestation)
	gate := gateManifestV3{SchemaVersion: 1, Kind: "stage2a-physical-gate-manifest", Gate: "T01",
		Profile: "managed-protected", HostID: host, CohortID: "fixture-cohort",
		SuiteRevision: suite, OwnerPlanSHA256: ownerPlan, PrimaryMeasurementBindingSHA256: bindingSHA,
		PrimarySegmentID: "fixture-segment"}
	segment := gateSegmentV3{Sequence: 0, SegmentID: "fixture-segment", Purpose: "initial", ReportAnchor: true,
		SegmentManifest: manifestRef, SegmentAttestation: attestationRef}
	return protectedSegmentFixtureV3{root: root, gate: gate, segment: segment, key: q.key, now: q, refs: refs}
}

func TestResolveCompletedProtectedSegmentV3(t *testing.T) {
	f := makeProtectedSegmentFixtureV3(t, true, true)
	got, err := resolveProtectedSegmentV3(f.root, f.gate, f.segment, f.key, f.now.now)
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		if err == nil || got.resolved {
			t.Fatal("unsupported host accepted protected segment object resolution")
		}
		return
	}
	if err != nil || !got.resolved || got.QSessionID != "1234567890abcdef1234567890abcdef" {
		t.Fatalf("signed segment component refused: %+v %v", got, err)
	}
	reservation, err := qSignedRecordV3(f.now.reservation, qReservationPurposeV3, 2, f.key)
	if err != nil {
		t.Fatal(err)
	}
	var signed struct {
		MeasurementBinding json.RawMessage `json:"measurement_binding"`
	}
	if err := json.Unmarshal(reservation, &signed); err != nil {
		t.Fatal(err)
	}
	reportBinding, err := parseMeasurementBindingV2(signed.MeasurementBinding)
	if err != nil || !sameProtectedInstalledIdentityV3(reportBinding, got.binding) {
		t.Fatalf("resolved segment lost signed installed identity: %v", err)
	}
	for name, change := range map[string]func(*measurementBinding){
		"other installation": func(b *measurementBinding) { b.InstallationID = "other-install" },
		"other Soul":         func(b *measurementBinding) { b.SoulID = "agent_aaaaaaaa-1234-1234-1234-1234567890ab" },
		"other plan":         func(b *measurementBinding) { b.InstalledPlanDigest = strings.Repeat("a", 64) },
		"other package":      func(b *measurementBinding) { b.PackageSHA256 = strings.Repeat("b", 64) },
		"other definition":   func(b *measurementBinding) { b.DefinitionMeasurement = digest([]byte("different definition")) },
		"other launch inputs": func(b *measurementBinding) {
			b.LaunchInputMeasurement = digest([]byte("different launch inputs"))
		},
		"other launch snapshot": func(b *measurementBinding) {
			b.Snapshots.LaunchInputs.Inode = "999"
		},
	} {
		t.Run("mixed signed cohort "+name, func(t *testing.T) {
			changed := got.binding
			change(&changed)
			if sameProtectedInstalledIdentityV3(reportBinding, changed) {
				t.Fatal("supplemental segment substituted installed identity")
			}
		})
	}
	freshStart := got.binding
	freshStart.StartID = "st_aaaaaaaaaaaaaaaaaaaaaaaa"
	freshStart.LaunchID = "ln_aaaaaaaaaaaaaaaaaaaaaaaa"
	freshStart.HQEpoch = strings.Repeat("a", 64)
	if !sameProtectedInstalledIdentityV3(reportBinding, freshStart) {
		t.Fatal("fresh start and HQ epoch in same installed cohort refused")
	}
	t.Run("signed non-idle stop", func(t *testing.T) {
		bad := makeProtectedSegmentFixtureV3(t, false, true)
		if _, err := resolveProtectedSegmentV3(bad.root, bad.gate, bad.segment, bad.key, bad.now.now); err == nil {
			t.Fatal("non-idle stop accepted")
		}
	})
	t.Run("signed out-of-range runner and bridge", func(t *testing.T) {
		bad := makeProtectedSegmentFixtureV3(t, true, true, 502, 503)
		if _, err := resolveProtectedSegmentV3(bad.root, bad.gate, bad.segment, bad.key, bad.now.now); err == nil {
			t.Fatal("non-role account UIDs accepted")
		}
	})
	t.Run("signed attestation changes Q digest", func(t *testing.T) {
		bad := makeProtectedSegmentFixtureV3(t, true, false)
		if _, err := resolveProtectedSegmentV3(bad.root, bad.gate, bad.segment, bad.key, bad.now.now); err == nil {
			t.Fatal("changed Q digest accepted")
		}
	})
	t.Run("raw ACP object changed", func(t *testing.T) {
		ref := f.refs["owner_acp_to_hq"]
		name := strings.TrimPrefix(ref.SHA256, "sha256:")
		if err := os.WriteFile(filepath.Join(f.root, "objects", "sha256", name[:2], name), []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveProtectedSegmentV3(f.root, f.gate, f.segment, f.key, f.now.now); err == nil {
			t.Fatal("changed raw object accepted")
		}
	})
	t.Run("wrong A trust anchor", func(t *testing.T) {
		wrong, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fresh := makeProtectedSegmentFixtureV3(t, true, true)
		if _, err := resolveProtectedSegmentV3(fresh.root, fresh.gate, fresh.segment, wrong, fresh.now.now); err == nil {
			t.Fatal("wrong A key accepted")
		}
	})
	t.Run("missing Q EOF blob", func(t *testing.T) {
		fresh := makeProtectedSegmentFixtureV3(t, true, true)
		name := strings.TrimPrefix(fresh.refs["q_eof"].SHA256, "sha256:")
		if err := os.Remove(filepath.Join(fresh.root, "objects", "sha256", name[:2], name)); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveProtectedSegmentV3(fresh.root, fresh.gate, fresh.segment, fresh.key, fresh.now.now); err == nil {
			t.Fatal("missing Q EOF accepted")
		}
	})
}

func TestResolveConfiguredV3Segment(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure object resolver unavailable")
	}
	raw, err := os.ReadFile("testdata/stage2a-hr-binding-v3-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(raw, &binding); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", ed25519.SeedSize)))
	cfg := &qAggregateConfigV3{private: key, binding: binding, session: "1234567890abcdef1234567890abcdef"}
	f := makeProtectedSegmentWithConfigV3(t, true, true, cfg, 331, 332)
	if _, err := resolveProtectedSegmentV3(f.root, f.gate, f.segment, f.key, f.now.now); err != nil {
		t.Fatalf("configured v3 segment: %v", err)
	}
}

func TestProtectedSegmentV3ReservationWireContracts(t *testing.T) {
	ordinary, err := os.ReadFile("testdata/stage2a-hr-binding-v3-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, purpose, kind string
		binding             []byte
	}{
		{"ordinary", qOrdinaryReservationPurposeV3, "stage2a-reservation", ordinary},
		{"candidate", qCandidateReservationPurposeV3, "stage2a-qualification-candidate-reservation", candidateContractBindingV3(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var parsed struct {
				measurementBinding
				HDescriptorDigest string           `json:"h_service_descriptor_digest"`
				RInventory        hrInventoryRefV3 `json:"r_inventory"`
			}
			if err := json.Unmarshal(tc.binding, &parsed); err != nil {
				t.Fatal(err)
			}
			b := parsed.measurementBinding
			reservationBinding := json.RawMessage(tc.binding)
			bindingSHA := digest(qJSONFixtureV3(t, reservationBinding))
			challenge := digest([]byte("launch challenge"))
			assignment := map[string]any{
				"installation_id": b.InstallationID, "soul_id": b.SoulID, "start_id": b.StartID,
				"launch_id": b.LaunchID, "plan_id": b.PlanID, "plan_digest": b.InstalledPlanDigest,
				"hq_epoch": b.HQEpoch, "runner_uid": parsed.RInventory.ReaderUID, "bridge_uid": 311,
				"h_service_descriptor_digest": parsed.HDescriptorDigest, "r_inventory_digest": parsed.RInventory.InventoryDigest,
			}
			payload := map[string]any{
				"contract": "machine/v3", "kind": tc.kind, "schema_version": 3,
				"admission_challenge_sha256": challenge, "host_id": b.HostID,
				"assignment": assignment, "measurement_binding": reservationBinding,
				"issued_at": "2026-11-22T11:59:50Z", "expires_at": "2026-11-22T12:00:20Z",
			}
			if tc.name == "candidate" {
				payload["qualification_attempt"] = map[string]any{"test_plan_sha256": digest([]byte("plan"))}
			}
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			reservation := qSignFixtureV3(t, payload, tc.purpose, 3, priv)
			selectors := map[string]any{
				"reservation_sha256": digest(reservation), "installation_id": b.InstallationID,
				"start_id": b.StartID, "launch_id": b.LaunchID, "plan_id": b.PlanID,
				"plan_digest": b.InstalledPlanDigest, "hq_epoch": b.HQEpoch, "bridge_pid": 813,
			}
			selectors["schema"] = "agent-bot-machine/stage2a-finalization/v1"
			selectors["finalized_at"] = "2026-11-22T11:59:55Z"
			selectors["bind_receipt_sha256"] = digest([]byte("B bind"))
			selectors["relay_socket"] = map[string]any{"path": "/tmp/relay", "socket": map[string]any{}}
			finalization := qSignFixtureV3(t, selectors, "agent-bot/stage2a-finalization/v1", 1, priv)

			delete(selectors, "finalized_at")
			delete(selectors, "bind_receipt_sha256")
			delete(selectors, "relay_socket")
			selectors["schema"] = "agent-bot-machine/stage2a-stop/v1"
			selectors["stopped_at"] = "2026-11-22T12:00:03Z"
			selectors["both_uids_idle"] = true
			selectors["runner_uid"], selectors["bridge_uid"], selectors["runner_pid"] = parsed.RInventory.ReaderUID, 311, 812
			selectors["child_launcher_pid"], selectors["child_pid"] = 814, 815
			selectors["child_receipt_sha256"] = digest([]byte("child receipt"))
			stop := qSignFixtureV3(t, selectors, "agent-bot/stage2a-stop/v1", 1, priv)
			segment := physicalSegmentV3{
				Profile: b.ProfileInForce, HostID: b.HostID, InstallationID: b.InstallationID,
				SoulID: b.SoulID, StartID: b.StartID, LaunchID: b.LaunchID,
				MeasurementBindingSHA256: bindingSHA, QChallengeSHA256: digest([]byte("Q challenge")),
			}
			got, err := verifyProtectedAChainV3(reservation, finalization, stop, segment, pub)
			if err != nil || got.binding.Contract != "machine/v3" || got.reservationSHA256 != digest(reservation) {
				t.Fatalf("signed v3 chain refused: %+v %v", got, err)
			}
			delete(selectors, "child_receipt_sha256")
			partialStop := qSignFixtureV3(t, selectors, "agent-bot/stage2a-stop/v1", 1, priv)
			if _, err := verifyProtectedAChainV3(reservation, finalization, partialStop, segment, pub); err == nil {
				t.Fatal("accepted partial child linkage")
			}
			segment.MeasurementBindingSHA256 = digest([]byte("other binding"))
			if _, err := verifyProtectedAChainV3(reservation, finalization, stop, segment, pub); err == nil {
				t.Fatal("accepted mismatched raw v3 binding")
			}
		})
	}
}
