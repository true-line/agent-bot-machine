package members

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestStage2aHQManifestMatchesAllAndOnlyReviewedRows(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	helper := hqStage2aManifestRow{Path: hqStage2aHelper, SHA256: digest}
	entry := hqStage2aManifestRow{Path: hqStage2aEntry, SHA256: digest}
	selected := map[string]string{helper.Path: helper.SHA256, entry.Path: entry.SHA256}
	for _, test := range []struct {
		name string
		rows []hqStage2aManifestRow
		pass bool
	}{
		{"exact", []hqStage2aManifestRow{helper, entry}, true},
		{"missing helper", []hqStage2aManifestRow{entry}, false},
		{"duplicate helper", []hqStage2aManifestRow{helper, helper}, false},
		{"unselected helper", []hqStage2aManifestRow{{Path: "helper.rb", SHA256: digest}, entry}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.rows)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
			if err := checkHQStage2aManifestRows(raw, want, selected); (err == nil) != test.pass {
				t.Fatalf("received %v", err)
			}
		})
	}
}

func TestStage2aHQApprovalBindsReleaseManifestAndLimits(t *testing.T) {
	service, _ := stage2aHQTestService(t)
	owner := "owner"
	launch, err := service.Stage2a.launch(owner, service.Stage2a.AuthorityKeySHA256)
	if err != nil {
		t.Fatal(err)
	}
	launch.LauncherSHA256 = service.Stage2a.AuthorityKeySHA256
	rec := launchRecord{Service: service, Stage2a: launch,
		Plist: renderHQStage2aPlist(renderLaunchPlist(service, 501, owner, launchControlV2), launch.OuterArgv), OwnerUID: 501}
	id, previousID := "plan-20261122T141517Z-abcd", "plan-20261122T141516Z-abcd"
	previous := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir}
	prior, err := previous.Digest()
	if err != nil {
		t.Fatal(err)
	}
	step, err := json.Marshal(launchUpgrade{PreviousID: previousID, PreviousDigest: prior, Next: rec})
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir, Steps: []Step{
		{Kind: KindHQAccount}, {Kind: KindService, Action: upgradeAction, Target: launchLabel, Owner: owner, Content: string(step)},
	}}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	saved := Saved{PlanID: id, PlanDigest: digest, HQService: &service, UpgradeFrom: &priorServicePlan{ID: previousID, Plan: previous}, Plan: plan}
	a := Approval{PlanID: id, PlanDigest: digest, Purpose: UpgradePurpose}
	if err := checkHQStage2aApprovedRecord(saved, rec, a, owner); err != nil {
		t.Fatal(err)
	}
	request := hqStage2aWorkerRequest{Action: hqStage2aWorkerReview, Saved: saved, Approval: a, Owner: owner}
	if _, err := request.record(); err != nil {
		t.Fatalf("offline worker rejected the exact approved record: %v", err)
	}
	originalR := service.Stage2a.RuntimeInstallationID
	service.Stage2a.RuntimeInstallationID = "different-runtime"
	if _, err := request.record(); err == nil {
		t.Fatal("offline worker accepted an unapproved R selector")
	}
	service.Stage2a.RuntimeInstallationID = originalR
	service.Stage2a.InventoryLimits.MaxFileBytes++
	if err := checkHQStage2aApprovedRecord(saved, rec, a, owner); err == nil {
		t.Fatal("changed signed numeric limits were accepted")
	}
	service.Stage2a.InventoryLimits.MaxFileBytes--
	service.Stage2a.Components[0].ManifestSHA256 = "sha256:" + strings.Repeat("2", 64)
	if err := checkHQStage2aApprovedRecord(saved, rec, a, owner); err == nil {
		t.Fatal("changed signed release manifest was accepted")
	}
}

func TestStage2aHQDescriptorPublicationIsExclusiveAndWithdrawsExactWitness(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	metadata, err := dir.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat := metadata.Sys().(*syscall.Stat_t)
	first := []byte(`{"fixture":1}`)
	witness, err := publishHQStage2aDescriptorAt(dir, stat.Uid, stat.Gid, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishHQStage2aDescriptorAt(dir, stat.Uid, stat.Gid, []byte(`{"fixture":2}`)); err == nil {
		t.Fatal("publication replaced an occupied descriptor")
	}
	stale := witness
	stale.SHA256 = "sha256:" + strings.Repeat("0", 64)
	if err := withdrawHQStage2aDescriptorAt(dir, stale); err == nil {
		t.Fatal("withdrawal accepted a changed witness")
	}
	if current, err := os.ReadFile(witness.Path); err != nil || string(current) != string(first) {
		t.Fatalf("changed witness removed the accepted publication: %q, %v", current, err)
	}
	if err := withdrawHQStage2aDescriptorAt(dir, witness); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(witness.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("accepted witness survived withdrawal: %v", err)
	}
}

func TestStage2aHQAppliedReceiptReentryUsesDurableWitnesses(t *testing.T) {
	service, _ := stage2aHQTestService(t)
	next := launchRecord{Service: service, Stage2a: &hqStage2aLaunch{}}
	namespace, snapshot, sidecar, err := stage2aDomainNamesV3("R-runtime", service.Stage2a.RuntimeInstallationID)
	if err != nil {
		t.Fatal(err)
	}
	runtime := stage2aDomainInventoryRefV3{Domain: "R-runtime", InstallationID: service.Stage2a.RuntimeInstallationID, MachineUID: uint32(service.Stage2a.MachineUID),
		ReaderUID: 331, ReaderGID: 331, Snapshot: stage2aDomainNodeRefV3{Path: filepath.Join(namespace, snapshot)},
		Sidecar: stage2aDomainSidecarRefV3{stage2aDomainNodeRefV3: stage2aDomainNodeRefV3{Path: filepath.Join(namespace, sidecar)}}}
	witness := &hqStage2aJournalDescriptor{Descriptor: &stage2aDomainSidecarRefV3{stage2aDomainNodeRefV3: stage2aDomainNodeRefV3{Path: hqStage2aDescriptor}}, Runtime: &runtime}
	approved := Approval{PlanID: "plan-20261122T141517Z-abcd", Purpose: UpgradePurpose}
	pair := func(a Approval, work func() error) error {
		if a != approved {
			t.Fatal("wrong approval")
		}
		if work != nil {
			return work()
		}
		return nil
	}
	initial := upgradeJournal{Approval: approved, pair: pair, Upgrade: launchUpgrade{Next: next}, ProtectedDescriptor: witness,
		protectedPublication: &hqStage2aPublication{recheck: func() error { t.Fatal("unexpected live verification after reentry"); return nil }}}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := initial.commitReceipt(path, Receipt{Result: "started"}, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt Receipt
	if err := json.Unmarshal(persisted, &receipt); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	resumed := upgradeJournal{pair: pair}
	if err := json.Unmarshal(raw, &resumed); err != nil {
		t.Fatal(err)
	}
	checked := false
	if err := resumed.checkProtectedHQCandidate(next, func(r launchRecord, a Approval, saved *hqStage2aJournalDescriptor) error {
		checked = true
		if a != approved || !reflect.DeepEqual(r, next) || !reflect.DeepEqual(saved, witness) {
			t.Fatal("changed durable witness")
		}
		return nil
	}); err != nil || !checked {
		t.Fatalf("recheck did not use durable state: %v", err)
	}
	if err := resumed.commitReceipt(path, receipt, true); err != nil {
		t.Fatal(err)
	}
	resumed.ProtectedDescriptor.Runtime.ReaderGID++
	if err := resumed.commitReceipt(path, receipt, true); err == nil {
		t.Fatal("accepted a different recovered R witness")
	}
}

func TestStage2aHQManifestPartitionsOnlyReviewedSyntheticFixtures(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	schema := "vendor/soul-contracts/schemas/machine/v3/stage2a-qualification-candidate-binding.schema.json"
	fixtures := hqStage2aContractsFixturePaths[:]
	selected := map[string]string{schema: digest, hqStage2aHelper: digest}
	rows := []hqStage2aManifestRow{{Path: schema, SHA256: digest}, {Path: hqStage2aHelper, SHA256: digest}}
	for _, path := range fixtures {
		rows = append(rows, hqStage2aManifestRow{Path: path, SHA256: digest})
	}
	check := func(rows []hqStage2aManifestRow, selected map[string]string, excluded []string) ([]hqStage2aManifestRow, error) {
		t.Helper()
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		return checkHQStage2aManifestPartition(raw, fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), selected, excluded)
	}
	omitted, err := check(rows, selected, fixtures)
	if err != nil || len(omitted) != len(fixtures) {
		t.Fatalf("exact fixture partition: %v", err)
	}
	if _, err := check(rows, selected, nil); err == nil {
		t.Fatal("implicitly dropped fixture rows")
	}
	if _, err := check(rows, selected, fixtures[:len(fixtures)-1]); err == nil {
		t.Fatal("accepted incomplete approved fixture set")
	}
	tampered := append([]hqStage2aManifestRow(nil), rows...)
	tampered[len(tampered)-1].Path = "vendor/soul-contracts/fixtures/unreviewed.json"
	if _, err := check(tampered, selected, fixtures); err == nil {
		t.Fatal("accepted a different omitted row under a matching manifest digest")
	}
	missingSchema := map[string]string{hqStage2aHelper: digest}
	if _, err := check(rows[1:], missingSchema, append([]string{schema}, fixtures[1:]...)); err == nil {
		t.Fatal("accepted runtime schema exclusion")
	}
	selected[fixtures[0]] = digest
	if _, err := check(rows, selected, fixtures); err == nil {
		t.Fatal("accepted a synthetic fixture in the sealed inventory")
	}
}

func TestStage2aHQFullArchiveRetainsEightFixturesOutsideSealedLimit(t *testing.T) {
	const retainedRuntimeRows = 509
	root := t.TempDir()
	contents := []byte("synthetic release row")
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	full := make(map[string]installedHQEntry)
	var manifest []hqStage2aManifestRow
	add := func(name string) {
		t.Helper()
		source := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(source), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, contents, 0644); err != nil {
			t.Fatal(err)
		}
		tarPath := "hq/" + name
		if err := writer.WriteHeader(&tar.Header{Name: tarPath, Mode: 0644, Size: int64(len(contents)),
			Format: tar.FormatUSTAR, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(contents); err != nil {
			t.Fatal(err)
		}
		manifest = append(manifest, hqStage2aManifestRow{Path: name, SHA256: digest})
		full[tarPath] = installedHQEntry{Entry: Entry{Regular: true, Mode: 0644}, path: source}
	}
	selected := make(map[string]string, retainedRuntimeRows)
	for i := 0; i < retainedRuntimeRows; i++ {
		path := fmt.Sprintf("runtime/file-%03d.mjs", i)
		add(path)
		selected[path] = digest
	}
	omitted := hqStage2aContractsFixturePaths[:]
	for _, path := range omitted {
		add(path)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if len(full)+1 != 518 || len(selected)+1 != 510 {
		t.Fatal("counts must include separately pinned Node")
	}
	if err := matchDarwinArchive(bytes.NewReader(archive.Bytes()), full); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := checkHQStage2aManifestPartition(raw, fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), selected, omitted); err != nil || len(rows) != 8 {
		t.Fatalf("full archive manifest did not prove selected H and excluded fixtures: %v", err)
	}
}
