package members

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const hqStage2aWorkerReview = "review"
const hqStage2aWorkerPublish = "publish"
const hqStage2aWorkerRecheck = "recheck"

type hqStage2aWorkerRequest struct {
	Action      string                       `json:"action"`
	Saved       Saved                        `json:"saved"`
	Approval    Approval                     `json:"approval"`
	Owner       string                       `json:"owner"`
	H           *stage2aDomainInventoryRefV3 `json:"h_inventory,omitempty"`
	Publication *hqStage2aSignedPublication  `json:"publication,omitempty"`
}

type hqStage2aWorkerReply struct {
	Runtime     stage2aDomainInventoryRefV3 `json:"runtime"`
	Publication *hqStage2aSignedPublication `json:"publication,omitempty"`
}

func (q hqStage2aWorkerRequest) record() (launchRecord, error) {
	var transition launchUpgrade
	if len(q.Saved.Plan.Steps) != 2 || !accountName.MatchString(q.Owner) ||
		stage2aDecodeExact([]byte(q.Saved.Plan.Steps[1].Content), &transition) != nil || transition.Next.Service.Stage2a == nil ||
		transition.Next.Stage2a == nil || transition.Next.Service.validate() != nil ||
		checkHQStage2aApprovedRecord(q.Saved, transition.Next, q.Approval, q.Owner) != nil ||
		!matchesReviewedHQPlist(transition.Next, q.Owner, launchControlV2) {
		return launchRecord{}, errStage2aReservationAuthority
	}
	return transition.Next, nil
}

// RunStage2aHQEvidence runs only in the fixed network-denied A subprocess.
// The daemon's enrolled key is opened locally after authenticating the worker
// executable and its Unix role. The reply holds only public witnesses.
func RunStage2aHQEvidence(loadKey func(string, string, func(string) error) (ed25519.PrivateKey, string, error),
	checkPair func(string, string, string, func() error) error) int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (512<<10)+1))
	var q hqStage2aWorkerRequest
	if err != nil || stage2aStrictJSONBounded(raw, 512<<10, 16384) != nil || stage2aDecodeExact(raw, &q) != nil ||
		loadKey == nil || checkPair == nil {
		return harnessRefused
	}
	rec, err := q.record()
	if err != nil || !hqStage2aIsOfflineAdmin(*rec.Service.Stage2a) {
		return harnessRefused
	}
	me, err := os.Executable()
	if err != nil || me != SoulLauncher {
		return harnessRefused
	}
	binary, err := managerBytes()
	if err != nil || "sha256:"+harnessSHA(binary) != rec.Stage2a.LauncherSHA256 {
		return harnessRefused
	}
	s := rec.Service.Stage2a
	switch q.Action {
	case hqStage2aWorkerReview, hqStage2aWorkerPublish, hqStage2aWorkerRecheck:
	default:
		return harnessRefused
	}
	key, dir, err := loadKey(s.MachineAccount, q.Approval.MachineFingerprint, func(dir string) error {
		pair := func(a Approval, run func() error) error {
			return checkPair(dir, s.MachineAccount, a.PairCommitment, run)
		}
		return checkHQStage2aStoredApproval(*s, q.Approval, dir, q.Owner, pair, q.Action != hqStage2aWorkerReview)
	})
	defer clear(key)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return harnessRefused
	}
	pair := func(a Approval, run func() error) error {
		return checkPair(dir, s.MachineAccount, a.PairCommitment, run)
	}
	var reply hqStage2aWorkerReply
	if err := pair(q.Approval, func() error {
		var err error
		reply, err = runStage2aHQEvidence(q, rec, key, dir, pair)
		return err
	}); err != nil || json.NewEncoder(os.Stdout).Encode(reply) != nil {
		return harnessRefused
	}
	return 0
}

func runStage2aHQEvidence(q hqStage2aWorkerRequest, rec launchRecord, key ed25519.PrivateKey, dir string,
	pair upgradePairGuard) (hqStage2aWorkerReply, error) {
	var empty hqStage2aWorkerReply
	s := rec.Service.Stage2a
	if s == nil || s.CooperativeOnly {
		return empty, errStage2aReservationAuthority
	}
	pub := key.Public().(ed25519.PublicKey)
	if err := checkHQStage2aPairedApproval(q.Saved, rec, q.Approval, pub, dir, q.Owner, pair, q.Action != hqStage2aWorkerReview); err != nil {
		return empty, err
	}
	r, err := loadStage2aHQInstalledRuntime(pub, *s)
	if err != nil || !hqStage2aRuntimeMatches(rec, r.ref) {
		return empty, errStage2aReservationAuthority
	}
	reply := hqStage2aWorkerReply{Runtime: r.ref}
	switch q.Action {
	case hqStage2aWorkerReview:
		if q.H != nil || q.Publication != nil {
			return empty, errStage2aReservationAuthority
		}
		raw, err := stage2aReadRootFile(s.InventorySource, 2<<20, 0444, 0644)
		if err != nil {
			return empty, err
		}
		inv, err := verifyHQStage2aReleaseRows(rec.Service, raw)
		if err != nil {
			return empty, err
		}
		if err := checkHQStage2aApprovedReleaseSources(rec.Service, inv); err != nil {
			return empty, err
		}
	case hqStage2aWorkerPublish:
		if q.H == nil || q.Publication != nil {
			return empty, errStage2aReservationAuthority
		}
		evidence := hqStage2aSigningAuthority{saved: q.Saved, daemonDir: dir, owner: q.Owner, pair: pair,
			verifyRuntime: func(_ launchRecord, verified stage2aVerifiedDomainRefV3) error {
				if !verified.verified || verified.ref != r.ref {
					return errStage2aReservationAuthority
				}
				return stage2aRecheckVerifiedDomainV3(verified)
			}}
		publication, err := NewStage2aService(key).signAndPublishHQStage2a(rec, q.Approval, *q.H, r, evidence)
		if err != nil {
			return empty, err
		}
		reply.Publication = &publication
	case hqStage2aWorkerRecheck:
		if q.H == nil || q.Publication == nil || q.Publication.Runtime != r.ref || !stage2aPrefixedDigest.MatchString(q.Publication.DescriptorDigest) {
			return empty, errStage2aReservationAuthority
		}
		witness, h, digest, err := recoverHQStage2aDescriptorWitness(rec, q.Approval)
		if err != nil || witness != q.Publication.Descriptor || digest != q.Publication.DescriptorDigest || h != *q.H || recheckHQStage2aDomainFiles(h) != nil {
			return empty, errStage2aReservationAuthority
		}
	default:
		return empty, errStage2aReservationAuthority
	}
	return reply, nil
}

func callHQStage2aWorker(q hqStage2aWorkerRequest, rec launchRecord) (hqStage2aWorkerReply, error) {
	var empty hqStage2aWorkerReply
	s := rec.Service.Stage2a
	if os.Getuid() != 0 || os.Geteuid() != 0 || s == nil || rec.Stage2a == nil || trustedPath(OSHost{}, SoulLauncher, false) != nil ||
		checkDarwinACLs(pathAncestry(SoulLauncher)) != nil {
		return empty, errStage2aReservationAuthority
	}
	raw, err := json.Marshal(q)
	if err != nil || len(raw) > 512<<10 {
		return empty, errStage2aReservationAuthority
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sandbox-exec", "-p", stage2aInstallSealProfile, SoulLauncher, "stage2a-h-evidence")
	cmd.Dir, cmd.Env, cmd.Stdin = "/", []string{"PATH=/usr/bin:/bin"}, bytes.NewReader(raw)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(s.MachineUID), Gid: uint32(s.MachineGID), Groups: []uint32{}}}
	out, err := cmd.Output()
	if err != nil || len(out) > 16<<10 || stage2aStrictJSON(out) != nil {
		return empty, errors.New("offline A worker refused the paired HQ evidence")
	}
	var reply hqStage2aWorkerReply
	if stage2aDecodeExact(out, &reply) != nil || !hqStage2aRuntimeMatches(rec, reply.Runtime) {
		return empty, errStage2aReservationAuthority
	}
	return reply, nil
}

func prepareHQStage2aApply(saved Saved, a Approval, owner, machineAccount string, pair upgradePairGuard) (func(Step) error, error) {
	q := hqStage2aWorkerRequest{Saved: saved, Approval: a, Owner: owner, Action: hqStage2aWorkerReview}
	rec, err := q.record()
	if err != nil || pair == nil || rec.Service.Stage2a.CooperativeOnly || rec.Service.Stage2a.MachineAccount != machineAccount {
		return nil, errors.New(hqStage2aCutoverRefusal)
	}
	if err := pair(a, nil); err != nil {
		return nil, err
	}
	reviewed, err := callHQStage2aWorker(q, rec)
	if err != nil || reviewed.Publication != nil {
		return nil, errors.New(hqStage2aCutoverRefusal)
	}
	evidence := &hqStage2aUpgradeEvidence{
		review: func(r launchRecord, current Approval) error {
			if checkHQStage2aApprovedRecord(saved, r, current, owner) != nil || current != a {
				return errStage2aReservationAuthority
			}
			reply, err := callHQStage2aWorker(q, rec)
			if err != nil || reply.Runtime != reviewed.Runtime || reply.Publication != nil {
				return errStage2aReservationAuthority
			}
			return nil
		},
		publish: func(r launchRecord, current Approval, h stage2aDomainInventoryRefV3) (*hqStage2aPublication, error) {
			if current != a || checkHQStage2aApprovedRecord(saved, r, current, owner) != nil {
				return nil, errStage2aReservationAuthority
			}
			publish := q
			publish.Action, publish.H = hqStage2aWorkerPublish, &h
			reply, err := callHQStage2aWorker(publish, rec)
			if err != nil || reply.Publication == nil || reply.Runtime != reviewed.Runtime || reply.Publication.Runtime != reviewed.Runtime {
				return nil, errStage2aReservationAuthority
			}
			return &hqStage2aPublication{witness: reply.Publication.Descriptor, runtime: reply.Runtime, recheck: func() error {
				check := publish
				check.Action, check.Publication = hqStage2aWorkerRecheck, reply.Publication
				verified, err := callHQStage2aWorker(check, rec)
				if err != nil || verified.Runtime != reply.Runtime || verified.Publication != nil {
					return errStage2aReservationAuthority
				}
				return nil
			}}, nil
		},
	}
	return func(step Step) error { return activateUpgradeWithEvidence(step, a, pair, evidence) }, nil
}
