//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Stage2aReserveReply struct {
	EnvelopeBase64URL string `json:"envelope_base64url"`
	SHA256            string `json:"sha256"`
}

type Stage2aService struct {
	mu                sync.Mutex
	key               ed25519.PrivateKey
	active            map[string]*stage2aLiveReservation
	cooperativeActive map[string]*soulCooperativeLiveV3
	candidateGrantsV3 stage2aCandidateGrantRegistryV3
	reserveV3         func(int, string, Stage2aReserveRequest, *stage2aSignedCandidateGrantV3) (stage2aReservation, stage2aReservationWorkerReplyV3, error)
}

type stage2aLiveReservation struct {
	digest, policyDigest string
	envelope             []byte
	request              SoulRunRequest
	payload              stage2aReservationPayload
	payloadV3            []byte
	runModeV3            stage2aReservationRunModeV3
	runtimeRefV3         stage2aDomainInventoryRefV3
	proofDigest          string
	bridgeProof          [32]byte
	bridgeAssignment     []byte
	finalizationEnvelope []byte
	bindReceiptSHA256    string
	runnerPID, bridgePID int
	childLauncherPID     int
	runnerProcess        soulKernelProcessSnapshot
	bridgeProcess        soulKernelProcessSnapshot
	childLauncherProcess soulKernelProcessSnapshot
	childGrantSHA256     string
	childGrantExpiresAt  time.Time
	childPID             int
	childProcess         soulKernelProcessSnapshot
	childReceiptEnvelope []byte
	liveSequence         uint64
	hello                *stage2aHelloState
}

func NewStage2aService(key ed25519.PrivateKey) *Stage2aService {
	return &Stage2aService{key: key, active: make(map[string]*stage2aLiveReservation), candidateGrantsV3: make(stage2aCandidateGrantRegistryV3),
		cooperativeActive: make(map[string]*soulCooperativeLiveV3)}
}

func (s *Stage2aService) sign(preimage []byte) ([]byte, error) {
	if len(s.key) != ed25519.PrivateKeySize {
		return nil, errStage2aReservationAuthority
	}
	return ed25519.Sign(s.key, preimage), nil
}

func stage2aActiveClaimName(installationID string) string {
	return ".stage2a-active-" + soulEndpointInstallationSlot(installationID)
}

// Lookup is read-only. The owner supplies an already installed package path;
// Machine never opens it. Only a unique, independently validated A-owned
// policy can turn that path into selectors for a later signed reservation.
func (s *Stage2aService) Lookup(hqUID int, epoch string, q Stage2aLookupRequest) (Stage2aLookupReply, error) {
	var reply Stage2aLookupReply
	if len(s.key) != ed25519.PrivateKeySize || !stage2aLookupPath(q.PackagePath) ||
		!soulHQEpoch.MatchString(epoch) {
		return reply, errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(stage2aAuthorityDirectory, uint32(os.Getuid()))
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	defer dir.Close()
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 ||
		st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) {
		return reply, errStage2aReservationAuthority
	}
	names, err := dir.Readdirnames(129)
	if err != nil && err != io.EOF || len(names) == 0 || len(names) > 128 {
		return reply, errStage2aReservationAuthority
	}
	for _, name := range names {
		if len(name) != 25 || !strings.HasSuffix(name, ".json") {
			return Stage2aLookupReply{}, errStage2aReservationAuthority
		}
		path := filepath.Join(stage2aAuthorityDirectory, name)
		raw, err := stage2aReadAdminPolicy(path, 1<<20)
		if err != nil || stage2aStrictJSON(raw) != nil {
			return Stage2aLookupReply{}, errStage2aReservationAuthority
		}
		var index struct {
			Binding Stage2aMeasurementBinding `json:"measurement_binding"`
			Runner  SoulRunner                `json:"runner"`
		}
		if json.Unmarshal(raw, &index) != nil {
			return Stage2aLookupReply{}, errStage2aReservationAuthority
		}
		expected, err := stage2aAuthorityPath(index.Binding.InstallationID)
		if err != nil || expected != path {
			return Stage2aLookupReply{}, errStage2aReservationAuthority
		}
		if index.Runner.PackageRoot != q.PackagePath {
			continue
		}
		runtime, err := stage2aLoadInstalledRuntimeV3(s.key.Public().(ed25519.PublicKey), hqUID, epoch, index.Binding.InstallationID)
		p := runtime.Policy
		if err != nil || !bytes.Equal(raw, runtime.PolicyRaw) || p.Runner.PackageRoot != q.PackagePath || reply.InstallationID != "" {
			return Stage2aLookupReply{}, errStage2aReservationAuthority
		}
		reply = Stage2aLookupReply{
			InstallationID: p.Binding.InstallationID, PlanID: p.Binding.PlanID,
			PlanDigest:    p.Binding.InstalledPlanDigest,
			RunnerAccount: p.Runner.Account, BridgeAccount: p.Bridge.Account,
		}
	}
	if reply.InstallationID == "" {
		return reply, errStage2aReservationAuthority
	}
	return reply, nil
}

func (s *Stage2aService) Reserve(hqUID int, epoch string, request Stage2aReserveRequest) (Stage2aReserveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aReserveReply
	if len(s.key) != ed25519.PrivateKeySize || s.reserveV3 == nil || epoch != request.HQEpoch || len(s.active) >= 128 {
		return reply, errStage2aReservationAuthority
	}
	// The only positive route supplies authority from the fixed offline A
	// worker. Its expected payload comes from installed evidence, not HQ.
	grant, err := s.candidateGrantsV3.consume(hqUID, request, s.key, time.Now())
	if err != nil {
		return reply, err
	}
	got, result, err := s.reserveV3(hqUID, epoch, request, grant)
	if err != nil || (result.Mode == stage2aCandidateRunV3) != (grant != nil) || !stage2aPrefixedDigest.MatchString(result.PolicyDigest) {
		return reply, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	guard, err := verifyStage2aReservationModeV3(result.Mode, got.envelope, got.sha256, result.Expected, key, time.Now())
	a := guard.assignment
	if err != nil || a.HQUID != hqUID || a.HQEpoch != epoch || a.InstallationID != request.InstallationID ||
		a.StartID != request.StartID || a.LaunchID != request.LaunchID || a.PlanDigest != request.PlanDigest {
		return reply, errStage2aReservationAuthority
	}
	// Role plumbing still uses a legacy field projection. The guard authenticates
	// the full v3 reservation and mode before any role can execute.
	payload := guard.payload
	payload.Assignment = a.stage2aReservationAssignment
	payload.Assignment.Schema = "agent-bot-machine/soul-start-assignment/v2"
	payload.MeasurementBinding = guard.binding
	payload.MeasurementBinding.Contract, payload.MeasurementBinding.SchemaVersion = "machine/v2", 2
	req := SoulRunRequest{PlanDigest: request.PlanDigest, InstallationID: request.InstallationID, StartID: request.StartID, HQEpoch: request.HQEpoch}
	var proof [32]byte
	defer clear(proof[:])
	if _, err := rand.Read(proof[:]); err != nil ||
		publishStage2aBridgeProof(payload.Assignment.SoulStartAssignment, proof[:]) != nil {
		return reply, errStage2aReservationAuthority
	}
	s.active[got.sha256] = &stage2aLiveReservation{
		digest: got.sha256, policyDigest: result.PolicyDigest, envelope: got.envelope,
		payload: payload, payloadV3: result.Expected, runModeV3: result.Mode, runtimeRefV3: guard.r, request: req, proofDigest: stage2aReservationSHA256(proof[:]), bridgeProof: proof,
	}
	return Stage2aReserveReply{EnvelopeBase64URL: stage2aEncodeEnvelope(got.envelope), SHA256: got.sha256}, nil
}

// Exec grants one fixed role process a single signed invocation. The role's
// private nonce and live kernel identity are checked before the durable claim
// is spent; a restart cannot reissue a grant for the same reserved start.
func (s *Stage2aService) Exec(hqUID int, epoch, digest, role, nonce string, pid int) (Stage2aExecReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aExecReply
	if (role != "runner" && role != "bridge" && role != "child") || !validStage2aExecDigest(digest) || pid <= 1 {
		return reply, errStage2aReservationAuthority
	}
	nonceBytes, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(nonceBytes) != 32 || base64.RawURLEncoding.EncodeToString(nonceBytes) != nonce {
		return reply, errStage2aReservationAuthority
	}
	if role == "child" {
		return s.execChild(hqUID, epoch, digest, nonce, pid)
	}
	r, p, expires, err := s.current(hqUID, epoch, digest)
	if err != nil || r.digest != stage2aReservationSHA256(r.envelope) ||
		r.payload.Assignment.LaunchID == "" || r.payload.Assignment.InstallationID != p.Binding.InstallationID {
		return reply, errStage2aReservationAuthority
	}
	roleUID, roleGID := p.Runner.UID, p.Runner.GID
	if role == "bridge" {
		if len(r.bridgeAssignment) == 0 || r.proofDigest != stage2aReservationSHA256(r.bridgeProof[:]) ||
			p.BridgeExecutable.Path != SoulBridgeBinary || verifyHarnessExecutable(SoulBridgeBinary, p.BridgeExecutable.SHA256) != nil {
			return reply, errStage2aReservationAuthority
		}
		roleUID, roleGID = p.Bridge.UID, p.Bridge.GID
	}
	roleProcess, err := observeStage2aRoleProcess(pid, roleUID, roleGID, role)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	store, snapshots := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, r.request.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	if err := store.checkDirectory(dir); err != nil || snapshots.check() != nil || p.verifyRunnerGroup() != nil {
		return reply, errStage2aReservationAuthority
	}
	definition, err := observeStage2aAdminSnapshot(snapshots, filepath.Base(p.Binding.Snapshots.Definition.RootPath),
		p.Binding.Snapshots.Definition, p.Definition)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	if definition != r.payload.MeasurementBinding.DefinitionMeasurement {
		return reply, errStage2aReservationAuthority
	}
	if err := observeInstalledStage2aLaunchInputs(snapshots, p.Binding, p.LaunchInputs); err != nil {
		return reply, err
	}
	nextProcess, err := observeStage2aRoleProcess(pid, roleUID, roleGID, role)
	if !time.Now().Before(expires) || err != nil || !sameSoulKernelProcess(roleProcess, nextProcess) {
		return reply, errStage2aReservationExpired
	}
	invocation := Stage2aRoleInvocation{
		Request: r.request, Start: r.payload.Assignment.SoulStartAssignment,
		Runner: p.Runner, Bridge: p.Bridge, Binding: r.payload.MeasurementBinding,
		Launch: p.LaunchInputs,
	}
	if role == "runner" {
		invocation.RunnerExec = &Stage2aRunnerExec{
			Definition: p.Definition, Node: p.Node, Entry: p.Entry,
			ReservationEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(r.envelope),
			ReservationSHA256:            r.digest,
			ReservationV3:                r.payloadV3,
			ReservationRunModeV3:         string(r.runModeV3),
		}
	} else {
		invocation.BridgeExec = &Stage2aBridgeExec{
			Executable:          p.BridgeExecutable,
			AssignmentBase64URL: base64.RawURLEncoding.EncodeToString(r.bridgeAssignment),
			ProofSHA256:         r.proofDigest,
		}
	}
	invocationRaw, err := marshalStage2aReservationJCS(invocation)
	if err != nil || len(invocationRaw) > stage2aExecMaxFrame {
		return reply, errStage2aReservationAuthority
	}
	grant := Stage2aRoleGrant{
		ReservationSHA256: digest, Role: role, Nonce: nonce, PID: pid,
		LaunchID: invocation.Start.LaunchID, InstallationID: r.request.InstallationID,
		StartID: r.request.StartID, HQEpoch: epoch, ExpiresAt: invocation.Start.ExpiresAt,
		InvocationSHA256: stage2aReservationSHA256(invocationRaw),
	}
	name := ".stage2a-exec-" + role + "-" + soulStartClaimName(r.request.InstallationID, r.request.StartID)
	if err := requireUnspentStage2aReservation(dir, name); err != nil {
		return reply, err
	}
	if err := spendStage2aAdminName(dir, name, store.uid, store.gid); err != nil {
		return reply, err
	}
	envelope, err := signStage2aEnvelope(grant, 1, Stage2aRoleExecPurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || !time.Now().Before(expires) {
		return reply, errStage2aReservationAuthority
	}
	reply = Stage2aExecReply{
		EnvelopeBase64URL:   base64.RawURLEncoding.EncodeToString(envelope),
		SHA256:              stage2aReservationSHA256(envelope),
		InvocationBase64URL: base64.RawURLEncoding.EncodeToString(invocationRaw),
	}
	if len(reply.EnvelopeBase64URL)+len(reply.InvocationBase64URL) > stage2aExecMaxFrame-1024 {
		return Stage2aExecReply{}, errStage2aReservationAuthority
	}
	if checkStage2aGrantedRoleProcess(pid, roleUID, roleGID, role, roleProcess) != nil {
		return Stage2aExecReply{}, errStage2aReservationAuthority
	}
	if role == "runner" {
		r.runnerPID = pid
		r.runnerProcess = roleProcess
	} else {
		r.bridgePID = pid
		r.bridgeProcess = roleProcess
	}
	return reply, nil
}

func checkStage2aGrantedRoleProcess(pid, uid, gid int, role string, granted soulKernelProcessSnapshot) error {
	observed, err := observeStage2aRoleProcess(pid, uid, gid, role)
	return checkStage2aGrantedRoleSnapshot(granted, observed, err)
}

func checkStage2aGrantedRoleSnapshot(granted, observed soulKernelProcessSnapshot, observationErr error) error {
	if observationErr != nil || !sameSoulKernelProcess(granted, observed) {
		return errStage2aReservationAuthority
	}
	return nil
}

func observeStage2aRoleProcess(pid, uid, gid int, role string) (soulKernelProcessSnapshot, error) {
	command := "soul-run"
	if role == "bridge" {
		command = "soul-bridge"
	} else if role == "child" {
		command = "soul-child"
	}
	observed, err := observeSoulProcess(pid, SoulLauncher, []string{SoulLauncher, command})
	if err != nil || observed.Kernel.RealUID != uint32(uid) ||
		observed.Kernel.EffectiveUID != uint32(uid) || observed.Kernel.SavedUID != uint32(uid) ||
		observed.Kernel.RealGID != uint32(gid) || observed.Kernel.PrimaryGroupGID != uint32(gid) ||
		observed.Kernel.SavedGID != uint32(gid) {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	return observed.Kernel, nil
}

// VerifyB accepts one live broker challenge proved with the per-reservation
// B-only key. HQ never sees that key; the signed assignment supplies B's UID
// and exact broker path, and a durable claim prevents replay after restart.
func (s *Stage2aService) VerifyB(hqUID int, epoch string, q Stage2aVerifyBRequest) (Stage2aVerifyBReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aVerifyBReply
	if !validStage2aBridgeSelector(q) || q.HQEpoch != epoch {
		return reply, errStage2aReservationAuthority
	}
	r, p, expires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || r.proofDigest != stage2aReservationSHA256(r.bridgeProof[:]) ||
		len(r.bridgeAssignment) == 0 ||
		p.Binding.InstallationID != q.InstallationID ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil ||
		verifyStage2aBridgeBind(r.bridgeProof[:], q, r.payload.Assignment.SoulStartAssignment) != nil {
		return reply, errStage2aReservationAuthority
	}
	store, _ := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	if err := store.checkDirectory(dir); err != nil || !time.Now().Before(expires) {
		return reply, errStage2aReservationAuthority
	}
	name := ".stage2a-b-bind-" + soulStartClaimName(q.InstallationID, q.StartID)
	if err := requireUnspentStage2aReservation(dir, name); err != nil {
		return reply, err
	}
	if err := spendStage2aAdminName(dir, name, store.uid, store.gid); err != nil {
		return reply, err
	}
	return Stage2aVerifyBReply{Verified: true}, nil
}

func (s *Stage2aService) current(hqUID int, epoch, digest string) (*stage2aLiveReservation, stage2aInstalledPolicy, time.Time, error) {
	var p stage2aInstalledPolicy
	var zero time.Time
	r := s.active[digest]
	if len(s.key) != ed25519.PrivateKeySize || r == nil || r.digest != digest ||
		r.request.HQEpoch != epoch || r.payload.Assignment.HQUID != hqUID {
		return nil, p, zero, errStage2aReservationAuthority
	}
	expires, err := time.Parse(time.RFC3339Nano, r.payload.Assignment.ExpiresAt)
	if err != nil || !time.Now().Before(expires) {
		return nil, p, zero, errStage2aReservationExpired
	}
	loaded, raw, err := loadStage2aActiveExecutionPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, r)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest {
		return nil, p, zero, errStage2aReservationAuthority
	}
	return r, loaded, expires, nil
}
