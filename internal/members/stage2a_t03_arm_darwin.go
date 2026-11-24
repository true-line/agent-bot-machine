//go:build darwin

package members

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type stage2aT03Review struct {
	ProviderAlgorithm               string `json:"provider_algorithm"`
	ProviderConfigSHA256            string `json:"provider_config_sha256"`
	ProviderSelector                string `json:"provider_selector"`
	RequestSHA256                   string `json:"request_sha256"`
	PromptBase64URL                 string `json:"prompt_base64url"`
	SiblingPath                     string `json:"sibling_path"`
	SiblingSocket                   string `json:"sibling_socket"`
	SiblingInstallationID           string `json:"sibling_installation_id"`
	SiblingStartID                  string `json:"sibling_start_id"`
	SiblingUID                      int    `json:"sibling_uid"`
	SiblingCredentialMetadataSHA256 string `json:"sibling_credential_metadata_sha256"`
}

func (p stage2aT03Review) matches(r Stage2aT03PositiveReceipt) bool {
	prompt, err := base64.RawURLEncoding.Strict().DecodeString(p.PromptBase64URL)
	return err == nil && len(prompt) > 0 && len(prompt) <= 2048 && utf8.Valid(prompt) &&
		base64.RawURLEncoding.EncodeToString(prompt) == p.PromptBase64URL &&
		!strings.ContainsAny(string(prompt), "\x00\r") && stage2aReservationSHA256(prompt) == r.PromptSHA256 && p.ProviderAlgorithm == stage2aT03ProviderAlgorithm &&
		p.ProviderConfigSHA256 == r.ProviderConfigSHA256 && p.ProviderSelector == r.ProviderSelector &&
		p.RequestSHA256 == r.RequestSHA256 &&
		stage2aAbsolutePath(p.SiblingPath) && len(p.SiblingPath) <= 512 &&
		stage2aAbsolutePath(p.SiblingSocket) && len(p.SiblingSocket) <= 103 &&
		soulInstallationID.MatchString(p.SiblingInstallationID) &&
		soulStartID.MatchString(p.SiblingStartID) && p.SiblingUID >= 300 && p.SiblingUID <= 399 &&
		stage2aPrefixedDigest.MatchString(p.SiblingCredentialMetadataSHA256)
}

type stage2aT03Pending struct {
	directive           Stage2aT03ProbeDirective
	issuedLease         string
	issuedAt            time.Time
	review              stage2aT03Review
	positiveBytes       []byte
	attempts            []stage2aT03ObservedAttempt
	complete, osWitness []byte
}

func (s *Stage2aService) armStage2aT03(hqUID int, epoch string, q Stage2aT03ArmRequest,
	command stage2aDriverCommand, review stage2aT03Review) error {
	if !review.matches(q.Receipt) || !validStage2aLiveChallenge(command.Challenge) ||
		command.InstallationID != q.InstallationID || command.StartID != q.StartID ||
		command.ReservationSHA256 != q.ReservationSHA256 || !stage2aPrefixedDigest.MatchString(command.TestPlanSHA256) ||
		len(command.SessionID) != 32 || !stage2aQualificationHex(command.SessionID) || command.Profile != "managed-protected" ||
		command.Phase != "live-t03" || command.Gate != "T03" || command.Event != "direct-route-refused" {
		return errStage2aReservationAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withStage2aT03Start(hqUID, epoch, q.Stage2aStopRequest,
		func(r *stage2aLiveReservation, p stage2aInstalledPolicy, store stage2aAdminClaimStore, dir *os.File) error {
			var reservation stage2aQualificationCandidateReservationV3
			if r.t03Pending != nil || json.Unmarshal(r.payloadV3, &reservation) != nil ||
				reservation.Attempt.TestPlanSHA256 != command.TestPlanSHA256 {
				return errStage2aReservationAuthority
			}
			startClaim := soulStartClaimName(q.InstallationID, q.StartID)
			raw, err := marshalStage2aReservationJCS(q)
			if err != nil || stage2aCheckFinalizationFile(dir, ".stage2a-t03-positive-"+startClaim+".json", store.uid, store.gid, raw) != nil {
				return errStage2aReservationAuthority
			}
			_, sidecar, err := stage2aV3SidecarAt(r.runtimeRefV3.Sidecar.Path, r.runtimeRefV3.MachineUID, r.runtimeRefV3.ReaderGID)
			if err != nil {
				return err
			}
			inventory, digest, err := stage2aDomainInventoryDigestV3(sidecar)
			if err != nil || digest != r.runtimeRefV3.InventoryDigest {
				return errStage2aReservationAuthority
			}
			cliSHA := ""
			for _, row := range inventory.Files {
				if row.Path == "runtime/bin/claude" {
					cliSHA = row.SHA256
					break
				}
			}
			if !stage2aPrefixedDigest.MatchString(cliSHA) || r.liveSequence >= (1<<53)-1 ||
				s.checkStage2aT03Sibling(review, p.Runner, hqUID, epoch) != nil {
				return errStage2aReservationAuthority
			}
			now := time.Now()
			policyExpiry, _ := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
			expires := minStage2aTime(policyExpiry, time.UnixMilli(q.Receipt.CompletedAtMS).Add(stage2aT03ReceiptLifetime))
			if !now.Before(expires) {
				return errStage2aReservationAuthority
			}
			directive := Stage2aT03ProbeDirective{
				Schema: stage2aT03ProbeSchema, ChallengeBase64URL: command.Challenge,
				SessionID: command.SessionID, TestPlanSHA256: command.TestPlanSHA256,
				ReservationSHA256: q.ReservationSHA256, InstallationID: q.InstallationID, StartID: q.StartID,
				ChildReceiptSHA256:  q.Receipt.ChildReceiptSHA256,
				CLIExecutableSHA256: cliSHA, ProviderIPv4URL: q.Receipt.ProviderIPv4URL,
				ProviderIPv6URL: q.Receipt.ProviderIPv6URL, Model: q.Receipt.Model, PromptBase64URL: review.PromptBase64URL,
				SiblingCredentialPath: review.SiblingPath, SiblingSocket: review.SiblingSocket, ExpiresAtMS: expires.UnixMilli(),
			}
			arm, err := marshalStage2aReservationJCS(directive)
			if err != nil {
				return err
			}
			if err := commitStage2aReservation(dir, ".stage2a-t03-arm-"+startClaim+".json", arm); err != nil {
				return err
			}
			r.t03Pending = &stage2aT03Pending{directive: directive, positiveBytes: raw, review: review}
			return nil
		})
}

func (s *Stage2aService) checkStage2aT03Sibling(p stage2aT03Review, primary SoulRunner, hqUID int, epoch string) error {
	sibling, err := s.findStage2aT03Sibling(p, primary, hqUID, epoch)
	if err != nil || sibling.t03SiblingWitness == nil || sibling.t03SiblingWitness.First == nil ||
		sibling.t03SiblingWitness.ExpectedDigest != p.SiblingCredentialMetadataSHA256 ||
		sibling.t03SiblingWitness.Path != p.SiblingPath {
		return errStage2aReservationAuthority
	}
	return nil
}

func (s *Stage2aService) findStage2aT03Sibling(p stage2aT03Review, primary SoulRunner, hqUID int, epoch string) (*stage2aLiveReservation, error) {
	if p.SiblingInstallationID == primary.InstallationID || p.SiblingUID == primary.UID {
		return nil, errStage2aReservationAuthority
	}
	accountName := soulRunnerName(p.SiblingInstallationID)
	account, exists, err := (OSHost{}).Account(accountName)
	home := darwinSoulRunnerHome(accountName)
	if err != nil || !exists || account.DarwinRole != darwinSoulRunnerRoleName ||
		account.UID != p.SiblingUID || account.GID != p.SiblingUID || account.Home != home ||
		account.Shell != DarwinNoLoginShell {
		return nil, errStage2aReservationAuthority
	}
	childState := filepath.Join(home, "state", "child-"+soulEndpointStartSlot(p.SiblingInstallationID, p.SiblingStartID))
	if !strings.HasPrefix(p.SiblingPath, childState+"/") {
		return nil, errStage2aReservationAuthority
	}
	var st unix.Stat_t
	if unix.Lstat(home, &st) != nil || st.Uid != uint32(p.SiblingUID) || st.Gid != uint32(p.SiblingUID) ||
		st.Mode != unix.S_IFDIR|0700 || checkDarwinACLs([]string{home}) != nil {
		return nil, errStage2aReservationAuthority
	}
	for _, sibling := range s.active {
		a := sibling.payload.Assignment
		if a.InstallationID == p.SiblingInstallationID && a.StartID == p.SiblingStartID &&
			a.HQEpoch == epoch && a.HQUID == hqUID && a.RunnerUID == p.SiblingUID &&
			a.Relay.SocketPath == p.SiblingSocket && sibling.bindReceiptSHA256 != "" &&
			sibling.hello != nil && sibling.hello.finalized && !sibling.hello.aborted &&
			len(sibling.childReceiptEnvelope) != 0 && sibling.childPID > 1 &&
			checkStage2aGrantedRoleProcess(sibling.childLauncherPID, a.RunnerUID, a.RunnerGID, "child", sibling.childLauncherProcess) == nil &&
			checkStage2aGrantedRoleProcess(sibling.bridgePID, a.BridgeUID, a.BridgeGID, "bridge", sibling.bridgeProcess) == nil {
			return sibling, nil
		}
	}
	return nil, errStage2aReservationAuthority
}

func loadStage2aT03Review(testPlan qualificationFile) (stage2aT03Review, error) {
	const maximum = 65536
	var doc struct {
		T03Probe stage2aT03Review `json:"t03_probe"`
	}
	if !stage2aAbsolutePath(testPlan.Path) || !qualificationDigest.MatchString(testPlan.SHA256) {
		return doc.T03Probe, errStage2aReservationAuthority
	}
	f, err := os.OpenFile(testPlan.Path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return doc.T03Probe, errStage2aReservationAuthority
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return doc.T03Probe, errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || len(raw) > maximum || stage2aQualificationSHA256(raw) != "sha256:"+testPlan.SHA256 ||
		rejectDuplicateJSONKeys(raw) != nil || json.Unmarshal(raw, &doc) != nil ||
		doc.T03Probe.ProviderAlgorithm != stage2aT03ProviderAlgorithm {
		return stage2aT03Review{}, errStage2aReservationAuthority
	}
	return doc.T03Probe, nil
}
