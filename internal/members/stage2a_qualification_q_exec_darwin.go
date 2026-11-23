package members

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	stage2aQualificationQSessionName = "q-session.sock"
	stage2aQualificationQSessionPath = stage2aQualificationQSocket + "/" + stage2aQualificationQSessionName
	stage2aQualificationQProfile     = stage2aQualificationQHome + "/observer.sb"
	stage2aQualificationQConfig      = stage2aQualificationQHome + "/installed.json"
)

type stage2aQualificationQInstall struct {
	ProfileSHA256    string                      `json:"profile_sha256"`
	AdminGID         int                         `json:"admin_gid"`
	SupplementalGIDs []int                       `json:"supplemental_gids"`
	HQUID            int                         `json:"hq_uid"`
	HQGID            int                         `json:"hq_gid"`
	RunnerGID        int                         `json:"runner_gid"`
	BridgeGID        int                         `json:"bridge_gid"`
	LauncherSHA256   string                      `json:"launcher_sha256"`
	Review           stage2aQualificationQReview `json:"review"`
	AdminUID         int                         `json:"admin_uid"`
	UID              int                         `json:"uid"`
	GID              int                         `json:"gid"`
	Node             qualificationFile           `json:"node"`
	Source           qualificationFile           `json:"source"`
	PS               qualificationFile           `json:"ps"`
	Roots            []string                    `json:"metadata_roots"`
}

// RunStage2aQualificationQ is the Q-only observer target of the proposed
// root-reviewed launchd job. Q reads only a socket selector from A.
func RunStage2aQualificationQ() int {
	self, err := os.Executable()
	if err != nil || self != SoulLauncher || len(os.Args) != 2 || os.Args[0] != SoulLauncher || os.Args[1] != stage2aQualificationQCommand || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return harnessRefused
	}
	install, err := readStage2aQualificationQInstall()
	if err != nil || os.Geteuid() != install.UID || os.Getegid() != install.GID {
		return harnessRefused
	}
	kernel, err := observeSoulKernelProcess(os.Getpid())
	if err != nil || !stage2aQualificationKernelMatches(kernel, os.Getpid(), install.UID, install.GID) ||
		!stage2aQualificationKernelGroupsMatch(kernel, install) {
		return harnessRefused
	}
	selector, err := takeStage2aQualificationQTrigger(install)
	if err != nil {
		return harnessRefused
	}
	if selector != stage2aQualificationQSessionName {
		return harnessRefused
	}
	if err := os.Chdir(stage2aQualificationQHome); err != nil {
		return harnessRefused
	}
	argv := stage2aQualificationQArguments(install)
	if syscall.Exec(argv[0], argv, []string{"HOME=" + stage2aQualificationQHome, "PATH=/usr/bin:/bin", "LC_ALL=C"}) != nil {
		return harnessRefused
	}
	return harnessRefused
}

func loadStage2aQualificationQInstall() (stage2aQualificationQInstall, error) {
	install, err := readStage2aQualificationQInstall()
	if err != nil {
		return install, err
	}
	path := stage2aQualificationQConfig
	h := OSHost{}
	if err := trustedPath(h, path, false); err != nil {
		return install, err
	}
	if err := checkDarwinACLs(pathAncestry(path)); err != nil {
		return install, err
	}
	if verifyQualificationFile(qualificationFile{Path: stage2aQualificationQProfile, SHA256: install.ProfileSHA256}) != nil ||
		trustedPath(h, stage2aQualificationQProfile, false) != nil || checkDarwinACLs(pathAncestry(stage2aQualificationQProfile)) != nil {
		return install, errStage2aReservationAuthority
	}
	if verifyHarnessExecutableLimit(SoulLauncher, install.LauncherSHA256, 512<<20) != nil ||
		verifyHarnessExecutableLimit(install.Node.Path, install.Node.SHA256, 2<<30) != nil ||
		verifyQualificationFile(install.Source) != nil || verifyHarnessExecutableLimit(install.PS.Path, install.PS.SHA256, 256<<10) != nil ||
		trustedPath(h, install.Source.Path, false) != nil || checkDarwinACLs(pathAncestry(install.Source.Path)) != nil {
		return install, errStage2aReservationAuthority
	}
	return install, nil
}

// The sandboxed Q bootstrap reads only the root-installed descriptor.
func readStage2aQualificationQInstall() (stage2aQualificationQInstall, error) {
	var install stage2aQualificationQInstall
	path := stage2aQualificationQConfig
	file, err := os.Open(path)
	if err != nil {
		return install, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 || stage2aStrictJSON(raw) != nil {
		return install, errStage2aReservationAuthority
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&install) != nil || !install.Review.valid() || !digestPattern.MatchString(install.LauncherSHA256) || install.AdminUID <= 0 || install.HQUID <= 0 || !stage2aQualificationQID(install.UID) ||
		install.AdminUID == install.UID || install.UID != install.GID || len(install.Roots) == 0 || len(install.Roots) > 16 ||
		install.ProfileSHA256 != stage2aQualificationProfileSHA256(install) ||
		!validStage2aQualificationQGroups(install.GID, install.SupplementalGIDs,
			install.AdminGID, install.HQGID, install.RunnerGID, install.BridgeGID) ||
		install.Source.Path != filepath.Join(stage2aQualificationQHome, "qualification-runner.mjs") || install.PS.Path != filepath.Join(stage2aQualificationQHome, "process-observer") {
		return install, errStage2aReservationAuthority
	}
	for _, root := range install.Roots {
		if root == "/" || !stage2aAbsolutePath(root) || strings.ContainsAny(root, "\r\n") {
			return install, errStage2aReservationAuthority
		}
	}
	return install, nil
}

func stage2aQualificationProfileSHA256(install stage2aQualificationQInstall) string {
	return strings.TrimPrefix(stage2aQualificationSHA256([]byte(stage2aQualificationQSandbox(install))), "sha256:")
}

func stage2aQualificationQSandbox(install stage2aQualificationQInstall) string {
	socket := stage2aQualificationQSessionPath
	var profile strings.Builder
	profile.WriteString("(version 1)\n(deny default)\n(allow sysctl-read)\n(allow process-fork)\n")
	profile.WriteString("(allow file-read* (subpath \"/System/Library\") (subpath \"/usr/lib\") (literal \"/\") (literal \"/dev/null\"))\n")
	fmt.Fprintf(&profile, "(allow process-exec (literal %q) (literal %q) (literal %q))\n", SoulLauncher, install.Node.Path, install.PS.Path)
	fmt.Fprintf(&profile, "(allow file-read* (literal %q) (literal %q) (literal %q) (literal %q) (literal %q))\n", SoulLauncher, stage2aQualificationQConfig, install.Node.Path, install.Source.Path, install.PS.Path)
	profile.WriteString("(allow file-write-data (literal \"/dev/null\"))\n")
	fmt.Fprintf(&profile, "(allow file-read-metadata (literal %q) (literal %q))\n", stage2aQualificationQSocket, socket)
	fmt.Fprintf(&profile, "(allow network-outbound (remote unix-socket (path-literal %q)))\n", socket)
	// Node realpath and Q's own no-follow walk need metadata on exact
	// ancestors. This does not grant reads of sibling files.
	seen := make(map[string]bool)
	for _, entry := range append([]string{SoulLauncher, stage2aQualificationQConfig, install.Node.Path, install.Source.Path, install.PS.Path, socket}, install.Roots...) {
		for _, ancestor := range pathAncestry(filepath.Dir(entry)) {
			if !seen[ancestor] {
				fmt.Fprintf(&profile, "(allow file-read-metadata (literal %q))\n", ancestor)
				seen[ancestor] = true
			}
		}
	}
	for _, root := range install.Roots {
		fmt.Fprintf(&profile, "(allow file-read-metadata (subpath %q))\n", root)
	}
	return profile.String()
}

func stage2aQualificationQArguments(install stage2aQualificationQInstall) []string {
	return []string{install.Node.Path, install.Source.Path, "--connect", stage2aQualificationQSessionPath}
}
