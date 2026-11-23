//go:build darwin

package members

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStage2aProtectedControlProbeSpecBindsInstalledSelectors(t *testing.T) {
	installation := "inst_0000000000000001"
	sibling := "inst_0000000000000002"
	start := "st_0123456789abcdef01234567"
	siblingStart := "st_0123456789abcdef01234568"
	provider := "sha256:" + strings.Repeat("a", 64)
	in := Stage2aRoleInvocation{
		Start: SoulStartAssignment{InstallationID: installation, StartID: start,
			LaunchID: "ln_0123456789abcdef01234567", PlanDigest: strings.Repeat("b", 64),
			HQEpoch:   strings.Repeat("d", 64),
			RunnerUID: 301, RunnerGID: 301, BridgeUID: 302, HQUID: 303, MachineUID: 501,
			Relay: SoulStartEndpoint{SocketPath: "/var/run/agent-bot/s/current.sock"}},
		Launch:    Stage2aLaunchInputRecords{ComponentDigests: map[string]string{"test_provider": provider}},
		ChildExec: &Stage2aChildExec{RelaySocket: "/var/run/agent-bot/s/current.sock"},
	}
	spec := Stage2aProtectedControlProbeSpec{
		Schema: stage2aProtectedControlProbeSchema, InstallationID: installation,
		StartID: start, LaunchID: in.Start.LaunchID, PlanDigest: in.Start.PlanDigest,
		HQEpoch: in.Start.HQEpoch, ProviderConfigSHA256: provider,
		ProviderPort:  stage2aProtectedProviderPortV1(in.Start.HQEpoch, installation, start),
		ProviderModel: "fixture-model", ProviderRequestSHA256: "sha256:" + strings.Repeat("e", 64),
		SiblingInstallationID: sibling, SiblingStartID: siblingStart, SiblingBridgeUID: 304,
		SiblingTokenPath: func() string {
			dir, name := stage2aBridgeProofPath(SoulStartAssignment{InstallationID: sibling, StartID: siblingStart})
			return filepath.Join(dir, name)
		}(),
		SiblingRelaySocket: filepath.Join(launchRuntimeDir, "s", soulEndpointInstallationSlot(sibling),
			soulEndpointStartSlot(sibling, siblingStart)+".sock"),
	}
	if !validStage2aProtectedControlProbeSpec(spec, in) {
		t.Fatal("reviewed selector refused")
	}
	for name, mutate := range map[string]func(*Stage2aProtectedControlProbeSpec){
		"provider digest": func(s *Stage2aProtectedControlProbeSpec) {
			s.ProviderConfigSHA256 = "sha256:" + strings.Repeat("c", 64)
		},
		"plan digest":          func(s *Stage2aProtectedControlProbeSpec) { s.PlanDigest = strings.Repeat("c", 64) },
		"sibling installation": func(s *Stage2aProtectedControlProbeSpec) { s.SiblingInstallationID = installation },
		"sibling uid":          func(s *Stage2aProtectedControlProbeSpec) { s.SiblingBridgeUID = in.Start.RunnerUID },
		"sibling socket":       func(s *Stage2aProtectedControlProbeSpec) { s.SiblingRelaySocket = in.Start.Relay.SocketPath },
		"sibling token escape": func(s *Stage2aProtectedControlProbeSpec) { s.SiblingTokenPath += "/../../current" },
		"wrong provider port":  func(s *Stage2aProtectedControlProbeSpec) { s.ProviderPort++ },
		"wrong epoch":          func(s *Stage2aProtectedControlProbeSpec) { s.HQEpoch = strings.Repeat("f", 64) },
	} {
		changed := spec
		mutate(&changed)
		if validStage2aProtectedControlProbeSpec(changed, in) {
			t.Errorf("accepted changed %s", name)
		}
	}
}

func TestStage2aProtectedControlProbeNativeSandbox(t *testing.T) {
	if os.Getenv("STAGE2A_PROBE_TEST_CHILD") == "1" {
		port4, e4 := strconv.Atoi(os.Getenv("STAGE2A_PROBE_PORT4"))
		port6, e6 := strconv.Atoi(os.Getenv("STAGE2A_PROBE_PORT6"))
		if e4 != nil || e6 != nil {
			t.Fatal("missing fixed test ports")
		}
		for name, result := range map[string]struct{ got, want string }{
			"tcp4":    {stage2aProtectedProbeDirectHTTP("tcp4", "127.0.0.1", port4, "fixture-model", "sha256:"+strings.Repeat("e", 64)), "denied"},
			"tcp6":    {stage2aProtectedProbeDirectHTTP("tcp6", "::1", port6, "fixture-model", "sha256:"+strings.Repeat("e", 64)), "denied"},
			"relay":   {stage2aProtectedProbeDial("unix", os.Getenv("STAGE2A_PROBE_RELAY")), "connected"},
			"sibling": {stage2aProtectedProbeDial("unix", os.Getenv("STAGE2A_PROBE_SIBLING")), "denied"},
			"token":   {stage2aProtectedProbeOpen(os.Getenv("STAGE2A_PROBE_TOKEN")), "denied"},
		} {
			if result.want == "denied" && (result.got == "EPERM" || result.got == "EACCES") {
				continue
			}
			if result.got != result.want {
				t.Errorf("%s: got %s, want %s", name, result.got, result.want)
			}
		}
		return
	}
	dir, err := os.MkdirTemp("/private/tmp", "stage2a-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	relayPath := filepath.Join(dir, "relay.sock")
	siblingPath := filepath.Join(dir, "sibling.sock")
	relay, err := net.Listen("unix", relayPath)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	sibling, err := net.Listen("unix", siblingPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	provider4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer provider4.Close()
	provider6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer provider6.Close()
	tokenPath := filepath.Join(dir, "sibling-token")
	if err := os.WriteFile(tokenPath, []byte("disposable fixture"), 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(tokenPath, 0600)
	profilePath := filepath.Join(dir, "child.sb")
	if err := os.WriteFile(profilePath, soulChildProfile, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/sandbox-exec", "-D", "RELAY_SOCKET="+relayPath,
		"-f", profilePath, os.Args[0], "-test.run=^TestStage2aProtectedControlProbeNativeSandbox$")
	command.Env = []string{
		"PATH=/usr/bin:/bin", "STAGE2A_PROBE_TEST_CHILD=1",
		"STAGE2A_PROBE_PORT4=" + strconv.Itoa(provider4.Addr().(*net.TCPAddr).Port),
		"STAGE2A_PROBE_PORT6=" + strconv.Itoa(provider6.Addr().(*net.TCPAddr).Port),
		"STAGE2A_PROBE_RELAY=" + relayPath, "STAGE2A_PROBE_SIBLING=" + siblingPath,
		"STAGE2A_PROBE_TOKEN=" + tokenPath,
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("confined native probe refused: %v: %s", err, output)
	}
	_ = provider4.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Millisecond))
	if conn, err := provider4.Accept(); err == nil {
		conn.Close()
		t.Fatal("direct IPv4 provider received a hit")
	}
	_ = provider6.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Millisecond))
	if conn, err := provider6.Accept(); err == nil {
		conn.Close()
		t.Fatal("direct IPv6 provider received a hit")
	}
}
