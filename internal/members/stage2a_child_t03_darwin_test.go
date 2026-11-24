//go:build darwin

package members

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func testStage2aT03Probe(t *testing.T) (Stage2aRoleInvocation, Stage2aLiveLeasePayload, Stage2aT03ProbeDirective) {
	t.Helper()
	const installation, start = "soul-one", "st_0123456789abcdef01234567"
	epoch := strings.Repeat("a", 64)
	reservation := "sha256:" + strings.Repeat("b", 64)
	receipt := "sha256:" + strings.Repeat("c", 64)
	cliSHA := "sha256:" + strings.Repeat("d", 64)
	port := stage2aT03ProviderPort(epoch, installation, start)
	if port < 49152 || port > 65535 {
		t.Fatalf("provider port outside ephemeral range: %d", port)
	}
	now := time.Now()
	in := Stage2aRoleInvocation{
		Request: SoulRunRequest{InstallationID: installation, StartID: start, HQEpoch: epoch},
		Start:   SoulStartAssignment{Member: SoulStartEndpoint{SocketPath: "/private/tmp/member.sock"}},
		Runner:  SoulRunner{UID: 310, GID: 310},
		Launch:  Stage2aLaunchInputRecords{EffectiveConfig: map[string]any{"profile": "managed-protected"}},
		ChildExec: &Stage2aChildExec{
			ReservationSHA256: reservation,
			Executable:        "/private/var/db/managed-machine/installed/soul-one/runtime/bin/claude-agent-acp",
			RuntimeV3:         &stage2aDomainInventoryRefV3{Snapshot: stage2aDomainNodeRefV3{Path: "/private/var/db/managed-machine/installed/soul-one"}},
			Environment:       map[string]string{"ANTHROPIC_MODEL": "test-model", "ANTHROPIC_BASE_URL": "http://fixture.invalid", "ANTHROPIC_UNIX_SOCKET": "/private/tmp/assigned.sock"},
			RelaySocket:       "/private/tmp/assigned.sock", Workdir: "/private/var/agent-bot/soul-one/work",
			SandboxPath: SoulChildSandbox, SandboxSHA256: "sha256:" + harnessSHA(soulChildProfile),
		},
	}
	lease := Stage2aLiveLeasePayload{
		Stage2aStopRequest: Stage2aStopRequest{ReservationSHA256: reservation, InstallationID: installation, StartID: start},
		ChildReceiptSHA256: receipt, Sequence: 7, IssuedAtMS: now.UnixMilli(), ExpiresAtMS: now.Add(5 * time.Second).UnixMilli(),
	}
	d := Stage2aT03ProbeDirective{
		Schema: stage2aT03ProbeSchema, ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		SessionID: strings.Repeat("e", 32), TestPlanSHA256: "sha256:" + strings.Repeat("f", 64),
		ReservationSHA256: reservation, InstallationID: installation, StartID: start,
		ChildReceiptSHA256: receipt, LeaseSequence: 7, CLIExecutableSHA256: cliSHA,
		ProviderIPv4URL: fmt.Sprintf("http://127.0.0.1:%d", port),
		ProviderIPv6URL: fmt.Sprintf("http://[::1]:%d", port),
		Model:           "test-model", PromptBase64URL: base64.RawURLEncoding.EncodeToString([]byte("T03 canary")),
		SiblingCredentialPath: "/private/var/agent-bot/soul-two/credentials/client-key",
		SiblingSocket:         "/private/var/agent-bot/soul-two/relay.sock", ExpiresAtMS: now.Add(20 * time.Second).UnixMilli(),
	}
	return in, lease, d
}

func TestStage2aT03DirectiveBindsPinnedChildAndBothProviderFamilies(t *testing.T) {
	in, lease, d := testStage2aT03Probe(t)
	prompt, err := validateStage2aT03ProbeDirective(&d, lease, in, d.ChildReceiptSHA256, d.CLIExecutableSHA256, time.Now())
	if err != nil || string(prompt) != "T03 canary" {
		t.Fatalf("valid signed probe refused: %v", err)
	}
	for name, mutate := range map[string]func(*Stage2aT03ProbeDirective){
		"different receipt":  func(p *Stage2aT03ProbeDirective) { p.ChildReceiptSHA256 = "sha256:" + strings.Repeat("0", 64) },
		"different CLI":      func(p *Stage2aT03ProbeDirective) { p.CLIExecutableSHA256 = "sha256:" + strings.Repeat("0", 64) },
		"different sequence": func(p *Stage2aT03ProbeDirective) { p.LeaseSequence++ },
		"wrong IPv4 port":    func(p *Stage2aT03ProbeDirective) { p.ProviderIPv4URL = "http://127.0.0.1:1" },
		"IPv6 path":          func(p *Stage2aT03ProbeDirective) { p.ProviderIPv6URL += "/v1/messages" },
		"foreign address": func(p *Stage2aT03ProbeDirective) {
			p.ProviderIPv4URL = strings.Replace(p.ProviderIPv4URL, "127.0.0.1", "127.0.0.2", 1)
		},
		"assigned socket": func(p *Stage2aT03ProbeDirective) { p.SiblingSocket = in.ChildExec.RelaySocket },
		"own credential": func(p *Stage2aT03ProbeDirective) {
			p.SiblingCredentialPath = "/private/var/agent-bot/soul-one/work/credential"
		},
		"expired": func(p *Stage2aT03ProbeDirective) { p.ExpiresAtMS = time.Now().Add(-time.Second).UnixMilli() },
	} {
		t.Run(name, func(t *testing.T) {
			bad := d
			mutate(&bad)
			if _, err := validateStage2aT03ProbeDirective(&bad, lease, in, d.ChildReceiptSHA256, d.CLIExecutableSHA256, time.Now()); err == nil {
				t.Fatal("altered probe accepted")
			}
		})
	}
}

func TestStage2aT03CommandUsesSamePinnedProfileAndInstalledCLI(t *testing.T) {
	in, _, d := testStage2aT03Probe(t)
	cli := strings.TrimSuffix(in.ChildExec.Executable, "-agent-acp")
	for _, tc := range []struct{ name, url, sibling string }{
		{"ipv4", d.ProviderIPv4URL, ""}, {"ipv6", d.ProviderIPv6URL, ""},
		{"sibling", d.ProviderIPv4URL, d.SiblingSocket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := stage2aT03ProbeCommand(context.Background(), in, tc.url, []byte("T03 canary"), tc.sibling)
			if err != nil {
				t.Fatal(err)
			}
			if cmd.Path != "/usr/bin/sandbox-exec" || !reflect.DeepEqual(cmd.Args[len(cmd.Args)-8:], stage2aT03CLIArguments(cli, "test-model")) {
				t.Fatalf("unexpected installed CLI invocation: %v", cmd.Args)
			}
			if !slices.Contains(cmd.Args, "RELAY_SOCKET="+in.ChildExec.RelaySocket) || !slices.Contains(cmd.Args, in.ChildExec.SandboxPath) {
				t.Fatalf("different sandbox profile or assigned relay: %v", cmd.Args)
			}
			if tc.sibling == "" {
				if !slices.Contains(cmd.Env, "ANTHROPIC_BASE_URL="+tc.url) || slices.Contains(cmd.Env, "ANTHROPIC_UNIX_SOCKET="+in.ChildExec.RelaySocket) {
					t.Fatalf("direct-IP probe retained the assigned socket: %v", cmd.Env)
				}
			} else if !slices.Contains(cmd.Env, "ANTHROPIC_UNIX_SOCKET="+tc.sibling) || !slices.Contains(cmd.Env, "ANTHROPIC_BASE_URL=http://fixture.invalid") {
				t.Fatalf("sibling probe changed selected socket or fallback URL: %v", cmd.Env)
			}
		})
	}
}

func TestStage2aT03DenialClassificationRequiresTargetAndConnect(t *testing.T) {
	for _, kind := range []string{"ipv4", "ipv6", "sibling"} {
		target := "/private/tmp/sibling.sock"
		if kind == "ipv4" {
			target = "http://127.0.0.1:55111"
		} else if kind == "ipv6" {
			target = "http://[::1]:55111"
		}
		errno, seen, class := stage2aT03ClassifyDenial(kind, target, nil, []byte("connect "+target+": operation not permitted"))
		if errno != "EPERM" || !seen || class != "connect_denied" {
			t.Fatalf("%s denial not preserved: %q %v %q", kind, errno, seen, class)
		}
	}
	if errno, seen, class := stage2aT03ClassifyDenial("ipv4", "http://127.0.0.1:55111", nil,
		[]byte("connect http://127.0.0.1:55112: operation not permitted")); errno != "" || seen || class != "unclassified" {
		t.Fatalf("different target misclassified: %q %v %q", errno, seen, class)
	}
	for _, output := range []struct{ stdout, stderr string }{
		{"http://127.0.0.1:55111\nconnect http://127.0.0.1:55112: EPERM", ""},
		{"http://127.0.0.1:55111", "connect http://127.0.0.1:55112: EACCES"},
		{"connect http://127.0.0.1:55111: EPERM and EACCES", ""},
	} {
		if errno, seen, class := stage2aT03ClassifyDenial("ipv4", "http://127.0.0.1:55111",
			[]byte(output.stdout), []byte(output.stderr)); errno != "" || seen || class != "unclassified" {
			t.Fatalf("mixed or ambiguous output counted as target denial: %q %v %q", errno, seen, class)
		}
	}
}

func TestStage2aT03SiblingCredentialProbeBindsSignedChildLease(t *testing.T) {
	in, lease, _ := testStage2aT03Probe(t)
	p := Stage2aT03SiblingCredentialProbe{
		Schema:                   "agent-bot-machine/stage2a-t03-sibling-credential-probe/v1",
		ChallengeBase64URL:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		PrimaryReservationSHA256: "sha256:" + strings.Repeat("e", 64),
		SiblingReservationSHA256: lease.ReservationSHA256,
		SiblingInstallationID:    in.Request.InstallationID, SiblingStartID: in.Request.StartID,
		ChildReceiptSHA256: lease.ChildReceiptSHA256, LeaseSequence: lease.Sequence,
		CredentialPath: "/private/var/agent-bot/soul-one/state/credential", ExpiresAtMS: lease.ExpiresAtMS,
	}
	if !validStage2aT03SiblingCredentialProbe(p, lease, in, lease.ChildReceiptSHA256) {
		t.Fatal("matching sibling probe refused")
	}
	for _, mutate := range []func(*Stage2aT03SiblingCredentialProbe){
		func(v *Stage2aT03SiblingCredentialProbe) {
			v.CredentialPath = "/private/var/agent-bot/other/credential"
		},
		func(v *Stage2aT03SiblingCredentialProbe) { v.LeaseSequence++ },
		func(v *Stage2aT03SiblingCredentialProbe) { v.ChildReceiptSHA256 = v.PrimaryReservationSHA256 },
		func(v *Stage2aT03SiblingCredentialProbe) { v.ExpiresAtMS++ },
	} {
		bad := p
		mutate(&bad)
		if validStage2aT03SiblingCredentialProbe(bad, lease, in, lease.ChildReceiptSHA256) {
			t.Fatal("unbound sibling probe accepted")
		}
	}
}
