package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedDownloadLinksExactNativeGate(t *testing.T) {
	dir := t.TempDir()
	unsigned, signed := filepath.Join(dir, "unsigned"), filepath.Join(dir, "signed")
	version, revision := "1.2.3", strings.Repeat("a", 40)
	code := bytes.Repeat([]byte{0x42}, 128)
	pre := syntheticMacho(code, []byte("adhoc"))
	post := syntheticMacho(code, []byte("developer id "+testTeam))
	writeArchiveDist(t, unsigned, version, unsignedDarwin(pre))
	writeArchiveDist(t, signed, version, signedTree(post))
	_, preSums, err := verifyDist(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	_, postSums, err := verifyDist(signed)
	if err != nil {
		t.Fatal(err)
	}
	name := darwinArchiveName(version)
	gatePath := filepath.Join(dir, "release-gate-darwin-arm64.json")
	writeGate := func(corrupt string) []byte {
		t.Helper()
		gate := map[string]any{
			"kind": "s6-release-gate", "schema_version": 1, "result": "pass",
			"version": version, "target": "darwin/arm64", "emulated": false,
			"source_revision": revision, "binary_sha256": sha256Hex(pre),
			"artifact": map[string]string{"name": name, "sha256": preSums[name]},
		}
		switch corrupt {
		case "":
		case "signed archive":
			gate["artifact"].(map[string]string)["sha256"] = postSums[name]
		case "name":
			gate["artifact"].(map[string]string)["name"] = "different-archive"
		case "signed binary":
			gate["binary_sha256"] = sha256Hex(post)
		case "revision":
			gate["source_revision"] = strings.Repeat("b", 40)
		case "emulated":
			gate["emulated"] = true
		case "missing emulation evidence":
			delete(gate, "emulated")
		case "failed":
			gate["result"] = "fail"
		}
		raw, err := json.MarshalIndent(gate, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(gatePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	args := []string{"-unsigned", unsigned, "-signed", signed, "-team", testTeam,
		"-darwin-gate", gatePath, "-source-revision", revision}
	var out bytes.Buffer
	raw := writeGate("")
	if err := verifySignedCmd(args, &out); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{name, sha256Hex(raw), preSums[name], postSums[name], sha256Hex(pre), sha256Hex(post), revision} {
		if !strings.Contains(out.String(), value) {
			t.Errorf("published mapping missing %s", value)
		}
	}
	after, err := os.ReadFile(gatePath)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("native receipt changed during publication")
	}
	for _, corrupt := range []string{"name", "signed archive", "signed binary", "revision", "emulated", "missing emulation evidence", "failed"} {
		t.Run(corrupt, func(t *testing.T) {
			writeGate(corrupt)
			out.Reset()
			if err := verifySignedCmd(args, &out); err == nil || out.Len() != 0 {
				t.Fatalf("published a mismatched native receipt: err=%v stdout=%q", err, out.String())
			}
		})
	}
}
