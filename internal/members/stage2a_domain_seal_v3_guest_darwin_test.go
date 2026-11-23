//go:build darwin && stage2a_guest

package members

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// This deliberately gated component fixture exercises root's fresh private
// handoff through the actual A-eUID sandboxed launcher in a disposable VM.
// It has no owner proof, released H/R artifacts, HQ start or T03 authority.
func TestStage2aV3GuestSealHAndR(t *testing.T) {
	if os.Getenv("STAGE2A_V3_GUEST_SEAL") != "1" {
		t.Skip("disposable Stage 2a v3 guest only")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("guest seal fixture requires root")
	}
	aName, hName, rName := os.Getenv("STAGE2A_V3_A_ACCOUNT"),
		os.Getenv("STAGE2A_V3_H_ACCOUNT"), os.Getenv("STAGE2A_V3_R_ACCOUNT")
	if aName == "" || hName == "" || rName == "" || hName == rName {
		t.Fatal("dedicated A, H and R guest accounts required")
	}
	aUID, aGID := stage2aGuestAccount(t, aName)
	hUID, hGID := stage2aGuestAccount(t, hName)
	rUID, rGID := stage2aGuestAccount(t, rName)
	if aUID < 400 || hUID == aUID || rUID == aUID || hGID == rGID {
		t.Fatal("guest A/H/R numeric identities overlap")
	}
	if err := os.MkdirAll(filepath.Dir(stage2aDomainSnapshotParentV3), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stage2aDomainSnapshotParentV3, 0711); err != nil {
		if !os.IsExist(err) {
			t.Fatal(err)
		}
	} else if err := os.Chmod(stage2aDomainSnapshotParentV3, 0711); err != nil {
		t.Fatal(err)
	}
	commonFD, err := unix.Open(stage2aDomainSnapshotParentV3, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage2aCommonSnapshotParent(commonFD); err != nil {
		t.Fatal(err)
	}
	unix.Close(commonFD)
	binary, err := os.ReadFile(SoulLauncher)
	if err != nil {
		t.Fatalf("install exact test SoulLauncher first: %v", err)
	}
	launcherHash := harnessSHA(binary)
	if want := os.Getenv("STAGE2A_V3_GUEST_LAUNCHER_SHA256"); want == "" || want != launcherHash {
		t.Fatalf("installed SoulLauncher hash %s differs from exact guest build %s", launcherHash, want)
	}
	for _, tc := range []struct {
		name, domain, reader string
		uid, gid             int
		files                int
		large                bool
	}{
		{"H-480", "H-code", hName, hUID, hGID, 480, false},
		{"R-large", "R-runtime", rName, rUID, rGID, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var nonce [12]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				t.Fatal(err)
			}
			installID := "guest-" + hex.EncodeToString(nonce[:])
			namespace, _, _, err := stage2aDomainNamesV3(tc.domain, installID)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(namespace, 0700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(namespace) })
			stage2aGuestChownMode(t, namespace, aUID, tc.gid, 0750)
			wrapper := filepath.Join(namespace, ".stage2a-"+hex.EncodeToString(nonce[:]))
			if err := os.Mkdir(wrapper, 0700); err != nil {
				t.Fatal(err)
			}
			stage2aGuestChownMode(t, wrapper, aUID, tc.gid, 0700)
			stage := filepath.Join(wrapper, "snapshot")
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			stage2aGuestChownMode(t, stage, aUID, tc.gid, 0700)
			child := "hq"
			if tc.large {
				child = "runtime"
			}
			childPath := filepath.Join(stage, child)
			if err := os.Mkdir(childPath, 0700); err != nil {
				t.Fatal(err)
			}
			stage2aGuestChownMode(t, childPath, aUID, tc.gid, 0700)
			inv := stage2aDomainInventoryV3{Contract: "machine/v3", Kind: "stage2a-domain-inventory",
				SchemaVersion: 3, Domain: tc.domain, InstallationID: installID,
				Limits: stage2aDomainInventoryLimitsV3{MaxFiles: 512,
					MaxFileBytes: stage2aV3MaxInventoryFileBytes, MaxTotalBytes: stage2aV3MaxInventoryTotalBytes},
				Directories: []stage2aDomainDirectoryV3{{Path: child, Kind: "directory", Mode: "0550"}},
			}
			for i := 0; i < tc.files; i++ {
				relative := fmt.Sprintf("%s/f%03d.bin", child, i)
				path := filepath.Join(stage, relative)
				var size uint64
				var sum [32]byte
				if tc.large {
					// Sparse zeros still force A to hash >256 MiB of opened bytes.
					size = 268435457
					file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					if err := file.Truncate(int64(size)); err != nil {
						file.Close()
						t.Fatal(err)
					}
					file.Close()
					h := sha256.New()
					if _, err := io.CopyN(h, zeroStage2aReader{}, int64(size)); err != nil {
						t.Fatal(err)
					}
					copy(sum[:], h.Sum(nil))
				} else {
					data := []byte("reviewed v3 guest file " + relative)
					size = uint64(len(data))
					sum = sha256.Sum256(data)
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				stage2aGuestChownMode(t, path, aUID, tc.gid, 0440)
				inv.Files = append(inv.Files, stage2aDomainFileV3{Path: relative,
					Kind: "regular", Mode: "0440", SizeBytes: size,
					SHA256: fmt.Sprintf("sha256:%x", sum), ComponentID: "guest-component", ReleasePath: relative})
				inv.TotalBytes += size
			}
			stage2aGuestChownMode(t, childPath, aUID, tc.gid, 0550)
			raw := stage2aV3TestCanonical(t, inv)
			_, digest, err := stage2aDomainInventoryDigestV3(raw)
			if err != nil {
				t.Fatal(err)
			}
			sidecar := filepath.Join(wrapper, "inventory")
			if err := os.WriteFile(sidecar, raw, 0600); err != nil {
				t.Fatal(err)
			}
			stage2aGuestChownMode(t, sidecar, aUID, tc.gid, 0600)
			wrapperID := stage2aGuestIdentity(t, wrapper, aUID, tc.gid)
			stageID := stage2aGuestIdentity(t, stage, aUID, tc.gid)
			var ns unix.Stat_t
			if err := unix.Stat(namespace, &ns); err != nil {
				t.Fatal(err)
			}
			r := stage2aDomainSealRequestV3{Schema: stage2aDomainSealSchemaV3,
				Domain: tc.domain, InstallationID: installID,
				MachineAccount: aName, MachineUID: aUID, MachineGID: aGID,
				ReaderAccount: tc.reader, ReaderUID: tc.uid, ReaderGID: tc.gid,
				OwnerPlanDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				ReviewedDigest:  digest, Namespace: stage2aInstalledDirectory{
					Path: namespace, Device: ns.Dev, Inode: strconv.FormatUint(ns.Ino, 10),
					BirthSeconds: ns.Btim.Sec, BirthNanoseconds: ns.Btim.Nsec},
				LauncherSHA256: launcherHash,
				Prepared: stage2aPreparedSnapshot{WrapperPath: wrapper, Wrapper: wrapperID,
					Stage: stageID, Digest: digest}, Inventory: raw,
			}
			ref, err := stage2aSealDomainV3AsAdmin(r)
			if err != nil || ref.Domain != tc.domain || ref.FileCount != tc.files ||
				ref.TotalBytes != inv.TotalBytes || ref.Snapshot.Mode != "0555" ||
				ref.Sidecar.Mode != "0440" || ref.MachineUID != uint32(aUID) ||
				ref.ReaderUID != uint32(tc.uid) || ref.ReaderGID != uint32(tc.gid) {
				t.Fatalf("A seal refused or incorrect: ref=%+v err=%v", ref, err)
			}
			t.Logf("COMPONENT_ONLY domain=%s A=%d:%d reader=%d:%d files=%d bytes=%d root=%s sidecar=%s digest=%s",
				tc.domain, aUID, aGID, tc.uid, tc.gid, ref.FileCount, ref.TotalBytes,
				ref.Snapshot.Path, ref.Sidecar.Path, ref.InventoryDigest)
		})
	}
}

type zeroStage2aReader struct{}

func (zeroStage2aReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func stage2aGuestAccount(t *testing.T, name string) (int, int) {
	t.Helper()
	account, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return uid, gid
}

func stage2aGuestChownMode(t *testing.T, path string, uid, gid int, mode os.FileMode) {
	t.Helper()
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func stage2aGuestIdentity(t *testing.T, path string, uid, gid int) Stage2aSnapshotIdentity {
	t.Helper()
	fd, err := unix.Open(path, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	id, _, err := stage2aSnapshotIdentityForSource(fd, uint32(uid), uint32(gid), true)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
