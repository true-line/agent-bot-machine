//go:build darwin

package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

var (
	testKeychainMu     sync.Mutex
	testKeychainStores []darwinKeychainStore
)

func TestMain(m *testing.M) {
	testKeychainAccountOverride = func(cleanPath string) string {
		sum := sha256.Sum256([]byte(cleanPath))
		acct := fmt.Sprintf("%s.test.%d.%s", keychainAccount, os.Getpid(), hex.EncodeToString(sum[:6]))
		testKeychainMu.Lock()
		testKeychainStores = append(testKeychainStores, darwinKeychainStore{
			service: keychainService,
			account: acct,
		})
		testKeychainMu.Unlock()
		return acct
	}
	code := m.Run()
	testKeychainMu.Lock()
	stores := append([]darwinKeychainStore(nil), testKeychainStores...)
	testKeychainStores = nil
	testKeychainMu.Unlock()
	for _, s := range stores {
		_ = s.Delete()
	}
	os.Exit(code)
}

func packageSourceDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

func TestDarwinKeychainNeverImportsExec(t *testing.T) {
	srcDir := packageSourceDir(t)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fullPath := filepath.Join(srcDir, name)
		f, err := parser.ParseFile(fset, fullPath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		importsExec := false
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == "os/exec" {
				importsExec = true
			}
		}
		if importsExec && name != "keys.go" && name != "activate.go" {
			t.Fatalf("%s imports os/exec; only keys.go (runKeyHelperCmd) and activate.go (launchctl/systemctl) may import os/exec in internal/daemon", name)
		}

		// Ban raw process-spawning primitives across all non-test files in internal/daemon.
		var execCalls []string
		for _, decl := range f.Decls {
			var scope string
			switch d := decl.(type) {
			case *ast.FuncDecl:
				scope = d.Name.Name
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
						scope = vs.Names[0].Name
					}
				}
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch pkgIdent.Name + "." + sel.Sel.Name {
				case "os.StartProcess", "syscall.ForkExec", "syscall.StartProcess", "syscall.Exec":
					t.Fatalf("%s (%s) calls %s.%s; process spawning must go through runKeyHelperCmd", name, scope, pkgIdent.Name, sel.Sel.Name)
				}
				if pkgIdent.Name == "exec" {
					execCalls = append(execCalls, scope+":"+sel.Sel.Name)
				}
				return true
			})
		}

		switch name {
		case "keys.go":
			if len(execCalls) != 1 || execCalls[0] != "runKeyHelperCmd:Command" {
				t.Fatalf("keys.go exec.* calls = %v, want [runKeyHelperCmd:Command]", execCalls)
			}
		case "activate.go":
			for _, c := range execCalls {
				if c != "launchctl:Command" && c != "systemctl:Command" {
					t.Fatalf("activate.go has unexpected exec call %s", c)
				}
			}
		default:
			if len(execCalls) != 0 {
				t.Fatalf("%s has unexpected exec.* calls: %v", name, execCalls)
			}
		}
	}
}

func TestDarwinKeychainStoreInProcessRoundTrip(t *testing.T) {
	acct := fmt.Sprintf("daemon.key.test.%d", os.Getpid())
	store := darwinKeychainStore{
		service: keychainService + ".test",
		account: acct,
	}
	t.Cleanup(func() { _ = store.Delete() })
	_ = store.Delete()

	got, ok, err := store.Load()
	if err != nil || ok || got != nil {
		t.Fatalf("expected absent item before save, got ok=%v err=%v", ok, err)
	}
	seed1 := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed1); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(seed1); err != nil {
		t.Fatalf("Save(seed1): %v", err)
	}
	got, ok, err = store.Load()
	if err != nil || !ok || !bytes.Equal(got, seed1) {
		t.Fatalf("Load after Save(seed1): ok=%v err=%v match=%v", ok, err, bytes.Equal(got, seed1))
	}

	// Second Save on a valid self-only item updates in-place via SecItemUpdate
	// without deleting first.
	seed2 := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed2); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(seed2); err != nil {
		t.Fatalf("Save(seed2) in-place update: %v", err)
	}
	got, ok, err = store.Load()
	if err != nil || !ok || !bytes.Equal(got, seed2) {
		t.Fatalf("Load after Save(seed2): ok=%v err=%v match=%v", ok, err, bytes.Equal(got, seed2))
	}

	if err := store.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, ok, err = store.Load()
	if err != nil || ok || got != nil {
		t.Fatalf("expected absent item after Delete, got ok=%v err=%v", ok, err)
	}
}

// createOpenAccess builds a SecAccessRef whose Decrypt ACL has
// applicationList == NULL ("allow all applications to access this item"),
// matching an item pre-planted with `security add-generic-password -A`.
func createOpenAccess(t *testing.T, label string) uintptr {
	t.Helper()
	access, err := createSelfOnlyAccess(label)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"ACLAuthorizationDecrypt", "ACLAuthorizationExportClear"} {
		tagRef := cfString(tag)
		aclList, _, _ := syscall_syscall(kc_SecAccessCopyMatchingACLList_trampoline_addr, access, tagRef, 0)
		cfRelease(tagRef)
		if aclList == 0 || cfArrayCount(aclList) == 0 {
			if aclList != 0 {
				cfRelease(aclList)
			}
			cfRelease(access)
			t.Fatalf("SecAccessCopyMatchingACLList(%s) empty", tag)
		}
		acl := cfArrayGet(aclList, 0)
		desc := cfString(label)
		r1, _, _ := syscall_syscall6(kc_SecACLSetContents_trampoline_addr, acl, 0, desc, 0, 0, 0)
		cfRelease(desc)
		cfRelease(aclList)
		if status := int32(r1); status != 0 {
			cfRelease(access)
			t.Fatalf("SecACLSetContents(%s, NULL): OSStatus %d", tag, status)
		}
	}
	return access
}

// createMultiAppAccess builds a SecAccessRef whose Decrypt ACL trusts both the
// current binary and /usr/bin/security, simulating a pre-planted item that
// grants access to an extra binary alongside the daemon.
func createMultiAppAccess(t *testing.T, label string) uintptr {
	t.Helper()
	var selfApp, otherApp uintptr
	r1, _, _ := syscall_syscall(kc_SecTrustedApplicationCreateFromPath_trampoline_addr, 0, uintptr(unsafe.Pointer(&selfApp)), 0)
	if int32(r1) != 0 || selfApp == 0 {
		t.Fatalf("SecTrustedApplicationCreateFromPath(NULL): %d", int32(r1))
	}
	defer cfRelease(selfApp)
	secPath := append([]byte("/usr/bin/security"), 0)
	r2, _, _ := syscall_syscall(kc_SecTrustedApplicationCreateFromPath_trampoline_addr, uintptr(unsafe.Pointer(unsafe.SliceData(secPath))), uintptr(unsafe.Pointer(&otherApp)), 0)
	runtime.KeepAlive(secPath)
	if int32(r2) != 0 || otherApp == 0 {
		t.Fatalf("SecTrustedApplicationCreateFromPath(/usr/bin/security): %d", int32(r2))
	}
	defer cfRelease(otherApp)
	items := [2]uintptr{selfApp, otherApp}
	arrCB := cfSymAddr("kCFTypeArrayCallBacks")
	trustedList, _, _ := syscall_syscall6(kc_CFArrayCreate_trampoline_addr, 0, uintptr(unsafe.Pointer(&items[0])), 2, arrCB, 0, 0)
	runtime.KeepAlive(items)
	defer cfRelease(trustedList)
	desc := cfString(label)
	defer cfRelease(desc)
	var access uintptr
	r3, _, _ := syscall_syscall(kc_SecAccessCreate_trampoline_addr, desc, trustedList, uintptr(unsafe.Pointer(&access)))
	if int32(r3) != 0 || access == 0 {
		t.Fatalf("SecAccessCreate(multi-app): %d", int32(r3))
	}
	return access
}

func TestDarwinKeychainRejectsPrePlantedOpenOrMultiAppACLAndReplacesOnSave(t *testing.T) {
	dir := t.TempDir()
	acct := fmt.Sprintf("daemon.key.preplant.%d", os.Getpid())
	store := darwinKeychainStore{
		service: keychainService + ".test",
		account: acct,
	}
	t.Cleanup(func() { _ = store.Delete() })
	_ = store.Delete()

	attackerSeed := bytes.Repeat([]byte{0x41}, ed25519.SeedSize)

	// 1. Pre-seed an item with an open ("allow all applications") ACL.
	openAccess := createOpenAccess(t, store.service)
	attrs, refs := store.loginQuery()
	kPdmn, vPdmn := cfString("pdmn"), cfString("cku")
	kAcc := cfString("acls")
	kData, vData := cfString("v_Data"), cfData(attackerSeed)
	refs = append(refs, openAccess, kPdmn, vPdmn, kAcc, kData, vData)
	cfDictSet(attrs, kPdmn, vPdmn)
	cfDictSet(attrs, kAcc, openAccess)
	cfDictSet(attrs, kData, vData)
	r1, _, _ := syscall_syscall(kc_SecItemAdd_trampoline_addr, attrs, 0, 0)
	releaseAll(refs)
	if int32(r1) != 0 {
		t.Fatalf("SecItemAdd(openAccess): OSStatus %d", int32(r1))
	}

	// Load and loadOrCreateKeyWithStore must refuse the pre-planted open-ACL item.
	if got, ok, err := store.Load(); err == nil || ok || got != nil {
		t.Fatalf("Load accepted pre-planted open-ACL item: ok=%v err=%v", ok, err)
	} else if !strings.Contains(err.Error(), "allows all applications") {
		t.Fatalf("Load error = %v, want 'allows all applications'", err)
	}
	keyPath := filepath.Join(dir, "daemon.key")
	if _, err := loadOrCreateKeyWithStore(keyPath, store); err == nil {
		t.Fatal("loadOrCreateKeyWithStore accepted pre-planted open-ACL item")
	}

	// Inject a failure on the second SecItemAdd call during Save's replacement
	// of the untrusted item and verify Save returns an error.
	var addCalls int
	secItemAddHook = func(uintptr) (int32, bool) {
		addCalls++
		if addCalls == 2 {
			return -25291, true // errSecNotAvailable on the replacement add
		}
		return 0, false
	}
	realSeed := bytes.Repeat([]byte{0x99}, ed25519.SeedSize)
	if err := store.Save(realSeed); err == nil {
		secItemAddHook = nil
		t.Fatal("expected Save to fail when the second SecItemAdd fails after deleting untrusted item")
	}
	secItemAddHook = nil

	// Re-plant the open-ACL item and verify a normal Save replaces it with a
	// self-only ACL item.
	openAccess2 := createOpenAccess(t, store.service)
	attrsR, refsR := store.loginQuery()
	kPdmnR, vPdmnR := cfString("pdmn"), cfString("cku")
	kAccR := cfString("acls")
	kDataR, vDataR := cfString("v_Data"), cfData(attackerSeed)
	refsR = append(refsR, openAccess2, kPdmnR, vPdmnR, kAccR, kDataR, vDataR)
	cfDictSet(attrsR, kPdmnR, vPdmnR)
	cfDictSet(attrsR, kAccR, openAccess2)
	cfDictSet(attrsR, kDataR, vDataR)
	_, _, _ = syscall_syscall(kc_SecItemAdd_trampoline_addr, attrsR, 0, 0)
	releaseAll(refsR)

	if err := store.Save(realSeed); err != nil {
		t.Fatalf("Save over pre-planted open-ACL item: %v", err)
	}
	got, ok, err := store.Load()
	if err != nil || !ok || !bytes.Equal(got, realSeed) {
		t.Fatalf("Load after Save replaced open-ACL item: ok=%v err=%v", ok, err)
	}

	// Now that the stored item has a valid self-only ACL, a subsequent Save updates
	// in place via SecItemUpdate without ever calling Delete or a second SecItemAdd
	// (so a second-add failure hook cannot fire or lose the valid key).
	secItemAddHook = func(uintptr) (int32, bool) {
		return errSecDuplicateItem, true
	}
	rotatedSeed := bytes.Repeat([]byte{0x77}, ed25519.SeedSize)
	err = store.Save(rotatedSeed)
	secItemAddHook = nil
	if err != nil {
		t.Fatalf("in-place Save(rotatedSeed) on valid self-only item: %v", err)
	}
	got, ok, err = store.Load()
	if err != nil || !ok || !bytes.Equal(got, rotatedSeed) {
		t.Fatalf("Load after in-place Save(rotatedSeed): ok=%v err=%v", ok, err)
	}
	_ = store.Delete()

	// 2. Pre-seed an item whose ACL trusts both self and /usr/bin/security.
	multiAccess := createMultiAppAccess(t, store.service)
	attrs2, refs2 := store.loginQuery()
	kPdmn2, vPdmn2 := cfString("pdmn"), cfString("cku")
	kAcc2 := cfString("acls")
	kData2, vData2 := cfString("v_Data"), cfData(attackerSeed)
	refs2 = append(refs2, multiAccess, kPdmn2, vPdmn2, kAcc2, kData2, vData2)
	cfDictSet(attrs2, kPdmn2, vPdmn2)
	cfDictSet(attrs2, kAcc2, multiAccess)
	cfDictSet(attrs2, kData2, vData2)
	r2, _, _ := syscall_syscall(kc_SecItemAdd_trampoline_addr, attrs2, 0, 0)
	releaseAll(refs2)
	if int32(r2) != 0 {
		t.Fatalf("SecItemAdd(multiAccess): OSStatus %d", int32(r2))
	}
	if got, ok, err := store.Load(); err == nil || ok || got != nil {
		t.Fatalf("Load accepted pre-planted multi-app ACL item: ok=%v err=%v", ok, err)
	} else if !strings.Contains(err.Error(), "trusts 2 applications, want 1") {
		t.Fatalf("Load error = %v, want 'trusts 2 applications, want 1'", err)
	}
}

func TestDarwinKeychainFailsClosedOnMalformedItemOrDiskKey(t *testing.T) {
	dir := t.TempDir()
	acct := fmt.Sprintf("daemon.key.malformed.%d", os.Getpid())
	store := darwinKeychainStore{
		service: keychainService + ".test",
		account: acct,
	}
	t.Cleanup(func() { _ = store.Delete() })
	_ = store.Delete()

	// Insert a non-32-byte payload with a valid self-only ACL.
	access, err := createSelfOnlyAccess(store.service)
	if err != nil {
		t.Fatal(err)
	}
	attrs, refs := store.loginQuery()
	kPdmn := cfString("pdmn")
	vPdmn := cfString("cku")
	kAcc := cfString("acls")
	kData := cfString("v_Data")
	vData := cfData([]byte("SEW1-corrupted-or-wrapped-payload-not-32-bytes"))
	refs = append(refs, access, kPdmn, vPdmn, kAcc, kData, vData)
	cfDictSet(attrs, kPdmn, vPdmn)
	cfDictSet(attrs, kAcc, access)
	cfDictSet(attrs, kData, vData)
	r1, _, _ := syscall_syscall(kc_SecItemAdd_trampoline_addr, attrs, 0, 0)
	releaseAll(refs)
	if status := int32(r1); status != 0 {
		t.Fatalf("SecItemAdd test setup failed: OSStatus %d", status)
	}

	keyPath := filepath.Join(dir, "daemon.key")
	if _, err := loadOrCreateKeyWithStore(keyPath, store); err == nil {
		t.Fatal("expected loadOrCreateKeyWithStore to fail closed on non-32-byte keychain item")
	}
	_ = store.Delete()

	// Malformed on-disk daemon.key must also fail closed rather than minting a new key.
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKeyWithStore(keyPath, store); err == nil {
		t.Fatal("expected loadOrCreateKeyWithStore to fail closed on malformed on-disk daemon.key")
	}
}

func TestDarwinKeychainMigratesLegacyDiskKeyAndIgnoresPlantedKeychainFile(t *testing.T) {
	dir := t.TempDir()
	acct := fmt.Sprintf("daemon.key.migrate.%d", os.Getpid())
	svc := keychainService + ".test"
	store := darwinKeychainStore{
		service: svc,
		account: acct,
	}
	t.Cleanup(func() { _ = store.Delete() })
	_ = store.Delete()

	// 1. An attacker-planted daemon.keychain-db file in the state directory must
	// be ignored by Load() (never opened or imported).
	plantedKCPath := filepath.Join(dir, "daemon.keychain-db")
	out, err := exec.Command("/usr/bin/security", "create-keychain", "-p", "", plantedKCPath).CombinedOutput()
	if err != nil {
		t.Fatalf("security create-keychain: %v: %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/security", "delete-keychain", plantedKCPath).Run()
		_ = os.Remove(plantedKCPath)
	})
	if got, ok, err := store.Load(); err != nil || ok || got != nil {
		t.Fatalf("Load must ignore planted daemon.keychain-db, got ok=%v err=%v", ok, err)
	}

	// 2. Migrate from a legacy on-disk daemon.key file.
	seedDisk := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seedDisk); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "daemon.key")
	if err := os.WriteFile(keyPath, seedDisk, 0o600); err != nil {
		t.Fatal(err)
	}
	priv, err := loadOrCreateKeyWithStore(keyPath, store)
	if err != nil {
		t.Fatalf("loadOrCreateKeyWithStore from legacy daemon.key: %v", err)
	}
	if !bytes.Equal(priv.Seed(), seedDisk) {
		t.Fatal("migrated key seed did not match legacy daemon.key")
	}
	if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("expected legacy daemon.key to be removed after migration, got err=%v", err)
	}
	got, ok, err := store.Load()
	if err != nil || !ok || !bytes.Equal(got, seedDisk) {
		t.Fatalf("login keychain after daemon.key migration: ok=%v err=%v", ok, err)
	}
}

func TestDarwinKeySaveLoadRotateNeverLeaksKeyToChildArgvOrEnv(t *testing.T) {
	dir := t.TempDir()
	acct := fmt.Sprintf("daemon.key.noleak.%d", os.Getpid())
	store := darwinKeychainStore{
		service: keychainService + ".test",
		account: acct,
	}
	t.Cleanup(func() { _ = store.Delete() })
	_ = store.Delete()

	type childCall struct {
		name string
		args []string
		env  []string
	}
	var (
		mu    sync.Mutex
		calls []childCall
	)
	origHelper := runKeyHelperCmd
	runKeyHelperCmd = func(name string, args ...string) error {
		mu.Lock()
		calls = append(calls, childCall{
			name: name,
			args: append([]string(nil), args...),
			env:  os.Environ(),
		})
		mu.Unlock()
		return origHelper(name, args...)
	}
	t.Cleanup(func() { runKeyHelperCmd = origHelper })

	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(state, "daemon.key")

	// 1. Initial key generation + Save.
	priv1, err := loadOrCreateKeyWithStore(keyPath, store)
	if err != nil {
		t.Fatalf("first loadOrCreateKeyWithStore: %v", err)
	}
	seed1 := append([]byte(nil), priv1.Seed()...)

	// 2. Load existing key.
	privLoaded, err := loadOrCreateKeyWithStore(keyPath, store)
	if err != nil {
		t.Fatalf("second loadOrCreateKeyWithStore: %v", err)
	}
	if !bytes.Equal(privLoaded.Seed(), seed1) {
		t.Fatal("loaded key did not match saved key")
	}

	// 3. Rotate key via Save + reload.
	seed2 := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed2); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(seed2); err != nil {
		t.Fatalf("rotate Save(seed2): %v", err)
	}
	priv2, err := loadOrCreateKeyWithStore(keyPath, store)
	if err != nil {
		t.Fatalf("loadOrCreateKeyWithStore after rotate: %v", err)
	}
	if !bytes.Equal(priv2.Seed(), seed2) {
		t.Fatal("reloaded key after rotate did not match seed2")
	}

	mu.Lock()
	recorded := append([]childCall(nil), calls...)
	mu.Unlock()
	if len(recorded) == 0 {
		t.Fatal("expected runKeyHelperCmd to record child process invocations for ACL stripping")
	}

	var needles []string
	for _, s := range [][]byte{seed1, seed2} {
		needles = append(needles,
			string(s),
			hex.EncodeToString(s),
			strings.ToUpper(hex.EncodeToString(s)),
			base64.StdEncoding.EncodeToString(s),
			base64.RawStdEncoding.EncodeToString(s),
			base64.URLEncoding.EncodeToString(s),
			base64.RawURLEncoding.EncodeToString(s),
		)
	}

	for _, c := range recorded {
		if filepath.Base(c.name) == "security" {
			t.Fatalf("unexpected execution of security CLI: %s %v", c.name, c.args)
		}
		for _, arg := range c.args {
			for _, n := range needles {
				if n != "" && strings.Contains(arg, n) {
					t.Fatalf("child process %s argv leaked key material", c.name)
				}
			}
		}
		for _, kv := range c.env {
			for _, n := range needles {
				if n != "" && strings.Contains(kv, n) {
					t.Fatalf("child process %s env leaked key material", c.name)
				}
			}
		}
	}
}
