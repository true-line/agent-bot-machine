//go:build darwin

package daemon

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	keychainService       = "ai.true-line.agent-bot-machine"
	keychainAccount       = "daemon.key"
	errSecItemNotFound    = -25300
	errSecDuplicateItem   = -25299
	kCFStringEncodingUTF8 = 0x08000100
	rtldDefault           = ^uintptr(1) // RTLD_DEFAULT (-2) on Darwin
)

// errStaleBinaryACL means the item still trusts this executable's path but
// not the current bytes (an unsigned rebuild at the same path). Load may
// rebind the ACL to this binary. A different path still fails closed.
var errStaleBinaryACL = errors.New("keychain item ACL trusts this path but not this binary")

// Implemented in the runtime package (runtime/sys_darwin.go).
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall_syscall syscall.syscall
//go:linkname syscall_syscall6 syscall.syscall6

//go:cgo_import_dynamic kc_dlsym dlsym "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic kc_CFDataCreate CFDataCreate "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFDataGetLength CFDataGetLength "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFDataGetBytes CFDataGetBytes "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFPropertyListCreateWithData CFPropertyListCreateWithData "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFStringCreateWithBytes CFStringCreateWithBytes "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFDictionaryCreateMutable CFDictionaryCreateMutable "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFDictionarySetValue CFDictionarySetValue "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFArrayCreate CFArrayCreate "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFArrayGetCount CFArrayGetCount "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFArrayGetValueAtIndex CFArrayGetValueAtIndex "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_CFRelease CFRelease "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic kc_SecItemCopyMatching SecItemCopyMatching "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecItemAdd SecItemAdd "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecItemUpdate SecItemUpdate "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecItemDelete SecItemDelete "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecTrustedApplicationCreateFromPath SecTrustedApplicationCreateFromPath "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecTrustedApplicationValidateWithPath SecTrustedApplicationValidateWithPath "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecTrustedApplicationCopyData SecTrustedApplicationCopyData "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecAccessCreate SecAccessCreate "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecAccessCopyMatchingACLList SecAccessCopyMatchingACLList "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecACLCopyContents SecACLCopyContents "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecACLSetContents SecACLSetContents "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainItemCopyAccess SecKeychainItemCopyAccess "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainItemCopyAttributesAndData SecKeychainItemCopyAttributesAndData "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainItemFreeContent SecKeychainItemFreeContent "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainCreate SecKeychainCreate "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainOpen SecKeychainOpen "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainUnlock SecKeychainUnlock "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainSetUserInteractionAllowed SecKeychainSetUserInteractionAllowed "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainCopyDefault SecKeychainCopyDefault "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainSetDefault SecKeychainSetDefault "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainGetStatus SecKeychainGetStatus "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic kc_SecKeychainSetSettings SecKeychainSetSettings "/System/Library/Frameworks/Security.framework/Versions/A/Security"

var (
	kc_dlsym_trampoline_addr                                 uintptr
	kc_CFDataCreate_trampoline_addr                          uintptr
	kc_CFDataGetLength_trampoline_addr                       uintptr
	kc_CFDataGetBytes_trampoline_addr                        uintptr
	kc_CFPropertyListCreateWithData_trampoline_addr          uintptr
	kc_CFStringCreateWithBytes_trampoline_addr               uintptr
	kc_CFDictionaryCreateMutable_trampoline_addr             uintptr
	kc_CFDictionarySetValue_trampoline_addr                  uintptr
	kc_CFArrayCreate_trampoline_addr                         uintptr
	kc_CFArrayGetCount_trampoline_addr                       uintptr
	kc_CFArrayGetValueAtIndex_trampoline_addr                uintptr
	kc_CFRelease_trampoline_addr                             uintptr
	kc_SecItemCopyMatching_trampoline_addr                   uintptr
	kc_SecItemAdd_trampoline_addr                            uintptr
	kc_SecItemUpdate_trampoline_addr                         uintptr
	kc_SecItemDelete_trampoline_addr                         uintptr
	kc_SecTrustedApplicationCreateFromPath_trampoline_addr   uintptr
	kc_SecTrustedApplicationValidateWithPath_trampoline_addr uintptr
	kc_SecTrustedApplicationCopyData_trampoline_addr         uintptr
	kc_SecAccessCreate_trampoline_addr                       uintptr
	kc_SecAccessCopyMatchingACLList_trampoline_addr          uintptr
	kc_SecACLCopyContents_trampoline_addr                    uintptr
	kc_SecACLSetContents_trampoline_addr                     uintptr
	kc_SecKeychainItemCopyAccess_trampoline_addr             uintptr
	kc_SecKeychainItemCopyAttributesAndData_trampoline_addr  uintptr
	kc_SecKeychainItemFreeContent_trampoline_addr            uintptr
	kc_SecKeychainCreate_trampoline_addr                     uintptr
	kc_SecKeychainOpen_trampoline_addr                       uintptr
	kc_SecKeychainUnlock_trampoline_addr                     uintptr
	kc_SecKeychainSetUserInteractionAllowed_trampoline_addr  uintptr
	kc_SecKeychainCopyDefault_trampoline_addr                uintptr
	kc_SecKeychainSetDefault_trampoline_addr                 uintptr
	kc_SecKeychainGetStatus_trampoline_addr                  uintptr
	kc_SecKeychainSetSettings_trampoline_addr                uintptr
)

const kSecUnlockStateStatus = 1

type secKeychainSettings struct {
	version         uint32
	lockOnSleep     uint8
	useLockInterval uint8
	_               uint16
	lockInterval    uint32
}

func cfSymAddr(name string) uintptr {
	b := append([]byte(name), 0)
	p := unsafe.Pointer(unsafe.SliceData(b))
	r1, _, _ := syscall_syscall(kc_dlsym_trampoline_addr, rtldDefault, uintptr(p), 0)
	runtime.KeepAlive(b)
	return r1
}

func cfTrue() uintptr {
	d := cfData([]byte(`<plist version="1.0"><true/></plist>`))
	defer cfRelease(d)
	r1, _, _ := syscall_syscall6(kc_CFPropertyListCreateWithData_trampoline_addr, 0, d, 0, 0, 0, 0)
	return r1
}

func cfString(s string) uintptr {
	p := unsafe.Pointer(unsafe.StringData(s))
	r1, _, _ := syscall_syscall6(kc_CFStringCreateWithBytes_trampoline_addr, 0, uintptr(p), uintptr(len(s)), kCFStringEncodingUTF8, 0, 0)
	runtime.KeepAlive(s)
	return r1
}

func cfData(b []byte) uintptr {
	var p unsafe.Pointer
	if len(b) > 0 {
		p = unsafe.Pointer(unsafe.SliceData(b))
	}
	r1, _, _ := syscall_syscall(kc_CFDataCreate_trampoline_addr, 0, uintptr(p), uintptr(len(b)))
	runtime.KeepAlive(b)
	return r1
}

func cfDataBytes(ref uintptr) []byte {
	n, _, _ := syscall_syscall(kc_CFDataGetLength_trampoline_addr, ref, 0, 0)
	if int(n) <= 0 {
		return nil
	}
	out := make([]byte, int(n))
	p := unsafe.Pointer(unsafe.SliceData(out))
	syscall_syscall6(kc_CFDataGetBytes_trampoline_addr, ref, 0, n, uintptr(p), 0, 0)
	runtime.KeepAlive(out)
	return out
}

func cfArrayCount(arr uintptr) int {
	if arr == 0 {
		return 0
	}
	r1, _, _ := syscall_syscall(kc_CFArrayGetCount_trampoline_addr, arr, 0, 0)
	return int(r1)
}

func cfArrayGet(arr uintptr, idx int) uintptr {
	r1, _, _ := syscall_syscall(kc_CFArrayGetValueAtIndex_trampoline_addr, arr, uintptr(idx), 0)
	return r1
}

func cfRelease(ref uintptr) {
	if ref != 0 {
		syscall_syscall(kc_CFRelease_trampoline_addr, ref, 0, 0)
	}
}

func cfNewDict() uintptr {
	keyCB := cfSymAddr("kCFTypeDictionaryKeyCallBacks")
	valCB := cfSymAddr("kCFTypeDictionaryValueCallBacks")
	r1, _, _ := syscall_syscall6(kc_CFDictionaryCreateMutable_trampoline_addr, 0, 0, keyCB, valCB, 0, 0)
	return r1
}

func cfDictSet(dict, key, val uintptr) {
	if dict != 0 && key != 0 && val != 0 {
		syscall_syscall(kc_CFDictionarySetValue_trampoline_addr, dict, key, val)
	}
}

func releaseAll(refs []uintptr) {
	for _, r := range refs {
		cfRelease(r)
	}
}

// createSelfOnlyAccess builds a SecAccessRef whose ACL trusts only the calling
// executable (SecTrustedApplicationCreateFromPath(NULL, ...)). For a Developer
// ID signed binary, macOS binds the trusted application to its code signing
// designated requirement (identifier + Developer ID Team ID).
func createSelfOnlyAccess(label string) (uintptr, error) {
	var selfApp uintptr
	r1, _, _ := syscall_syscall(kc_SecTrustedApplicationCreateFromPath_trampoline_addr, 0, uintptr(unsafe.Pointer(&selfApp)), 0)
	if status := int32(r1); status != 0 || selfApp == 0 {
		return 0, fmt.Errorf("SecTrustedApplicationCreateFromPath failed: OSStatus %d", int32(r1))
	}
	defer cfRelease(selfApp)
	items := [1]uintptr{selfApp}
	arrCB := cfSymAddr("kCFTypeArrayCallBacks")
	trustedList, _, _ := syscall_syscall6(kc_CFArrayCreate_trampoline_addr, 0, uintptr(unsafe.Pointer(&items[0])), 1, arrCB, 0, 0)
	runtime.KeepAlive(items)
	if trustedList == 0 {
		return 0, errors.New("CFArrayCreate for trusted application list returned nil")
	}
	defer cfRelease(trustedList)
	desc := cfString(label)
	defer cfRelease(desc)
	var accessRef uintptr
	r2, _, _ := syscall_syscall(kc_SecAccessCreate_trampoline_addr, desc, trustedList, uintptr(unsafe.Pointer(&accessRef)))
	if status := int32(r2); status != 0 || accessRef == 0 {
		return 0, fmt.Errorf("SecAccessCreate failed: OSStatus %d", int32(r2))
	}
	return accessRef, nil
}

// verifyItemSelfOnlyACL inspects a SecKeychainItemRef's SecAccessRef before its
// secret data is read and verifies that:
//   - ACLAuthorizationDecrypt and ACLAuthorizationExportClear each have exactly
//     one ACL entry whose trusted application list is non-NULL (rejecting an
//     "allow all applications" -A ACL), has length 1, and validates against the
//     calling executable (SecTrustedApplicationValidateWithPath(app, NULL) == 0).
//   - ACLAuthorizationChangeACL has an empty trusted application list so no
//     process can silently alter the item's ACL.
func verifyItemSelfOnlyACL(itemRef uintptr) error {
	var accessRef uintptr
	r1, _, _ := syscall_syscall(kc_SecKeychainItemCopyAccess_trampoline_addr, itemRef, uintptr(unsafe.Pointer(&accessRef)), 0)
	if status := int32(r1); status != 0 || accessRef == 0 {
		return fmt.Errorf("SecKeychainItemCopyAccess failed: OSStatus %d", int32(r1))
	}
	defer cfRelease(accessRef)

	for _, authTag := range []string{"ACLAuthorizationDecrypt", "ACLAuthorizationExportClear"} {
		tagRef := cfString(authTag)
		aclList, _, _ := syscall_syscall(kc_SecAccessCopyMatchingACLList_trampoline_addr, accessRef, tagRef, 0)
		cfRelease(tagRef)
		if aclList == 0 {
			return fmt.Errorf("keychain item missing %s ACL", authTag)
		}
		if n := cfArrayCount(aclList); n != 1 {
			cfRelease(aclList)
			return fmt.Errorf("keychain item has %d %s ACL entries, want 1", n, authTag)
		}
		acl := cfArrayGet(aclList, 0)
		var appList, desc uintptr
		var prompt uint16
		r2, _, _ := syscall_syscall6(kc_SecACLCopyContents_trampoline_addr, acl, uintptr(unsafe.Pointer(&appList)), uintptr(unsafe.Pointer(&desc)), uintptr(unsafe.Pointer(&prompt)), 0, 0)
		cfRelease(aclList)
		if desc != 0 {
			cfRelease(desc)
		}
		if status := int32(r2); status != 0 {
			if appList != 0 {
				cfRelease(appList)
			}
			return fmt.Errorf("SecACLCopyContents(%s) failed: OSStatus %d", authTag, status)
		}
		if appList == 0 {
			return fmt.Errorf("keychain item %s ACL allows all applications (unrestricted)", authTag)
		}
		if n := cfArrayCount(appList); n != 1 {
			cfRelease(appList)
			return fmt.Errorf("keychain item %s ACL trusts %d applications, want 1", authTag, n)
		}
		app := cfArrayGet(appList, 0)
		rv, _, _ := syscall_syscall(kc_SecTrustedApplicationValidateWithPath_trampoline_addr, app, 0, 0)
		vstatus := int32(rv)
		samePath := trustedAppMatchesExecutable(app)
		cfRelease(appList)
		if vstatus != 0 {
			if samePath {
				return fmt.Errorf("%w (%s): OSStatus %d", errStaleBinaryACL, authTag, vstatus)
			}
			return fmt.Errorf("keychain item %s ACL does not trust only this binary: OSStatus %d", authTag, vstatus)
		}
	}

	chgTag := cfString("ACLAuthorizationChangeACL")
	chgList, _, _ := syscall_syscall(kc_SecAccessCopyMatchingACLList_trampoline_addr, accessRef, chgTag, 0)
	cfRelease(chgTag)
	if chgList == 0 {
		return errors.New("keychain item missing ACLAuthorizationChangeACL entry")
	}
	defer cfRelease(chgList)
	if n := cfArrayCount(chgList); n != 1 {
		return fmt.Errorf("keychain item has %d ACLAuthorizationChangeACL entries, want 1", n)
	}
	var chgApps, chgDesc uintptr
	var chgPrompt uint16
	rc, _, _ := syscall_syscall6(kc_SecACLCopyContents_trampoline_addr, cfArrayGet(chgList, 0), uintptr(unsafe.Pointer(&chgApps)), uintptr(unsafe.Pointer(&chgDesc)), uintptr(unsafe.Pointer(&chgPrompt)), 0, 0)
	if chgDesc != 0 {
		cfRelease(chgDesc)
	}
	if chgApps != 0 {
		defer cfRelease(chgApps)
	}
	if status := int32(rc); status != 0 {
		return fmt.Errorf("SecACLCopyContents(ACLAuthorizationChangeACL) failed: OSStatus %d", status)
	}
	if chgApps == 0 || cfArrayCount(chgApps) != 0 {
		return errors.New("keychain item ACLAuthorizationChangeACL is not restricted")
	}
	return nil
}

func currentExecutablePath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved, nil
	}
	return filepath.Clean(p), nil
}

func trustedAppPath(app uintptr) (string, error) {
	var data uintptr
	r1, _, _ := syscall_syscall(kc_SecTrustedApplicationCopyData_trampoline_addr, app, uintptr(unsafe.Pointer(&data)), 0)
	if status := int32(r1); status != 0 || data == 0 {
		return "", fmt.Errorf("SecTrustedApplicationCopyData failed: OSStatus %d", int32(r1))
	}
	defer cfRelease(data)
	return pathFromTrustedAppData(cfDataBytes(data))
}

func pathFromTrustedAppData(b []byte) (string, error) {
	i := bytes.IndexByte(b, '/')
	if i < 0 {
		return "", errors.New("trusted application data has no path")
	}
	rest := b[i:]
	if n := bytes.IndexByte(rest, 0); n >= 0 {
		rest = rest[:n]
	}
	p := string(rest)
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("trusted application path %q is not absolute", p)
	}
	return filepath.Clean(p), nil
}

func trustedAppMatchesExecutable(app uintptr) bool {
	trusted, err := trustedAppPath(app)
	if err != nil {
		return false
	}
	self, err := currentExecutablePath()
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(trusted); err == nil {
		trusted = resolved
	}
	return trusted == self
}

func readKeychainItemBytes(itemRef uintptr) ([]byte, error) {
	var length uint32
	var dataPtr *byte
	r1, _, _ := syscall_syscall6(
		kc_SecKeychainItemCopyAttributesAndData_trampoline_addr,
		itemRef,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&length)),
		uintptr(unsafe.Pointer(&dataPtr)),
	)
	if status := int32(r1); status != 0 {
		return nil, fmt.Errorf("SecKeychainItemCopyAttributesAndData failed: OSStatus %d", status)
	}
	if dataPtr == nil {
		return nil, errors.New("SecKeychainItemCopyAttributesAndData returned nil data")
	}
	defer syscall_syscall(kc_SecKeychainItemFreeContent_trampoline_addr, 0, uintptr(unsafe.Pointer(dataPtr)), 0)
	src := unsafe.Slice(dataPtr, int(length))
	out := append([]byte(nil), src...)
	zeroBytes(src)
	return out, nil
}

var (
	// testKeychainAccountOverride is nil in production builds; tests in
	// keychain_darwin_test.go set it so unit tests use an isolated test account
	// name without touching the host's live daemon.key keychain item.
	testKeychainAccountOverride func(cleanPath string) string

	// secItemAddHook is nil in production builds; tests set it to inject a
	// failure on the second SecItemAdd call during duplicate replacement.
	secItemAddHook func(attrs uintptr) (int32, bool)
)

func callSecItemAdd(attrs uintptr) int32 {
	if secItemAddHook != nil {
		if st, ok := secItemAddHook(attrs); ok {
			return st
		}
	}
	r1, _, _ := syscall_syscall(kc_SecItemAdd_trampoline_addr, attrs, 0, 0)
	return int32(r1)
}

// darwinKeychainStore stores the daemon's 32-byte Ed25519 seed in a dedicated
// file keychain next to daemon state (daemon.keychain-db). The prefix-owner
// account has no usable login keychain, so Save never asks securityd for
// login.keychain-db or System.keychain. The item carries a self-only
// SecAccessRef ACL. kSecAttrAccessible is omitted: that Data Protection
// attribute on a file keychain makes SecItemAdd call Authorization Services
// and fail with OSStatus -60008 when no GUI session can prompt.
type darwinKeychainStore struct {
	service      string
	account      string
	keychainPath string
}

// defaultKeyStore returns a darwinKeychainStore backed by a dedicated file
// keychain beside the would-be daemon.key path.
func defaultKeyStore(path string) keyStore {
	clean := filepath.Clean(path)
	acct := keychainAccount
	if testKeychainAccountOverride != nil {
		if a := testKeychainAccountOverride(clean); a != "" {
			acct = a
		}
	}
	return darwinKeychainStore{
		service:      keychainService,
		account:      acct,
		keychainPath: filepath.Join(filepath.Dir(clean), "daemon.keychain-db"),
	}
}

func disableKeychainPrompts() {
	syscall_syscall(kc_SecKeychainSetUserInteractionAllowed_trampoline_addr, 0, 0, 0)
}

func copyDefaultKeychain() uintptr {
	var def uintptr
	r1, _, _ := syscall_syscall(kc_SecKeychainCopyDefault_trampoline_addr, uintptr(unsafe.Pointer(&def)), 0, 0)
	if int32(r1) != 0 {
		return 0
	}
	return def
}

func restoreDefaultKeychain(prev uintptr) {
	if prev == 0 {
		return
	}
	syscall_syscall(kc_SecKeychainSetDefault_trampoline_addr, prev, 0, 0)
	cfRelease(prev)
}

func configureDedicatedKeychain(kc uintptr) {
	settings := secKeychainSettings{version: 1, lockOnSleep: 0, useLockInterval: 0, lockInterval: 0}
	syscall_syscall(kc_SecKeychainSetSettings_trampoline_addr, kc, uintptr(unsafe.Pointer(&settings)), 0)
	runtime.KeepAlive(settings)
}

func unlockDedicatedKeychain(kc uintptr) error {
	var status uint32
	rg, _, _ := syscall_syscall(kc_SecKeychainGetStatus_trampoline_addr, kc, uintptr(unsafe.Pointer(&status)), 0)
	if int32(rg) == 0 && status&kSecUnlockStateStatus != 0 {
		return nil
	}
	disableKeychainPrompts()
	defer syscall_syscall(kc_SecKeychainSetUserInteractionAllowed_trampoline_addr, 1, 0, 0)
	empty := [1]byte{0}
	r2, _, _ := syscall_syscall6(kc_SecKeychainUnlock_trampoline_addr, kc, 0, uintptr(unsafe.Pointer(&empty[0])), 1, 0, 0)
	runtime.KeepAlive(empty)
	if st := int32(r2); st != 0 {
		rg, _, _ = syscall_syscall(kc_SecKeychainGetStatus_trampoline_addr, kc, uintptr(unsafe.Pointer(&status)), 0)
		if int32(rg) == 0 && status&kSecUnlockStateStatus != 0 {
			return nil
		}
		return fmt.Errorf("SecKeychainUnlock failed: OSStatus %d (password is empty — do not type one)", st)
	}
	return nil
}

func (s darwinKeychainStore) openDedicatedKeychain(create bool) (uintptr, uintptr, error) {
	if s.keychainPath == "" {
		return 0, 0, errors.New("dedicated keychain path is required")
	}
	dir := filepath.Dir(s.keychainPath)
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return 0, 0, err
		}
		_ = stripDarwinACL(dir)
		_ = os.Chmod(dir, 0o700)
	}
	prevDefault := copyDefaultKeychain()
	defer restoreDefaultKeychain(prevDefault)
	cpath := append([]byte(s.keychainPath), 0)
	p := unsafe.Pointer(unsafe.SliceData(cpath))
	empty := [1]byte{0}
	ep := unsafe.Pointer(&empty[0])
	var kc uintptr
	if _, err := os.Lstat(s.keychainPath); errors.Is(err, os.ErrNotExist) {
		if !create {
			return 0, 0, nil
		}
		r1, _, _ := syscall_syscall6(kc_SecKeychainCreate_trampoline_addr, uintptr(p), 0, uintptr(ep), 0, 0, uintptr(unsafe.Pointer(&kc)))
		runtime.KeepAlive(cpath)
		runtime.KeepAlive(empty)
		if status := int32(r1); status != 0 || kc == 0 {
			return 0, 0, fmt.Errorf("SecKeychainCreate failed: OSStatus %d", status)
		}
		_ = stripDarwinACL(s.keychainPath)
		_ = os.Chmod(s.keychainPath, 0o600)
	} else if err != nil {
		return 0, 0, err
	} else {
		r1, _, _ := syscall_syscall(kc_SecKeychainOpen_trampoline_addr, uintptr(p), uintptr(unsafe.Pointer(&kc)), 0)
		runtime.KeepAlive(cpath)
		if status := int32(r1); status != 0 || kc == 0 {
			return 0, 0, fmt.Errorf("SecKeychainOpen failed: OSStatus %d", status)
		}
		if err := unlockDedicatedKeychain(kc); err != nil {
			cfRelease(kc)
			return 0, 0, err
		}
	}
	items := [1]uintptr{kc}
	arrCB := cfSymAddr("kCFTypeArrayCallBacks")
	searchList, _, _ := syscall_syscall6(kc_CFArrayCreate_trampoline_addr, 0, uintptr(unsafe.Pointer(&items[0])), 1, arrCB, 0, 0)
	runtime.KeepAlive(items)
	if searchList == 0 {
		cfRelease(kc)
		return 0, 0, errors.New("CFArrayCreate for dedicated keychain search list returned nil")
	}
	return kc, searchList, nil
}

func (s darwinKeychainStore) itemQuery(kc, searchList uintptr, useKeychain bool) (uintptr, []uintptr) {
	dict := cfNewDict()
	kClass := cfString("class")
	vClass := cfString("genp")
	kSvc := cfString("svce")
	vSvc := cfString(s.service)
	kAcct := cfString("acct")
	vAcct := cfString(s.account)
	kSearch := cfString("m_SearchList")
	cfDictSet(dict, kClass, vClass)
	cfDictSet(dict, kSvc, vSvc)
	cfDictSet(dict, kAcct, vAcct)
	cfDictSet(dict, kSearch, searchList)
	refs := []uintptr{dict, kClass, vClass, kSvc, vSvc, kAcct, vAcct, kSearch}
	if useKeychain && kc != 0 {
		kUse := cfString("u_Keychain")
		refs = append(refs, kUse)
		cfDictSet(dict, kUse, kc)
	}
	return dict, refs
}

func (s darwinKeychainStore) copyItemRef() (uintptr, int32, error) {
	kc, searchList, err := s.openDedicatedKeychain(false)
	if err != nil {
		return 0, 0, err
	}
	if kc == 0 {
		return 0, errSecItemNotFound, nil
	}
	defer cfRelease(kc)
	defer cfRelease(searchList)
	query, refs := s.itemQuery(kc, searchList, false)
	kRetRef := cfString("r_Ref")
	vTrue := cfTrue()
	kLim := cfString("m_Limit")
	vLim := cfString("m_LimitOne")
	refs = append(refs, kRetRef, vTrue, kLim, vLim)
	cfDictSet(query, kRetRef, vTrue)
	cfDictSet(query, kLim, vLim)
	var itemRef uintptr
	r1, _, _ := syscall_syscall(kc_SecItemCopyMatching_trampoline_addr, query, uintptr(unsafe.Pointer(&itemRef)), 0)
	releaseAll(refs)
	return itemRef, int32(r1), nil
}

// Load reads the 32-byte Ed25519 seed from the dedicated keychain in-process
// via SecItemCopyMatching, verifying the item's SecAccessRef ACL trusts only
// this binary before reading its secret bytes. Only a missing keychain file
// or errSecItemNotFound (-25300) is treated as absent; every other OSStatus
// (locked keychain or an untrusted ACL) fails closed with an error.
func (s darwinKeychainStore) Load() ([]byte, bool, error) {
	itemRef, status, err := s.copyItemRef()
	if err != nil {
		return nil, false, err
	}
	if status == 0 {
		if itemRef == 0 {
			return nil, false, errors.New("keychain SecItemCopyMatching returned nil item reference")
		}
		aclErr := verifyItemSelfOnlyACL(itemRef)
		if aclErr != nil && !errors.Is(aclErr, errStaleBinaryACL) {
			cfRelease(itemRef)
			return nil, false, aclErr
		}
		raw, err := readKeychainItemBytes(itemRef)
		cfRelease(itemRef)
		if err != nil {
			if errors.Is(aclErr, errStaleBinaryACL) {
				if derr := s.Delete(); derr != nil {
					return nil, false, fmt.Errorf("stale binary ACL and rotate failed: %v (read: %v)", derr, err)
				}
				return nil, false, nil
			}
			return nil, false, err
		}
		if len(raw) != ed25519.SeedSize {
			zeroBytes(raw)
			return nil, false, fmt.Errorf("keychain item has invalid length %d", len(raw))
		}
		if errors.Is(aclErr, errStaleBinaryACL) {
			if err := s.Save(raw); err != nil {
				zeroBytes(raw)
				return nil, false, err
			}
		}
		return raw, true, nil
	}
	if status != errSecItemNotFound {
		return nil, false, fmt.Errorf("keychain SecItemCopyMatching failed: OSStatus %d", status)
	}
	return nil, false, nil
}

// Save stores the 32-byte Ed25519 seed in the dedicated keychain with a
// SecAccessRef ACL trusting only the daemon binary. It targets that keychain
// with kSecUseKeychain so SecItemAdd never falls through to the login or
// System keychain.
//
// On errSecDuplicateItem:
//   - If the existing item already passes verifyItemSelfOnlyACL, Save updates
//     its data in place via SecItemUpdate so a failure or crash can never delete
//     a valid existing daemon key.
//   - Only if the existing item fails verifyItemSelfOnlyACL (an untrusted
//     pre-planted item) does Save delete it and re-add with a fresh self-only
//     SecAccessRef.
func (s darwinKeychainStore) Save(seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return os.ErrInvalid
	}
	kc, searchList, err := s.openDedicatedKeychain(true)
	if err != nil {
		return err
	}
	defer cfRelease(kc)
	defer cfRelease(searchList)
	access, err := createSelfOnlyAccess(s.service)
	if err != nil {
		return err
	}
	attrs, refs := s.itemQuery(kc, searchList, true)
	kAcc := cfString("acls")
	kData := cfString("v_Data")
	vData := cfData(seed)
	refs = append(refs, access, kAcc, kData, vData)
	defer releaseAll(refs)
	cfDictSet(attrs, kAcc, access)
	cfDictSet(attrs, kData, vData)
	status := callSecItemAdd(attrs)
	if status == 0 {
		return nil
	}
	if status != errSecDuplicateItem {
		return fmt.Errorf("keychain SecItemAdd failed: OSStatus %d", status)
	}

	itemRef, lstatus, err := s.copyItemRef()
	if err != nil {
		return err
	}
	if lstatus != 0 || itemRef == 0 {
		return fmt.Errorf("keychain duplicate item lookup failed: OSStatus %d", lstatus)
	}
	aclErr := verifyItemSelfOnlyACL(itemRef)
	cfRelease(itemRef)
	if aclErr == nil {
		matchQ, mRefs := s.itemQuery(kc, searchList, false)
		upd := cfNewDict()
		ukData := cfString("v_Data")
		uvData := cfData(seed)
		mRefs = append(mRefs, upd, ukData, uvData)
		cfDictSet(upd, ukData, uvData)
		ru, _, _ := syscall_syscall(kc_SecItemUpdate_trampoline_addr, matchQ, upd, 0)
		releaseAll(mRefs)
		if ust := int32(ru); ust != 0 {
			return fmt.Errorf("keychain SecItemUpdate failed: OSStatus %d", ust)
		}
		return nil
	}

	if err := s.deleteIn(kc, searchList); err != nil {
		return err
	}
	if status = callSecItemAdd(attrs); status != 0 {
		return fmt.Errorf("keychain SecItemAdd after replacing untrusted item failed: OSStatus %d", status)
	}
	return nil
}

func (s darwinKeychainStore) deleteIn(kc, searchList uintptr) error {
	query, refs := s.itemQuery(kc, searchList, false)
	r1, _, _ := syscall_syscall(kc_SecItemDelete_trampoline_addr, query, 0, 0)
	releaseAll(refs)
	status := int32(r1)
	if status != 0 && status != errSecItemNotFound {
		return fmt.Errorf("keychain SecItemDelete failed: OSStatus %d", status)
	}
	return nil
}

func (s darwinKeychainStore) Delete() error {
	kc, searchList, err := s.openDedicatedKeychain(false)
	if err != nil {
		return err
	}
	if kc == 0 {
		return nil
	}
	defer cfRelease(kc)
	defer cfRelease(searchList)
	return s.deleteIn(kc, searchList)
}
