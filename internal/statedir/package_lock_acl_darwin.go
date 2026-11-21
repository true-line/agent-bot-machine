package statedir

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:linkname macLockSyscall6 syscall.syscall6
func macLockSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno)

//go:cgo_import_dynamic mac_lock_fgetattrlist fgetattrlist "/usr/lib/libSystem.B.dylib"

var macGetattrlistAddr uintptr

// Read the ACL on the same open descriptor checked by Fstat. Darwin extended
// ACLs can grant rights independently of the group/other mode bits.
func SafeMacPathACL(fd int, allowReadOnlyACE bool) bool {
	attrs := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	var buf [8192]byte // enough for Darwin's maximum extended ACL
	rc, _, _ := macLockSyscall6(macGetattrlistAddr, uintptr(fd), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf)), uintptr(len(buf)), 0, 0)
	runtime.KeepAlive(&attrs)
	runtime.KeepAlive(&buf)
	if rc != 0 {
		return false
	}
	// getattrlist(2): packed result length and an attrreference_t relative
	// to its own address; payload is sys/kauth.h's kauth_filesec.
	word := binary.NativeEndian.Uint32
	total, offset, size := int(word(buf[0:4])), int(word(buf[4:8]))+4, int(word(buf[8:12]))
	if total < 12 || total > len(buf) || offset < 12 || offset > total || size > total-offset {
		return false
	}
	if size == 0 {
		return true
	}
	acl := buf[offset : offset+size]
	const header, entrySize = 44, 24 // magic, owner/group GUIDs, entry count, flags; each ACE has GUID, flags, rights
	if size < header || word(acl[:4]) != 0x012cc16d {
		return false
	}
	count := word(acl[36:40])
	if count == 0xffffffff {
		return size == header
	} // KAUTH_FILESEC_NOACL
	if int(count)*entrySize != size-header {
		return false
	}
	for entry := header; entry < size; entry += entrySize {
		flags, rights := word(acl[entry+16:]), word(acl[entry+20:])
		switch flags & 0xf {
		case 2: // KAUTH_ACE_DENY, including the standard home-directory deny-delete ACE
		case 1: // KAUTH_ACE_PERMIT
			// Directories may grant listing, searching, and reading attributes
			// or security metadata. An allow ACE on a private file is refused.
			const readOnly = 1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11 | 1<<20 | 1<<22 | 1<<24
			if !allowReadOnlyACE || rights & ^uint32(readOnly) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
