// Machine's device signer uses the CryptoKit representation exercised by HQ's
// macOS probe. Only the admin keyd stores it, in a code-restricted item.
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

private typealias DeviceKey = SecureEnclave.P256.Signing.PrivateKey

// Return only a reference on create, public point on inspect, or raw signature
// on sign. Each call disables authentication prompts in the service account.
@_cdecl("keyd_device_enclave")
public func keydDeviceEnclave(
    _ op: Int32, _ reference: UnsafePointer<UInt8>, _ nr: Int,
    _ message: UnsafePointer<UInt8>, _ nm: Int, _ output: UnsafeMutablePointer<UInt8>, _ cap: Int
) -> Int {
    guard nr >= 0, nr <= 8192, nm >= 0, nm <= 8192, cap > 0, SecureEnclave.isAvailable else { return -1 }
    let ctx = LAContext()
    ctx.interactionNotAllowed = true
    do {
        let result: Data
        switch op {
        case 0:
            guard nr == 0, nm == 0, let access = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], nil)
            else { return -1 }
            let key = try DeviceKey(compactRepresentable: true, accessControl: access, authenticationContext: ctx)
            result = key.dataRepresentation
        case 1, 2:
            guard nr > 0 else { return -1 }
            let key = try DeviceKey(dataRepresentation: Data(bytes: reference, count: nr), authenticationContext: ctx)
            if op == 1 {
                result = key.publicKey.x963Representation
            } else {
                guard nm > 0 else { return -1 }
                let payload = Data(bytes: message, count: nm)
                let signature = try key.signature(for: payload)
                guard key.publicKey.isValidSignature(signature, for: payload) else { return -1 }
                result = signature.rawRepresentation
            }
        default:
            return -1
        }
        guard !result.isEmpty, result.count <= cap else { return -1 }
        result.copyBytes(to: output, count: result.count)
        return result.count
    } catch {
        return -1
    }
}

// Inspect the ACL on the same descriptor as the ownership and mode checks.
// Allow read-only directory grants and the standard owner-home deny-delete entry.
@_cdecl("keyd_device_safe_acl")
public func keydDeviceSafeACL(_ fd: Int32, _ directory: Int32) -> Int32 {
    guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
        return errno == ENOENT ? 1 : 0
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    var next = ACL_FIRST_ENTRY
    while acl_get_entry(acl, next.rawValue, &entry) == 0 {
        var tag = ACL_UNDEFINED_TAG
        guard let entry, acl_get_tag_type(entry, &tag) == 0 else { return 0 }
        if tag != ACL_EXTENDED_DENY {
            guard tag == ACL_EXTENDED_ALLOW, directory == 1 else { return 0 }
            var mask: acl_permset_mask_t = 0
            let reads = [ACL_LIST_DIRECTORY, ACL_SEARCH, ACL_READ_ATTRIBUTES, ACL_READ_EXTATTRIBUTES,
                         ACL_READ_SECURITY, ACL_SYNCHRONIZE].reduce(UInt64(0)) { $0 | UInt64($1.rawValue) }
            guard acl_get_permset_mask_np(entry, &mask) == 0, mask & ~reads == 0 else { return 0 }
        }
        next = ACL_NEXT_ENTRY
    }
    return errno == EINVAL ? 1 : 0
}

@_cdecl("keyd_device_valid_point")
public func keydDeviceValidPoint(_ bytes: UnsafePointer<UInt8>, _ count: Int) -> Int32 {
    guard count == 65, bytes.pointee == 4 else { return 0 }
    return (try? P256.Signing.PublicKey(x963Representation: Data(bytes: bytes, count: count))) == nil ? 0 : 1
}
