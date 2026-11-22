use crate::{
    hq_device::{self, Enclave, Pair, UNAVAILABLE},
    store::keychain::Keychain,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawFd, FromRawFd},
    },
    path::Path,
};

extern "C" {
    fn keyd_device_enclave(
        op: i32,
        r: *const u8,
        nr: isize,
        m: *const u8,
        nm: isize,
        out: *mut u8,
        cap: isize,
    ) -> isize;
    fn keyd_device_safe_acl(fd: i32, directory: i32) -> i32;
    fn keyd_device_valid_point(point: *const u8, count: isize) -> i32;
}

const CREATE_INTERACTION_DENIED: &str =
    "macOS denied user interaction during Secure Enclave device key creation";

fn enclave_output_size(op: i32, size: isize, capacity: usize) -> Result<usize, &'static str> {
    if op == 0 && size == -2 {
        return Err(CREATE_INTERACTION_DENIED);
    }
    if size <= 0 || size as usize > capacity {
        return Err(UNAVAILABLE);
    }
    Ok(size as usize)
}

pub(crate) struct Native<'a> {
    pub(crate) dir: &'a File,
    pub(crate) pair: &'a Pair,
}
impl Native<'_> {
    fn invoke(&self, op: i32, reference: &[u8], message: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.check_live()?;
        let mut out = vec![0u8; 8192];
        // All pointers remain valid for the call. The Swift entry bounds its output.
        let n = unsafe {
            keyd_device_enclave(
                op,
                reference.as_ptr(),
                reference.len() as isize,
                message.as_ptr(),
                message.len() as isize,
                out.as_mut_ptr(),
                out.len() as isize,
            )
        };
        let size = enclave_output_size(op, n, out.len())?;
        self.check_live()?;
        out.truncate(size);
        Ok(out)
    }
}
impl Enclave for Native<'_> {
    fn check_live(&self) -> Result<(), &'static str> {
        if &read_pair(self.dir, unsafe { libc::getuid() })? != self.pair {
            return Err(UNAVAILABLE);
        }
        Ok(())
    }
    fn create(&self) -> Result<Vec<u8>, &'static str> {
        self.invoke(0, &[], &[])
    }
    fn public(&self, r: &[u8]) -> Result<[u8; 65], &'static str> {
        self.invoke(1, r, &[])?.try_into().map_err(|_| UNAVAILABLE)
    }
    fn sign(&self, r: &[u8], m: &[u8]) -> Result<[u8; 64], &'static str> {
        self.invoke(2, r, m)?.try_into().map_err(|_| UNAVAILABLE)
    }
}

fn openat(parent: i32, name: &OsStr, flags: i32) -> Result<File, std::io::Error> {
    let name = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn checked(file: &File, uid: u32, directory: bool) -> Result<(), &'static str> {
    let m = file.metadata().map_err(|_| UNAVAILABLE)?;
    if m.uid() != uid
        || (if directory {
            !m.is_dir() || m.mode() & 0o022 != 0
        } else {
            !m.is_file() || m.nlink() != 1 || m.mode() & 0o077 != 0
        })
        || unsafe { keyd_device_safe_acl(file.as_raw_fd(), i32::from(directory)) } != 1
    {
        return Err(UNAVAILABLE);
    }
    Ok(())
}
fn read_at(dir: &File, name: &str, uid: u32, max: usize) -> Result<Vec<u8>, &'static str> {
    let f = openat(dir.as_raw_fd(), OsStr::new(name), libc::O_RDONLY).map_err(|_| UNAVAILABLE)?;
    checked(&f, uid, false)?;
    let mut buf = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| UNAVAILABLE)?;
    if buf.len() > max {
        return Err(UNAVAILABLE);
    }
    Ok(buf)
}
fn hex_key(s: &str) -> Result<[u8; 32], &'static str> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(UNAVAILABLE);
    }
    let mut key = [0; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| UNAVAILABLE)?
    }
    Ok(key)
}

pub(crate) fn trusted_state() -> Result<(File, File, Pair), &'static str> {
    let uid = unsafe { libc::getuid() };
    // main already verified the nonroot admin prefix owner. Resolve its home
    // through the account database, independently of command-line/env input.
    let user = unsafe { libc::getpwuid(uid) };
    if user.is_null() {
        return Err(UNAVAILABLE);
    }
    let home = unsafe { CStr::from_ptr((*user).pw_dir) }
        .to_bytes()
        .to_owned();
    let path = Path::new(OsStr::from_bytes(&home));
    if !path.is_absolute() {
        return Err(UNAVAILABLE);
    }
    let mut dir = openat(
        libc::AT_FDCWD,
        OsStr::new("/"),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
    .map_err(|_| UNAVAILABLE)?;
    for component in path.components().skip(1) {
        let std::path::Component::Normal(name) = component else {
            return Err(UNAVAILABLE);
        };
        dir = openat(dir.as_raw_fd(), name, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|_| UNAVAILABLE)?;
        let owner = dir.metadata().map_err(|_| UNAVAILABLE)?.uid();
        if owner != 0 && owner != uid {
            return Err(UNAVAILABLE);
        }
        checked(&dir, owner, true)?;
    }
    checked(&dir, uid, true)?;
    for name in [".config", "agent-machine"] {
        dir = openat(
            dir.as_raw_fd(),
            OsStr::new(name),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .map_err(|_| UNAVAILABLE)?;
        checked(&dir, uid, true)?;
    }
    load_pair(dir, uid)
}

fn load_pair(dir: File, uid: u32) -> Result<(File, File, Pair), &'static str> {
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(UNAVAILABLE);
    }
    let pair_lock = openat(
        dir.as_raw_fd(),
        OsStr::new("owner-pair.lock"),
        libc::O_RDONLY,
    )
    .map_err(|_| UNAVAILABLE)?;
    checked(&pair_lock, uid, false)?;
    if unsafe { libc::flock(pair_lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(UNAVAILABLE);
    }
    let pair = read_pair(&dir, uid)?;
    Ok((dir, pair_lock, pair))
}

fn read_pair(dir: &File, uid: u32) -> Result<Pair, &'static str> {
    #[derive(Deserialize)]
    struct OwnerPair {
        machine: String,
        hq: String,
        uid: u32,
        owner: String,
        #[serde(default)]
        hq_epoch: Option<String>,
    }
    let rec: OwnerPair = serde_json::from_slice(&read_at(dir, "owner-pair.json", uid, 4096)?)
        .map_err(|_| UNAVAILABLE)?;
    let machine = hex_key(&rec.machine)?;
    if let Some(epoch) = &rec.hq_epoch {
        hex_key(epoch)?;
    }
    if rec.uid == 0
        || rec.uid == uid
        || unsafe { libc::getpwuid(rec.uid) }.is_null()
        || read_at(dir, "daemon.pub", uid, 32)? != machine
    {
        return Err(UNAVAILABLE);
    }
    let owner = STANDARD.decode(&rec.owner).map_err(|_| UNAVAILABLE)?;
    if owner.len() != 65
        || unsafe { keyd_device_valid_point(owner.as_ptr(), 65) } != 1
        || STANDARD.encode(owner) != rec.owner
    {
        return Err(UNAVAILABLE);
    }
    let peers = openat(
        dir.as_raw_fd(),
        OsStr::new("peers"),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
    .map_err(|_| UNAVAILABLE)?;
    checked(&peers, uid, true)?;
    match openat(
        peers.as_raw_fd(),
        OsStr::new("agent-daemon.revoked"),
        libc::O_RDONLY,
    ) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err(UNAVAILABLE),
    }
    Ok(Pair {
        machine_pub: STANDARD.encode(machine),
        hq_pub: STANDARD.encode(hex_key(&rec.hq)?),
        hq_uid: rec.uid,
        owner: rec.owner,
        hq_epoch: rec.hq_epoch.unwrap_or_else(|| "legacy".into()),
    })
}

// The peer command can create an ephemeral key, but it never gets native diagnostics.
pub(crate) fn cli_result(
    init: bool,
    result: Result<(), &'static str>,
    stderr: &mut impl Write,
) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let message = match (init, error) {
                (true, CREATE_INTERACTION_DENIED | hq_device::READ_INTERACTION_DENIED) => error,
                _ => UNAVAILABLE,
            };
            let _ = writeln!(stderr, "agent-bot-keyd: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn device_request_size_allowed(option: &str, size: usize) -> bool {
    let limit = match option {
        "qualification-host-report" | "qualification-host-report-v2" => 2 * 1024 * 1024,
        _ => 16384,
    };
    size <= limit
}

pub(crate) fn command(init: bool) -> Result<(), &'static str> {
    if init {
        crate::standalone::begin_custody()?;
    } else {
        crate::standalone::admission(std::path::Path::new("/Library"))?;
    }
    let (dir, _pair_lock, pair) = trusted_state()?;
    let native = Native {
        dir: &dir,
        pair: &pair,
    };
    let items = Keychain::login();
    if init {
        return hq_device::initialize(&items, &native, pair.clone());
    }
    let mut raw = Vec::new();
    std::io::stdin()
        .lock()
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| UNAVAILABLE)?;
    if raw.len() > 2 * 1024 * 1024 {
        return Err(UNAVAILABLE);
    }
    let request: hq_device::Request = serde_json::from_slice(&raw).map_err(|_| UNAVAILABLE)?;
    if !device_request_size_allowed(&request.option, raw.len()) {
        return Err(UNAVAILABLE);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| UNAVAILABLE)?;
    let result = hq_device::run(&items, &native, &pair, request, now)?;
    native.check_live()?;
    writeln!(std::io::stdout().lock(), "{result}").map_err(|_| UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    #[test]
    fn both_host_report_versions_use_the_bounded_large_request_limit() {
        for option in ["qualification-host-report", "qualification-host-report-v2"] {
            assert!(device_request_size_allowed(option, 16385));
            assert!(device_request_size_allowed(option, 2 * 1024 * 1024));
            assert!(!device_request_size_allowed(option, 2 * 1024 * 1024 + 1));
        }
        assert!(!device_request_size_allowed("whoami", 16385));
    }

    #[test]
    fn only_explicit_initialization_reports_denied_interaction_at_creation() {
        let report = |init, op, n| {
            let mut stderr = Vec::new();
            let result = enclave_output_size(op, n, 8192).map(|_| ());
            assert_eq!(
                cli_result(init, result, &mut stderr),
                std::process::ExitCode::FAILURE
            );
            String::from_utf8(stderr).unwrap()
        };
        assert_eq!(report(true, 0, -2),
            "agent-bot-keyd: macOS denied user interaction during Secure Enclave device key creation\n");
        let generic = "agent-bot-keyd: device custody unavailable\n";
        assert_eq!(report(false, 0, -2), generic);
        for (op, n) in [(0, -1), (0, -9), (1, -2), (2, -2)] {
            assert_eq!(report(true, op, n), generic);
            assert_eq!(report(false, op, n), generic);
        }
    }

    #[test]
    fn only_admin_init_reports_a_keychain_lookup_denial() {
        for (init, expected) in [
            (true, hq_device::READ_INTERACTION_DENIED),
            (false, UNAVAILABLE),
        ] {
            let mut out = Vec::new();
            assert_eq!(
                cli_result(init, Err(hq_device::READ_INTERACTION_DENIED), &mut out),
                std::process::ExitCode::FAILURE
            );
            assert_eq!(
                String::from_utf8(out).unwrap(),
                format!("agent-bot-keyd: {expected}\n")
            );
        }
    }

    #[test]
    fn reads_only_a_locked_admin_pair_and_honors_revocation() {
        let root_path = crate::paths::tests::short_temp_dir("device-pair");
        let root = &root_path;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::getuid() };
        // An installed system account supplies only a UID, never credentials.
        let role = unsafe { libc::getpwnam(c"daemon".as_ptr()) };
        assert!(!role.is_null());
        let role_uid = unsafe { (*role).pw_uid };
        assert_ne!(role_uid, uid);
        let write = |name: &str, body: &[u8]| {
            let p = root.join(name);
            fs::write(&p, body).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
        };
        let load = || load_pair(File::open(root).unwrap(), uid);
        let point =
            hex_key("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296").unwrap();
        let y =
            hex_key("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap();
        let pk = STANDARD.encode([&[4][..], &point, &y].concat());
        let pair = serde_json::json!({"machine":"01".repeat(32),"hq":"02".repeat(32),"owner":pk,"uid":role_uid});
        write("owner-pair.json", pair.to_string().as_bytes());
        write("daemon.pub", &[1; 32]);
        write("owner-pair.lock", &[]);
        fs::create_dir(root.join("peers")).unwrap();
        fs::set_permissions(root.join("peers"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(load().is_ok());
        let guard = File::open(root.join("owner-pair.lock")).unwrap();
        assert_eq!(
            unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(load().is_err());
        drop(guard);
        write("peers/agent-daemon.revoked", b"marker");
        assert!(load().is_err());
        fs::remove_file(root.join("peers/agent-daemon.revoked")).unwrap();
        write("daemon.pub", &[3; 32]);
        assert!(load().is_err());
        fs::remove_file(root.join("daemon.pub")).unwrap();
        write("other.pub", &[1; 32]);
        symlink(root.join("other.pub"), root.join("daemon.pub")).unwrap();
        assert!(load().is_err());
        // ACLs can grant writes independently of POSIX mode. Exercise only the
        // fixture directory; the daemon never invokes chmod on production inputs.
        let fixture = File::open(root).unwrap();
        let acl = |rule: &str| {
            std::process::Command::new("/bin/chmod")
                .args(["+a", rule])
                .arg(root)
                .status()
                .unwrap()
                .success()
        };
        assert!(acl("everyone allow readattr"));
        assert!(checked(&fixture, uid, true).is_ok());
        assert!(acl("everyone allow add_file"));
        assert!(checked(&fixture, uid, true).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
