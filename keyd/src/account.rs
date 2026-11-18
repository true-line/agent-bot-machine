// Machine's supported Darwin package is the Apple Silicon Homebrew prefix
// (internal/provider/brew.DefaultPrefix). Its owner is the service account.
// Looking up the directory independently of argv, HOME and the binary path
// keeps this check effective when somebody extracts another copy of keyd.
use std::os::unix::fs::MetadataExt;

unsafe extern "C" {
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> libc::c_int;
    fn mbr_group_name_to_uuid(name: *const libc::c_char, uuid: *mut u8) -> libc::c_int;
    fn mbr_check_membership(
        user: *const u8,
        group: *const u8,
        member: *mut libc::c_int,
    ) -> libc::c_int;
}

fn is_administrator(uid: libc::uid_t) -> bool {
    let mut user = [0u8; 16];
    let mut admin = [0u8; 16];
    let mut member = 0;
    // The macOS membership API resolves directory-service group membership,
    // including nested groups. Lookup failure is never approval.
    unsafe {
        mbr_uid_to_uuid(uid, user.as_mut_ptr()) == 0
            && mbr_group_name_to_uuid(c"admin".as_ptr(), admin.as_mut_ptr()) == 0
            && mbr_check_membership(user.as_ptr(), admin.as_ptr(), &mut member) == 0
            && member == 1
    }
}

pub fn require_custodian() -> Result<(), &'static str> {
    // No privilege transition is part of this service's launch.
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    let prefix = std::fs::metadata("/opt/homebrew")
        .map_err(|_| "cannot verify the owner of the Homebrew prefix")?;
    if !prefix.is_dir() || uid == 0 || uid != euid || uid != prefix.uid() || !is_administrator(uid)
    {
        return Err("custody requires the nonroot administrator who owns the Homebrew prefix");
    }
    Ok(())
}
