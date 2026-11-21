//! Publish operational first use in the prefix owner's registered Machine state,
//! which the standalone administrator inventories after posting a pending record.
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

const NAMESPACE: &str = "Application Support/ai.true-line.agent-bot-hq/standalone";

pub fn begin_custody() -> Result<(), &'static str> {
    machine(Path::new("/Library"), &crate::account::registered_home()?)
}

pub fn admission(library: &Path) -> Result<(), &'static str> {
    for name in ["declaration-pending-v1", "declaration-v1"] {
        match fs::symlink_metadata(library.join(NAMESPACE).join(name)) {
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            _ => return Err("the administrator must finish or retire the standalone HQ signing declaration before starting keyd"),
        }
    }
    Ok(())
}

pub fn machine(library: &Path, home: &Path) -> Result<(), &'static str> {
    admission(library)?;
    let config = home.join(".config");
    for path in [&config, &config.join("agent-machine")] {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(_) => return Err("cannot publish Machine's registered state"),
        }
        if !fs::symlink_metadata(path).is_ok_and(|s| s.is_dir()) {
            return Err("cannot verify Machine's registered state");
        }
    }
    admission(library)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_declaration_precedes_custody() {
        let base = crate::paths::tests::short_temp_dir("standalone");
        let home = base.join("admin");
        fs::create_dir(&home).unwrap();
        let ns = base.join(NAMESPACE);
        fs::create_dir_all(&ns).unwrap();
        for name in ["declaration-pending-v1", "declaration-v1"] {
            fs::write(ns.join(name), b"public fixture").unwrap();
            assert!(machine(&base, &home).is_err());
            assert!(!home.join(".config").exists());
            fs::remove_file(ns.join(name)).unwrap();
        }
        machine(&base, &home).unwrap();
        assert!(home.join(".config/agent-machine").is_dir());
        fs::remove_dir_all(base).unwrap();
    }
}
