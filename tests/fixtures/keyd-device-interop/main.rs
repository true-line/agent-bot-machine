//! Test-only adapter, built outside the release crate. Key references are
//! disposable software keys. The copied device request and receipt code is
//! byte-for-byte the production module and uses a compiled-in test pin.
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::PathBuf,
    process::{Command, Stdio},
};
mod hq_device;
mod store {
    pub trait Items {
        fn read(&self, s: &str, a: &str) -> Result<Option<Vec<u8>>, String>;
        fn write(&self, s: &str, a: &str, v: &[u8]) -> Result<(), String>;
        fn insert(&self, s: &str, a: &str, v: &[u8]) -> Result<bool, String>;
    }
}
struct State(PathBuf);

fn open_state(path: &std::path::Path, write: bool) -> std::io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::getuid() }
    {
        return Err(std::io::Error::other("fixture file must be private"));
    }
    Ok(file)
}

impl store::Items for State {
    fn read(&self, _: &str, _: &str) -> Result<Option<Vec<u8>>, String> {
        match open_state(&self.0, false) {
            Ok(mut file) => {
                let mut bytes = vec![];
                file.read_to_end(&mut bytes)
                    .map_err(|_| String::from("fixture read"))?;
                Ok(Some(bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Err("read".into()),
        }
    }
    fn write(&self, _: &str, _: &str, v: &[u8]) -> Result<(), String> {
        let mut file = open_state(&self.0, true).map_err(|_| String::from("fixture write"))?;
        file.set_len(0)
            .and_then(|_| file.write_all(v))
            .map_err(|_| "fixture write".into())
    }
    fn insert(&self, _: &str, _: &str, v: &[u8]) -> Result<bool, String> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.0)
            .map_err(|_| String::from("create"))?;
        f.write_all(v).map_err(|_| String::from("insert"))?;
        Ok(true)
    }
}
struct Soft;
impl Soft {
    fn call(&self, op: &str, r: &[u8], m: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut child = Command::new(env!("KEYD_FIXTURE_NODE"))
            .args([
                "--input-type=module",
                "-e",
                include_str!("software.mjs"),
                "--",
                op,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "fixture node")?;
        write!(
            child.stdin.take().unwrap(),
            "{}",
            serde_json::json!({"reference":STANDARD.encode(r),"message":STANDARD.encode(m)})
        )
        .map_err(|_| "fixture input")?;
        let out = child.wait_with_output().map_err(|_| "fixture wait")?;
        if !out.status.success() {
            return Err("fixture native");
        };
        Ok(out.stdout)
    }
}
impl hq_device::Enclave for Soft {
    fn check_live(&self) -> Result<(), &'static str> {
        Ok(())
    }
    fn create(&self) -> Result<Vec<u8>, &'static str> {
        self.call("create", &[], &[])
    }
    fn public(&self, r: &[u8]) -> Result<[u8; 65], &'static str> {
        self.call("public", r, &[])?.try_into().map_err(|_| "point")
    }
    fn sign(&self, r: &[u8], m: &[u8]) -> Result<[u8; 64], &'static str> {
        self.call("sign", r, m)?.try_into().map_err(|_| "signature")
    }
}
fn go() -> Result<(), &'static str> {
    let dir = PathBuf::from(std::env::var_os("KEYD_FIXTURE_STATE").ok_or("fixture dir")?);
    let root = fs::canonicalize(std::env::temp_dir()).map_err(|_| "private temp unavailable")?;
    let canonical = fs::canonicalize(&dir).map_err(|_| "private fixture dir")?;
    let meta = fs::symlink_metadata(&dir).map_err(|_| "private fixture dir")?;
    let in_temp = canonical.starts_with(&root)
        || canonical.starts_with("/private/tmp")
        || canonical.starts_with("/tmp");
    if !meta.is_dir()
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::getuid() }
        || !in_temp
        || canonical == root
    {
        return Err("private fixture dir");
    }
    let guard = fs::File::open(&canonical).map_err(|_| "fixture lock")?;
    if unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err("fixture lock");
    }
    let file = open_state(&dir.join("pair.json"), false).map_err(|_| "fixture pair")?;
    let pair: hq_device::Pair =
        serde_json::from_reader(file.take(4097)).map_err(|_| "invalid fixture pair")?;
    let items = State(dir.join("disposable-state.json"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock")?;
    match std::env::args().nth(1).as_deref() {
        Some("hq-device-init") => hq_device::initialize(&items, &Soft, pair),
        Some("hq-device") => {
            let mut body = Vec::new();
            std::io::stdin()
                .take(16385)
                .read_to_end(&mut body)
                .map_err(|_| "input")?;
            if body.len() > 16384 {
                return Err("size");
            }
            let req = serde_json::from_slice(&body).map_err(|_| "request")?;
            println!("{}", hq_device::run(&items, &Soft, &pair, req, now)?);
            Ok(())
        }
        _ => Err("fixture verb"),
    }
}
fn main() {
    if let Err(e) = go() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
