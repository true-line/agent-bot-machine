//! agent-bot-keyd: the custodian of each soul's GitHub App key
//! (agent-bot-identity #397). agent-bot-machine ships it signed with the
//! agent-machine Developer ID, and launchd runs it as `dev.qwts.agent-bot.keyd`.
//!
//!   agent-bot-keyd serve [--state-dir DIR] [--keychain FILE]
//!       Serves keyd.sock (souls' MCP tools) and owner.sock (the owner's
//!       channel) under DIR/keyd (default: agent-bot's state directory).
//!   agent-bot-keyd mcp [--state-dir DIR]
//!       The harness side: an MCP server on stdio that relays to keyd.sock
//!       and adds a daemon grant, fetched with the soul's binding, to each
//!       tool call. It holds no key.
//!   agent-bot-keyd presence-key [--keychain FILE]
//!       Prints the public half of keyd's presence key (made on first use),
//!       which agent-bot pins from this code-signed binary before trusting
//!       an `owner/presence` assertion (agent-bot-identity #416) or a record
//!       of the owner's statement keys (#753).
//!   agent-bot-keyd --version
//!
//! Keys live only in Keychain items keyd created, so their access lists
//! trust keyd's code signature and nothing else. Policy (which soul may mint
//! for which App) stays in agent-bot: keyd acts only on a grant the daemon
//! signed with the key the owner pinned.

#[cfg(target_os = "macos")]
mod account;
mod audit;
mod consent;
mod github;
mod grant;
#[cfg(any(target_os = "macos", test))]
mod hq_device;
#[cfg(target_os = "macos")]
mod hq_device_darwin;
mod ids;
mod paths;
mod pins;
mod presence;
mod qualification_policy;
mod relay;
mod server;
#[cfg(target_os = "macos")]
mod standalone;
mod store;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Condvar, Mutex};

const USAGE: &str = "usage: agent-bot-keyd serve [--state-dir DIR] [--keychain FILE] | mcp [--state-dir DIR] | presence-key [--keychain FILE] | --version";

/// Identity 0.15.20 reserves exit 3 for a presence item whose ACL keyd rejects.
const EXIT_UNTRUSTED_ITEM: u8 = 3;

struct Options {
    command: String,
    state_dir: Option<PathBuf>,
    keychain: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        command: String::new(),
        state_dir: None,
        keychain: None,
    };
    let mut iter = args.iter();
    options.command = iter.next().cloned().ok_or(USAGE)?;
    while let Some(arg) = iter.next() {
        let mut value = || {
            iter.next()
                .map(PathBuf::from)
                .ok_or_else(|| USAGE.to_owned())
        };
        match arg.as_str() {
            "--state-dir" => options.state_dir = Some(value()?),
            "--keychain" if matches!(options.command.as_str(), "serve" | "presence-key") => {
                options.keychain = Some(value()?)
            }
            _ => return Err(USAGE.into()),
        }
    }
    Ok(options)
}

#[cfg(target_os = "macos")]
fn items(options: &Options) -> Box<dyn store::Items> {
    match &options.keychain {
        Some(path) => Box::new(store::keychain::Keychain::at(path.clone())),
        None => Box::new(store::keychain::Keychain::login()),
    }
}

/// The line `presence-key` prints: the public half of the store's seed.
fn presence_key_line(store: &store::Store) -> Result<String, store::StoreError> {
    Ok(presence::public_key(&store.presence_seed()?))
}

#[cfg(target_os = "macos")]
fn presence_key(options: &Options) -> Result<(), store::StoreError> {
    println!("{}", presence_key_line(&store::Store::new(items(options)))?);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn presence_key(_: &Options) -> Result<(), store::StoreError> {
    Err("agent-bot-keyd keeps a presence key only on macOS".into())
}

fn exit_status(error: &store::StoreError) -> u8 {
    if error.is_untrusted() {
        EXIT_UNTRUSTED_ITEM
    } else {
        1
    }
}

#[cfg(target_os = "macos")]
fn serve(options: &Options, paths: &paths::Paths) -> Result<(), String> {
    standalone::begin_custody()?;
    let items = items(options);
    let listeners = server::listen(paths)?;
    let keyd = Arc::new(server::Keyd {
        store: store::Store::new(items),
        http: Box::new(github::Ureq::new()),
        consent: Box::new(consent::DeviceOwner),
        audit: audit::Audit::to(paths.audit.clone()),
        replay: Mutex::default(),
        tokens: Mutex::default(),
        token_wait: Condvar::new(),
        owner_lock: Mutex::default(),
        now: server::unix_now,
    });
    eprintln!(
        "agent-bot-keyd {} serving {}",
        env!("CARGO_PKG_VERSION"),
        paths.dir.display()
    );
    server::serve(keyd, listeners);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn serve(_: &Options, _: &paths::Paths) -> Result<(), String> {
    Err("agent-bot-keyd has no supported custody provider on this platform".into())
}

fn main() -> ExitCode {
    #[cfg(target_os = "macos")]
    if let Err(message) = account::require_custodian() {
        eprintln!("agent-bot-keyd: {message}");
        return ExitCode::FAILURE;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("qualification-policy") {
        #[cfg(target_os = "macos")]
        return match qualification_policy::command(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("agent-bot-keyd: {error}");
                ExitCode::FAILURE
            }
        };
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("agent-bot-keyd: qualification policy custody requires macOS");
            return ExitCode::FAILURE;
        }
    }
    if matches!(
        args.first().map(String::as_str),
        Some("hq-device" | "hq-device-init")
    ) {
        #[cfg(target_os = "macos")]
        if args.len() == 1 {
            let init = args[0] == "hq-device-init";
            return hq_device_darwin::cli_result(
                init,
                hq_device_darwin::command(init),
                &mut std::io::stderr().lock(),
            );
        }
        eprintln!("agent-bot-keyd: device custody unavailable");
        return ExitCode::FAILURE;
    }
    if args.first().map(String::as_str) == Some("--version") {
        println!("agent-bot-keyd {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let result = parse(&args)
        .map_err(store::StoreError::from)
        .and_then(|options| {
            let state = match &options.state_dir {
                Some(dir) => dir.clone(),
                None => paths::state_dir()?,
            };
            let paths = paths::Paths::under(&state);
            match options.command.as_str() {
                "serve" => serve(&options, &paths).map_err(store::StoreError::from),
                "mcp" => relay::run(&paths.socket).map_err(store::StoreError::from),
                "presence-key" => presence_key(&options),
                _ => Err(USAGE.into()),
            }
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("agent-bot-keyd: {error}");
            ExitCode::from(exit_status(&error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::tests::Memory;
    use store::{Items, PIN_SERVICE, PRESENCE_ACCOUNT};

    #[test]
    fn presence_key_first_use_and_ordinary_failures_keep_their_status() {
        let items = Memory::default();
        let store = store::Store::new(Box::new(items.clone()));
        let public = presence_key_line(&store).unwrap();
        assert_eq!(public, presence_key_line(&store).unwrap());

        items
            .write(PIN_SERVICE, PRESENCE_ACCOUNT, b"malformed")
            .unwrap();
        let error = presence_key_line(&store).unwrap_err();
        assert_eq!(exit_status(&error), 1);
        assert_eq!(error.to_string(), "presence key is malformed");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires a disposable macOS Keychain"]
    fn presence_key_marks_a_readable_item_with_untrusted_access() {
        use security_framework::os::macos::keychain::SecKeychain;
        use store::tests::with_temporary_keychain;

        with_temporary_keychain(|path| {
            let fixture = b"synthetic presence item";
            let keychain = SecKeychain::open(path).unwrap();
            keychain
                .add_generic_password(PIN_SERVICE, PRESENCE_ACCOUNT, fixture)
                .unwrap();
            let store = store::Store::new(Box::new(store::keychain::Keychain::at(path.to_owned())));
            let error = presence_key_line(&store).unwrap_err();
            assert!(error.is_untrusted());
            assert_eq!(exit_status(&error), 3, "Identity protocol exit status");
            let (retained, _) = keychain
                .find_generic_password(PIN_SERVICE, PRESENCE_ACCOUNT)
                .unwrap();
            assert_eq!(retained.as_ref(), fixture);
        });
    }
}
