//! Explicit, local, owner-present qualification policy ceremony. No socket
//! request can reach this module. The seed never leaves keyd's Keychain item.

use crate::{consent::Consent, store::Store};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const PURPOSE: &str = "agent-bot/qualification-policy/v1";
const MAX_BYTES: usize = 1 << 20;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

fn key_id(key: &SigningKey) -> String {
    format!(
        "qual-owner-ed25519-{}",
        &hex(&Sha256::digest(key.verifying_key().as_bytes()))[..16]
    )
}

pub fn init_root(store: &Store, owner: &dyn Consent) -> Result<(String, String), String> {
    // Even an attempted second initialization is refused before asking the
    // owner; the Store's atomic insert closes a concurrent first-use race.
    if store.qualification_policy_root_exists()? || store.qualification_policy_state()?.is_some() {
        return Err("qualification policy state exists; root rotation requires review".into());
    }
    owner
        .ask("Create the dedicated qualification policy root in keyd")
        .map_err(String::from)?;
    let mut seed = store
        .init_qualification_policy_seed()
        .map_err(String::from)?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok((hex(key.verifying_key().as_bytes()), key_id(&key)))
}

pub fn public_root(store: &Store) -> Result<(String, String), String> {
    let mut seed = store.qualification_policy_seed().map_err(String::from)?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok((hex(key.verifying_key().as_bytes()), key_id(&key)))
}

fn fields<'a>(
    value: &'a Value,
    names: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let object = value.as_object().ok_or("qualification object is invalid")?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return Err("qualification object has missing or extra fields".into());
    }
    Ok(object)
}

fn string<'a>(object: &'a serde_json::Map<String, Value>, name: &str) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("invalid {name}"))
}

fn timestamp(value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| "invalid qualification timestamp".into())
}

fn canonical(raw: &[u8]) -> Result<Value, String> {
    if raw.is_empty() || raw.len() > MAX_BYTES || !raw.is_ascii() {
        return Err("policy must be bounded ASCII canonical JSON".into());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|_| "invalid policy JSON")?;
    let encoded = serde_json::to_vec(&value).map_err(|_| "invalid policy JSON")?;
    if encoded != raw {
        return Err("policy must be ASCII RFC 8785 canonical bytes".into());
    }
    // serde_json's parser accepts duplicate keys; reject them by requiring
    // a second, strict token walk before a signature is possible.
    if !strict_json::unique_keys(raw)? {
        return Err("policy has duplicate JSON keys".into());
    }
    Ok(value)
}

mod strict_json {
    use serde::{
        de::{self, MapAccess, SeqAccess, Visitor},
        Deserialize,
    };
    use std::{collections::HashSet, fmt};

    struct Unique;
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Check;
            impl<'de> Visitor<'de> for Check {
                type Value = Unique;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("JSON value")
                }
                fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Unique, M::Error> {
                    let mut seen = HashSet::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if !seen.insert(key) {
                            return Err(de::Error::custom("duplicate JSON key"));
                        }
                        let _: Unique = map.next_value()?;
                    }
                    Ok(Unique)
                }
                fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Unique, S::Error> {
                    while seq.next_element::<Unique>()?.is_some() {}
                    Ok(Unique)
                }
                fn visit_bool<E: de::Error>(self, _: bool) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_i64<E: de::Error>(self, value: i64) -> Result<Unique, E> {
                    if value < 0 {
                        return Err(de::Error::custom("negative number"));
                    }
                    Ok(Unique)
                }
                fn visit_u64<E: de::Error>(self, _: u64) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_f64<E: de::Error>(self, _: f64) -> Result<Unique, E> {
                    Err(de::Error::custom("noninteger number"))
                }
                fn visit_str<E: de::Error>(self, _: &str) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_string<E: de::Error>(self, _: String) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_none<E: de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique)
                }
            }
            deserializer.deserialize_any(Check)
        }
    }
    pub fn unique_keys(raw: &[u8]) -> Result<bool, String> {
        let mut d = serde_json::Deserializer::from_slice(raw);
        Unique::deserialize(&mut d)
            .map_err(|_| "policy has duplicate or invalid JSON keys".to_owned())?;
        d.end().map_err(|_| "policy has trailing JSON".to_owned())?;
        Ok(true)
    }
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphanumeric() || (i > 0 && matches!(b, b'.' | b'_' | b':' | b'-'))
        })
}

fn sha(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate(
    raw: &[u8],
    revocations: &[u8],
    expected_id: &str,
    now: OffsetDateTime,
) -> Result<u64, String> {
    let value = canonical(raw)?;
    let p = fields(
        &value,
        &[
            "contract",
            "kind",
            "policy_revision",
            "owner_key_id",
            "issued_at",
            "expires_at",
            "release_workflow",
            "evidence_signers",
            "revocation_snapshot",
            "max_revocation_age_seconds",
        ],
    )?;
    if string(p, "contract")? != "control/v1"
        || string(p, "kind")? != "qualification-trust-policy"
        || string(p, "owner_key_id")? != expected_id
        || p.get("max_revocation_age_seconds").and_then(Value::as_u64) != Some(3600)
    {
        return Err("policy purpose, root or revocation age is invalid".into());
    }
    let revision = p
        .get("policy_revision")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .ok_or("invalid policy revision")?;
    let issued = timestamp(string(p, "issued_at")?)?;
    let expires = timestamp(string(p, "expires_at")?)?;
    if issued > now || expires <= now {
        return Err("policy is not current".into());
    }
    let workflow = fields(
        &p["release_workflow"],
        &[
            "id",
            "repository",
            "workflow_path",
            "source_commit",
            "oidc_issuer",
            "certificate_identity",
            "trust_root_sha256",
        ],
    )?;
    let source_commit = string(workflow, "source_commit")?;
    if !identifier(string(workflow, "id")?)
        || string(workflow, "repository")? != "true-line/soul-adapters"
        || !string(workflow, "workflow_path")?.starts_with(".github/workflows/")
        || ![".yml", ".yaml"].iter().any(|suffix| {
            string(workflow, "workflow_path")
                .unwrap_or("")
                .ends_with(suffix)
        })
        || source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !sha(string(workflow, "trust_root_sha256")?)
        || !string(workflow, "oidc_issuer")?.starts_with("https://")
        || !string(workflow, "certificate_identity")?.starts_with("https://")
    {
        return Err("release workflow identity is invalid".into());
    }
    let signers = p["evidence_signers"]
        .as_array()
        .filter(|v| !v.is_empty())
        .ok_or("missing evidence signers")?;
    let mut seen = std::collections::HashSet::new();
    for signer in signers {
        let s = fields(
            signer,
            &["id", "host_id", "algorithm", "public_key_spki_der_base64"],
        )?;
        if !identifier(string(s, "id")?)
            || !seen.insert(string(s, "id")?)
            || !identifier(string(s, "host_id")?)
            || string(s, "algorithm")? != "ES256"
            || base64::engine::general_purpose::STANDARD
                .decode(string(s, "public_key_spki_der_base64")?)
                .is_err()
        {
            return Err("invalid evidence signer".into());
        }
    }
    let source = canonical(revocations)?;
    let snapshot = fields(
        &source,
        &[
            "updated_at",
            "revoked_attestation_sha256",
            "revoked_evidence_signer_ids",
            "revoked_release_workflow_ids",
        ],
    )?;
    if p["revocation_snapshot"] != source {
        return Err("policy revocations differ from owner ledger".into());
    }
    let updated = timestamp(string(snapshot, "updated_at")?)?;
    if updated < issued || updated > now || now - updated > time::Duration::seconds(3600) {
        return Err("revocation snapshot is outside the 3600-second window".into());
    }
    for (name, check) in [
        ("revoked_attestation_sha256", sha as fn(&str) -> bool),
        ("revoked_evidence_signer_ids", identifier),
        ("revoked_release_workflow_ids", identifier),
    ] {
        let list = snapshot[name].as_array().ok_or("invalid revocation set")?;
        let mut unique = std::collections::HashSet::new();
        for member in list {
            let item = member.as_str().ok_or("invalid revocation member")?;
            if !check(item) || !unique.insert(item) {
                return Err("invalid revocation member".into());
            }
        }
    }
    if snapshot["revoked_release_workflow_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some(string(workflow, "id").unwrap_or("")))
    {
        return Err("release workflow is revoked".into());
    }
    Ok(revision)
}

pub fn sign(
    store: &Store,
    owner: &dyn Consent,
    policy: &[u8],
    revocations: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, String> {
    let mut seed = store.qualification_policy_seed().map_err(String::from)?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let id = key_id(&key);
    let nanoseconds = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| "invalid system clock")?
        .as_nanos();
    let now = OffsetDateTime::from_unix_timestamp_nanos(
        i128::try_from(nanoseconds).map_err(|_| "invalid system clock")?,
    )
    .map_err(|_| "invalid system clock")?;
    let revision = validate(policy, revocations, &id, now)?;
    let prior = store
        .qualification_policy_state()?
        .map(|raw| {
            serde_json::from_slice::<Value>(&raw)
                .map_err(|_| "malformed qualification policy state".to_owned())
        })
        .transpose()?;
    let prior_revision = match prior.as_ref() {
        Some(value) => {
            let state = fields(value, &["revision", "policy_sha256"])?;
            if !sha(string(state, "policy_sha256")?) {
                return Err("malformed qualification policy state".into());
            }
            state["revision"]
                .as_u64()
                .filter(|revision| *revision > 0)
                .ok_or("malformed qualification policy state")?
        }
        None => 0,
    };
    if revision <= prior_revision {
        return Err("policy revision must increase".into());
    }
    let policy_digest = digest(policy);
    let prompt = format!(
        "Sign qualification policy revision {revision}, {policy_digest}, ledger {}",
        digest(revocations)
    );
    owner.ask(&prompt).map_err(String::from)?;
    // The caller serializes this operation with the secure-admin lock. State
    // is advanced before returning signature bytes, so a failed output write
    // consumes a revision instead of allowing an unattended replay.
    let mut preimage = PURPOSE.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(policy);
    let signature = key.sign(&preimage);
    let state = serde_json::to_vec(&json!({"revision": revision, "policy_sha256": policy_digest}))
        .map_err(|_| "invalid policy state")?;
    store
        .put_qualification_policy_state(&state)
        .map_err(String::from)?;
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "purpose": PURPOSE,
        "owner_key_id": id,
        "policy_sha256": policy_digest,
        "policy_base64url": URL_SAFE_NO_PAD.encode(policy),
        "signature_base64url": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    }))
    .map_err(|_| "invalid policy envelope".into())
}

#[cfg(target_os = "macos")]
pub fn command(args: &[String]) -> Result<(), String> {
    use crate::{consent::DeviceOwner, store::keychain::Keychain};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            io::AsRawFd,
        },
        path::Path,
    };

    let home = crate::account::registered_home()?;
    let dir = home.join(".config/agent-machine/qualification");
    let store = Store::new(Box::new(Keychain::login()));
    match args {
        [mode] if mode == "init-root" => {
            let (root, id) = init_root(&store, &DeviceOwner)?;
            println!("owner-root.hex: {root}\nowner-key-id.txt: {id}");
        }
        [mode] if mode == "public-root" => {
            let (root, id) = public_root(&store)?;
            println!("owner-root.hex: {root}\nowner-key-id.txt: {id}");
        }
        [mode, a, policy_path, b, revocations_path, c, out_path]
            if mode == "sign" && a == "--policy" && b == "--revocations" && c == "--out" =>
        {
            if Path::new(revocations_path) != dir.join("revocations.json") {
                return Err("revocations must be the fixed secure-admin ledger".into());
            }
            let metadata = fs::symlink_metadata(&dir).map_err(|_| "qualification ledger directory is missing")?;
            if !metadata.is_dir() || metadata.uid() != unsafe { libc::getuid() } || metadata.permissions().mode() & 0o777 != 0o700 {
                return Err("qualification ledger directory must be mode 0700".into());
            }
            let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(dir.join(".sign.lock")).map_err(|_| "qualification lock unavailable")?;
            let lock_meta = lock.metadata().map_err(|_| "qualification lock unavailable")?;
            if !lock_meta.is_file() || lock_meta.uid() != unsafe { libc::getuid() } || lock_meta.permissions().mode() & 0o777 != 0o600 { return Err("qualification lock is not private".into()); }
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 { return Err("qualification lock unavailable".into()); }
            let read = |path: &Path, private: bool| -> Result<Vec<u8>, String> {
                let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(|_| "qualification input unavailable")?;
                let meta = file.metadata().map_err(|_| "qualification input unavailable")?;
                if !meta.is_file() || private && (meta.uid() != unsafe { libc::getuid() } || meta.permissions().mode() & 0o777 != 0o600) || meta.len() > MAX_BYTES as u64 { return Err("qualification input permissions or size invalid".into()); }
                let mut data = Vec::new();
                file.take(MAX_BYTES as u64 + 1).read_to_end(&mut data).map_err(|_| "qualification input unreadable")?;
                if data.len() > MAX_BYTES { return Err("qualification input too large".into()); }
                Ok(data)
            };
            let policy = read(Path::new(policy_path), false)?;
            let ledger = read(Path::new(revocations_path), true)?;
            let envelope = sign(&store, &DeviceOwner, &policy, &ledger, SystemTime::now())?;
            let mut out = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(out_path).map_err(|_| "qualification output already exists or is unavailable")?;
            out.write_all(&envelope).and_then(|_| out.write_all(b"\n")).and_then(|_| out.sync_all()).map_err(|_| "qualification output write failed")?;
            println!("policy-envelope: {}", digest(&envelope));
        }
        _ => return Err("usage: agent-bot-keyd qualification-policy init-root | public-root | sign --policy FILE --revocations FILE --out FILE".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consent::tests::Scripted,
        store::{tests::Memory, Items, PIN_SERVICE, QUALIFICATION_POLICY_ACCOUNT},
    };
    use ed25519_dalek::{Signature, Verifier};
    use std::time::Duration;

    fn fixture(id: &str, updated: &str) -> (Vec<u8>, Vec<u8>, SystemTime) {
        let snapshot = json!({
            "updated_at": updated,
            "revoked_attestation_sha256": [],
            "revoked_evidence_signer_ids": [],
            "revoked_release_workflow_ids": []
        });
        let policy = json!({
            "contract": "control/v1",
            "kind": "qualification-trust-policy",
            "policy_revision": 1,
            "owner_key_id": id,
            "issued_at": "2026-11-21T20:00:00Z",
            "expires_at": "2026-11-21T23:00:00Z",
            "release_workflow": {
                "id": "fixture-workflow",
                "repository": "true-line/soul-adapters",
                "workflow_path": ".github/workflows/release.yml",
                "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "oidc_issuer": "https://token.actions.githubusercontent.com",
                "certificate_identity": "https://github.com/true-line/soul-adapters/.github/workflows/release.yml@refs/heads/main",
                "trust_root_sha256": format!("sha256:{}", "a".repeat(64))
            },
            "evidence_signers": [{
                "id": "fixture-signer", "host_id": "fixture-host", "algorithm": "ES256", "public_key_spki_der_base64": "AQID"
            }],
            "revocation_snapshot": snapshot,
            "max_revocation_age_seconds": 3600
        });
        let when = timestamp("2026-11-21T21:00:00Z").unwrap();
        (
            serde_json::to_vec(&policy).unwrap(),
            serde_json::to_vec(&snapshot).unwrap(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(when.unix_timestamp() as u64),
        )
    }

    #[test]
    fn root_is_distinct_create_only_and_presence_gated() {
        let memory = Memory::default();
        let store = Store::new(Box::new(memory.clone()));
        assert!(init_root(&store, &Scripted::new(false)).is_err());
        assert!(store.qualification_policy_seed().is_err());
        let (root, id) = init_root(&store, &Scripted::new(true)).unwrap();
        assert_eq!((root.clone(), id.clone()), public_root(&store).unwrap());
        assert!(init_root(&store, &Scripted::new(true)).is_err());
        assert!(root.len() == 64 && id.starts_with("qual-owner-ed25519-"));
        memory
            .write(PIN_SERVICE, QUALIFICATION_POLICY_ACCOUNT, b"bad")
            .unwrap();
        assert!(public_root(&store).is_err());
    }

    #[test]
    fn signs_exact_purpose_and_consumes_revision() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        let owner = Scripted::new(true);
        let envelope = sign(&store, &owner, &policy, &ledger, now).unwrap();
        assert!(owner.asked.lock().unwrap()[0].contains(&digest(&policy)));
        let value: Value = serde_json::from_slice(&envelope).unwrap();
        assert_eq!(value["purpose"], PURPOSE);
        assert_eq!(value["policy_sha256"], digest(&policy));
        let signature = URL_SAFE_NO_PAD
            .decode(value["signature_base64url"].as_str().unwrap())
            .unwrap();
        let mut preimage = PURPOSE.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&policy);
        let mut seed = store.qualification_policy_seed().unwrap();
        let key = SigningKey::from_bytes(&seed).verifying_key();
        seed.fill(0);
        key.verify(&preimage, &Signature::from_slice(&signature).unwrap())
            .unwrap();
        assert!(sign(&store, &owner, &policy, &ledger, now).is_err());
    }

    #[test]
    fn rejects_stale_changed_ledger_and_missing_owner() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        assert!(sign(&store, &Scripted::new(false), &policy, &ledger, now).is_err());
        assert!(store.qualification_policy_state().unwrap().is_none());
        let (_, changed_ledger, _) = fixture(&id, "2026-11-21T20:59:59Z");
        assert!(sign(&store, &Scripted::new(true), &policy, &changed_ledger, now).is_err());
        let (stale_policy, stale_ledger, _) = fixture(&id, "2026-11-21T20:00:00Z");
        assert!(sign(
            &store,
            &Scripted::new(true),
            &stale_policy,
            &stale_ledger,
            now + Duration::from_secs(3601)
        )
        .is_err());
    }

    #[test]
    fn revocation_age_accepts_exact_boundary_only() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T20:00:00Z");
        assert!(validate(&policy, &ledger, &id, OffsetDateTime::from(now)).is_ok());
        assert!(validate(
            &policy,
            &ledger,
            &id,
            OffsetDateTime::from(now + Duration::from_nanos(1))
        )
        .is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires a disposable macOS Keychain"]
    fn native_root_stays_in_disposable_keychain() {
        use crate::store::{
            keychain::Keychain,
            tests::{keychain_tests_enabled, with_temporary_keychain},
        };
        if !keychain_tests_enabled() {
            return;
        }
        with_temporary_keychain(|path| {
            let store = Store::new(Box::new(Keychain::at(path.to_owned())));
            let public = init_root(&store, &Scripted::new(true)).unwrap();
            assert_eq!(public, public_root(&store).unwrap());
            assert!(init_root(&store, &Scripted::new(true)).is_err());
            assert!(store.qualification_policy_state().unwrap().is_none());
        });
    }
}
