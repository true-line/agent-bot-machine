//! Explicit, local, owner-present qualification policy ceremony. No socket
//! request can reach this module. The seed never leaves keyd's Keychain item.

use crate::{consent::Consent, store::Store};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const PURPOSE: &str = "agent-bot/qualification-policy/v1";
const PURPOSE_V2: &str = "agent-bot/qualification-policy/v2";
const PURPOSE_V3: &str = "agent-bot/qualification-policy/v3";
const MAX_BYTES: usize = 1 << 20;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn keyd_qualification_valid_spki(bytes: *const u8, count: isize) -> i32;
}

fn valid_p256_spki(der: &[u8]) -> bool {
    // RFC 5480 P-256 SPKI with an uncompressed SEC1 point. Requiring the
    // fixed DER wrapper excludes extra attributes and trailing bytes; the
    // native check below validates that the point is actually on the curve.
    const PREFIX: [u8; 27] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    if der.len() != 91 || !der.starts_with(&PREFIX) {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        der.len() <= 8192
            && unsafe { keyd_qualification_valid_spki(der.as_ptr(), der.len() as isize) == 1 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = der;
        false
    }
}

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
    // A root without its revision marker is deliberately unusable. If this
    // write fails after root creation, recovery requires a reviewed rotation.
    store
        .put_qualification_policy_state(br#"{"policy_sha256":null,"revision":0}"#)
        .map_err(String::from)?;
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

fn hex_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git_oid(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    // The release identity is a DNS URL. Reject ambiguous authority syntax
    // and encodings before spending a signed revision; Go's net/url consumer
    // is the final verifier and accepts this deliberately narrower form.
    if value
        .bytes()
        .any(|b| b <= 0x20 || b >= 0x7f || matches!(b, b'#' | b'%' | b'\\'))
    {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if authority.contains('@') {
        return false;
    }
    if let Some(port) = port {
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|p| *p > 0).is_none()
        {
            return false;
        }
    }
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn validate(
    raw: &[u8],
    revocations: &[u8],
    expected_id: &str,
    now: OffsetDateTime,
) -> Result<u64, String> {
    validate_version(raw, revocations, expected_id, now, 1)
}

fn validate_frozen_soul_policy(
    p: &serde_json::Map<String, Value>,
    provenance_enabled: bool,
) -> Result<(), String> {
    let mut mapping_names = vec![
        "soul_id",
        "artifact_sha256",
        "claimed_definition_digest",
        "definition_measurement",
    ];
    if provenance_enabled {
        mapping_names.push("receipt_sha256");
    }
    let mapping = fields(&p["frozen_soul_mapping"], &mapping_names)?;
    let soul_id = string(mapping, "soul_id")?;
    let parts: Vec<_> = soul_id
        .strip_prefix("agent_")
        .unwrap_or("")
        .split('-')
        .collect();
    if parts.len() != 5
        || parts.iter().zip([8, 4, 4, 4, 12]).any(|(part, len)| {
            part.len() != len
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || !hex_digest(string(mapping, "artifact_sha256")?)
        || !sha(string(mapping, "claimed_definition_digest")?)
        || !sha(string(mapping, "definition_measurement")?)
    {
        return Err("frozen Soul artifact mapping is invalid".into());
    }
    if !provenance_enabled {
        return Ok(());
    }
    if !sha(string(mapping, "receipt_sha256")?) {
        return Err("frozen Soul receipt is invalid".into());
    }
    let build = fields(
        &p["frozen_soul_build_workflow"],
        &[
            "id",
            "repository",
            "workflow_path",
            "source_commit",
            "source_tree",
            "oidc_issuer",
            "certificate_identity",
            "trust_root_sha256",
            "builder_sha256",
            "toolchain_sha256",
            "receipt_predicate_type",
            "bundle_media_type",
            "dsse_payload_type",
            "artifact_format",
            "subject_name_template",
            "rekor_entry_kind",
            "rekor_entry_version",
            "transparency_log_id",
            "template",
        ],
    )?;
    let kind = string(build, "rekor_entry_kind")?;
    let entry_version = string(build, "rekor_entry_version")?;
    if !identifier(string(build, "id")?)
        || string(build, "repository")? != "true-line/soul-package"
        || string(build, "workflow_path")? != ".github/workflows/stage2a-frozen-soul-receipt.yml"
        || !git_oid(string(build, "source_commit")?)
        || !git_oid(string(build, "source_tree")?)
        || !https_url(string(build, "oidc_issuer")?)
        || !https_url(string(build, "certificate_identity")?)
        || !sha(string(build, "trust_root_sha256")?)
        || !sha(string(build, "builder_sha256")?)
        || !sha(string(build, "toolchain_sha256")?)
        || string(build, "receipt_predicate_type")?
            != "https://true-line.ai/soul-contracts/package/v1/frozen-soul-build"
        || string(build, "bundle_media_type")? != "application/vnd.dev.sigstore.bundle.v0.3+json"
        || string(build, "dsse_payload_type")? != "application/vnd.in-toto+json"
        || string(build, "artifact_format")? != "stage2a-frozen-hello-ustar/v1"
        || string(build, "subject_name_template")? != "sha256-{artifact_sha256}.soul"
        || !matches!(
            (kind, entry_version),
            ("dsse", "0.0.1") | ("hashedrekord", "0.0.2")
        )
        || !hex_digest(string(build, "transparency_log_id")?)
    {
        return Err("frozen Soul build authority is invalid".into());
    }
    let template = fields(
        &build["template"],
        &[
            "repository",
            "source_commit",
            "source_tree",
            "path",
            "template_tree",
        ],
    )?;
    if string(template, "repository")? != "true-line/soul-conformance"
        || !git_oid(string(template, "source_commit")?)
        || !git_oid(string(template, "source_tree")?)
        || string(template, "path")? != "templates/hello.soul"
        || !git_oid(string(template, "template_tree")?)
    {
        return Err("frozen Soul template authority is invalid".into());
    }
    Ok(())
}

fn validate_version(
    raw: &[u8],
    revocations: &[u8],
    expected_id: &str,
    now: OffsetDateTime,
    version: u64,
) -> Result<u64, String> {
    let value = canonical(raw)?;
    let mut names = vec![
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
    ];
    if version >= 2 {
        names.push("souls_build_workflow");
    }
    let frozen_provenance_enabled = if version == 3 {
        value["frozen_soul_release_provenance_enabled"]
            .as_bool()
            .ok_or("missing explicit frozen Soul release provenance flag")?
    } else {
        false
    };
    if version == 3 {
        names.extend([
            "frozen_soul_release_provenance_enabled",
            "frozen_soul_mapping",
        ]);
        if frozen_provenance_enabled {
            names.push("frozen_soul_build_workflow");
        }
    }
    let p = fields(&value, &names)?;
    if string(p, "contract")? != format!("control/v{version}")
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
    let workflow_path = string(workflow, "workflow_path")?;
    let basename = workflow_path
        .strip_prefix(".github/workflows/")
        .ok_or("invalid workflow path")?;
    let basename = basename
        .strip_suffix(".yaml")
        .or_else(|| basename.strip_suffix(".yml"))
        .ok_or("invalid workflow path")?;
    if basename.is_empty()
        || !basename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || !identifier(string(workflow, "id")?)
        || string(workflow, "repository")? != "true-line/soul-adapters"
        || source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !sha(string(workflow, "trust_root_sha256")?)
        || !https_url(string(workflow, "oidc_issuer")?)
        || !https_url(string(workflow, "certificate_identity")?)
    {
        return Err("release workflow identity is invalid".into());
    }
    if version >= 2 {
        let build = fields(
            &p["souls_build_workflow"],
            &[
                "id",
                "repository",
                "workflow_path",
                "source_commit",
                "source_tree",
                "oidc_issuer",
                "certificate_identity",
                "trust_root_sha256",
                "builder_sha256",
                "toolchain_sha256",
                "receipt_predicate_type",
                "bundle_media_type",
                "dsse_payload_type",
            ],
        )?;
        let build_path = string(build, "workflow_path")?;
        let build_basename = build_path
            .strip_prefix(".github/workflows/")
            .ok_or("invalid Souls build workflow path")?;
        let build_basename = build_basename
            .strip_suffix(".yaml")
            .or_else(|| build_basename.strip_suffix(".yml"))
            .ok_or("invalid Souls build workflow path")?;
        let valid_hex40 = |s: &str| {
            s.len() == 40
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !identifier(string(build, "id")?)
            || string(build, "repository")? != "true-line/agent-bot-souls"
            || build_basename.is_empty()
            || !build_basename
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            || !valid_hex40(string(build, "source_commit")?)
            || !valid_hex40(string(build, "source_tree")?)
            || !https_url(string(build, "oidc_issuer")?)
            || !https_url(string(build, "certificate_identity")?)
            || !sha(string(build, "trust_root_sha256")?)
            || !sha(string(build, "builder_sha256")?)
            || !sha(string(build, "toolchain_sha256")?)
            || string(build, "receipt_predicate_type")?
                != "https://true-line.ai/soul-contracts/adapter/v2/souls-build"
            || string(build, "bundle_media_type")?
                != "application/vnd.dev.sigstore.bundle.v0.3+json"
            || string(build, "dsse_payload_type")? != "application/vnd.in-toto+json"
        {
            return Err("Souls build workflow identity is invalid".into());
        }
    }
    if version == 3 {
        validate_frozen_soul_policy(p, frozen_provenance_enabled)?;
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
        let spki = base64::engine::general_purpose::STANDARD
            .decode(string(s, "public_key_spki_der_base64")?)
            .map_err(|_| "invalid evidence signer SPKI")?;
        if base64::engine::general_purpose::STANDARD.encode(&spki)
            != string(s, "public_key_spki_der_base64")?
            || !valid_p256_spki(&spki)
            || !identifier(string(s, "id")?)
            || !seen.insert(string(s, "id")?)
            || !identifier(string(s, "host_id")?)
            || string(s, "algorithm")? != "ES256"
        {
            return Err("invalid evidence signer".into());
        }
    }
    let source = canonical(revocations)?;
    let mut snapshot_names = vec![
        "updated_at",
        "revoked_attestation_sha256",
        "revoked_evidence_signer_ids",
        "revoked_release_workflow_ids",
    ];
    if version >= 2 {
        snapshot_names.extend([
            "revoked_souls_build_workflow_ids",
            "revoked_souls_build_receipt_sha256",
        ]);
    }
    if version == 3 {
        snapshot_names.push("revoked_frozen_soul_artifact_sha256");
        if frozen_provenance_enabled {
            snapshot_names.extend([
                "revoked_frozen_soul_build_workflow_ids",
                "revoked_frozen_soul_receipt_sha256",
            ]);
        }
    }
    let snapshot = fields(&source, &snapshot_names)?;
    if p["revocation_snapshot"] != source {
        return Err("policy revocations differ from owner ledger".into());
    }
    let updated = timestamp(string(snapshot, "updated_at")?)?;
    if updated < issued || updated > now || now - updated > time::Duration::seconds(3600) {
        return Err("revocation snapshot is outside the 3600-second window".into());
    }
    let mut revocation_lists = vec![
        ("revoked_attestation_sha256", sha as fn(&str) -> bool),
        ("revoked_evidence_signer_ids", identifier),
        ("revoked_release_workflow_ids", identifier),
    ];
    if version >= 2 {
        revocation_lists.extend([
            (
                "revoked_souls_build_workflow_ids",
                identifier as fn(&str) -> bool,
            ),
            (
                "revoked_souls_build_receipt_sha256",
                sha as fn(&str) -> bool,
            ),
        ]);
    }
    if version == 3 {
        revocation_lists.push((
            "revoked_frozen_soul_artifact_sha256",
            hex_digest as fn(&str) -> bool,
        ));
        if frozen_provenance_enabled {
            revocation_lists.extend([
                (
                    "revoked_frozen_soul_build_workflow_ids",
                    identifier as fn(&str) -> bool,
                ),
                (
                    "revoked_frozen_soul_receipt_sha256",
                    sha as fn(&str) -> bool,
                ),
            ]);
        }
    }
    for (name, check) in revocation_lists {
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
    if version >= 2
        && snapshot["revoked_souls_build_workflow_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(p["souls_build_workflow"]["id"].as_str().unwrap_or("")))
    {
        return Err("Souls build workflow is revoked".into());
    }
    if version == 3 {
        let mapping = &p["frozen_soul_mapping"];
        if snapshot["revoked_frozen_soul_artifact_sha256"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &mapping["artifact_sha256"])
        {
            return Err("frozen Soul artifact is revoked".into());
        }
        if frozen_provenance_enabled {
            let frozen = &p["frozen_soul_build_workflow"];
            if snapshot["revoked_frozen_soul_build_workflow_ids"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == &frozen["id"])
                || snapshot["revoked_frozen_soul_receipt_sha256"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v == &mapping["receipt_sha256"])
            {
                return Err("frozen Soul release provenance is revoked".into());
            }
        }
    }
    Ok(revision)
}

fn clock_time(now: SystemTime) -> Result<OffsetDateTime, String> {
    let nanoseconds = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| "invalid system clock")?
        .as_nanos();
    OffsetDateTime::from_unix_timestamp_nanos(
        i128::try_from(nanoseconds).map_err(|_| "invalid system clock")?,
    )
    .map_err(|_| "invalid system clock".into())
}

// AuthenticatedPolicy is the exact owner-signed payload accepted by keyd's
// independent witness ledger. It carries no launch authority by itself.
pub(crate) struct AuthenticatedPolicy {
    pub version: u64,
    pub revision: u64,
    pub payload_sha256: String,
    pub owner_key_id: String,
    pub evidence_signer_spki: Vec<Vec<u8>>,
    pub evidence_signer_hosts: Vec<String>,
}

pub(crate) fn verify_signed_envelope(
    envelope: &[u8],
    pinned_root: &[u8; 32],
    pinned_id: &str,
    now: OffsetDateTime,
) -> Result<AuthenticatedPolicy, String> {
    verify_signed_envelope_internal(envelope, pinned_root, pinned_id, now, false)
}

// The v3 host-report issuer will use this exact-version policy check after it
// has independent A-owned completed-run authorization. The witness ledger is
// still v1/v2, so its existing verifier deliberately does not accept v3.
#[allow(dead_code)]
pub(crate) fn verify_signed_envelope_v3(
    envelope: &[u8],
    pinned_root: &[u8; 32],
    pinned_id: &str,
    now: OffsetDateTime,
) -> Result<AuthenticatedPolicy, String> {
    let policy = verify_signed_envelope_internal(envelope, pinned_root, pinned_id, now, true)?;
    if policy.version != 3 {
        return Err("signed policy is not v3".into());
    }
    Ok(policy)
}

fn verify_signed_envelope_internal(
    envelope: &[u8],
    pinned_root: &[u8; 32],
    pinned_id: &str,
    now: OffsetDateTime,
    allow_v3: bool,
) -> Result<AuthenticatedPolicy, String> {
    if envelope.is_empty() || envelope.len() > 2 * MAX_BYTES || !envelope.is_ascii() {
        return Err("signed policy envelope is unavailable".into());
    }
    let value: Value =
        serde_json::from_slice(envelope).map_err(|_| "invalid signed policy envelope")?;
    if !strict_json::unique_keys(envelope)?
        || serde_json::to_vec(&value).map_err(|_| "invalid signed policy envelope")? != envelope
    {
        return Err("signed policy envelope is not canonical".into());
    }
    let e = fields(
        &value,
        &[
            "schema_version",
            "purpose",
            "owner_key_id",
            "policy_sha256",
            "policy_base64url",
            "signature_base64url",
        ],
    )?;
    let version = e["schema_version"]
        .as_u64()
        .ok_or("invalid signed policy version")?;
    let purpose = match version {
        1 => PURPOSE,
        2 => PURPOSE_V2,
        3 if allow_v3 => PURPOSE_V3,
        _ => return Err("unsupported signed policy version".into()),
    };
    let id = format!(
        "qual-owner-ed25519-{}",
        &hex(&Sha256::digest(pinned_root))[..16]
    );
    if string(e, "purpose")? != purpose
        || string(e, "owner_key_id")? != pinned_id
        || pinned_id != id
    {
        return Err("signed policy root or purpose differs from release pin".into());
    }
    let encoded = string(e, "policy_base64url")?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "invalid signed policy payload")?;
    if raw.is_empty()
        || raw.len() > MAX_BYTES
        || URL_SAFE_NO_PAD.encode(&raw) != encoded
        || digest(&raw) != string(e, "policy_sha256")?
    {
        return Err("signed policy exact bytes differ".into());
    }
    let policy = canonical(&raw)?;
    let revocations = serde_json::to_vec(&policy["revocation_snapshot"])
        .map_err(|_| "invalid policy revocations")?;
    let revision = validate_version(&raw, &revocations, pinned_id, now, version)?;
    let encoded_signature = string(e, "signature_base64url")?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| "invalid policy signature")?;
    if signature.len() != 64 || URL_SAFE_NO_PAD.encode(&signature) != encoded_signature {
        return Err("invalid policy signature".into());
    }
    let key = VerifyingKey::from_bytes(pinned_root).map_err(|_| "invalid pinned owner root")?;
    let signature = Signature::from_slice(&signature).map_err(|_| "invalid policy signature")?;
    let mut preimage = purpose.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&raw);
    key.verify_strict(&preimage, &signature)
        .map_err(|_| "owner policy signature does not verify")?;
    let evidence_signer_spki = policy["evidence_signers"]
        .as_array()
        .ok_or("missing evidence signers")?
        .iter()
        .map(|signer| {
            STANDARD
                .decode(
                    signer["public_key_spki_der_base64"]
                        .as_str()
                        .ok_or("invalid evidence signer")?,
                )
                .map_err(|_| "invalid evidence signer".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let revoked_signers: std::collections::HashSet<&str> = policy["revocation_snapshot"]
        ["revoked_evidence_signer_ids"]
        .as_array()
        .ok_or("invalid revoked evidence signers")?
        .iter()
        .map(|id| id.as_str().ok_or("invalid revoked evidence signer"))
        .collect::<Result<_, _>>()?;
    let evidence_signer_hosts = policy["evidence_signers"]
        .as_array()
        .ok_or("missing evidence signers")?
        .iter()
        .filter(|signer| !revoked_signers.contains(signer["id"].as_str().unwrap_or("")))
        .map(|signer| {
            signer["host_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or("invalid evidence signer".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AuthenticatedPolicy {
        version,
        revision,
        payload_sha256: digest(&raw),
        owner_key_id: pinned_id.to_owned(),
        evidence_signer_spki,
        evidence_signer_hosts,
    })
}

#[cfg(test)]
fn sign<F: Fn() -> SystemTime>(
    store: &Store,
    owner: &dyn Consent,
    policy: &[u8],
    revocations: &[u8],
    clock: F,
) -> Result<Vec<u8>, String> {
    sign_version(store, owner, policy, revocations, clock, 1, || {
        Ok(revocations.to_vec())
    })
}

fn sign_version<F: Fn() -> SystemTime, R: Fn() -> Result<Vec<u8>, String>>(
    store: &Store,
    owner: &dyn Consent,
    policy: &[u8],
    revocations: &[u8],
    clock: F,
    version: u64,
    read_revocations: R,
) -> Result<Vec<u8>, String> {
    if !(1..=3).contains(&version) {
        return Err("unsupported qualification policy version".into());
    }
    let mut seed = store.qualification_policy_seed().map_err(String::from)?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let id = key_id(&key);
    let revision = validate_version(policy, revocations, &id, clock_time(clock())?, version)?;
    let prior_raw = store
        .qualification_policy_state()?
        .ok_or("qualification policy state is missing")?;
    let prior: Value =
        serde_json::from_slice(&prior_raw).map_err(|_| "malformed qualification policy state")?;
    let prior_version = if prior
        .as_object()
        .is_some_and(|v| v.contains_key("policy_version"))
    {
        prior["policy_version"]
            .as_u64()
            .ok_or("malformed qualification policy state")?
    } else {
        1
    };
    let state = if prior_version >= 2 {
        fields(&prior, &["revision", "policy_sha256", "policy_version"])?
    } else {
        fields(&prior, &["revision", "policy_sha256"])?
    };
    if !(1..=3).contains(&prior_version)
        || (prior_version == 1
            && prior
                .as_object()
                .is_some_and(|v| v.contains_key("policy_version")))
        || version < prior_version
    {
        return Err("qualification policy version cannot roll back".into());
    }
    let prior_revision = state["revision"]
        .as_u64()
        .ok_or("malformed qualification policy state")?;
    if prior_revision == 0 {
        if !state["policy_sha256"].is_null() {
            return Err("malformed qualification policy state".into());
        }
    } else if !sha(string(state, "policy_sha256")?) {
        return Err("malformed qualification policy state".into());
    }
    if revision <= prior_revision {
        return Err("policy revision must increase".into());
    }
    let policy_digest = digest(policy);
    let source_tree = if version >= 2 {
        let value: Value = serde_json::from_slice(policy).map_err(|_| "invalid policy JSON")?;
        format!(
            ", Souls tree {}",
            value["souls_build_workflow"]["source_tree"]
                .as_str()
                .ok_or("missing Souls source tree")?
        )
    } else {
        String::new()
    };
    let frozen = if version == 3 {
        let value: Value = serde_json::from_slice(policy).map_err(|_| "invalid policy JSON")?;
        let mapping = &value["frozen_soul_mapping"];
        if value["frozen_soul_release_provenance_enabled"] == false {
            format!(
                ", frozen Soul {}, artifact {}, definition {}, release provenance OFF",
                mapping["soul_id"].as_str().ok_or("missing Soul ID")?,
                mapping["artifact_sha256"]
                    .as_str()
                    .ok_or("missing frozen artifact")?,
                mapping["definition_measurement"]
                    .as_str()
                    .ok_or("missing frozen definition")?,
            )
        } else {
            let build = &value["frozen_soul_build_workflow"];
            format!(
                ", frozen Soul {}, artifact {}, receipt {}, definition {}, frozen builder {} at {}, root {}, Rekor log {}",
                mapping["soul_id"].as_str().ok_or("missing Soul ID")?,
                mapping["artifact_sha256"].as_str().ok_or("missing frozen artifact")?,
                mapping["receipt_sha256"].as_str().ok_or("missing frozen receipt")?,
                mapping["definition_measurement"].as_str().ok_or("missing frozen definition")?,
                build["source_commit"].as_str().ok_or("missing frozen source commit")?,
                build["source_tree"].as_str().ok_or("missing frozen source tree")?,
                build["trust_root_sha256"].as_str().ok_or("missing frozen root digest")?,
                build["transparency_log_id"].as_str().ok_or("missing Rekor log ID")?,
            )
        }
    } else {
        String::new()
    };
    let prompt = format!(
        "Sign qualification policy v{version} revision {revision}{source_tree}{frozen}, {policy_digest}, ledger {}",
        digest(revocations)
    );
    owner.ask(&prompt).map_err(String::from)?;
    // The owner prompt can take two minutes. A revocation changed during that
    // time must not be omitted from a newly signed policy. The CLI reopens the
    // secure-admin ledger under the signing lock, rather than reusing bytes it
    // read before asking the owner.
    if read_revocations()?.as_slice() != revocations {
        return Err("qualification revocation ledger changed during owner approval".into());
    }
    // An owner prompt can wait for two minutes. Recheck both expiry and the
    // 3,600-second snapshot limit with a fresh clock before using the key.
    validate_version(policy, revocations, &id, clock_time(clock())?, version)?;
    if store.qualification_policy_state()?.as_deref() != Some(prior_raw.as_slice())
        || public_root(store)?.1 != id
    {
        return Err("qualification key or revision state changed during owner approval".into());
    }
    // The caller serializes this operation with the secure-admin lock. State
    // is advanced before returning signature bytes, so a failed output write
    // consumes a revision instead of allowing an unattended replay.
    let purpose = match version {
        3 => PURPOSE_V3,
        2 => PURPOSE_V2,
        _ => PURPOSE,
    };
    let mut preimage = purpose.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(policy);
    let signature = key.sign(&preimage);
    let next_state = if version >= 2 {
        json!({"revision": revision, "policy_sha256": policy_digest, "policy_version": version})
    } else {
        json!({"revision": revision, "policy_sha256": policy_digest})
    };
    let state = serde_json::to_vec(&next_state).map_err(|_| "invalid policy state")?;
    store
        .put_qualification_policy_state(&state)
        .map_err(String::from)?;
    serde_json::to_vec(&json!({
        "schema_version": version,
        "purpose": purpose,
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
            if (mode == "sign" || mode == "sign-v2" || mode == "sign-v3") && a == "--policy" && b == "--revocations" && c == "--out" =>
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
            let version = match mode.as_str() { "sign-v3" => 3, "sign-v2" => 2, _ => 1 };
            let envelope = sign_version(&store, &DeviceOwner, &policy, &ledger, SystemTime::now, version,
                || read(Path::new(revocations_path), true))?;
            let mut out = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(out_path).map_err(|_| "qualification output already exists or is unavailable")?;
            out.write_all(&envelope).and_then(|_| out.write_all(b"\n")).and_then(|_| out.sync_all()).map_err(|_| "qualification output write failed")?;
            println!("policy-envelope: {}", digest(&envelope));
        }
        _ => return Err("usage: agent-bot-keyd qualification-policy init-root | public-root | sign|sign-v2|sign-v3 --policy FILE --revocations FILE --out FILE".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consent::tests::Scripted,
        store::{
            tests::Memory, Items, PIN_SERVICE, QUALIFICATION_POLICY_ACCOUNT,
            QUALIFICATION_POLICY_STATE_ACCOUNT,
        },
    };
    use ed25519_dalek::{Signature, Verifier};
    use std::time::Duration;

    fn fixture(id: &str, updated: &str) -> (Vec<u8>, Vec<u8>, SystemTime) {
        // P-256 generator point as DER SubjectPublicKeyInfo, test-only.
        let spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==";
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
                "id": "fixture-signer", "host_id": "fixture-host", "algorithm": "ES256", "public_key_spki_der_base64": spki
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
    fn v2_signing_pins_separate_souls_build_and_prevents_downgrade() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (v1, v1_ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        sign(&store, &Scripted::new(true), &v1, &v1_ledger, || now).unwrap();
        let mut policy: Value = serde_json::from_slice(&v1).unwrap();
        let mut ledger: Value = serde_json::from_slice(&v1_ledger).unwrap();
        policy["contract"] = json!("control/v2");
        policy["policy_revision"] = json!(2);
        policy["souls_build_workflow"] = json!({
            "id": "souls-build-fixture",
            "repository": "true-line/agent-bot-souls",
            "workflow_path": ".github/workflows/release.yml",
            "source_commit": "1111111111111111111111111111111111111111",
            "source_tree": "2222222222222222222222222222222222222222",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity": "https://github.com/true-line/agent-bot-souls/.github/workflows/release.yml@refs/heads/main",
            "trust_root_sha256": format!("sha256:{}", "3".repeat(64)),
            "builder_sha256": format!("sha256:{}", "4".repeat(64)),
            "toolchain_sha256": format!("sha256:{}", "5".repeat(64)),
            "receipt_predicate_type": "https://true-line.ai/soul-contracts/adapter/v2/souls-build",
            "bundle_media_type": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsse_payload_type": "application/vnd.in-toto+json"
        });
        ledger["revoked_souls_build_workflow_ids"] = json!([]);
        ledger["revoked_souls_build_receipt_sha256"] = json!([]);
        policy["revocation_snapshot"] = ledger.clone();
        let raw = serde_json::to_vec(&policy).unwrap();
        let ledger_raw = serde_json::to_vec(&ledger).unwrap();
        let envelope = sign_version(
            &store,
            &Scripted::new(true),
            &raw,
            &ledger_raw,
            || now,
            2,
            || Ok(ledger_raw.clone()),
        )
        .unwrap();
        let signed: Value = serde_json::from_slice(&envelope).unwrap();
        assert_eq!(signed["schema_version"], 2);
        assert_eq!(signed["purpose"], PURPOSE_V2);
        let signature = URL_SAFE_NO_PAD
            .decode(signed["signature_base64url"].as_str().unwrap())
            .unwrap();
        let mut preimage = PURPOSE_V2.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&raw);
        let mut seed = store.qualification_policy_seed().unwrap();
        let key = SigningKey::from_bytes(&seed).verifying_key();
        seed.fill(0);
        key.verify(&preimage, &Signature::from_slice(&signature).unwrap())
            .unwrap();
        assert!(verify_signed_envelope_v3(
            &envelope,
            &key.to_bytes(),
            &id,
            OffsetDateTime::from(now)
        )
        .is_err());
        let mut downgraded: Value = serde_json::from_slice(&v1).unwrap();
        downgraded["policy_revision"] = json!(3);
        assert!(sign(
            &store,
            &Scripted::new(true),
            &serde_json::to_vec(&downgraded).unwrap(),
            &v1_ledger,
            || now
        )
        .is_err());
        policy["souls_build_workflow"]
            .as_object_mut()
            .unwrap()
            .remove("source_tree");
        policy["policy_revision"] = json!(3);
        assert!(sign_version(
            &store,
            &Scripted::new(true),
            &serde_json::to_vec(&policy).unwrap(),
            &ledger_raw,
            || now,
            2,
            || Ok(ledger_raw.clone())
        )
        .is_err());
    }

    #[test]
    fn v3_signing_pins_frozen_soul_and_shares_revision_state() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (v1, _, now) = fixture(&id, "2026-11-21T21:00:00Z");
        let mut policy: Value = serde_json::from_slice(&v1).unwrap();
        policy["contract"] = json!("control/v3");
        policy["policy_revision"] = json!(3);
        policy["frozen_soul_release_provenance_enabled"] = json!(true);
        policy["souls_build_workflow"] = json!({
            "id": "fixture-souls-build", "repository": "true-line/agent-bot-souls",
            "workflow_path": ".github/workflows/release.yml",
            "source_commit": "1111111111111111111111111111111111111111",
            "source_tree": "2222222222222222222222222222222222222222",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity": "https://github.com/true-line/agent-bot-souls/.github/workflows/release.yml@refs/heads/main",
            "trust_root_sha256": format!("sha256:{}", "3".repeat(64)),
            "builder_sha256": format!("sha256:{}", "4".repeat(64)),
            "toolchain_sha256": format!("sha256:{}", "5".repeat(64)),
            "receipt_predicate_type": "https://true-line.ai/soul-contracts/adapter/v2/souls-build",
            "bundle_media_type": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsse_payload_type": "application/vnd.in-toto+json"
        });
        policy["frozen_soul_build_workflow"] = json!({
            "id": "fixture-frozen-build", "repository": "true-line/soul-package",
            "workflow_path": ".github/workflows/stage2a-frozen-soul-receipt.yml",
            "source_commit": "6666666666666666666666666666666666666666",
            "source_tree": "7777777777777777777777777777777777777777",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity": "https://github.com/true-line/soul-package/.github/workflows/stage2a-frozen-soul-receipt.yml@refs/heads/main",
            "trust_root_sha256": format!("sha256:{}", "8".repeat(64)),
            "builder_sha256": format!("sha256:{}", "9".repeat(64)),
            "toolchain_sha256": format!("sha256:{}", "a".repeat(64)),
            "receipt_predicate_type": "https://true-line.ai/soul-contracts/package/v1/frozen-soul-build",
            "bundle_media_type": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsse_payload_type": "application/vnd.in-toto+json",
            "artifact_format": "stage2a-frozen-hello-ustar/v1",
            "subject_name_template": "sha256-{artifact_sha256}.soul",
            "rekor_entry_kind": "dsse", "rekor_entry_version": "0.0.1",
            "transparency_log_id": "b".repeat(64),
            "template": {
                "repository": "true-line/soul-conformance",
                "source_commit": "8e82f47781e583e4b09352cbfef5ca3bfefe45aa",
                "source_tree": "5f3ab3acee16de02a38a51204fb9401c3566a6d0",
                "path": "templates/hello.soul",
                "template_tree": "e944d40e5f495f6de395619b254ed890e36b53ee"
            }
        });
        policy["frozen_soul_mapping"] = json!({
            "soul_id": "agent_00000000-0000-0000-0000-000000000000",
            "artifact_sha256": "c".repeat(64),
            "receipt_sha256": format!("sha256:{}", "f".repeat(64)),
            "claimed_definition_digest": format!("sha256:{}", "d".repeat(64)),
            "definition_measurement": format!("sha256:{}", "e".repeat(64))
        });
        let mut ledger = policy["revocation_snapshot"].clone();
        for name in [
            "revoked_souls_build_workflow_ids",
            "revoked_souls_build_receipt_sha256",
            "revoked_frozen_soul_build_workflow_ids",
            "revoked_frozen_soul_receipt_sha256",
            "revoked_frozen_soul_artifact_sha256",
        ] {
            ledger[name] = json!([]);
        }
        policy["revocation_snapshot"] = ledger.clone();
        let raw = serde_json::to_vec(&policy).unwrap();
        let ledger_raw = serde_json::to_vec(&ledger).unwrap();
        let owner = Scripted::new(true);
        let envelope = sign_version(
            &store,
            &owner,
            &raw,
            &ledger_raw,
            || now,
            3,
            || Ok(ledger_raw.clone()),
        )
        .unwrap();
        let prompt = owner.asked.lock().unwrap()[0].clone();
        for expected in [
            "agent_00000000-0000-0000-0000-000000000000",
            &"c".repeat(64),
            &format!("sha256:{}", "8".repeat(64)),
            &"b".repeat(64),
        ] {
            assert!(prompt.contains(expected));
        }
        let signed: Value = serde_json::from_slice(&envelope).unwrap();
        assert_eq!(signed["schema_version"], 3);
        assert_eq!(signed["purpose"], PURPOSE_V3);
        let sig = URL_SAFE_NO_PAD
            .decode(signed["signature_base64url"].as_str().unwrap())
            .unwrap();
        let mut preimage = PURPOSE_V3.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&raw);
        let mut seed = store.qualification_policy_seed().unwrap();
        let verifying = SigningKey::from_bytes(&seed).verifying_key();
        seed.fill(0);
        verifying
            .verify(&preimage, &Signature::from_slice(&sig).unwrap())
            .unwrap();
        let root = verifying.to_bytes();
        let accepted =
            verify_signed_envelope_v3(&envelope, &root, &id, OffsetDateTime::from(now)).unwrap();
        assert_eq!(accepted.version, 3);
        assert_eq!(accepted.revision, 3);
        assert_eq!(accepted.payload_sha256, digest(&raw));
        assert!(verify_signed_envelope(&envelope, &root, &id, OffsetDateTime::from(now)).is_err());
        assert!(verify_signed_envelope_v3(
            &envelope,
            &root,
            &id,
            OffsetDateTime::from(now + Duration::from_secs(3600))
        )
        .is_ok());
        assert!(verify_signed_envelope_v3(
            &envelope,
            &root,
            &id,
            OffsetDateTime::from(now + Duration::from_secs(3601))
        )
        .is_err());
        assert!(
            verify_signed_envelope_v3(&envelope, &[0u8; 32], &id, OffsetDateTime::from(now))
                .is_err()
        );
        let mut wrong_purpose: Value = serde_json::from_slice(&envelope).unwrap();
        wrong_purpose["purpose"] = json!(PURPOSE_V2);
        assert!(verify_signed_envelope_v3(
            &serde_json::to_vec(&wrong_purpose).unwrap(),
            &root,
            &id,
            OffsetDateTime::from(now)
        )
        .is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&store.qualification_policy_state().unwrap().unwrap())
                .unwrap()["policy_version"],
            3
        );
        assert!(sign_version(
            &store,
            &Scripted::new(true),
            &raw,
            &ledger_raw,
            || now,
            2,
            || Ok(ledger_raw.clone())
        )
        .is_err());
        policy["policy_revision"] = json!(4);
        policy["frozen_soul_build_workflow"]["rekor_entry_version"] = json!("0.0.2");
        assert!(validate_version(
            &serde_json::to_vec(&policy).unwrap(),
            &ledger_raw,
            &id,
            OffsetDateTime::from(now),
            3
        )
        .is_err());
        policy["frozen_soul_build_workflow"]["rekor_entry_version"] = json!("0.0.1");
        let saved_receipt = policy["frozen_soul_mapping"]["receipt_sha256"].clone();
        policy["frozen_soul_mapping"]
            .as_object_mut()
            .unwrap()
            .remove("receipt_sha256");
        assert!(validate_version(
            &serde_json::to_vec(&policy).unwrap(),
            &ledger_raw,
            &id,
            OffsetDateTime::from(now),
            3
        )
        .is_err());
        policy["frozen_soul_mapping"]["receipt_sha256"] = saved_receipt;
        let mut receipt_revoked = policy.clone();
        receipt_revoked["revocation_snapshot"]["revoked_frozen_soul_receipt_sha256"] =
            json!(["sha256:".to_owned() + &"f".repeat(64)]);
        let receipt_ledger = serde_json::to_vec(&receipt_revoked["revocation_snapshot"]).unwrap();
        assert!(validate_version(
            &serde_json::to_vec(&receipt_revoked).unwrap(),
            &receipt_ledger,
            &id,
            OffsetDateTime::from(now),
            3
        )
        .is_err());
        assert!(validate_version(
            &serde_json::to_vec(&policy).unwrap(),
            &ledger_raw,
            &id,
            OffsetDateTime::from(now + Duration::from_secs(3601)),
            3
        )
        .is_err());
        policy
            .as_object_mut()
            .unwrap()
            .remove("frozen_soul_mapping");
        assert!(validate_version(
            &serde_json::to_vec(&policy).unwrap(),
            &ledger_raw,
            &id,
            OffsetDateTime::from(now),
            3
        )
        .is_err());
        let mut revoked: Value = serde_json::from_slice(&raw).unwrap();
        revoked["policy_revision"] = json!(4);
        revoked["revocation_snapshot"]["revoked_frozen_soul_artifact_sha256"] =
            json!(["c".repeat(64)]);
        let revoked_ledger = serde_json::to_vec(&revoked["revocation_snapshot"]).unwrap();
        assert!(validate_version(
            &serde_json::to_vec(&revoked).unwrap(),
            &revoked_ledger,
            &id,
            OffsetDateTime::from(now),
            3
        )
        .is_err());
        let mut off: Value = serde_json::from_slice(&raw).unwrap();
        off["policy_revision"] = json!(4);
        off["frozen_soul_release_provenance_enabled"] = json!(false);
        off.as_object_mut()
            .unwrap()
            .remove("frozen_soul_build_workflow");
        off["frozen_soul_mapping"]
            .as_object_mut()
            .unwrap()
            .remove("receipt_sha256");
        for name in [
            "revoked_frozen_soul_build_workflow_ids",
            "revoked_frozen_soul_receipt_sha256",
        ] {
            off["revocation_snapshot"]
                .as_object_mut()
                .unwrap()
                .remove(name);
        }
        let off_raw = serde_json::to_vec(&off).unwrap();
        let off_ledger = serde_json::to_vec(&off["revocation_snapshot"]).unwrap();
        assert!(validate_version(&off_raw, &off_ledger, &id, OffsetDateTime::from(now), 3).is_ok());
        let off_owner = Scripted::new(true);
        sign_version(
            &store,
            &off_owner,
            &off_raw,
            &off_ledger,
            || now,
            3,
            || Ok(off_ledger.clone()),
        )
        .unwrap();
        assert!(off_owner.asked.lock().unwrap()[0].contains("release provenance OFF"));
        off["frozen_soul_mapping"]["receipt_sha256"] = json!(format!("sha256:{}", "f".repeat(64)));
        assert!(validate_version(
            &serde_json::to_vec(&off).unwrap(),
            &off_ledger,
            &id,
            OffsetDateTime::from(now),
            3
        )
        .is_err());
        off["frozen_soul_mapping"]
            .as_object_mut()
            .unwrap()
            .remove("receipt_sha256");
        off["frozen_soul_build_workflow"] =
            serde_json::from_slice::<Value>(&raw).unwrap()["frozen_soul_build_workflow"].clone();
        assert!(validate_version(
            &serde_json::to_vec(&off).unwrap(),
            &off_ledger,
            &id,
            OffsetDateTime::from(now),
            3
        )
        .is_err());
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
        assert!(store.qualification_policy_state().unwrap().is_some());
        memory
            .write(PIN_SERVICE, QUALIFICATION_POLICY_ACCOUNT, b"bad")
            .unwrap();
        assert!(public_root(&store).is_err());
    }

    #[test]
    fn signs_exact_purpose_and_consumes_revision() {
        let memory = Memory::default();
        let store = Store::new(Box::new(memory.clone()));
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        let owner = Scripted::new(true);
        let envelope = sign(&store, &owner, &policy, &ledger, || now).unwrap();
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
        assert!(sign(&store, &owner, &policy, &ledger, || now).is_err());
        assert!(memory
            .remove(PIN_SERVICE, QUALIFICATION_POLICY_STATE_ACCOUNT)
            .unwrap());
        assert!(
            sign(&store, &owner, &policy, &ledger, || now).is_err(),
            "a missing marker cannot reset revision to zero"
        );
    }

    #[test]
    fn independently_verifies_exact_owner_signed_policy_at_freshness_boundary() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T20:00:00Z");
        let envelope = sign(&store, &Scripted::new(true), &policy, &ledger, || now).unwrap();
        let mut seed = store.qualification_policy_seed().unwrap();
        let root = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        seed.fill(0);
        let accepted =
            verify_signed_envelope(&envelope, &root, &id, OffsetDateTime::from(now)).unwrap();
        assert_eq!(
            (
                accepted.version,
                accepted.revision,
                accepted.payload_sha256.as_str(),
                accepted.owner_key_id.as_str()
            ),
            (1, 1, digest(&policy).as_str(), id.as_str())
        );
        assert!(verify_signed_envelope(
            &envelope,
            &root,
            &id,
            OffsetDateTime::from(now + Duration::from_secs(1))
        )
        .is_err());
        let mut wrong: Value = serde_json::from_slice(&envelope).unwrap();
        wrong["purpose"] = json!(PURPOSE_V2);
        assert!(verify_signed_envelope(
            &serde_json::to_vec(&wrong).unwrap(),
            &root,
            &id,
            OffsetDateTime::from(now)
        )
        .is_err());
        wrong["purpose"] = json!(PURPOSE);
        wrong["signature_base64url"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        assert!(verify_signed_envelope(
            &serde_json::to_vec(&wrong).unwrap(),
            &root,
            &id,
            OffsetDateTime::from(now)
        )
        .is_err());
    }

    #[test]
    fn revoked_signer_cannot_designate_witness_host() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy_raw, ledger_raw, now) = fixture(&id, "2026-11-21T21:00:00Z");
        let mut policy: Value = serde_json::from_slice(&policy_raw).unwrap();
        let mut ledger: Value = serde_json::from_slice(&ledger_raw).unwrap();
        ledger["revoked_evidence_signer_ids"] = json!(["fixture-signer"]);
        policy["revocation_snapshot"] = ledger.clone();
        let envelope = sign(
            &store,
            &Scripted::new(true),
            &serde_json::to_vec(&policy).unwrap(),
            &serde_json::to_vec(&ledger).unwrap(),
            || now,
        )
        .unwrap();
        let mut seed = store.qualification_policy_seed().unwrap();
        let root = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        seed.fill(0);
        let accepted =
            verify_signed_envelope(&envelope, &root, &id, OffsetDateTime::from(now)).unwrap();
        assert!(accepted.evidence_signer_hosts.is_empty());
        assert_eq!(accepted.evidence_signer_spki.len(), 1);
    }

    #[test]
    fn rejects_stale_changed_ledger_and_missing_owner() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        assert!(sign(&store, &Scripted::new(false), &policy, &ledger, || now).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&store.qualification_policy_state().unwrap().unwrap())
                .unwrap()["revision"],
            0
        );
        let (_, changed_ledger, _) = fixture(&id, "2026-11-21T20:59:59Z");
        assert!(sign(
            &store,
            &Scripted::new(true),
            &policy,
            &changed_ledger,
            || now
        )
        .is_err());
        let (stale_policy, stale_ledger, _) = fixture(&id, "2026-11-21T20:00:00Z");
        assert!(sign(
            &store,
            &Scripted::new(true),
            &stale_policy,
            &stale_ledger,
            || now + Duration::from_secs(3601)
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

    #[test]
    fn rejects_bad_workflow_url_and_host_spki_before_approval() {
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        for (field, invalid) in [
            ("workflow_path", ".github/workflows/../release.yml"),
            ("oidc_issuer", "https://"),
            ("oidc_issuer", "https://host:bad/path"),
            ("oidc_issuer", "https://host%2fpath"),
            ("oidc_issuer", "https://[::1]x"),
            ("oidc_issuer", "https://host\\evil"),
            (
                "certificate_identity",
                "https://user@github.com/release#fragment",
            ),
        ] {
            let mut value: Value = serde_json::from_slice(&policy).unwrap();
            value["release_workflow"][field] = Value::String(invalid.into());
            let owner = Scripted::new(true);
            assert!(sign(
                &store,
                &owner,
                &serde_json::to_vec(&value).unwrap(),
                &ledger,
                || now
            )
            .is_err());
            assert!(owner.asked.lock().unwrap().is_empty());
        }
        let mut value: Value = serde_json::from_slice(&policy).unwrap();
        value["evidence_signers"][0]["public_key_spki_der_base64"] = Value::String("AQID".into());
        assert!(sign(
            &store,
            &Scripted::new(true),
            &serde_json::to_vec(&value).unwrap(),
            &ledger,
            || now
        )
        .is_err());
        let mut value: Value = serde_json::from_slice(&policy).unwrap();
        let mut spki = base64::engine::general_purpose::STANDARD
            .decode(
                value["evidence_signers"][0]["public_key_spki_der_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        spki.push(0);
        value["evidence_signers"][0]["public_key_spki_der_base64"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode(spki));
        assert!(sign(
            &store,
            &Scripted::new(true),
            &serde_json::to_vec(&value).unwrap(),
            &ledger,
            || now
        )
        .is_err());
    }

    #[test]
    fn expiry_during_owner_prompt_refuses_without_consuming_revision() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        let calls = AtomicUsize::new(0);
        let clock = || {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                now
            } else {
                now + Duration::from_secs(3601)
            }
        };
        let owner = Scripted::new(true);
        assert!(sign(&store, &owner, &policy, &ledger, clock).is_err());
        assert_eq!(owner.asked.lock().unwrap().len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&store.qualification_policy_state().unwrap().unwrap())
                .unwrap()["revision"],
            0
        );
    }

    #[test]
    fn state_removed_during_owner_prompt_refuses_signature() {
        use crate::consent::{Consent, Refusal};
        struct RemoveState(Memory);
        impl Consent for RemoveState {
            fn ask(&self, _: &str) -> Result<(), Refusal> {
                self.0
                    .remove(PIN_SERVICE, QUALIFICATION_POLICY_STATE_ACCOUNT)
                    .unwrap();
                Ok(())
            }
        }
        let memory = Memory::default();
        let store = Store::new(Box::new(memory.clone()));
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        assert!(sign(&store, &RemoveState(memory), &policy, &ledger, || now).is_err());
    }

    #[test]
    fn revocation_added_during_owner_prompt_refuses_signature() {
        use crate::consent::{Consent, Refusal};
        use std::sync::{Arc, Mutex};

        struct ChangeLedger {
            current: Arc<Mutex<Vec<u8>>>,
            changed: Vec<u8>,
        }
        impl Consent for ChangeLedger {
            fn ask(&self, _: &str) -> Result<(), Refusal> {
                *self.current.lock().unwrap() = self.changed.clone();
                Ok(())
            }
        }

        let store = Store::new(Box::<Memory>::default());
        let (_, id) = init_root(&store, &Scripted::new(true)).unwrap();
        let (policy, ledger, now) = fixture(&id, "2026-11-21T21:00:00Z");
        let mut changed: Value = serde_json::from_slice(&ledger).unwrap();
        changed["revoked_evidence_signer_ids"] = json!(["fixture-signer"]);
        let current = Arc::new(Mutex::new(ledger.clone()));
        let owner = ChangeLedger {
            current: Arc::clone(&current),
            changed: serde_json::to_vec(&changed).unwrap(),
        };
        let refused = sign_version(
            &store,
            &owner,
            &policy,
            &ledger,
            || now,
            1,
            || Ok(current.lock().unwrap().clone()),
        );
        assert!(refused
            .unwrap_err()
            .contains("ledger changed during owner approval"));
        assert_eq!(
            serde_json::from_slice::<Value>(&store.qualification_policy_state().unwrap().unwrap())
                .unwrap()["revision"],
            0
        );
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
            assert_eq!(
                serde_json::from_slice::<Value>(
                    &store.qualification_policy_state().unwrap().unwrap()
                )
                .unwrap()["revision"],
                0
            );
        });
    }
}
