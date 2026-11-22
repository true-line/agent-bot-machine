//! A distinct Secure Enclave witness for the greatest owner-signed policy.
//! The Darwin entry point must hold the secure-admin pairing lock and accept
//! only a Machine-authenticated challenge. Nothing here is an HQ device option.

use crate::{
    consent::Consent,
    hq_device::{Enclave, Pair},
    qualification_policy::AuthenticatedPolicy,
    store::Items,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime, UtcOffset};

pub(crate) const PURPOSE: &str = "agent-bot/qualification-policy-acceptance-witness/v1";
pub(crate) const SERVICE: &str = "agent-bot.keyd.qualification-witness.v1";
const KEY_ACCOUNT: &str = "secure-enclave-reference";
const LEDGER_ACCOUNT: &str = "accepted-owner-policy";
const SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema_version: u64,
    host_id: String,
    pair: Pair,
    owner_root_hex: String,
    owner_key_id: String,
    witness_key_id: String,
    witness_spki_der_base64: String,
    policy_version: u64,
    policy_revision: u64,
    policy_sha256: String,
}

pub(crate) struct Pin {
    pub key_id: String,
    pub spki_der_base64: String,
}

fn identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().enumerate().all(|(i, c)| {
            c.is_ascii_alphanumeric() || (i > 0 && matches!(c, b'.' | b'_' | b':' | b'-'))
        })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

fn valid_pair(pair: &Pair) -> bool {
    let key = |text: &str| {
        STANDARD
            .decode(text)
            .is_ok_and(|bytes| bytes.len() == 32 && STANDARD.encode(bytes) == text)
    };
    let owner = STANDARD.decode(&pair.owner).is_ok_and(|bytes| {
        bytes.len() == 65 && bytes[0] == 4 && STANDARD.encode(bytes) == pair.owner
    });
    key(&pair.machine_pub)
        && key(&pair.hq_pub)
        && pair.hq_uid > 0
        && owner
        && pair.hq_epoch.len() == 64
        && pair
            .hq_epoch
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn spki(point: &[u8; 65]) -> Result<Vec<u8>, &'static str> {
    if point[0] != 4 {
        return Err("qualification witness point is invalid");
    }
    let mut out = SPKI_PREFIX.to_vec();
    out.extend_from_slice(&point[1..]);
    Ok(out)
}

fn key_id(spki: &[u8]) -> String {
    format!("qual-witness-p256-{}", &hex(&Sha256::digest(spki))[..16])
}

fn read_ledger(items: &dyn Items) -> Result<(Ledger, Vec<u8>), String> {
    let raw = items
        .read(SERVICE, LEDGER_ACCOUNT)?
        .ok_or("qualification witness ledger is missing")?;
    let ledger: Ledger =
        serde_json::from_slice(&raw).map_err(|_| "qualification witness ledger is malformed")?;
    if serde_json::to_vec(&ledger).map_err(|_| "qualification witness ledger is malformed")? != raw
        || ledger.schema_version != 1
        || !identifier(&ledger.host_id)
        || !valid_pair(&ledger.pair)
        || !identifier(&ledger.owner_key_id)
        || !identifier(&ledger.witness_key_id)
        || ledger.policy_revision == 0
        || !matches!(ledger.policy_version, 1 | 2)
        || ledger.policy_sha256.len() != 71
        || !ledger.policy_sha256.starts_with("sha256:")
        || !ledger.policy_sha256[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || ledger.owner_root_hex.len() != 64
        || !ledger
            .owner_root_hex
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("qualification witness ledger is malformed".into());
    }
    Ok((ledger, raw))
}

fn next_policy(prior: &Ledger, policy: &AuthenticatedPolicy) -> Result<Ledger, String> {
    if !matches!(policy.version, 1 | 2)
        || policy.revision == 0
        || policy.owner_key_id != prior.owner_key_id
        || policy.version < prior.policy_version
        || policy.revision < prior.policy_revision
        || (policy.revision == prior.policy_revision
            && (policy.version != prior.policy_version
                || policy.payload_sha256 != prior.policy_sha256))
    {
        return Err("qualification witness policy rollback or equivocation".into());
    }
    let mut next = prior.clone();
    next.policy_version = policy.version;
    next.policy_revision = policy.revision;
    next.policy_sha256 = policy.payload_sha256.clone();
    Ok(next)
}

// Public pin recovery is read-only. It requires the same live pair and
// protected key reference, so a lost stdout write cannot strand enrollment.
pub(crate) fn public_pin(
    items: &dyn Items,
    enclave: &dyn Enclave,
    pair: &Pair,
    host_id: &str,
    pinned_root: &[u8; 32],
) -> Result<Pin, String> {
    if !identifier(host_id) || !valid_pair(pair) {
        return Err("qualification witness live pair is invalid".into());
    }
    enclave.check_live().map_err(String::from)?;
    let (ledger, _) = read_ledger(items)?;
    if &ledger.pair != pair
        || ledger.host_id != host_id
        || ledger.owner_root_hex != hex(pinned_root)
    {
        return Err("qualification witness host, pair or root changed".into());
    }
    let mut reference = items
        .read(SERVICE, KEY_ACCOUNT)?
        .ok_or("qualification witness key is missing")?;
    let point = enclave.public(&reference).map_err(String::from)?;
    reference.fill(0);
    let public = spki(&point)?;
    if STANDARD.encode(&public) != ledger.witness_spki_der_base64
        || key_id(&public) != ledger.witness_key_id
    {
        return Err("qualification witness key differs from pin".into());
    }
    enclave.check_live().map_err(String::from)?;
    Ok(Pin {
        key_id: ledger.witness_key_id,
        spki_der_base64: ledger.witness_spki_der_base64,
    })
}

// First installation is an explicit owner-present operation. A missing half
// of previously initialized state is never recreated by this path.
pub(crate) fn initialize(
    items: &dyn Items,
    enclave: &dyn Enclave,
    owner: &dyn Consent,
    pair: &Pair,
    host_id: &str,
    pinned_root: &[u8; 32],
    policy: &AuthenticatedPolicy,
) -> Result<Pin, String> {
    if !identifier(host_id)
        || !valid_pair(pair)
        || policy.revision == 0
        || !policy
            .evidence_signer_hosts
            .iter()
            .any(|host| host == host_id)
        || items.read(SERVICE, KEY_ACCOUNT)?.is_some()
        || items.read(SERVICE, LEDGER_ACCOUNT)?.is_some()
    {
        return Err("qualification witness already exists or input is invalid".into());
    }
    owner
        .ask(&format!(
            "Initialize qualification witness for host {host_id}, policy v{} revision {} {}",
            policy.version, policy.revision, policy.payload_sha256
        ))
        .map_err(String::from)?;
    enclave.check_live().map_err(String::from)?;
    if items.read(SERVICE, KEY_ACCOUNT)?.is_some() || items.read(SERVICE, LEDGER_ACCOUNT)?.is_some()
    {
        return Err("qualification witness state changed during owner approval".into());
    }
    let mut reference = enclave.create().map_err(String::from)?;
    let point = enclave.public(&reference).map_err(String::from)?;
    let public = spki(&point)?;
    if policy.evidence_signer_spki.iter().any(|key| key == &public)
        || STANDARD
            .decode(&pair.owner)
            .is_ok_and(|owner| owner == point)
    {
        reference.fill(0);
        return Err("qualification witness key is not distinct".into());
    }
    let pin = Pin {
        key_id: key_id(&public),
        spki_der_base64: STANDARD.encode(&public),
    };
    if pin.key_id == policy.owner_key_id {
        reference.fill(0);
        return Err("qualification witness key is not distinct".into());
    }
    let ledger = Ledger {
        schema_version: 1,
        host_id: host_id.to_owned(),
        pair: pair.clone(),
        owner_root_hex: hex(pinned_root),
        owner_key_id: policy.owner_key_id.clone(),
        witness_key_id: pin.key_id.clone(),
        witness_spki_der_base64: pin.spki_der_base64.clone(),
        policy_version: policy.version,
        policy_revision: policy.revision,
        policy_sha256: policy.payload_sha256.clone(),
    };
    let inserted = items.insert(SERVICE, KEY_ACCOUNT, &reference);
    reference.fill(0);
    if !inserted? {
        return Err("qualification witness key already exists".into());
    }
    let raw = serde_json::to_vec(&ledger)
        .map_err(|_| "qualification witness ledger cannot be encoded")?;
    if !items.insert(SERVICE, LEDGER_ACCOUNT, &raw)? {
        return Err("qualification witness ledger already exists".into());
    }
    enclave.check_live().map_err(String::from)?;
    Ok(pin)
}

pub(crate) fn sign(
    items: &dyn Items,
    enclave: &dyn Enclave,
    pair: &Pair,
    host_id: &str,
    pinned_root: &[u8; 32],
    policy: &AuthenticatedPolicy,
    challenge: &[u8; 32],
    now: OffsetDateTime,
    trusted_time: bool,
) -> Result<Vec<u8>, String> {
    if !trusted_time || !valid_pair(pair) || !identifier(host_id) || now.offset() != UtcOffset::UTC
    {
        return Err("qualification witness trusted state is unavailable".into());
    }
    if !policy
        .evidence_signer_hosts
        .iter()
        .any(|host| host == host_id)
    {
        return Err("qualification host is not owner-designated".into());
    }
    enclave.check_live().map_err(String::from)?;
    let (prior, prior_raw) = read_ledger(items)?;
    if &prior.pair != pair || prior.host_id != host_id || prior.owner_root_hex != hex(pinned_root) {
        return Err("qualification witness host, pair or root changed".into());
    }
    let next = next_policy(&prior, policy)?;
    let mut reference = items
        .read(SERVICE, KEY_ACCOUNT)?
        .ok_or("qualification witness key is missing")?;
    let point = enclave.public(&reference).map_err(String::from)?;
    let public = spki(&point)?;
    if STANDARD.encode(&public) != prior.witness_spki_der_base64
        || key_id(&public) != prior.witness_key_id
        || policy.evidence_signer_spki.iter().any(|key| key == &public)
    {
        reference.fill(0);
        return Err("qualification witness key differs from pin".into());
    }
    if items.read(SERVICE, LEDGER_ACCOUNT)?.as_deref() != Some(prior_raw.as_slice()) {
        reference.fill(0);
        return Err("qualification witness ledger changed".into());
    }
    if next != prior {
        let raw = serde_json::to_vec(&next)
            .map_err(|_| "qualification witness ledger cannot be encoded")?;
        items.write(SERVICE, LEDGER_ACCOUNT, &raw)?;
        if items.read(SERVICE, LEDGER_ACCOUNT)?.as_deref() != Some(raw.as_slice()) {
            reference.fill(0);
            return Err("qualification witness ledger advance is unavailable".into());
        }
    }
    let issued = now
        .replace_nanosecond(0)
        .map_err(|_| "qualification witness clock is invalid")?;
    let expires = issued + Duration::seconds(60);
    let raw = serde_json::to_vec(&json!({
        "contract":"control/v1", "kind":"qualification-policy-acceptance-witness", "schema_version":1,
        "host_id": host_id, "machine_pub":pair.machine_pub, "hq_pub":pair.hq_pub, "hq_uid":pair.hq_uid,
        "hq_epoch":pair.hq_epoch, "pair_owner_pub":pair.owner,
        "witness_key_id":prior.witness_key_id, "challenge_base64url":URL_SAFE_NO_PAD.encode(challenge),
        "policy_version":next.policy_version, "policy_revision":next.policy_revision,
        "policy_sha256":next.policy_sha256, "owner_key_id":next.owner_key_id,
        "issued_at":issued.format(&Rfc3339).map_err(|_| "qualification witness timestamp is invalid")?,
        "expires_at":expires.format(&Rfc3339).map_err(|_| "qualification witness timestamp is invalid")?
    })).map_err(|_| "qualification witness cannot be encoded")?;
    if raw.len() > 4096 || !raw.is_ascii() {
        reference.fill(0);
        return Err("qualification witness payload is too large".into());
    }
    let mut preimage = PURPOSE.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&raw);
    let signature = enclave.sign(&reference, &preimage).map_err(String::from)?;
    reference.fill(0);
    enclave.check_live().map_err(String::from)?;
    if items.read(SERVICE, LEDGER_ACCOUNT)?.as_deref()
        != Some(
            serde_json::to_vec(&next)
                .map_err(|_| "invalid qualification witness ledger")?
                .as_slice(),
        )
    {
        return Err("qualification witness ledger changed after signing".into());
    }
    let envelope = serde_json::to_vec(&json!({
        "schema_version":1, "purpose":PURPOSE, "witness_key_id":next.witness_key_id,
        "payload_sha256":format!("sha256:{}", hex(&Sha256::digest(&raw))),
        "payload_base64url":URL_SAFE_NO_PAD.encode(&raw), "signature_base64url":URL_SAFE_NO_PAD.encode(signature)
    })).map_err(|_| "qualification witness envelope cannot be encoded")?;
    if envelope.len() > 8192 {
        return Err("qualification witness envelope is too large".into());
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consent::tests::Scripted, store::tests::Memory};
    use serde_json::Value;

    struct SyntheticEnclave;
    impl Enclave for SyntheticEnclave {
        fn check_live(&self) -> Result<(), &'static str> {
            Ok(())
        }
        fn create(&self) -> Result<Vec<u8>, &'static str> {
            Ok(vec![1, 2, 3])
        }
        fn public(&self, _: &[u8]) -> Result<[u8; 65], &'static str> {
            let mut point = [8u8; 65];
            point[0] = 4;
            Ok(point)
        }
        fn sign(&self, _: &[u8], _: &[u8]) -> Result<[u8; 64], &'static str> {
            Ok([7u8; 64])
        }
    }

    fn pair() -> Pair {
        let mut owner = [9u8; 65];
        owner[0] = 4;
        Pair {
            machine_pub: STANDARD.encode([1u8; 32]),
            hq_pub: STANDARD.encode([2u8; 32]),
            hq_uid: 504,
            owner: STANDARD.encode(owner),
            hq_epoch: "e".repeat(64),
        }
    }
    fn policy(version: u64, revision: u64, digit: char) -> AuthenticatedPolicy {
        AuthenticatedPolicy {
            version,
            revision,
            payload_sha256: format!("sha256:{}", digit.to_string().repeat(64)),
            owner_key_id: "fixture-root".into(),
            evidence_signer_spki: vec![],
            evidence_signer_hosts: vec!["fixture-host".into()],
        }
    }

    #[test]
    fn owner_presence_initializes_once_and_missing_state_refuses() {
        let items = Memory::default();
        let enclave = SyntheticEnclave;
        let refused = Scripted::new(false);
        let root = [3u8; 32];
        assert!(initialize(
            &items,
            &enclave,
            &refused,
            &pair(),
            "fixture-host",
            &root,
            &policy(1, 1, 'a')
        )
        .is_err());
        assert!(items.read(SERVICE, KEY_ACCOUNT).unwrap().is_none());
        let approved = Scripted::new(true);
        let pin = initialize(
            &items,
            &enclave,
            &approved,
            &pair(),
            "fixture-host",
            &root,
            &policy(1, 1, 'a'),
        )
        .unwrap();
        assert!(pin.key_id.starts_with("qual-witness-p256-") && pin.spki_der_base64.len() > 100);
        let recovered = public_pin(&items, &enclave, &pair(), "fixture-host", &root).unwrap();
        assert_eq!(recovered.key_id, pin.key_id);
        assert_eq!(recovered.spki_der_base64, pin.spki_der_base64);
        assert!(public_pin(&items, &enclave, &pair(), "other-host", &root).is_err());
        assert!(initialize(
            &items,
            &enclave,
            &approved,
            &pair(),
            "fixture-host",
            &root,
            &policy(1, 1, 'a')
        )
        .is_err());
        let now = OffsetDateTime::from_unix_timestamp(1_795_300_000).unwrap();
        let challenge = [4u8; 32];
        assert!(sign(
            &items,
            &enclave,
            &pair(),
            "fixture-host",
            &root,
            &policy(1, 1, 'a'),
            &challenge,
            now,
            true
        )
        .is_ok());
        items.remove(SERVICE, LEDGER_ACCOUNT).unwrap();
        assert!(sign(
            &items,
            &enclave,
            &pair(),
            "fixture-host",
            &root,
            &policy(1, 1, 'a'),
            &challenge,
            now,
            true
        )
        .is_err());
        assert!(initialize(
            &items,
            &enclave,
            &approved,
            &pair(),
            "fixture-host",
            &root,
            &policy(1, 1, 'a')
        )
        .is_err());
    }

    #[test]
    fn secure_admin_ledger_rejects_version_and_revision_rollback() {
        let items = Memory::default();
        let enclave = SyntheticEnclave;
        let root = [3u8; 32];
        let pair = pair();
        initialize(
            &items,
            &enclave,
            &Scripted::new(true),
            &pair,
            "fixture-host",
            &root,
            &policy(1, 1, 'a'),
        )
        .unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_795_300_000).unwrap();
        let challenge = [4u8; 32];
        let issued = sign(
            &items,
            &enclave,
            &pair,
            "fixture-host",
            &root,
            &policy(2, 2, 'b'),
            &challenge,
            now,
            true,
        )
        .unwrap();
        let envelope: Value = serde_json::from_slice(&issued).unwrap();
        assert_eq!(envelope["purpose"], PURPOSE);
        let raw = URL_SAFE_NO_PAD
            .decode(envelope["payload_base64url"].as_str().unwrap())
            .unwrap();
        let payload: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(payload["policy_version"], 2);
        assert_eq!(payload["policy_revision"], 2);
        assert_eq!(
            payload["challenge_base64url"],
            URL_SAFE_NO_PAD.encode(challenge)
        );
        for denied in [
            policy(1, 3, 'c'),
            policy(1, 1, 'a'),
            policy(2, 1, 'b'),
            policy(2, 2, 'c'),
        ] {
            assert!(sign(
                &items,
                &enclave,
                &pair,
                "fixture-host",
                &root,
                &denied,
                &challenge,
                now,
                true
            )
            .is_err());
        }
        assert!(sign(
            &items,
            &enclave,
            &pair,
            "other-host",
            &root,
            &policy(2, 2, 'b'),
            &challenge,
            now,
            true
        )
        .is_err());
        assert!(sign(
            &items,
            &enclave,
            &pair,
            "fixture-host",
            &[5u8; 32],
            &policy(2, 2, 'b'),
            &challenge,
            now,
            true
        )
        .is_err());
        assert!(sign(
            &items,
            &enclave,
            &pair,
            "fixture-host",
            &root,
            &policy(2, 2, 'b'),
            &challenge,
            now,
            false
        )
        .is_err());
        let mut changed_pair = pair.clone();
        changed_pair.hq_epoch = "f".repeat(64);
        assert!(sign(
            &items,
            &enclave,
            &changed_pair,
            "fixture-host",
            &root,
            &policy(2, 2, 'b'),
            &challenge,
            now,
            true
        )
        .is_err());
    }
}
