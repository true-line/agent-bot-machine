use crate::{
    consent::{Consent, DeviceOwner, Refusal},
    hq_device::{Enclave, Pair},
    hq_device_darwin::{trusted_state, Native},
    qualification_policy::{self, AuthenticatedPolicy},
    qualification_witness,
    store::{keychain::Keychain, Store},
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use time::OffsetDateTime;

const REQUEST_PURPOSE: &str = "agent-bot-machine/keyd-qualification-witness-request/v1";
const MAX_REQUEST: usize = 3 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: String,
    host_id: String,
    machine_pub: String,
    hq_pub: String,
    hq_uid: u32,
    hq_epoch: String,
    pair_owner_pub: String,
    owner_root_hex: String,
    owner_key_id: String,
    policy_envelope_base64url: String,
    challenge_base64url: Option<String>,
    request_nonce_base64url: String,
    timestamp: i64,
    trusted_time: bool,
    signature_base64url: String,
}

fn hex_root(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("qualification owner root is invalid".into());
    }
    let mut root = [0u8; 32];
    for (i, byte) in root.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| "qualification owner root is invalid")?;
    }
    Ok(root)
}

fn segment(text: &str, min: usize, max: usize) -> Result<Vec<u8>, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| "qualification witness request segment is invalid")?;
    if raw.len() < min || raw.len() > max || URL_SAFE_NO_PAD.encode(&raw) != text {
        return Err("qualification witness request segment is invalid".into());
    }
    Ok(raw)
}

fn verify_request(
    raw: &[u8],
    mode: &str,
    pair: &Pair,
    now: OffsetDateTime,
) -> Result<(Request, Vec<u8>, Option<[u8; 32]>), String> {
    if raw.is_empty() || raw.len() > MAX_REQUEST || !raw.is_ascii() {
        return Err("qualification witness request is unavailable".into());
    }
    let mut object: Value =
        serde_json::from_slice(raw).map_err(|_| "qualification witness request JSON is invalid")?;
    let request: Request = serde_json::from_slice(raw)
        .map_err(|_| "qualification witness request fields are invalid")?;
    if serde_json::to_vec(&object).map_err(|_| "qualification witness request is invalid")? != raw
        || request.mode != mode
        || !matches!(mode, "init" | "sign" | "pin")
        || !request.trusted_time
        || request.machine_pub != pair.machine_pub
        || request.hq_pub != pair.hq_pub
        || request.hq_uid != pair.hq_uid
        || request.hq_epoch != pair.hq_epoch
        || request.pair_owner_pub != pair.owner
        || now.unix_timestamp().abs_diff(request.timestamp) > 30
    {
        return Err("qualification witness request differs from live Machine state".into());
    }
    let nonce = segment(&request.request_nonce_base64url, 16, 32)?;
    if nonce.len() < 16 {
        return Err("qualification witness request nonce is invalid".into());
    }
    let challenge = match (mode, &request.challenge_base64url) {
        ("init" | "pin", None) => None,
        ("sign", Some(text)) => Some(
            segment(text, 32, 32)?
                .try_into()
                .map_err(|_| "qualification witness challenge is invalid")?,
        ),
        _ => return Err("qualification witness challenge is unavailable".into()),
    };
    let signature = segment(&request.signature_base64url, 64, 64)?;
    object
        .as_object_mut()
        .ok_or("qualification witness request is invalid")?
        .remove("signature_base64url")
        .ok_or("qualification witness signature is missing")?;
    let payload =
        serde_json::to_vec(&object).map_err(|_| "qualification witness request is invalid")?;
    let machine = STANDARD
        .decode(&pair.machine_pub)
        .map_err(|_| "qualification Machine key is invalid")?;
    if machine.len() != 32 || STANDARD.encode(&machine) != pair.machine_pub {
        return Err("qualification Machine key is invalid".into());
    }
    let key = VerifyingKey::from_bytes(
        machine
            .as_slice()
            .try_into()
            .map_err(|_| "qualification Machine key is invalid")?,
    )
    .map_err(|_| "qualification Machine key is invalid")?;
    let mut preimage = REQUEST_PURPOSE.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&payload);
    key.verify_strict(
        &preimage,
        &Signature::from_slice(&signature)
            .map_err(|_| "qualification witness request signature is invalid")?,
    )
    .map_err(|_| "qualification witness request signature is invalid")?;
    let envelope = if mode == "pin" && request.policy_envelope_base64url.is_empty() {
        Vec::new()
    } else if mode == "pin" {
        return Err("qualification pin request must omit policy envelope".into());
    } else {
        segment(&request.policy_envelope_base64url, 1, 2 * 1024 * 1024)?
    };
    Ok((request, envelope, challenge))
}

struct FreshOwner<'a> {
    consent: DeviceOwner,
    envelope: &'a [u8],
    root: &'a [u8; 32],
    id: &'a str,
    initial: &'a AuthenticatedPolicy,
}
impl Consent for FreshOwner<'_> {
    fn ask(&self, reason: &str) -> Result<(), Refusal> {
        self.consent.ask(reason)?;
        let again = qualification_policy::verify_signed_envelope(
            self.envelope,
            self.root,
            self.id,
            OffsetDateTime::now_utc(),
        )
        .map_err(Refusal::Declined)?;
        if again.version != self.initial.version
            || again.revision != self.initial.revision
            || again.payload_sha256 != self.initial.payload_sha256
        {
            return Err(Refusal::Declined(
                "qualification policy changed during owner approval".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn command(mode: &str) -> Result<(), String> {
    if mode == "init" {
        crate::standalone::begin_custody().map_err(String::from)?;
    } else if matches!(mode, "sign" | "pin") {
        crate::standalone::admission(std::path::Path::new("/Library")).map_err(String::from)?;
    } else {
        return Err("usage: agent-bot-keyd qualification-witness init|sign|pin".into());
    }
    let (dir, _pair_lock, pair) = trusted_state().map_err(String::from)?;
    let native = Native {
        dir: &dir,
        pair: &pair,
    };
    let mut raw = Vec::new();
    std::io::stdin()
        .lock()
        .take((MAX_REQUEST + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "qualification witness request cannot be read")?;
    let now = OffsetDateTime::now_utc();
    let (request, envelope, challenge) = verify_request(&raw, mode, &pair, now)?;
    let store = Store::new(Box::new(Keychain::login()));
    let (local_root_hex, local_key_id) = qualification_policy::public_root(&store)?;
    if local_root_hex != request.owner_root_hex || local_key_id != request.owner_key_id {
        return Err("qualification owner root differs from keyd custody".into());
    }
    let root = hex_root(&request.owner_root_hex)?;
    let items = Keychain::login();
    let output = if mode == "pin" {
        let pin =
            qualification_witness::public_pin(&items, &native, &pair, &request.host_id, &root)?;
        serde_json::to_vec(
            &json!({"witness_key_id":pin.key_id, "public_key_spki_der_base64":pin.spki_der_base64}),
        )
        .map_err(|_| "qualification witness pin cannot be encoded")?
    } else if mode == "init" {
        let policy = qualification_policy::verify_signed_envelope(
            &envelope,
            &root,
            &request.owner_key_id,
            now,
        )?;
        let owner = FreshOwner {
            consent: DeviceOwner,
            envelope: &envelope,
            root: &root,
            id: &request.owner_key_id,
            initial: &policy,
        };
        let pin = qualification_witness::initialize(
            &items,
            &native,
            &owner,
            &pair,
            &request.host_id,
            &root,
            &policy,
        )?;
        qualification_policy::verify_signed_envelope(
            &envelope,
            &root,
            &request.owner_key_id,
            OffsetDateTime::now_utc(),
        )?;
        serde_json::to_vec(
            &json!({"witness_key_id":pin.key_id, "public_key_spki_der_base64":pin.spki_der_base64}),
        )
        .map_err(|_| "qualification witness pin cannot be encoded")?
    } else {
        let policy = qualification_policy::verify_signed_envelope(
            &envelope,
            &root,
            &request.owner_key_id,
            now,
        )?;
        let challenge = challenge.ok_or("qualification witness challenge is missing")?;
        let witness = qualification_witness::sign(
            &items,
            &native,
            &pair,
            &request.host_id,
            &root,
            &policy,
            &challenge,
            now,
            request.trusted_time,
        )?;
        // An owner policy may expire while the Secure Enclave signs. A
        // post-sign refusal consumes its advanced ledger but emits no proof.
        qualification_policy::verify_signed_envelope(
            &envelope,
            &root,
            &request.owner_key_id,
            OffsetDateTime::now_utc(),
        )?;
        witness
    };
    native.check_live().map_err(String::from)?;
    std::io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| "qualification witness cannot be returned")?;
    std::io::stdout()
        .lock()
        .write_all(b"\n")
        .map_err(|_| "qualification witness cannot be returned")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (Pair, SigningKey, Value, OffsetDateTime) {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let mut owner = [9u8; 65];
        owner[0] = 4;
        let pair = Pair {
            machine_pub: STANDARD.encode(key.verifying_key().to_bytes()),
            hq_pub: STANDARD.encode([2u8; 32]),
            hq_uid: 504,
            owner: STANDARD.encode(owner),
            hq_epoch: "e".repeat(64),
        };
        let now = OffsetDateTime::from_unix_timestamp(1_795_300_000).unwrap();
        let request = json!({
            "mode":"sign", "host_id":"fixture-host", "machine_pub":pair.machine_pub,
            "hq_pub":pair.hq_pub, "hq_uid":pair.hq_uid, "hq_epoch":pair.hq_epoch,
            "pair_owner_pub":pair.owner, "owner_root_hex":"a".repeat(64),
            "owner_key_id":"fixture-root", "policy_envelope_base64url":URL_SAFE_NO_PAD.encode(b"{}"),
            "challenge_base64url":URL_SAFE_NO_PAD.encode([6u8;32]),
            "request_nonce_base64url":URL_SAFE_NO_PAD.encode([7u8;16]),
            "timestamp":now.unix_timestamp(), "trusted_time":true
        });
        (pair, key, request, now)
    }

    fn signed(mut payload: Value, key: &SigningKey) -> Vec<u8> {
        let raw = serde_json::to_vec(&payload).unwrap();
        let mut preimage = REQUEST_PURPOSE.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&raw);
        payload["signature_base64url"] =
            json!(URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes()));
        serde_json::to_vec(&payload).unwrap()
    }

    #[test]
    fn only_live_machine_signed_request_reaches_witness_custody() {
        let (pair, key, payload, now) = fixture();
        let raw = signed(payload.clone(), &key);
        let (_, envelope, challenge) = verify_request(&raw, "sign", &pair, now).unwrap();
        assert_eq!(envelope, b"{}");
        assert_eq!(challenge.unwrap(), [6u8; 32]);
        let mut pin = payload.clone();
        pin["mode"] = json!("pin");
        pin["policy_envelope_base64url"] = json!("");
        pin.as_object_mut().unwrap().remove("challenge_base64url");
        let (request, envelope, challenge) =
            verify_request(&signed(pin, &key), "pin", &pair, now).unwrap();
        assert_eq!(request.mode, "pin");
        assert!(envelope.is_empty() && challenge.is_none());
        for changed in [
            json!({"hq_epoch":"f".repeat(64)}),
            json!({"trusted_time":false}),
            json!({"timestamp":now.unix_timestamp()+31}),
        ] {
            let mut request = payload.clone();
            for (k, v) in changed.as_object().unwrap() {
                request[k] = v.clone();
            }
            assert!(verify_request(&signed(request, &key), "sign", &pair, now).is_err());
        }
        let mut wrong = payload.clone();
        wrong["extra"] = json!(1);
        assert!(verify_request(&signed(wrong, &key), "sign", &pair, now).is_err());
        let mut wrong = payload.clone();
        wrong["mode"] = json!("init");
        assert!(verify_request(&signed(wrong, &key), "sign", &pair, now).is_err());
        let mut wrong = payload.clone();
        wrong["signature_base64url"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        assert!(verify_request(&serde_json::to_vec(&wrong).unwrap(), "sign", &pair, now).is_err());
        let mut wrong = payload.clone();
        wrong["machine_pub"] = json!(STANDARD.encode([8u8; 32]));
        assert!(verify_request(&signed(wrong, &key), "sign", &pair, now).is_err());
        let duplicate = String::from_utf8(raw).unwrap().replacen(
            "\"mode\":\"sign\"",
            "\"mode\":\"sign\",\"mode\":\"sign\"",
            1,
        );
        assert!(verify_request(duplicate.as_bytes(), "sign", &pair, now).is_err());
    }
}
