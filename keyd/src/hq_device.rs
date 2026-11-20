//! Offline device operations. The paired Machine selects a named purpose;
//! keyd authenticates it before constructing a fixed-format enrollment proof.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as URL},
    Engine,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const UNAVAILABLE: &str = "device custody unavailable";
const ORIGIN: &str = "https://agents.true-line.ai";
const SERVICE: &str = "agent-bot.keyd.device.v1";
const ITEM: &str = "managed-device";
const WINDOW: u64 = 30;
const MAX_RECENT: usize = 256;

use crate::store::Items;

pub(crate) trait Enclave {
    fn check_live(&self) -> Result<(), &'static str>;
    fn proof_time(&self) -> Result<u64, &'static str> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs())
            .map_err(|_| UNAVAILABLE)
    }
    fn create(&self) -> Result<Vec<u8>, &'static str>;
    fn public(&self, reference: &[u8]) -> Result<[u8; 65], &'static str>;
    fn sign(&self, reference: &[u8], message: &[u8]) -> Result<[u8; 64], &'static str>;
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(crate) struct Pair {
    pub machine_pub: String,
    pub hq_pub: String,
    pub hq_uid: u32,
    pub owner: String,
    pub hq_epoch: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    machine_pub: String,
    hq_pub: String,
    hq_uid: u32,
    hq_epoch: String,
    req_nonce: String,
    timestamp: u64,
    option: String,
    #[serde(default, deserialize_with = "optional_text")]
    session: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    receipt_body: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    receipt_jti: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    receipt_kid: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    receipt_signature: Option<String>,
    signature: String,
}

fn optional_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

impl Request {
    fn verify(&self, pair: &Pair, now: u64) -> Result<(), &'static str> {
        if self.machine_pub != pair.machine_pub
            || self.hq_pub != pair.hq_pub
            || self.hq_uid != pair.hq_uid
            || self.hq_epoch != pair.hq_epoch
            || self.timestamp.abs_diff(now) > WINDOW
            || !(8..=128).contains(&self.req_nonce.len())
            || !self.req_nonce.bytes().all(|b| b.is_ascii_graphic())
            || !matches!(
                self.option.as_str(),
                "identity"
                    | "enrollment-proof"
                    | "bind-enrollment"
                    | "access-assertion"
                    | "bind-access"
                    | "whoami"
            )
        {
            return Err(UNAVAILABLE);
        }
        let raw = STANDARD
            .decode(&pair.machine_pub)
            .map_err(|_| UNAVAILABLE)?;
        let public = VerifyingKey::from_bytes(raw.as_slice().try_into().map_err(|_| UNAVAILABLE)?)
            .map_err(|_| UNAVAILABLE)?;
        let sig = STANDARD.decode(&self.signature).map_err(|_| UNAVAILABLE)?;
        let signature = Signature::from_slice(&sig).map_err(|_| UNAVAILABLE)?;
        if STANDARD.encode(raw) != pair.machine_pub || STANDARD.encode(sig) != self.signature {
            return Err(UNAVAILABLE);
        }
        let mut transcript = format!(
            "agent-bot-machine/keyd-hq-device/v1\n{}\n{}\n{}\n{}\n{}\n{}\n\n\n",
            self.machine_pub, self.hq_pub, self.hq_uid, self.req_nonce, self.timestamp, self.option
        );
        transcript.push_str(&format!("\nhq_epoch\n{}", self.hq_epoch));
        match (&*self.option, &self.session) {
            ("whoami", Some(s))
                if s.len() == 43
                    && URL
                        .decode(s)
                        .is_ok_and(|b| b.len() == 32 && URL.encode(&b) == *s) =>
            {
                transcript.push_str(&format!("\nsession\n{s}"));
            }
            ("whoami", _) | (_, Some(_)) => return Err(UNAVAILABLE),
            _ => (),
        }
        for (label, field) in [
            ("receipt_body", &self.receipt_body),
            ("receipt_jti", &self.receipt_jti),
            ("receipt_kid", &self.receipt_kid),
            ("receipt_signature", &self.receipt_signature),
        ] {
            match (self.option.as_str(), field) {
                ("bind-enrollment" | "bind-access", Some(text))
                    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_graphic()) =>
                {
                    transcript.push_str(&format!("\n{label}\n{text}"));
                }
                ("bind-enrollment" | "bind-access", _) | (_, Some(_)) => return Err(UNAVAILABLE),
                _ => (),
            }
        }
        public
            .verify_strict(transcript.as_bytes(), &signature)
            .map_err(|_| UNAVAILABLE)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    pair: Pair,
    reference: String,
    thumbprint: String,
    #[serde(default)]
    pending: Vec<Pending>,
    #[serde(default)]
    bound: Option<Bound>,
    #[serde(default)]
    sessions: Vec<Session>,
    recent: Vec<(u64, String)>,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    jti: String,
    expires: u64,
}
#[derive(Serialize, Deserialize, PartialEq)]
struct Bound {
    device_id: String,
    receipt_jti: String,
    receipt_sha256: String,
}
#[derive(Serialize, Deserialize)]
struct Session {
    jti: String,
    reference: String,
    thumbprint: String,
    expires: u64,
    issued: u64,
    token: Option<BoundToken>,
}
#[derive(Serialize, Deserialize)]
struct BoundToken {
    ath: String,
    receipt_sha256: String,
}
const CODE_LIFETIME: u64 = 600 + 120; // service DeviceCodeTTL plus initial proof skew and a final polling interval
const ACCESS_LIFETIME: u64 = 15 * 60;
const MAX_PENDING: usize = 10;
const MAX_SESSIONS: usize = 12;

fn add_binding(result: &mut Value, bound: &Bound) {
    result["device_id"] = json!(bound.device_id);
    result["receipt_jti"] = json!(bound.receipt_jti);
    result["receipt_sha256"] = json!(bound.receipt_sha256);
}

fn digest(input: &[u8]) -> String {
    format!("{:x}", Sha256::digest(input))
}
fn nonce() -> Result<String, &'static str> {
    let mut buf = [0; 16];
    getrandom::fill(&mut buf).map_err(|_| UNAVAILABLE)?;
    Ok(URL.encode(buf))
}

fn jwt(
    provider: &dyn Enclave,
    reference: &[u8],
    header: Value,
    claims: Value,
) -> Result<String, &'static str> {
    let input = format!(
        "{}.{}",
        URL.encode(header.to_string()),
        URL.encode(claims.to_string())
    );
    Ok(format!(
        "{input}.{}",
        URL.encode(provider.sign(reference, input.as_bytes())?)
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    server: String,
    keys: Vec<Pin>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Pin {
    kid: String,
    x: String,
    status: String,
    not_before: String,
    not_after: String,
}

fn release_key(manifest: &str, kid: &str, now: u64) -> Result<VerifyingKey, &'static str> {
    let pins: Manifest = serde_json::from_str(manifest).map_err(|_| UNAVAILABLE)?;
    if pins.server != ORIGIN {
        return Err(UNAVAILABLE);
    }
    let mut ids = std::collections::HashSet::new();
    let mut pubkeys = std::collections::HashSet::new();
    let mut selected = None;
    for p in pins.keys {
        let date = |s: &str| {
            s.parse::<der::DateTime>()
                .map(|t| t.unix_duration().as_secs())
                .map_err(|_| UNAVAILABLE)
        };
        let (start, end) = (date(&p.not_before)?, date(&p.not_after)?);
        if start >= end
            || !matches!(p.status.as_str(), "active" | "next" | "retired")
            || p.kid.is_empty()
            || p.kid.len() > 128
            || !p
                .kid
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || !ids.insert(p.kid.clone())
            || !pubkeys.insert(p.x.clone())
        {
            return Err(UNAVAILABLE);
        }
        let key = URL.decode(&p.x).map_err(|_| UNAVAILABLE)?;
        if URL.encode(&key) != p.x {
            return Err(UNAVAILABLE);
        }
        let vk = VerifyingKey::from_bytes(key.as_slice().try_into().map_err(|_| UNAVAILABLE)?)
            .map_err(|_| UNAVAILABLE)?;
        if p.kid == kid && p.status != "retired" && start <= now && now < end {
            selected = Some(vk)
        }
    }
    selected.ok_or(UNAVAILABLE)
}

fn verify_receipt(
    req: &Request,
    manifest: &str,
    now: u64,
) -> Result<(Vec<u8>, String, String), &'static str> {
    let jti = req.receipt_jti.as_deref().ok_or(UNAVAILABLE)?;
    let enc = req.receipt_body.as_deref().ok_or(UNAVAILABLE)?;
    let raw = URL.decode(enc).map_err(|_| UNAVAILABLE)?;
    if raw.is_empty() || raw.len() > 8192 || URL.encode(&raw) != enc {
        return Err(UNAVAILABLE);
    }
    let sha = digest(&raw);
    let key = release_key(
        manifest,
        req.receipt_kid.as_deref().ok_or(UNAVAILABLE)?,
        now,
    )?;
    let encoded = req.receipt_signature.as_deref().ok_or(UNAVAILABLE)?;
    let bytes = URL.decode(encoded).map_err(|_| UNAVAILABLE)?;
    if URL.encode(&bytes) != encoded {
        return Err(UNAVAILABLE);
    }
    let sig = Signature::from_slice(&bytes).map_err(|_| UNAVAILABLE)?;
    key.verify_strict(
        format!("agent-bot-sig-v1\n200\n{sha}\n{jti}").as_bytes(),
        &sig,
    )
    .map_err(|_| UNAVAILABLE)?;
    Ok((raw, sha, jti.into()))
}

fn binding(
    req: &Request,
    manifest: &str,
    now: u64,
    record: &Record,
) -> Result<Bound, &'static str> {
    let (raw, sha, jti) = verify_receipt(req, manifest, now)?;
    #[derive(Deserialize)]
    struct Approved {
        device_id: String,
        jkt: String,
        token_type: String,
    }
    let body: Approved = serde_json::from_slice(&raw).map_err(|_| UNAVAILABLE)?;
    if body.token_type != "N_A"
        || body.jkt != record.thumbprint
        || body.device_id.is_empty()
        || body.device_id.len() > 256
        || !body
            .device_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
    {
        return Err(UNAVAILABLE);
    }
    let bound = Bound {
        device_id: body.device_id,
        receipt_jti: jti,
        receipt_sha256: sha,
    };
    if let Some(previous) = &record.bound {
        if previous != &bound {
            return Err(UNAVAILABLE);
        }
    } else if !record
        .pending
        .iter()
        .any(|p| p.jti == bound.receipt_jti && p.expires >= now)
    {
        return Err(UNAVAILABLE);
    }
    Ok(bound)
}

fn identity(public: &[u8; 65]) -> Result<(Value, String), &'static str> {
    if public[0] != 4 {
        return Err(UNAVAILABLE);
    }
    let x = URL.encode(&public[1..33]);
    let y = URL.encode(&public[33..]);
    let thumbprint = URL.encode(Sha256::digest(format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#
    )));
    Ok((json!({"kty":"EC","crv":"P-256","x":x,"y":y}), thumbprint))
}

// Called only by the explicit admin initialization command under the same
// exclusive state lock as run(). Existing or unreadable custody is terminal.
pub(crate) fn initialize(
    items: &dyn Items,
    provider: &dyn Enclave,
    pair: Pair,
) -> Result<(), &'static str> {
    if items
        .read(SERVICE, ITEM)
        .map_err(|_| UNAVAILABLE)?
        .is_some()
    {
        return Err(UNAVAILABLE);
    }
    let reference = provider.create()?;
    let (_, thumbprint) = identity(&provider.public(&reference)?)?;
    let record = Record {
        pair,
        reference: STANDARD.encode(reference),
        thumbprint,
        recent: Vec::new(),
        pending: Vec::new(),
        bound: None,
        sessions: Vec::new(),
    };
    let data = serde_json::to_vec(&record).map_err(|_| UNAVAILABLE)?;
    provider.check_live()?;
    if !items
        .insert(SERVICE, ITEM, &data)
        .map_err(|_| UNAVAILABLE)?
    {
        return Err(UNAVAILABLE);
    }
    Ok(())
}

fn whoami_proof(
    record: &Record,
    request: &Request,
    provider: &dyn Enclave,
    now: u64,
) -> Result<Value, &'static str> {
    record.bound.as_ref().ok_or(UNAVAILABLE)?;
    let selector = request.session.as_deref().ok_or(UNAVAILABLE)?;
    let session = record
        .sessions
        .iter()
        .find(|s| s.thumbprint == selector && s.issued <= now && s.expires > now)
        .ok_or(UNAVAILABLE)?;
    let token = session.token.as_ref().ok_or(UNAVAILABLE)?;
    if URL.decode(&token.ath).map_err(|_| UNAVAILABLE)?.len() != 32 {
        return Err(UNAVAILABLE);
    }
    let reference = STANDARD
        .decode(&session.reference)
        .map_err(|_| UNAVAILABLE)?;
    let (jwk, thumb) = identity(&provider.public(&reference)?)?;
    if thumb != selector || thumb == record.thumbprint {
        return Err(UNAVAILABLE);
    }
    provider.check_live()?;
    let issued = provider.proof_time()?;
    if issued < now || issued >= session.expires || issued.abs_diff(request.timestamp) > WINDOW {
        return Err(UNAVAILABLE);
    }
    let proof = jwt(
        provider,
        &reference,
        json!({"alg":"ES256","typ":"dpop+jwt","jwk":jwk}),
        json!({"htm":"GET","htu":format!("{ORIGIN}/api/daemon/whoami"),"ath":token.ath,"iat":issued,"jti":nonce()?}),
    )?;
    // Its request nonce is already durable. Only release the proof while the
    // same pairing and bound session remain valid after native signing.
    provider.check_live()?;
    let completed = provider.proof_time()?;
    if completed < issued
        || completed >= session.expires
        || completed.abs_diff(request.timestamp) > WINDOW
    {
        return Err(UNAVAILABLE);
    }
    Ok(json!({"session":thumb,"proof":proof}))
}

pub(crate) fn run(
    items: &dyn Items,
    provider: &dyn Enclave,
    pair: &Pair,
    request: Request,
    now: u64,
) -> Result<Value, &'static str> {
    execute(
        items,
        provider,
        pair,
        request,
        now,
        include_str!("../trusted/server-keys.json"),
    )
}

fn execute(
    items: &dyn Items,
    provider: &dyn Enclave,
    pair: &Pair,
    request: Request,
    now: u64,
    manifest: &str,
) -> Result<Value, &'static str> {
    request.verify(pair, now)?;
    provider.check_live()?;
    let data = items
        .read(SERVICE, ITEM)
        .map_err(|_| UNAVAILABLE)?
        .ok_or(UNAVAILABLE)?;
    let mut record: Record = serde_json::from_slice(&data).map_err(|_| UNAVAILABLE)?;
    if &record.pair != pair
        || record.recent.len() > MAX_RECENT
        || record.pending.len() > MAX_PENDING
        || record.sessions.len() > MAX_SESSIONS
    {
        return Err(UNAVAILABLE);
    }
    let reference = STANDARD
        .decode(&record.reference)
        .map_err(|_| UNAVAILABLE)?;
    let (jwk, thumbprint) = identity(&provider.public(&reference)?)?;
    if thumbprint != record.thumbprint {
        return Err(UNAVAILABLE);
    }
    let mut result =
        json!({"jwk":jwk,"thumbprint":thumbprint,"key_storage":"hardware","generation":1});
    if request.option == "identity" {
        if let Some(bound) = &record.bound {
            add_binding(&mut result, bound);
        }
        provider.check_live()?;
        return Ok(result);
    }
    // Retain until the latest instant at which this signed timestamp is valid,
    // including the future-skew allowance. Never evict a still valid nonce.
    record
        .recent
        .retain(|(ts, _)| ts.saturating_add(WINDOW) >= now);
    record.pending.retain(|p| p.expires >= now);
    record.sessions.retain(|s| s.expires > now);
    let nonce_hash = digest(request.req_nonce.as_bytes());
    if record.recent.len() >= MAX_RECENT
        || record.recent.iter().any(|(_, nonce)| nonce == &nonce_hash)
    {
        return Err(UNAVAILABLE);
    }
    record.recent.push((request.timestamp, nonce_hash));
    provider.check_live()?;
    items
        .write(
            SERVICE,
            ITEM,
            &serde_json::to_vec(&record).map_err(|_| UNAVAILABLE)?,
        )
        .map_err(|_| UNAVAILABLE)?;
    match request.option.as_str() {
        "enrollment-proof" => {
            if record.bound.is_some() || record.pending.len() >= MAX_PENDING {
                return Err(UNAVAILABLE);
            }
            let proof = jwt(
                provider,
                &reference,
                json!({"alg":"ES256","typ":"ab-enroll+jwt","jwk":jwk}),
                json!({"aud":format!("{ORIGIN}/oauth/device_authorization"),"iat":now,"jti":nonce()?}),
            )?;
            record.pending.push(Pending {
                jti: format!("enroll-v1:{}", digest(proof.as_bytes())),
                expires: now + CODE_LIFETIME,
            });
            result["proof"] = Value::String(proof);
        }
        "bind-enrollment" => {
            let bound = binding(&request, manifest, now, &record)?;
            record.bound = Some(bound);
            record.pending.clear();
        }
        "access-assertion" => {
            let bound = record.bound.as_ref().ok_or(UNAVAILABLE)?;
            if record.sessions.len() >= MAX_SESSIONS {
                return Err(UNAVAILABLE);
            }
            let session = provider.create()?;
            let (ephemeral, thumb) = identity(&provider.public(&session)?)?;
            if thumb == record.thumbprint || record.sessions.iter().any(|s| s.thumbprint == thumb) {
                return Err(UNAVAILABLE);
            }
            let jti = nonce()?;
            let assertion = jwt(
                provider,
                &reference,
                json!({"alg":"ES256","typ":"JWT"}),
                json!({"iss":bound.device_id,"sub":bound.device_id,"aud":format!("{ORIGIN}/oauth/token"),"iat":now,"exp":now+120,
                    "jti":jti,"cnf":{"jwk":ephemeral}}),
            )?;
            record.sessions.push(Session {
                jti,
                reference: STANDARD.encode(session),
                thumbprint: thumb,
                expires: now + 120 + 30,
                issued: now,
                token: None,
            });
            result["assertion"] = Value::String(assertion);
        }
        "bind-access" => {
            let bound = record.bound.as_ref().ok_or(UNAVAILABLE)?;
            let (raw, sha, jti) = verify_receipt(&request, manifest, now)?;
            let session = record
                .sessions
                .iter_mut()
                .find(|s| s.jti == jti && s.expires > now)
                .ok_or(UNAVAILABLE)?;
            #[derive(Deserialize)]
            struct Accepted {
                token_type: String,
                access_token: String,
                expires_in: u64,
                device_id: String,
            }
            let reply: Accepted = serde_json::from_slice(&raw).map_err(|_| UNAVAILABLE)?;
            if reply.token_type != "DPoP"
                || reply.device_id != bound.device_id
                || !(1..=ACCESS_LIFETIME).contains(&reply.expires_in)
                || reply.access_token.is_empty()
                || reply.access_token.len() > 4096
                || !reply.access_token.bytes().all(|c| c.is_ascii_graphic())
            {
                return Err(UNAVAILABLE);
            }
            let expires_at = session
                .issued
                .checked_add(reply.expires_in)
                .ok_or(UNAVAILABLE)?;
            if expires_at <= now {
                return Err(UNAVAILABLE);
            }
            let ath = URL.encode(Sha256::digest(reply.access_token.as_bytes()));
            if let Some(t) = &session.token {
                if t.ath != ath || t.receipt_sha256 != sha || session.expires != expires_at {
                    return Err(UNAVAILABLE);
                }
            } else {
                session.expires = expires_at;
                session.token = Some(BoundToken {
                    ath,
                    receipt_sha256: sha,
                });
            }
            result = json!({"session":session.thumbprint,"expires_at":expires_at});
        }
        "whoami" => return whoami_proof(&record, &request, provider, now),
        _ => return Err(UNAVAILABLE),
    }
    if request.option == "bind-enrollment" {
        add_binding(&mut result, record.bound.as_ref().ok_or(UNAVAILABLE)?);
    }
    provider.check_live()?;
    items
        .write(
            SERVICE,
            ITEM,
            &serde_json::to_vec(&record).map_err(|_| UNAVAILABLE)?,
        )
        .map_err(|_| UNAVAILABLE)?;
    provider.check_live()?;
    Ok(result)
}

#[cfg(test)]
mod tests;
