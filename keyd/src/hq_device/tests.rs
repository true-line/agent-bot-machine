use super::*;
use crate::store::tests::Memory;
use ed25519_dalek::{Signer, SigningKey};
use std::cell::{Cell, RefCell};

#[derive(Default)]
struct Fake {
    created: Cell<u8>,
    revoked: Cell<bool>,
    revoke_after_sign: Cell<bool>,
    signed: RefCell<Vec<Vec<u8>>>,
}
impl Enclave for Fake {
    fn check_live(&self) -> Result<(), &'static str> {
        if self.revoked.get() {
            return Err(UNAVAILABLE);
        }
        Ok(())
    }
    fn create(&self) -> Result<Vec<u8>, &'static str> {
        self.created.set(self.created.get() + 1);
        Ok(vec![self.created.get()])
    }
    fn public(&self, r: &[u8]) -> Result<[u8; 65], &'static str> {
        if r.len() != 1 || r[0] == 0 || r[0] > self.created.get() {
            return Err(UNAVAILABLE);
        }
        let mut p = [r[0]; 65];
        p[0] = 4;
        Ok(p)
    }
    fn sign(&self, r: &[u8], m: &[u8]) -> Result<[u8; 64], &'static str> {
        self.public(r)?;
        self.signed.borrow_mut().push(m.to_vec());
        if self.revoke_after_sign.get() {
            self.revoked.set(true)
        }
        Ok([11; 64])
    }
}
fn pair() -> Pair {
    let pk = SigningKey::from_bytes(&[1; 32]).verifying_key();
    Pair {
        machine_pub: STANDARD.encode(pk.as_bytes()),
        hq_pub: STANDARD.encode([2; 32]),
        hq_uid: 123,
        owner: String::from("synthetic-pin"),
        hq_epoch: "legacy".into(),
    }
}
fn request(p: &Pair, op: &str, nonce: &str, now: u64) -> Request {
    let msg = [
        "agent-bot-machine/keyd-hq-device/v1",
        &p.machine_pub,
        &p.hq_pub,
        &p.hq_uid.to_string(),
        nonce,
        &now.to_string(),
        op,
        "",
        "",
        "",
    ]
    .join("\n");
    let msg = format!("{msg}\nhq_epoch\n{}", p.hq_epoch);
    let sig = SigningKey::from_bytes(&[1; 32]).sign(msg.as_bytes());
    serde_json::from_value(json!({"machine_pub":p.machine_pub,"hq_pub":p.hq_pub,"hq_uid":p.hq_uid,"hq_epoch":p.hq_epoch,
            "req_nonce":nonce,"timestamp":now,"option":op,"signature":STANDARD.encode(sig.to_bytes())})).unwrap()
}
#[test]
fn public_identity_and_enrollment_are_typed_and_offline() {
    let (items, native, p) = (Memory::default(), Fake::default(), pair());
    assert!(run(
        &items,
        &native,
        &p,
        request(&p, "identity", "nonce-id1", 100),
        100
    )
    .is_err());
    assert_eq!(native.created.get(), 0);
    initialize(&items, &native, p.clone()).unwrap();
    assert!(initialize(&items, &native, p.clone()).is_err());
    assert_eq!(native.created.get(), 1);
    let before_identity = items.read(SERVICE, ITEM).unwrap();
    let id = run(
        &items,
        &native,
        &p,
        request(&p, "identity", "nonce-id1", 100),
        100,
    )
    .unwrap();
    assert_eq!(items.read(SERVICE, ITEM).unwrap(), before_identity);
    assert_eq!(id["key_storage"], "hardware");
    assert_eq!(id["generation"], 1);
    assert_eq!(id.as_object().unwrap().len(), 4);
    assert!(native.signed.borrow().is_empty());
    let proof = run(
        &items,
        &native,
        &p,
        request(&p, "enrollment-proof", "nonce-pf1", 100),
        100,
    )
    .unwrap();
    let jwt = proof["proof"]
        .as_str()
        .unwrap()
        .split('.')
        .collect::<Vec<_>>();
    assert_eq!(jwt.len(), 3);
    let header: Value = serde_json::from_slice(&URL.decode(jwt[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&URL.decode(jwt[1]).unwrap()).unwrap();
    assert_eq!(
        header,
        json!({"alg":"ES256","typ":"ab-enroll+jwt","jwk":id["jwk"]})
    );
    assert_eq!(claims.as_object().unwrap().len(), 3);
    assert_eq!(
        claims["aud"],
        "https://agents.true-line.ai/oauth/device_authorization"
    );
    assert_eq!(claims["iat"], 100);
    assert_eq!(
        URL.decode(claims["jti"].as_str().unwrap()).unwrap().len(),
        16
    );
    assert_eq!(jwt[2], URL.encode([11; 64]));
    assert_eq!(native.signed.borrow()[0], jwt[..2].join(".").as_bytes());
    assert!(run(
        &items,
        &native,
        &p,
        request(&p, "enrollment-proof", "nonce-pf1", 100),
        100
    )
    .is_err());
    assert_eq!(native.signed.borrow().len(), 1);
}
#[test]
fn binding_freshness_and_unavailable_purposes_fail_closed() {
    let (items, native, p) = (Memory::default(), Fake::default(), pair());
    initialize(&items, &native, p.clone()).unwrap();
    for op in ["access-assertion", "sign", "rekey", "approval", "dpop"] {
        assert!(run(&items, &native, &p, request(&p, op, "nonce-123", 100), 100).is_err());
    }
    for ts in [69, 131] {
        assert!(run(
            &items,
            &native,
            &p,
            request(&p, "identity", "nonce-123", ts),
            100
        )
        .is_err());
    }
    let mut req = request(&p, "identity", "nonce-123", 100);
    req.option = "enrollment-proof".into();
    assert!(run(&items, &native, &p, req, 100).is_err());
    for i in 0..4 {
        let mut other = p.clone();
        match i {
            0 => other.hq_uid += 1,
            1 => other.hq_pub = STANDARD.encode([4; 32]),
            2 => other.machine_pub = STANDARD.encode([5; 32]),
            _ => other.owner.push('x'),
        }
        assert!(run(
            &items,
            &native,
            &other,
            request(&p, "identity", "nonce-123", 100),
            100
        )
        .is_err());
    }
    let bad = json!({"machine_pub":p.machine_pub,"hq_pub":p.hq_pub,"hq_uid":123,"timestamp":100,"req_nonce":"abcdefgh","option":"identity","signature":"x","aud":"https://test.invalid"});
    assert!(serde_json::from_value::<Request>(bad).is_err());
    assert_eq!(native.created.get(), 1);
    assert!(native.signed.borrow().is_empty());
}
fn manifest(key: &SigningKey) -> String {
    json!({"server":ORIGIN,"keys":[{"kid":"test-key","x":URL.encode(key.verifying_key().as_bytes()),"status":"active","notBefore":"2026-01-01T00:00:00Z","notAfter":"2027-01-01T00:00:00Z"}]}).to_string()
}
fn receipt(
    p: &Pair,
    op: &str,
    now: u64,
    nonce: &str,
    origin: &SigningKey,
    raw: &[u8],
    jti: &str,
) -> Request {
    let mut req = request(p, op, nonce, now);
    let b64 = URL.encode(raw);
    let sig = URL.encode(
        origin
            .sign(format!("agent-bot-sig-v1\n200\n{}\n{jti}", digest(raw)).as_bytes())
            .to_bytes(),
    );
    let transcript = [
        "agent-bot-machine/keyd-hq-device/v1",
        &p.machine_pub,
        &p.hq_pub,
        &p.hq_uid.to_string(),
        nonce,
        &now.to_string(),
        op,
        "",
        "",
        "",
        "hq_epoch",
        &p.hq_epoch,
        "receipt_body",
        &b64,
        "receipt_jti",
        jti,
        "receipt_kid",
        "test-key",
        "receipt_signature",
        &sig,
    ]
    .join("\n");
    req.receipt_body = Some(b64);
    req.receipt_jti = Some(jti.into());
    req.receipt_kid = Some("test-key".into());
    req.receipt_signature = Some(sig);
    req.signature = STANDARD.encode(
        SigningKey::from_bytes(&[1; 32])
            .sign(transcript.as_bytes())
            .to_bytes(),
    );
    req
}
#[test]
fn signed_poll_binds_pending_key_once_and_survives_restart() {
    let (items, native, p) = (Memory::default(), Fake::default(), pair());
    let issuer = SigningKey::from_bytes(&[4; 32]);
    let pins = manifest(&issuer);
    let now = 1780000000;
    initialize(&items, &native, p.clone()).unwrap();
    let enroll = run(
        &items,
        &native,
        &p,
        request(&p, "enrollment-proof", "enroll-000", now),
        now,
    )
    .unwrap();
    let jti = format!(
        "enroll-v1:{}",
        digest(enroll["proof"].as_str().unwrap().as_bytes())
    );
    let raw=json!({"token_type":"N_A","device_id":"device-synthetic","jkt":enroll["thumbprint"],"harnesses":[],"read_only":true}).to_string();
    // Owner approval can outlive the Machine transport's short request window.
    let poll = now + 590;
    let bind = |nonce: &str, body: &str, jti: &str, authority: &SigningKey, pins: &str| {
        execute(
            &items,
            &native,
            &p,
            receipt(
                &p,
                "bind-enrollment",
                poll,
                nonce,
                authority,
                body.as_bytes(),
                jti,
            ),
            poll,
            pins,
        )
    };
    assert!(bind(
        "bind-bad1",
        &raw,
        &jti,
        &SigningKey::from_bytes(&[8; 32]),
        &pins
    )
    .is_err());
    assert!(bind("bind-bad2", &raw, "enroll-v1:other", &issuer, &pins).is_err());
    assert!(bind(
        "bind-bad3",
        &raw.replace(enroll["thumbprint"].as_str().unwrap(), "wrong"),
        &jti,
        &issuer,
        &pins
    )
    .is_err());
    assert!(bind(
        "bind-bad4",
        &raw,
        &jti,
        &issuer,
        &pins.replace("active", "retired")
    )
    .is_err());
    assert!(bind(
        "bind-bad5",
        &raw,
        &jti,
        &issuer,
        &pins.replace("2027-01-01", "2026-01-02")
    )
    .is_err());
    let bound = bind("bind-good", &raw, &jti, &issuer, &pins).unwrap();
    assert_eq!(bound["receipt_sha256"], digest(raw.as_bytes()));
    assert_eq!(bound["receipt_jti"], jti);
    assert_eq!(bound["device_id"], "device-synthetic");
    assert_eq!(
        bind("bind-dup1", &raw, &jti, &issuer, &pins).unwrap(),
        bound
    );
    assert!(bind(
        "bind-swap",
        &raw.replace("device-synthetic", "another"),
        &jti,
        &issuer,
        &pins
    )
    .is_err());
    assert_eq!(
        run(
            &items,
            &native,
            &p,
            request(&p, "identity", "identity2", poll),
            poll
        )
        .unwrap(),
        bound
    );
    let access = run(
        &items,
        &native,
        &p,
        request(&p, "access-assertion", "access-11", poll),
        poll,
    )
    .unwrap();
    let parts = access["assertion"]
        .as_str()
        .unwrap()
        .split('.')
        .collect::<Vec<_>>();
    let claims: Value = serde_json::from_slice(&URL.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], "device-synthetic");
    assert_eq!(claims["sub"], "device-synthetic");
    assert_eq!(claims["aud"], "https://agents.true-line.ai/oauth/token");
    assert_ne!(claims["cnf"]["jwk"], bound["jwk"]);
    assert_eq!(claims["exp"], poll + 120);
    assert_eq!(access.as_object().unwrap().len(), 5);
    assert!(access.get("privateKey").is_none());
    let token_body=json!({"token_type":"DPoP","device_id":"device-synthetic","access_token":"synthetic-short-lived-token","expires_in":900}).to_string();
    let token_jti = claims["jti"].as_str().unwrap();
    let access_bind = |n: &str, body: &str, at: u64, key: &SigningKey| {
        execute(
            &items,
            &native,
            &p,
            receipt(&p, "bind-access", at, n, key, body.as_bytes(), token_jti),
            at,
            &pins,
        )
    };
    assert!(access_bind(
        "token-err",
        &token_body.replace("device-synthetic", "other"),
        poll + 1,
        &issuer
    )
    .is_err());
    assert!(access_bind(
        "token-bad",
        &token_body,
        poll + 1,
        &SigningKey::from_bytes(&[8; 32])
    )
    .is_err());
    let session = access_bind("token-yes", &token_body, poll + 1, &issuer).unwrap();
    assert_eq!(session["expires_at"], poll + 900);
    assert_eq!(session.as_object().unwrap().len(), 2);
    assert_eq!(
        access_bind("token-dup", &token_body, poll + 2, &issuer).unwrap(),
        session
    );
    assert!(access_bind(
        "token-alt",
        &token_body.replace("short-lived", "changed"),
        poll + 3,
        &issuer
    )
    .is_err());
    assert!(access_bind("token-exp", &token_body, poll + 901, &issuer).is_err());
    let saved = items.read(SERVICE, ITEM).unwrap().unwrap();
    assert!(!String::from_utf8(saved)
        .unwrap()
        .contains("synthetic-short-lived-token"));
    let mut replaced = p.clone();
    replaced.hq_epoch = "aa".repeat(32);
    assert!(run(
        &items,
        &native,
        &replaced,
        request(&replaced, "identity", "new-epoch", poll),
        poll
    )
    .is_err());
}

#[test]
fn revoke_during_native_work_withholds_result_and_pending_proof() {
    let (items, provider, p) = (Memory::default(), Fake::default(), pair());
    initialize(&items, &provider, p.clone()).unwrap();
    provider.revoke_after_sign.set(true);
    assert!(run(
        &items,
        &provider,
        &p,
        request(&p, "enrollment-proof", "cutoff-000", 100),
        100
    )
    .is_err());
    let record: Record =
        serde_json::from_slice(&items.read(SERVICE, ITEM).unwrap().unwrap()).unwrap();
    assert!(record.pending.is_empty());
    assert!(run(
        &items,
        &provider,
        &p,
        request(&p, "identity", "cutoff-001", 101),
        101
    )
    .is_err());
    assert_eq!(provider.signed.borrow().len(), 1);
}
