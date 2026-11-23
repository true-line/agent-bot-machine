use super::*;
use crate::store::tests::Memory;
use ed25519_dalek::{Signer, SigningKey};
use std::cell::{Cell, RefCell};

fn seconds(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[derive(Default)]
struct Fake {
    created: Cell<u8>,
    clock: Cell<u64>,
    time_after_sign: Cell<Option<u64>>,
    revoked: Cell<bool>,
    revoke_after_sign: Cell<bool>,
    signed: RefCell<Vec<Vec<u8>>>,
    create_error: Option<&'static str>,
}
impl Enclave for Fake {
    fn custody_uid(&self) -> Result<u32, &'static str> {
        Ok(500)
    }
    fn proof_time(&self) -> Result<u64, &'static str> {
        Ok(self.clock.get())
    }
    fn check_live(&self) -> Result<(), &'static str> {
        if self.revoked.get() {
            return Err(UNAVAILABLE);
        }
        Ok(())
    }
    fn create(&self) -> Result<Vec<u8>, &'static str> {
        if let Some(error) = self.create_error {
            return Err(error);
        }
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
        if let Some(now) = self.time_after_sign.take() {
            self.clock.set(now);
        }
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
fn request(p: &Pair, op: &str, now: u64) -> Request {
    request_with_nonce(p, op, &nonce().unwrap(), now)
}

fn request_with_nonce(p: &Pair, op: &str, nonce: &str, now: u64) -> Request {
    request_for_session(p, op, nonce, now, None)
}
fn request_for_session(
    p: &Pair,
    op: &str,
    nonce: &str,
    now: u64,
    session: Option<&str>,
) -> Request {
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
    let mut msg = format!("{msg}\nhq_epoch\n{}", p.hq_epoch);
    if let Some(s) = session {
        msg.push_str(&format!("\nsession\n{s}"));
    }
    let sig = SigningKey::from_bytes(&[1; 32]).sign(msg.as_bytes());
    let mut wire = json!({"machine_pub":p.machine_pub,"hq_pub":p.hq_pub,"hq_uid":p.hq_uid,"hq_epoch":p.hq_epoch,
            "req_nonce":nonce,"timestamp":now,"option":op,"signature":STANDARD.encode(sig.to_bytes())});
    if let Some(s) = session {
        wire["session"] = json!(s);
    }
    serde_json::from_value(wire).unwrap()
}

fn host_report_request(p: &Pair, raw: &[u8]) -> Request {
    host_report_request_for(p, raw, "qualification-host-report", "fixture-host")
}

fn host_report_request_for(p: &Pair, raw: &[u8], option: &str, host_id: &str) -> Request {
    let mut req = request(p, option, 100);
    req.report_base64url = Some(URL.encode(raw));
    req.host_id = Some(host_id.into());
    req.signer_id = Some("fixture-signer".into());
    let mut msg = [
        "agent-bot-machine/keyd-hq-device/v1",
        &p.machine_pub,
        &p.hq_pub,
        &p.hq_uid.to_string(),
        &req.req_nonce,
        "100",
        option,
        "",
        "",
        "",
        "hq_epoch",
        &p.hq_epoch,
    ]
    .join("\n");
    for (label, value) in [
        ("report_base64url", req.report_base64url.as_deref().unwrap()),
        ("host_id", req.host_id.as_deref().unwrap()),
        ("signer_id", req.signer_id.as_deref().unwrap()),
    ] {
        msg.push_str(&format!("\n{label}\n{value}"));
    }
    req.signature = STANDARD.encode(
        SigningKey::from_bytes(&[1; 32])
            .sign(msg.as_bytes())
            .to_bytes(),
    );
    req
}

#[test]
fn host_report_signing_is_fixed_and_pair_bound() {
    let (items, native, p) = (Memory::default(), Fake::default(), pair());
    initialize(&items, &native, p.clone()).unwrap();
    let evidence =
        json!({"uri":"fixture:observation","sha256":format!("sha256:{}", "a".repeat(64))});
    let check = json!({"outcome":"pass","evidence":[evidence]});
    let sha = format!("sha256:{}", "a".repeat(64));
    let raw = serde_json::to_vec(&json!({
        "adapter":{"id":"fixture-adapter","version":"1.0.0","package_sha256":sha},
        "checks":{"egress":check,"credentials":check,"state_redirect":check,
            "safe_interrupt_resume":check,"session_reuse":check,"cost_bound":check,"render_coverage":check},
        "cost_bound":"estimate", "evaluation_cells":[{"role":"assistant","model":"fixture-model","provider":"fixture-provider","revision":"fixture-revision","evidence":evidence}],
        "gates":{"T01":{"outcome":"pass","evidence":evidence},"T02":{"outcome":"pass","evidence":evidence},"T03":{"outcome":"pass","evidence":evidence}},
        "harness":{"name":"fixture-harness","version":"1.0.0","binary_path":"/fixture/harness","binary_sha256":sha},
        "host":{"id":"fixture-host","os":"darwin","os_version":"27.0","architecture":"arm64","profile":"fixture-profile","evidence":[evidence]},
        "launch":{"executable":"/fixture/adapter","executable_sha256":sha,"argv":["run"],"code_inputs":[]},
        "outcome":"pass", "profile_in_force":"managed-protected",
        "recorded_at":"2026-11-21T00:00:00Z", "renders":["text"], "run_id":"run",
        "runner":{"binary_path":"/fixture/runner","binary_sha256":sha},
        "schema_version":1,
        "soul_start":{"initiator":"hq","hq_launch_receipt":evidence,"machine_observation":evidence},
        "suite_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }))
    .unwrap();
    let req = host_report_request(&p, &raw);
    let result = run(&items, &native, &p, req, seconds(100)).unwrap();
    assert_eq!(result["purpose"], HOST_REPORT_PURPOSE);
    assert_eq!(result["host_id"], "fixture-host");
    assert_eq!(result["report_sha256"], format!("sha256:{}", digest(&raw)));
    assert_eq!(
        native.signed.borrow().last().unwrap(),
        &[HOST_REPORT_PURPOSE.as_bytes(), &[0], raw.as_slice()].concat()
    );
    let mut changed = host_report_request(&p, &raw);
    changed.host_id = Some("other-host".into());
    assert!(run(&items, &native, &p, changed, seconds(100)).is_err());
    let mut invalid = raw.clone();
    invalid.push(b'\n');
    assert!(fixed_host_report(&host_report_request(&p, &invalid)).is_err());
    let incomplete_gates = String::from_utf8(raw.clone()).unwrap().replace(
        "\"T03\":{\"evidence\":{\"sha256\":",
        "\"missing-gate\":{\"evidence\":{\"sha256\":",
    );
    assert!(fixed_host_report(&host_report_request(&p, incomplete_gates.as_bytes())).is_err());
    let missing_adapter = String::from_utf8(raw.clone()).unwrap().replace(
        &format!("\"package_sha256\":\"{sha}\""),
        "\"package_sha256\":\"sha256:fixture\"",
    );
    assert!(fixed_host_report(&host_report_request(&p, missing_adapter.as_bytes())).is_err());
}

#[test]
fn bridge_v2_host_report_has_distinct_purpose_and_custody_shape() {
    let (items, native, p) = (Memory::default(), Fake::default(), pair());
    initialize(&items, &native, p.clone()).unwrap();
    let raw = include_bytes!("../../../internal/qualification/testdata/bridge-v2-synthetic.json");
    let req = host_report_request_for(
        &p,
        raw,
        "qualification-host-report-v2",
        "fixture-qualification-mac",
    );
    let result = run(&items, &native, &p, req, seconds(100)).unwrap();
    assert_eq!(result["schema_version"], 2);
    assert_eq!(result["purpose"], HOST_REPORT_PURPOSE_V2);
    assert_eq!(result["report_sha256"], format!("sha256:{}", digest(raw)));
    assert_eq!(
        native.signed.borrow().last().unwrap(),
        &[HOST_REPORT_PURPOSE_V2.as_bytes(), &[0], raw.as_slice()].concat()
    );
    assert!(run(
        &items,
        &native,
        &p,
        host_report_request_for(
            &p,
            raw,
            "qualification-host-report",
            "fixture-qualification-mac"
        ),
        seconds(100)
    )
    .is_err());
    let mut report: Value = serde_json::from_slice(raw).unwrap();
    report["bridge"]["endpoints"]["hq_broker"]["socket_mode"] = json!("0666");
    let changed = serde_json::to_vec(&report).unwrap();
    assert!(run(
        &items,
        &native,
        &p,
        host_report_request_for(
            &p,
            &changed,
            "qualification-host-report-v2",
            "fixture-qualification-mac"
        ),
        seconds(100)
    )
    .is_err());
    report["bridge"]["endpoints"]["hq_broker"]["socket_mode"] = json!("0660");
    report["bridge"]["principals"]["credential_uid"] = json!(502);
    let changed = serde_json::to_vec(&report).unwrap();
    assert!(run(
        &items,
        &native,
        &p,
        host_report_request_for(
            &p,
            &changed,
            "qualification-host-report-v2",
            "fixture-qualification-mac"
        ),
        seconds(100)
    )
    .is_err());
    report["bridge"]["principals"]["credential_uid"] = json!(503);
    report["bridge"]["assignment"]["machine_observation"]["sha256"] =
        json!(format!("sha256:{}", "d".repeat(64)));
    let changed = serde_json::to_vec(&report).unwrap();
    assert!(run(
        &items,
        &native,
        &p,
        host_report_request_for(
            &p,
            &changed,
            "qualification-host-report-v2",
            "fixture-qualification-mac"
        ),
        seconds(100)
    )
    .is_err());
    report["bridge"]["assignment"]["machine_observation"] =
        report["soul_start"]["machine_observation"].clone();
    report["bridge"]["principals"]["credential_uid"] = json!(504);
    let changed = serde_json::to_vec(&report).unwrap();
    assert!(run(
        &items,
        &native,
        &p,
        host_report_request_for(
            &p,
            &changed,
            "qualification-host-report-v2",
            "fixture-qualification-mac"
        ),
        seconds(100)
    )
    .is_err());
}

#[test]
fn measured_v3_host_report_shape_is_valid_but_signing_requires_a_completed_run() {
    let (items, native, mut p) = (Memory::default(), Fake::default(), pair());
    p.hq_epoch = "e".repeat(64);
    initialize(&items, &native, p.clone()).unwrap();
    for raw in [
        include_bytes!(
            "../../../internal/qualification/testdata/stage2a-report-v3-protected-synthetic.json"
        )
        .as_slice(),
        include_bytes!(
            "../../../internal/qualification/testdata/stage2a-report-v3-cooperative-synthetic.json"
        )
        .as_slice(),
    ] {
        let req = host_report_request_for(
            &p,
            raw,
            "qualification-host-report-v3",
            "fixture-physical-mac",
        );
        assert_eq!(fixed_host_report_version(&req, 3, 500).unwrap(), raw);
        assert!(run(&items, &native, &p, req, seconds(100)).is_err());
        assert!(native.signed.borrow().is_empty());
        assert!(run(
            &items,
            &native,
            &p,
            host_report_request_for(
                &p,
                raw,
                "qualification-host-report-v2",
                "fixture-physical-mac"
            ),
            seconds(100)
        )
        .is_err());
        let mut changed: Value = serde_json::from_slice(raw).unwrap();
        changed["measurement_binding"]["host_id"] = json!("other-host");
        let bytes = serde_json::to_vec(&changed).unwrap();
        assert!(run(
            &items,
            &native,
            &p,
            host_report_request_for(
                &p,
                &bytes,
                "qualification-host-report-v3",
                "fixture-physical-mac"
            ),
            seconds(100)
        )
        .is_err());
        changed["measurement_binding"]["host_id"] = json!("fixture-physical-mac");
        changed["run_evidence"]["finalization"]["sha256"] =
            changed["run_evidence"]["reservation"]["sha256"].clone();
        let bytes = serde_json::to_vec(&changed).unwrap();
        assert!(run(
            &items,
            &native,
            &p,
            host_report_request_for(
                &p,
                &bytes,
                "qualification-host-report-v3",
                "fixture-physical-mac"
            ),
            seconds(100)
        )
        .is_err());
        changed["run_evidence"] =
            serde_json::from_slice::<Value>(raw).unwrap()["run_evidence"].clone();
        changed["measurement_binding"]
            .as_object_mut()
            .unwrap()
            .remove("soul_artifact_sha256");
        let bytes = serde_json::to_vec(&changed).unwrap();
        assert!(run(
            &items,
            &native,
            &p,
            host_report_request_for(
                &p,
                &bytes,
                "qualification-host-report-v3",
                "fixture-physical-mac"
            ),
            seconds(100)
        )
        .is_err());
    }
    let raw = include_bytes!(
        "../../../internal/qualification/testdata/stage2a-report-v3-protected-synthetic.json"
    );
    let mut changed: Value = serde_json::from_slice(raw).unwrap();
    changed["run_evidence"]["reservation"]["sha256"] = json!(format!("sha256:{}", "0".repeat(64)));
    let bytes = serde_json::to_vec(&changed).unwrap();
    assert!(run(
        &items,
        &native,
        &p,
        host_report_request_for(
            &p,
            &bytes,
            "qualification-host-report-v3",
            "fixture-physical-mac"
        ),
        seconds(100)
    )
    .is_err());
    changed = serde_json::from_slice(raw).unwrap();
    changed["host"]["id"] = json!("invalid/host");
    changed["measurement_binding"]["host_id"] = json!("invalid/host");
    let bytes = serde_json::to_vec(&changed).unwrap();
    assert!(run(
        &items,
        &native,
        &p,
        host_report_request_for(&p, &bytes, "qualification-host-report-v3", "invalid/host"),
        seconds(100)
    )
    .is_err());
}

#[test]
fn measured_v3_host_report_refuses_noncanonical_and_unsafe_snapshot() {
    let (items, native, mut p) = (Memory::default(), Fake::default(), pair());
    p.hq_epoch = "e".repeat(64);
    initialize(&items, &native, p.clone()).unwrap();
    let raw = include_bytes!(
        "../../../internal/qualification/testdata/stage2a-report-v3-protected-synthetic.json"
    );
    let mut newline = raw.to_vec();
    newline.push(b'\n');
    let check = |bytes: &[u8]| {
        assert!(run(
            &items,
            &native,
            &p,
            host_report_request_for(
                &p,
                bytes,
                "qualification-host-report-v3",
                "fixture-physical-mac"
            ),
            seconds(100)
        )
        .is_err());
    };
    check(&newline);
    let original: Value = serde_json::from_slice(raw).unwrap();
    assert!(!integer_only_json(&json!([1.0])));
    assert!(!integer_only_json(&json!([9_007_199_254_740_992_u64])));
    let mut changed = original.clone();
    changed["renders"] = json!([1.0]);
    check(&serde_json::to_vec(&changed).unwrap());
    changed["renders"] = json!([9_007_199_254_740_992_u64]);
    check(&serde_json::to_vec(&changed).unwrap());
    changed["renders"] = json!([7]);
    check(&serde_json::to_vec(&changed).unwrap());
    changed["renders"] = json!(["instructions", "instructions"]);
    check(&serde_json::to_vec(&changed).unwrap());
    changed["renders"] = json!(["bad/render"]);
    check(&serde_json::to_vec(&changed).unwrap());
    let negative_zero = std::str::from_utf8(raw).unwrap().replacen(
        "\"renders\":[\"instructions\",\"tools\"]",
        "\"renders\":[-0]",
        1,
    );
    check(negative_zero.as_bytes());
    let exponent = std::str::from_utf8(raw).unwrap().replacen(
        "\"renders\":[\"instructions\",\"tools\"]",
        "\"renders\":[1e0]",
        1,
    );
    check(exponent.as_bytes());
    let mut changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["device"] = json!("01");
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["root_path"] =
        json!("/private/stage2a\\snapshot-definition");
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["mode"] = json!("0777");
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["mode"] = json!("0750");
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["mode"] = json!("0444");
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["device"] =
        json!("18446744073709551616");
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["owner_uid"] = json!(501);
    changed["measurement_binding"]["snapshots"]["launch_inputs"]["owner_uid"] = json!(501);
    changed["bridge"]["principals"]["machine_uid"] = json!(501);
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["hq_epoch"] = json!("f".repeat(64));
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["contract"] = json!("machine/v1");
    changed["measurement_binding"]["schema_version"] = json!(1);
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["owner_uid"] = json!(0);
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["launch_inputs"]["owner_gid"] = json!(705);
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["measurement_binding"]["snapshots"]["definition"]["owner_gid"] = json!(704);
    changed["measurement_binding"]["snapshots"]["launch_inputs"]["owner_gid"] = json!(704);
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed["bridge"]["principals"]["machine_uid"] = json!(0);
    check(&serde_json::to_vec(&changed).unwrap());
    changed = original.clone();
    changed.as_object_mut().unwrap().remove("bridge");
    check(&serde_json::to_vec(&changed).unwrap());
    let old = include_bytes!("../../../internal/qualification/testdata/bridge-v2-synthetic.json");
    check(old);
}
#[test]
fn initialization_preserves_creation_failure_and_leaves_custody_absent() {
    let items = Memory::default();
    let provider = Fake {
        create_error: Some("creation refused"),
        ..Default::default()
    };
    assert_eq!(
        initialize(&items, &provider, pair()),
        Err("creation refused")
    );
    assert!(items.read(SERVICE, ITEM).unwrap().is_none());
}

#[test]
fn admin_lookup_denial_stops_before_creation_and_peers_receive_only_unavailable() {
    use crate::store::StoreError;
    use std::sync::atomic::{AtomicU8, Ordering};
    struct ReadError {
        status: i32,
        reads: AtomicU8,
    }
    impl ReadError {
        fn new(status: i32) -> Self {
            Self {
                status,
                reads: AtomicU8::new(0),
            }
        }
    }
    impl Items for ReadError {
        fn read(&self, _: &str, _: &str) -> Result<Option<Vec<u8>>, StoreError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Err(StoreError::KeychainRead(self.status))
        }
        fn write(&self, _: &str, _: &str, _: &[u8]) -> Result<(), String> {
            panic!("unexpected write")
        }
        fn insert(&self, _: &str, _: &str, _: &[u8]) -> Result<bool, String> {
            panic!("unexpected insert")
        }
        fn remove(&self, _: &str, _: &str) -> Result<bool, String> {
            panic!("unexpected removal")
        }
    }
    let native = Fake::default();
    let p = pair();
    let items = ReadError::new(-25308);
    assert_eq!(
        initialize(&items, &native, p.clone()),
        Err("macOS denied user interaction while reading existing device custody from Keychain")
    );
    assert_eq!(
        initialize(&ReadError::new(-1), &native, p.clone()),
        Err(UNAVAILABLE)
    );
    assert_eq!(
        run(
            &items,
            &native,
            &p,
            request(&p, "identity", 0),
            Default::default()
        ),
        Err(UNAVAILABLE)
    );
    assert_eq!(items.reads.load(Ordering::Relaxed), 2);
    assert_eq!(native.created.get(), 0);
}

#[test]
fn public_identity_and_enrollment_are_typed_and_offline() {
    let at = Duration::from_secs(100);
    let (items, native, p) = (Memory::default(), Fake::default(), pair());
    assert!(run(&items, &native, &p, request(&p, "identity", 100), at).is_err());
    assert_eq!(native.created.get(), 0);
    initialize(&items, &native, p.clone()).unwrap();
    assert!(initialize(&items, &native, p.clone()).is_err());
    assert_eq!(native.created.get(), 1);
    let before_identity = items.read(SERVICE, ITEM).unwrap();
    let id = run(&items, &native, &p, request(&p, "identity", 100), at).unwrap();
    assert_eq!(items.read(SERVICE, ITEM).unwrap(), before_identity);
    assert_eq!(id["key_storage"], "hardware");
    assert_eq!(id["generation"], 1);
    assert_eq!(id.as_object().unwrap().len(), 4);
    assert!(native.signed.borrow().is_empty());
    let proof_nonce = nonce().unwrap();
    let proof = run(
        &items,
        &native,
        &p,
        request_with_nonce(&p, "enrollment-proof", &proof_nonce, 100),
        at,
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
        request_with_nonce(&p, "enrollment-proof", &proof_nonce, 100),
        at
    )
    .is_err());
    assert_eq!(native.signed.borrow().len(), 1);
}
#[test]
fn binding_freshness_and_unavailable_purposes_fail_closed() {
    let at = Duration::from_secs(100);
    let (items, native, p) = (Memory::default(), Fake::default(), pair());
    initialize(&items, &native, p.clone()).unwrap();
    for op in ["access-assertion", "sign", "rekey", "approval", "dpop"] {
        assert!(run(&items, &native, &p, request(&p, op, 100), at).is_err());
    }
    for ts in [69, 131] {
        assert!(run(&items, &native, &p, request(&p, "identity", ts), at).is_err());
    }
    let mut req = request(&p, "identity", 100);
    req.option = "enrollment-proof".into();
    assert!(run(&items, &native, &p, req, at).is_err());
    for i in 0..4 {
        let mut other = p.clone();
        match i {
            0 => other.hq_uid += 1,
            1 => other.hq_pub = STANDARD.encode([4; 32]),
            2 => other.machine_pub = STANDARD.encode([5; 32]),
            _ => other.owner.push('x'),
        }
        assert!(run(&items, &native, &other, request(&p, "identity", 100), at).is_err());
    }
    let bad = json!({"machine_pub":p.machine_pub,"hq_pub":p.hq_pub,"hq_uid":123,"timestamp":100,"req_nonce":"abcdefgh","option":"identity","signature":"x","aud":"https://test.invalid"});
    assert!(serde_json::from_value::<Request>(bad).is_err());
    assert_eq!(native.created.get(), 1);
    assert!(native.signed.borrow().is_empty());
}
fn manifest(key: &SigningKey) -> String {
    json!({"server":ORIGIN,"keys":[{"kid":"test-key","x":URL.encode(key.verifying_key().as_bytes()),"status":"active","notBefore":"2026-01-01T00:00:00Z","notAfter":"2027-01-01T00:00:00Z"}]}).to_string()
}
fn receipt(p: &Pair, op: &str, now: u64, origin: &SigningKey, raw: &[u8], jti: &str) -> Request {
    let mut req = request(p, op, now);
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
        &req.req_nonce,
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
        request(&p, "enrollment-proof", now),
        seconds(now),
    )
    .unwrap();
    let jti = format!(
        "enroll-v1:{}",
        digest(enroll["proof"].as_str().unwrap().as_bytes())
    );
    let raw=json!({"token_type":"N_A","device_id":"device-synthetic","jkt":enroll["thumbprint"],"harnesses":[],"read_only":true}).to_string();
    // Owner approval can outlive the Machine transport's short request window.
    let poll = now + 590;
    let bind = |body: &str, jti: &str, authority: &SigningKey, pins: &str| {
        execute(
            &items,
            &native,
            &p,
            receipt(&p, "bind-enrollment", poll, authority, body.as_bytes(), jti),
            seconds(poll),
            pins,
        )
    };
    assert!(bind(&raw, &jti, &SigningKey::from_bytes(&[8; 32]), &pins).is_err());
    assert!(bind(&raw, "enroll-v1:other", &issuer, &pins).is_err());
    assert!(bind(
        &raw.replace(enroll["thumbprint"].as_str().unwrap(), "wrong"),
        &jti,
        &issuer,
        &pins
    )
    .is_err());
    assert!(bind(&raw, &jti, &issuer, &pins.replace("active", "retired")).is_err());
    assert!(bind(
        &raw,
        &jti,
        &issuer,
        &pins.replace("2027-01-01", "2026-01-02")
    )
    .is_err());
    let bound = bind(&raw, &jti, &issuer, &pins).unwrap();
    assert_eq!(bound["receipt_sha256"], digest(raw.as_bytes()));
    assert_eq!(bound["receipt_jti"], jti);
    assert_eq!(bound["device_id"], "device-synthetic");
    assert_eq!(bind(&raw, &jti, &issuer, &pins).unwrap(), bound);
    assert!(bind(
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
            request(&p, "identity", poll),
            seconds(poll)
        )
        .unwrap(),
        bound
    );
    let access = run(
        &items,
        &native,
        &p,
        request(&p, "access-assertion", poll),
        seconds(poll),
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
    let access_bind = |body: &str, at: u64, key: &SigningKey| {
        execute(
            &items,
            &native,
            &p,
            receipt(&p, "bind-access", at, key, body.as_bytes(), token_jti),
            seconds(at),
            &pins,
        )
    };
    assert!(access_bind(
        &token_body.replace("device-synthetic", "other"),
        poll + 1,
        &issuer
    )
    .is_err());
    assert!(access_bind(&token_body, poll + 1, &SigningKey::from_bytes(&[8; 32])).is_err());
    let (_, selector) = identity(&native.public(&[2]).unwrap()).unwrap();
    let query = |s: &str, at: u64| {
        let request = request_for_session(&p, "whoami", &nonce().unwrap(), at, Some(s));
        request.verify(&p, at)?;
        native.clock.set(at);
        let saved = items.read(SERVICE, ITEM).unwrap().unwrap();
        let record: Record = serde_json::from_slice(&saved).unwrap();
        whoami_proof(&record, &request, &native, at)
    };
    let before = native.signed.borrow().len();
    assert!(query(&selector, poll).is_err()); // Access assertion exists, signed token binding does not.
    assert_eq!(native.signed.borrow().len(), before);
    let session = access_bind(&token_body, poll + 1, &issuer).unwrap();
    assert_eq!(session["expires_at"], poll + 900);
    assert_eq!(session.as_object().unwrap().len(), 2);
    assert_eq!(
        access_bind(&token_body, poll + 2, &issuer).unwrap(),
        session
    );
    assert!(access_bind(
        &token_body.replace("short-lived", "changed"),
        poll + 3,
        &issuer
    )
    .is_err());
    assert_eq!(session["session"], selector);
    let valid = query(&selector, poll + 3).unwrap();
    assert_eq!(valid.as_object().unwrap().len(), 2);
    assert_eq!(valid["session"], selector);
    let decode = |part: &str| serde_json::from_slice::<Value>(&URL.decode(part).unwrap()).unwrap();
    let parts: Vec<_> = valid["proof"].as_str().unwrap().split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(
        decode(parts[0]),
        json!({"alg":"ES256","typ":"dpop+jwt","jwk":claims["cnf"]["jwk"]})
    );
    let body = decode(parts[1]);
    let jti = body["jti"].as_str().unwrap();
    assert_eq!(URL.decode(jti).unwrap().len(), 16);
    assert_eq!(
        body,
        json!({"htu":"https://agents.true-line.ai/api/daemon/whoami","htm":"GET","ath":URL.encode(Sha256::digest(b"synthetic-short-lived-token")),"jti":jti,"iat":poll+3})
    );
    let next = query(&selector, poll + 3).unwrap();
    assert_ne!(
        decode(next["proof"].as_str().unwrap().split('.').nth(1).unwrap())["jti"],
        jti
    );
    native.time_after_sign.set(Some(poll + 900));
    assert!(query(&selector, poll + 899).is_err()); // Expired during the native operation.
    let count = native.signed.borrow().len();
    assert!(query(&URL.encode([22; 32]), poll + 4).is_err());
    assert!(query(&selector, poll + 900).is_err());
    assert!(access_bind(&token_body, poll + 901, &issuer).is_err());
    assert_eq!(native.signed.borrow().len(), count);
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
        request(&replaced, "identity", poll),
        seconds(poll)
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
        request(&p, "enrollment-proof", 100),
        seconds(100)
    )
    .is_err());
    let record: Record =
        serde_json::from_slice(&items.read(SERVICE, ITEM).unwrap().unwrap()).unwrap();
    assert!(record.pending.is_empty());
    assert!(run(
        &items,
        &provider,
        &p,
        request(&p, "identity", 101),
        seconds(101)
    )
    .is_err());
    assert_eq!(provider.signed.borrow().len(), 1);
}

#[test]
fn receipt_window_uses_the_actual_instant_across_offsets_and_fractional_boundaries() {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let pins = manifest(&signer)
        .replace(
            "2026-01-01T00:00:00Z",
            "2025-12-31T19:00:00.125000001-05:00",
        )
        .replace(
            "2027-01-01T00:00:00Z",
            "2026-01-01T05:30:00.875000001+05:30",
        );
    let midnight = 1_767_225_600;
    let signed = receipt(
        &pair(),
        "bind-enrollment",
        midnight,
        &signer,
        b"{}",
        "test-jti",
    );
    for (nanos, accepted) in [
        (125_000_000, false),
        (125_000_001, true),
        (875_000_000, true),
        (875_000_001, false),
        (875_000_002, false),
    ] {
        let now = Duration::new(midnight, nanos);
        assert_eq!(verify_receipt(&signed, &pins, now).is_ok(), accepted);
    }
    let active = Duration::new(midnight, 500_000_000);
    for invalid in [
        "2025-02-31T00:00:00Z",
        "2025-12-31T23:59:60Z",
        "2026-01-01 00:00:00Z",
        "2026-01-01T00:00:00z",
        "2026-01-01T00:00:00+24:00",
        "2026-01-01T00:00:00",
    ] {
        let bad = pins.replace("2025-12-31T19:00:00.125000001-05:00", invalid);
        assert!(verify_receipt(&signed, &bad, active).is_err());
    }
    assert!(verify_receipt(&signed, &pins.replace("active", "retired"), active).is_err());
}
