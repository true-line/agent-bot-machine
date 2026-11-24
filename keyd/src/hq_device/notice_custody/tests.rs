use super::*;
use crate::store::{tests::Memory, StoreError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as URL, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

const NOW: u64 = 1_767_225_600;
const REVISION: &str = "abcdefghijklmnopqrstuvwxyz012345";
const ID: &str = "synthetic-delivery";
const JTI: &str = "fixture-take-1";

fn scope() -> Scope {
    Scope {
        pair: Pair {
            machine_pub: "synthetic-machine".into(),
            hq_pub: "synthetic-hq".into(),
            hq_uid: 123,
            owner: "synthetic-owner".into(),
            hq_epoch: "paired-epoch".into(),
        },
        device_id: "synthetic-device".into(),
        harness: "codex".into(),
        revision: REVISION.into(),
    }
}

fn reserve(items: &Memory, scope: &Scope, jti: &str, issued: u64) {
    let mut state = mailbox(items).unwrap_or(Mailbox {
        pending: None,
        entries: BTreeMap::new(),
    });
    state.pending = Some(PendingTake {
        scope: scope.clone(),
        jti: jti.into(),
        issued,
        deadline: issued + 30,
        lease_seconds: 60,
    });
    items
        .write(SERVICE, ITEM, &serde_json::to_vec(&state).unwrap())
        .unwrap();
}

fn body(lease_suffix: &str, expires: &str, content: &str) -> String {
    json!({
        "harness": "codex", "remaining": 0, "lease_seconds": 60, "next_lease_expiry": expires,
        "notices": [{
            "id": ID, "lease": format!("{ID}.{REVISION}_{lease_suffix}"), "attempts": 1,
            "lease_expires_at": expires, "title": content,
            "data": {"name": "synthetic", "nested":[true, null, {"preserve": "complete"}]},
        }],
    })
    .to_string()
}

fn apply(
    items: &dyn Items,
    scope: &Scope,
    jti: &str,
    now: u64,
    body: &str,
    options: Options,
) -> Result<(), &'static str> {
    let trusted = SigningKey::from_bytes(&[55; 32]);
    let untrusted = SigningKey::from_bytes(&[56; 32]);
    let manifest = json!({
        "server":"https://agents.true-line.ai",
        "keys":[{
            "kid":"fixture", "x": URL.encode(trusted.verifying_key().to_bytes()),
            "status":"active", "notBefore":"2025-01-01T00:00:00Z", "notAfter":"2027-01-01T00:00:00Z"
        }]
    });
    let signing = if options.untrusted {
        &untrusted
    } else {
        &trusted
    };
    let signed_body = options.signed_body.as_deref().unwrap_or(body);
    let status = options.status.unwrap_or(200);
    let signed = format!(
        "agent-bot-sig-v1\n{status}\n{}\n{jti}",
        digest(signed_body.as_bytes())
    );
    let signature = URL.encode(signing.sign(signed.as_bytes()).to_bytes());
    commit_take(
        items,
        scope,
        &manifest.to_string(),
        Duration::from_secs(now),
        Response {
            status: options.reported_status.unwrap_or(status),
            body,
            jti,
            kid: "fixture",
            signature: &signature,
        },
    )
}

#[derive(Default)]
struct Options {
    untrusted: bool,
    signed_body: Option<String>,
    status: Option<u16>,
    reported_status: Option<u16>,
}

#[test]
fn custody_requires_current_scope_and_preserves_complete_bytes_before_lease_lookup() {
    let items = Memory::default();
    let scope = scope();
    reserve(&items, &scope, JTI, NOW);
    let bytes = body("first-lease", "2026-01-01T00:01:00Z", "fixture title");
    let now = Duration::from_secs(NOW);
    assert!(committed_lease(&items, &scope, ID, now).is_err());
    apply(&items, &scope, JTI, NOW, &bytes, Options::default()).unwrap();

    let reopened = items.clone();
    let state = mailbox(&reopened).unwrap();
    let stored = &state.entries[&format!("codex/{ID}")];
    assert_eq!(stored.response_body, bytes);
    assert!(state.pending.is_none());
    assert_eq!(
        committed_lease(&reopened, &scope, ID, now).unwrap(),
        format!("{ID}.{REVISION}_first-lease")
    );
    assert!(apply(&reopened, &scope, JTI, NOW, &bytes, Options::default()).is_err());
    let mut rotated = scope.clone();
    rotated.pair.hq_epoch = "rotated".into();
    assert!(committed_lease(&reopened, &rotated, ID, now).is_err());
    assert!(committed_lease(&reopened, &scope, ID, now + Duration::from_secs(60)).is_err());

    let replacement_jti = "fixture-take-2";
    reserve(&items, &rotated, replacement_jti, NOW + 60);
    let changed = body("second-lease", "2026-01-01T00:02:00Z", "changed");
    let replacement = body("second-lease", "2026-01-01T00:02:00Z", "fixture title");
    assert!(apply(
        &items,
        &rotated,
        replacement_jti,
        NOW + 60,
        &changed,
        Options::default()
    )
    .is_err());
    apply(
        &items,
        &rotated,
        replacement_jti,
        NOW + 60,
        &replacement,
        Options::default(),
    )
    .unwrap();
    assert!(committed_lease(&items, &scope, ID, now + Duration::from_secs(60)).is_err());
    assert_eq!(mailbox(&items).unwrap().entries.len(), 1);
}

#[test]
fn rejects_wrong_pin_jti_status_bytes_scope_and_expiry_without_mutation() {
    let items = Memory::default();
    let scope = scope();
    reserve(&items, &scope, JTI, NOW);
    let bytes = body("first-lease", "2026-01-01T00:01:00Z", "fixture title");
    let before = items.read(SERVICE, ITEM).unwrap();
    for invalid in [
        Options {
            untrusted: true,
            ..Options::default()
        },
        Options {
            signed_body: Some(format!("{bytes}\n")),
            ..Options::default()
        },
        Options {
            status: Some(403),
            ..Options::default()
        },
        Options {
            status: Some(403),
            reported_status: Some(200),
            ..Options::default()
        },
    ] {
        assert!(apply(&items, &scope, JTI, NOW, &bytes, invalid).is_err());
    }
    assert!(apply(&items, &scope, "other-jti", NOW, &bytes, Options::default()).is_err());
    assert!(apply(&items, &scope, JTI, NOW + 30, &bytes, Options::default()).is_err());
    let mut revoked = scope.clone();
    revoked.pair.hq_epoch = "new-epoch".into();
    assert!(apply(&items, &revoked, JTI, NOW, &bytes, Options::default()).is_err());
    let wrong_harness = bytes.replace("codex", "different");
    assert!(apply(&items, &scope, JTI, NOW, &wrong_harness, Options::default()).is_err());
    let wrong_revision = bytes.replace(REVISION, "1234567890abcdefghijklmnopqrstuv");
    assert!(apply(
        &items,
        &scope,
        JTI,
        NOW,
        &wrong_revision,
        Options::default()
    )
    .is_err());
    let expired = body("first-lease", "2026-01-01T00:00:00Z", "fixture title");
    assert!(apply(&items, &scope, JTI, NOW, &expired, Options::default()).is_err());
    assert_eq!(items.read(SERVICE, ITEM).unwrap(), before);
}

struct ReadOnly(Memory);

impl Items for ReadOnly {
    fn read(&self, service: &str, item: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.read(service, item)
    }

    fn write(&self, _: &str, _: &str, _: &[u8]) -> Result<(), String> {
        Err("write interrupted".into())
    }

    fn insert(&self, _: &str, _: &str, _: &[u8]) -> Result<bool, String> {
        panic!("unexpected insert")
    }

    fn remove(&self, _: &str, _: &str) -> Result<bool, String> {
        panic!("unexpected remove")
    }
}

#[test]
fn write_failure_leaves_reservation_and_content_uncommitted_for_retry() {
    let items = Memory::default();
    let scope = scope();
    reserve(&items, &scope, JTI, NOW);
    let bytes = body("first-lease", "2026-01-01T00:01:00Z", "fixture title");
    let before = items.read(SERVICE, ITEM).unwrap();
    assert!(apply(
        &ReadOnly(items.clone()),
        &scope,
        JTI,
        NOW,
        &bytes,
        Options::default()
    )
    .is_err());
    assert_eq!(items.read(SERVICE, ITEM).unwrap(), before);
    assert!(committed_lease(&items, &scope, ID, Duration::from_secs(NOW)).is_err());
    apply(&items, &scope, JTI, NOW, &bytes, Options::default()).unwrap();
}
