//! Offline receipt and mailbox transaction for a single reserved notice take.
//! The paired request allowlist has no notice operation.
use super::{digest, pin_time, verify_signed_response, Items, Pair, SERVICE, UNAVAILABLE};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, time::Duration};

const ITEM: &str = "notice-mailbox-v1";
const MAX_BODY: usize = 16 * 1024;
const MAX_STATE: usize = 256 * 1024;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Scope {
    pair: Pair,
    device_id: String,
    harness: String,
    revision: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingTake {
    scope: Scope,
    jti: String,
    issued: u64,
    deadline: u64,
    lease_seconds: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Mailbox {
    pending: Option<PendingTake>,
    // Retained through epoch/policy changes. Full body bytes plus their notice
    // content digest allow expiry/re-lease without accepting changed content.
    entries: BTreeMap<String, CommittedNotice>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommittedNotice {
    scope: Scope,
    jti: String,
    lease: String,
    expires_ns: i128,
    content_sha: String,
    response_body: String,
}

struct Response<'a> {
    status: u16,
    body: &'a str,
    jti: &'a str,
    kid: &'a str,
    signature: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TakeBody {
    harness: String,
    notices: Vec<Notice>,
    lease_seconds: u16,
    #[serde(rename = "remaining")]
    _remaining: u64,
    next_lease_expiry: Option<String>,
}

#[derive(Deserialize)]
struct Notice {
    id: String,
    lease: String,
    #[serde(rename = "attempts")]
    _attempts: u64,
    lease_expires_at: String,
    #[serde(flatten)]
    content: Map<String, Value>,
}

fn url_id(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn mailbox(items: &dyn Items) -> Result<Mailbox, &'static str> {
    let data = items
        .read(SERVICE, ITEM)
        .map_err(|_| UNAVAILABLE)?
        .ok_or(UNAVAILABLE)?;
    if data.len() > MAX_STATE {
        return Err(UNAVAILABLE);
    }
    serde_json::from_slice(&data).map_err(|_| UNAVAILABLE)
}

// The caller will hold keyd's trusted pairing lock across this entire
// transaction, including its check of live scope from admin-owned state.
// The reservation and local authority must come from that boundary.
fn commit_take(
    items: &dyn Items,
    live: &Scope,
    manifest: &str,
    now: Duration,
    response: Response<'_>,
) -> Result<(), &'static str> {
    let mut state = mailbox(items)?;
    let pending = state.pending.take().ok_or(UNAVAILABLE)?;
    if &pending.scope != live
        || pending.jti != response.jti
        || !url_id(response.jti, 8, 128)
        || now.as_secs() < pending.issued
        || now.as_secs() >= pending.deadline
        || !url_id(&live.revision, 32, 32)
        || response.body.is_empty()
        || response.body.len() > MAX_BODY
    {
        return Err(UNAVAILABLE);
    }
    verify_signed_response(
        manifest,
        now,
        response.kid,
        response.signature,
        response.status,
        &digest(response.body.as_bytes()),
        response.jti,
    )?;
    if response.status != 200 {
        return Err(UNAVAILABLE);
    }
    let body: TakeBody = serde_json::from_str(response.body).map_err(|_| UNAVAILABLE)?;
    if body.harness != live.harness
        || body.lease_seconds != pending.lease_seconds
        || !(10..=3600).contains(&body.lease_seconds)
    {
        return Err(UNAVAILABLE);
    }
    match body.notices.as_slice() {
        [] if body.next_lease_expiry.is_none() => (),
        [notice] => {
            let expires_ns = pin_time(&notice.lease_expires_at)?;
            let now_ns = i128::try_from(now.as_nanos()).map_err(|_| UNAVAILABLE)?;
            let suffix = notice
                .lease
                .strip_prefix(&format!("{}.{}_", notice.id, live.revision))
                .ok_or(UNAVAILABLE)?;
            if !url_id(&notice.id, 8, 64)
                || notice.id.contains('_')
                || !url_id(suffix, 8, 128)
                || notice.content.is_empty()
                || body.next_lease_expiry.as_deref() != Some(&notice.lease_expires_at)
                || expires_ns <= now_ns
                || expires_ns > now_ns + i128::from(body.lease_seconds) * 1_000_000_000
            {
                return Err(UNAVAILABLE);
            }
            let key = format!("{}/{}", live.harness, notice.id);
            let content_sha =
                digest(&serde_json::to_vec(&notice.content).map_err(|_| UNAVAILABLE)?);
            if state.entries.get(&key).is_some_and(|old| {
                old.content_sha != content_sha
                    || old.jti == pending.jti
                    || (old.scope == *live && old.expires_ns > now_ns)
            }) {
                return Err(UNAVAILABLE);
            }
            state.entries.insert(
                key,
                CommittedNotice {
                    scope: pending.scope,
                    jti: pending.jti,
                    lease: notice.lease.clone(),
                    expires_ns,
                    content_sha,
                    response_body: response.body.to_owned(),
                },
            );
        }
        _ => return Err(UNAVAILABLE),
    }
    let data = serde_json::to_vec(&state).map_err(|_| UNAVAILABLE)?;
    if data.len() > MAX_STATE {
        return Err(UNAVAILABLE);
    }
    // No result escapes before one update commits the full response bytes,
    // exact lease, and consumed take reservation together.
    items.write(SERVICE, ITEM, &data).map_err(|_| UNAVAILABLE)
}

// Prepared for later authorization. Looking up a committed lease neither
// signs nor settles it, and an old epoch cannot make its lease eligible.
fn committed_lease(
    items: &dyn Items,
    live: &Scope,
    id: &str,
    now: Duration,
) -> Result<String, &'static str> {
    let state = mailbox(items)?;
    let entry = state
        .entries
        .get(&format!("{}/{id}", live.harness))
        .ok_or(UNAVAILABLE)?;
    let now_ns = i128::try_from(now.as_nanos()).map_err(|_| UNAVAILABLE)?;
    if &entry.scope != live || entry.expires_ns <= now_ns {
        return Err(UNAVAILABLE);
    }
    Ok(entry.lease.clone())
}

#[cfg(test)]
mod tests;
