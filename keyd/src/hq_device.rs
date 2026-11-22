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
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(crate) const UNAVAILABLE: &str = "device custody unavailable";
pub(crate) const READ_INTERACTION_DENIED: &str =
    "macOS denied user interaction while reading existing device custody from Keychain";
const ORIGIN: &str = "https://agents.true-line.ai";
pub(crate) const SERVICE: &str = "agent-bot.keyd.device.v1";
const ITEM: &str = "managed-device";
const WINDOW: u64 = 30;
const MAX_RECENT: usize = 256;
const HOST_REPORT_PURPOSE: &str = "agent-bot/qualification-host-report/v1";
const HOST_REPORT_PURPOSE_V2: &str = "agent-bot/qualification-host-report/v2";

use crate::store::{keychain_read_interaction_denied, Items};

// Kept off the paired request allowlist until the notice authority and wire
// contract are approved. Component tests exercise the custody transaction.
#[cfg(test)]
mod notice_custody;

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
    pub(crate) option: String,
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
    #[serde(default, deserialize_with = "optional_text")]
    report_base64url: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    host_id: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    signer_id: Option<String>,
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
                    | "qualification-host-report"
                    | "qualification-host-report-v2"
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
        match self.option.as_str() {
            "qualification-host-report" | "qualification-host-report-v2" => {
                for (label, value) in [
                    ("report_base64url", &self.report_base64url),
                    ("host_id", &self.host_id),
                    ("signer_id", &self.signer_id),
                ] {
                    let value = value.as_ref().ok_or(UNAVAILABLE)?;
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic()) {
                        return Err(UNAVAILABLE);
                    }
                    transcript.push_str(&format!("\n{label}\n{value}"));
                }
            }
            _ if self.report_base64url.is_some()
                || self.host_id.is_some()
                || self.signer_id.is_some() =>
            {
                return Err(UNAVAILABLE)
            }
            _ => (),
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

fn exact_fields(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn report_sha(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    })
}

fn report_path(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() >= 2
            && s.len() <= 4096
            && s.starts_with('/')
            && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
            && !s.split('/').any(|part| part == "." || part == "..")
            && !s.contains("//")
            && !s.ends_with('/')
    })
}

fn report_evidence(value: &Value) -> bool {
    exact_fields(value, &["uri", "sha256"])
        && value["uri"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 1024)
        && report_sha(&value["sha256"])
}

fn report_artifacts(value: &Value) -> bool {
    exact_fields(value, &["id", "version", "package_sha256"])
        && value["id"].as_str().is_some_and(|s| !s.is_empty())
        && value["version"].as_str().is_some_and(|s| !s.is_empty())
        && report_sha(&value["package_sha256"])
}

fn bridge_pass(value: &Value) -> bool {
    exact_fields(value, &["outcome", "evidence"])
        && value["outcome"] == "pass"
        && report_evidence(&value["evidence"])
}

fn bridge_uid(value: &Value) -> Option<u32> {
    value.as_u64().and_then(|n| u32::try_from(n).ok())
}

fn bridge_id(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        (1..=128).contains(&s.len())
            && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    })
}

fn bridge_soul_id(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        if !s.starts_with("agent_") || s.len() != 42 {
            return false;
        }
        s[6..].bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    })
}

fn bridge_endpoint(value: &Value, owner: u32, group: u32, peer: u32) -> bool {
    exact_fields(
        value,
        &[
            "socket_path",
            "parent_uid",
            "parent_gid",
            "parent_mode",
            "parent_inode",
            "socket_uid",
            "socket_gid",
            "socket_mode",
            "socket_inode",
            "observed_peer_uid",
            "machine_custody",
            "kernel_peer_check",
        ],
    ) && report_path(&value["socket_path"])
        && bridge_uid(&value["parent_uid"]) == Some(owner)
        && bridge_uid(&value["socket_uid"]) == Some(owner)
        && bridge_uid(&value["parent_gid"]) == Some(group)
        && bridge_uid(&value["socket_gid"]) == Some(group)
        && value["parent_mode"] == "2750"
        && value["socket_mode"] == "0660"
        && value["parent_inode"].as_u64().is_some_and(|n| n > 0)
        && value["socket_inode"].as_u64().is_some_and(|n| n > 0)
        && bridge_uid(&value["observed_peer_uid"]) == Some(peer)
        && bridge_pass(&value["machine_custody"])
        && bridge_pass(&value["kernel_peer_check"])
}

fn bridge_shape(value: &Value) -> bool {
    if !exact_fields(
        value,
        &[
            "assignment",
            "principals",
            "endpoints",
            "handoff",
            "admission",
            "lifecycle",
        ],
    ) {
        return false;
    }
    let a = &value["assignment"];
    let p = &value["principals"];
    let e = &value["endpoints"];
    let h = &value["handoff"];
    let admission = &value["admission"];
    let life = &value["lifecycle"];
    if !exact_fields(
        a,
        &[
            "installation_id",
            "soul_id",
            "start_id",
            "launch_id",
            "runtime_id",
            "plan_id",
            "plan_digest",
            "machine_reservation_sha256",
            "machine_observation",
        ],
    ) || ![
        "installation_id",
        "start_id",
        "launch_id",
        "runtime_id",
        "plan_id",
    ]
    .iter()
    .all(|name| bridge_id(&a[*name]))
        || !bridge_soul_id(&a["soul_id"])
        || !report_sha(&a["plan_digest"])
        || !report_sha(&a["machine_reservation_sha256"])
        || !report_evidence(&a["machine_observation"])
        || !exact_fields(
            p,
            &[
                "runner_uid",
                "bridge_uid",
                "credential_uid",
                "hq_uid",
                "machine_uid",
                "bridge_private_gid",
                "runner_private_gid",
            ],
        )
    {
        return false;
    }
    let [Some(r), Some(b), Some(c), Some(hq), Some(machine), Some(bg), Some(rg)] = [
        "runner_uid",
        "bridge_uid",
        "credential_uid",
        "hq_uid",
        "machine_uid",
        "bridge_private_gid",
        "runner_private_gid",
    ]
    .map(|name| bridge_uid(&p[name])) else {
        return false;
    };
    if r == 0
        || b == 0
        || c == 0
        || r == b
        || r == c
        || r == hq
        || r == machine
        || b == c
        || b == hq
        || b == machine
        || c == hq
        || c == machine
        || hq == machine
        || bg == 0
        || rg == 0
        || bg == rg
        || !exact_fields(e, &["hq_broker", "souls_member", "http_relay"])
        || !bridge_endpoint(&e["hq_broker"], hq, bg, b)
        || !bridge_endpoint(&e["souls_member"], r, bg, b)
        || !bridge_endpoint(&e["http_relay"], b, rg, r)
    {
        return false;
    }
    let paths = [
        &e["hq_broker"]["socket_path"],
        &e["souls_member"]["socket_path"],
        &e["http_relay"]["socket_path"],
    ];
    let inodes = [
        &e["hq_broker"]["socket_inode"],
        &e["souls_member"]["socket_inode"],
        &e["http_relay"]["socket_inode"],
    ];
    let parent_inodes = [
        &e["hq_broker"]["parent_inode"],
        &e["souls_member"]["parent_inode"],
        &e["http_relay"]["parent_inode"],
    ];
    if paths[0] == paths[1]
        || paths[0] == paths[2]
        || paths[1] == paths[2]
        || inodes[0] == inodes[1]
        || inodes[0] == inodes[2]
        || inodes[1] == inodes[2]
        || parent_inodes[0] == parent_inodes[1]
        || parent_inodes[0] == parent_inodes[2]
        || parent_inodes[1] == parent_inodes[2]
        || !exact_fields(
            h,
            &[
                "transport",
                "recipient_uid",
                "bootstrap_sha256",
                "bind_receipt_sha256",
                "b_only_custody",
                "r_denied",
                "c_denied",
                "other_b_denied",
            ],
        )
        || h["transport"] != "one-use-inherited-anonymous-fds"
        || bridge_uid(&h["recipient_uid"]) != Some(b)
        || !report_sha(&h["bootstrap_sha256"])
        || !report_sha(&h["bind_receipt_sha256"])
        || !["b_only_custody", "r_denied", "c_denied", "other_b_denied"]
            .iter()
            .all(|name| bridge_pass(&h[*name]))
        || !exact_fields(
            admission,
            &[
                "runner_endpoint",
                "member_hello",
                "hq_broker_hmac_bind",
                "hq_bind_receipt_sha256",
                "bind_before_acp",
                "relay_peer",
            ],
        )
        || !report_sha(&admission["hq_bind_receipt_sha256"])
        || ![
            "runner_endpoint",
            "member_hello",
            "hq_broker_hmac_bind",
            "bind_before_acp",
            "relay_peer",
        ]
        .iter()
        .all(|name| bridge_pass(&admission[*name]))
        || !exact_fields(
            life,
            &[
                "one_use",
                "restart_replay_refused",
                "failed_bind_prevents_acp",
                "stop_cleanup",
            ],
        )
        || ![
            "one_use",
            "restart_replay_refused",
            "failed_bind_prevents_acp",
            "stop_cleanup",
        ]
        .iter()
        .all(|name| bridge_pass(&life[*name]))
    {
        return false;
    }
    true
}

fn fixed_host_report(request: &Request) -> Result<Vec<u8>, &'static str> {
    fixed_host_report_version(request, 1)
}

fn fixed_host_report_version(request: &Request, version: u64) -> Result<Vec<u8>, &'static str> {
    let encoded = request.report_base64url.as_ref().ok_or(UNAVAILABLE)?;
    let raw = URL.decode(encoded).map_err(|_| UNAVAILABLE)?;
    if raw.is_empty() || raw.len() > 1024 * 1024 || URL.encode(&raw) != *encoded || !raw.is_ascii()
    {
        return Err(UNAVAILABLE);
    }
    let report: Value = serde_json::from_slice(&raw).map_err(|_| UNAVAILABLE)?;
    if serde_json::to_vec(&report).map_err(|_| UNAVAILABLE)? != raw {
        return Err(UNAVAILABLE);
    }
    let mut keys = vec![
        "adapter",
        "checks",
        "cost_bound",
        "evaluation_cells",
        "gates",
        "harness",
        "host",
        "launch",
        "outcome",
        "profile_in_force",
        "recorded_at",
        "renders",
        "run_id",
        "runner",
        "schema_version",
        "soul_start",
        "suite_revision",
    ];
    if version == 2 {
        keys.push("bridge");
    }
    let fields = report.as_object().ok_or(UNAVAILABLE)?;
    if fields.len() != keys.len()
        || keys.iter().any(|key| !fields.contains_key(*key))
        || report["schema_version"] != version
        || report["outcome"] != "pass"
        || !report_artifacts(&report["adapter"])
        || !exact_fields(
            &report["launch"],
            &["executable", "executable_sha256", "argv", "code_inputs"],
        )
        || !report_path(&report["launch"]["executable"])
        || !report_sha(&report["launch"]["executable_sha256"])
        || !report["launch"]["argv"].as_array().is_some_and(|argv| {
            argv.len() <= 128
                && argv
                    .iter()
                    .all(|arg| arg.as_str().is_some_and(|s| s.len() <= 4096))
        })
        || !report["launch"]["code_inputs"]
            .as_array()
            .is_some_and(|inputs| {
                inputs.iter().all(|input| {
                    exact_fields(input, &["path", "sha256"])
                        && report_path(&input["path"])
                        && report_sha(&input["sha256"])
                })
            })
        || !exact_fields(
            &report["harness"],
            &["name", "version", "binary_path", "binary_sha256"],
        )
        || report["harness"]["name"].as_str().is_none_or(str::is_empty)
        || report["harness"]["version"]
            .as_str()
            .is_none_or(str::is_empty)
        || !report_path(&report["harness"]["binary_path"])
        || !report_sha(&report["harness"]["binary_sha256"])
        || !exact_fields(&report["runner"], &["binary_path", "binary_sha256"])
        || !report_path(&report["runner"]["binary_path"])
        || !report_sha(&report["runner"]["binary_sha256"])
        || !exact_fields(
            &report["soul_start"],
            &["initiator", "hq_launch_receipt", "machine_observation"],
        )
        || report["host"]["os"] != "darwin"
        || !exact_fields(
            &report["host"],
            &[
                "os",
                "os_version",
                "architecture",
                "profile",
                "evidence",
                "id",
            ],
        )
        || report["host"]["os_version"]
            .as_str()
            .is_none_or(str::is_empty)
        || report["host"]["architecture"]
            .as_str()
            .is_none_or(str::is_empty)
        || report["host"]["profile"].as_str().is_none_or(str::is_empty)
        || !report["host"]["evidence"]
            .as_array()
            .is_some_and(|evidence| !evidence.is_empty() && evidence.iter().all(report_evidence))
        || report["host"]["id"] != request.host_id.as_deref().ok_or(UNAVAILABLE)?
        || report["soul_start"]["initiator"] != "hq"
        || !report["soul_start"]["machine_observation"].is_object()
        || !report["soul_start"]["hq_launch_receipt"].is_object()
        || !report["renders"].is_array()
        || !report["evaluation_cells"].as_array().is_some_and(|cells| {
            !cells.is_empty()
                && cells.iter().all(|cell| {
                    exact_fields(cell, &["role", "model", "provider", "revision", "evidence"])
                        && report_evidence(&cell["evidence"])
                })
        })
        || report["run_id"].as_str().is_none_or(str::is_empty)
        || report["suite_revision"].as_str().is_none_or(|s| {
            s.len() != 40
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || report["recorded_at"].as_str().is_none_or(str::is_empty)
        || !matches!(
            report["profile_in_force"].as_str(),
            Some("managed-protected" | "managed-cooperative")
        )
    {
        return Err(UNAVAILABLE);
    }
    for evidence in [
        &report["soul_start"]["machine_observation"],
        &report["soul_start"]["hq_launch_receipt"],
    ] {
        if !report_evidence(evidence) {
            return Err(UNAVAILABLE);
        }
    }
    let checks = report["checks"].as_object().ok_or(UNAVAILABLE)?;
    let required_checks = [
        "egress",
        "credentials",
        "state_redirect",
        "safe_interrupt_resume",
        "session_reuse",
        "cost_bound",
        "render_coverage",
    ];
    if checks.len() != required_checks.len()
        || required_checks.iter().any(|name| {
            let check = &report["checks"][*name];
            !exact_fields(check, &["outcome", "evidence"])
                || !matches!(
                    check["outcome"].as_str(),
                    Some("pass" | "fail" | "unenforced" | "not-run")
                )
                || !check["evidence"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty() && items.iter().all(report_evidence))
                || (report["profile_in_force"] == "managed-protected" && check["outcome"] != "pass")
        })
    {
        return Err(UNAVAILABLE);
    }
    let gates = report["gates"].as_object().ok_or(UNAVAILABLE)?;
    if gates.is_empty()
        || gates.len() > 3
        || gates.iter().any(|(name, gate)| {
            !matches!(name.as_str(), "T01" | "T02" | "T03" | "T21")
                || !exact_fields(gate, &["outcome", "evidence"])
                || gate["outcome"] != "pass"
                || !report_evidence(&gate["evidence"])
        })
        || (report["profile_in_force"] == "managed-protected"
            && (gates.len() != 3
                || !["T01", "T02", "T03"]
                    .iter()
                    .all(|name| gates.contains_key(*name))))
        || (report["profile_in_force"] == "managed-cooperative"
            && (gates.len() != 1 || !gates.contains_key("T21")))
    {
        return Err(UNAVAILABLE);
    }
    if version == 2
        && (report["profile_in_force"] != "managed-protected"
            || !bridge_shape(&report["bridge"])
            || report["bridge"]["assignment"]["machine_observation"]
                != report["soul_start"]["machine_observation"])
    {
        return Err(UNAVAILABLE);
    }
    Ok(raw)
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

fn pin_time(text: &str) -> Result<i128, &'static str> {
    // HQ and the service use uppercase RFC 3339 without leap seconds. The
    // time parser also accepts alternate separators and leap-second stand-ins.
    let bytes = text.as_bytes();
    if bytes.get(10) != Some(&b'T') || bytes.get(17..19) == Some(b"60") || text.ends_with('z') {
        return Err(UNAVAILABLE);
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .map(|t| t.unix_timestamp_nanos())
        .map_err(|_| UNAVAILABLE)
}

fn release_key(manifest: &str, kid: &str, instant: Duration) -> Result<VerifyingKey, &'static str> {
    let now = i128::try_from(instant.as_nanos()).map_err(|_| UNAVAILABLE)?;
    let pins: Manifest = serde_json::from_str(manifest).map_err(|_| UNAVAILABLE)?;
    if pins.server != ORIGIN {
        return Err(UNAVAILABLE);
    }
    let mut ids = std::collections::HashSet::new();
    let mut pubkeys = std::collections::HashSet::new();
    let mut selected = None;
    for p in pins.keys {
        let (start, end) = (pin_time(&p.not_before)?, pin_time(&p.not_after)?);
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
    instant: Duration,
) -> Result<(Vec<u8>, String, String), &'static str> {
    let jti = req.receipt_jti.as_deref().ok_or(UNAVAILABLE)?;
    let enc = req.receipt_body.as_deref().ok_or(UNAVAILABLE)?;
    let raw = URL.decode(enc).map_err(|_| UNAVAILABLE)?;
    if raw.is_empty() || raw.len() > 8192 || URL.encode(&raw) != enc {
        return Err(UNAVAILABLE);
    }
    let sha = digest(&raw);
    verify_signed_response(
        manifest,
        instant,
        req.receipt_kid.as_deref().ok_or(UNAVAILABLE)?,
        req.receipt_signature.as_deref().ok_or(UNAVAILABLE)?,
        200,
        &sha,
        jti,
    )?;
    Ok((raw, sha, jti.into()))
}

fn verify_signed_response(
    manifest: &str,
    instant: Duration,
    kid: &str,
    encoded: &str,
    status: u16,
    sha: &str,
    jti: &str,
) -> Result<(), &'static str> {
    let key = release_key(manifest, kid, instant)?;
    let bytes = URL.decode(encoded).map_err(|_| UNAVAILABLE)?;
    if URL.encode(&bytes) != encoded {
        return Err(UNAVAILABLE);
    }
    let sig = Signature::from_slice(&bytes).map_err(|_| UNAVAILABLE)?;
    key.verify_strict(
        format!("agent-bot-sig-v1\n{status}\n{sha}\n{jti}").as_bytes(),
        &sig,
    )
    .map_err(|_| UNAVAILABLE)
}

fn binding(
    req: &Request,
    manifest: &str,
    instant: Duration,
    record: &Record,
) -> Result<Bound, &'static str> {
    let (raw, sha, jti) = verify_receipt(req, manifest, instant)?;
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
        .any(|p| p.jti == bound.receipt_jti && p.expires >= instant.as_secs())
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
        .map_err(|err| {
            if keychain_read_interaction_denied(&err) {
                READ_INTERACTION_DENIED
            } else {
                UNAVAILABLE
            }
        })?
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
    instant: Duration,
) -> Result<Value, &'static str> {
    execute(
        items,
        provider,
        pair,
        request,
        instant,
        include_str!("../trusted/server-keys.json"),
    )
}

fn execute(
    items: &dyn Items,
    provider: &dyn Enclave,
    pair: &Pair,
    request: Request,
    instant: Duration,
    manifest: &str,
) -> Result<Value, &'static str> {
    let now = instant.as_secs();
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
            let bound = binding(&request, manifest, instant, &record)?;
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
            let (raw, sha, jti) = verify_receipt(&request, manifest, instant)?;
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
        "qualification-host-report" => {
            let raw = fixed_host_report(&request)?;
            let mut message = HOST_REPORT_PURPOSE.as_bytes().to_vec();
            message.push(0);
            message.extend_from_slice(&raw);
            let signature = provider.sign(&reference, &message)?;
            result = json!({
                "schema_version": 1,
                "purpose": HOST_REPORT_PURPOSE,
                "host_id": request.host_id.as_ref().ok_or(UNAVAILABLE)?,
                "signer_id": request.signer_id.as_ref().ok_or(UNAVAILABLE)?,
                "report_sha256": format!("sha256:{}", digest(&raw)),
                "report_base64url": URL.encode(&raw),
                "signature_base64url": URL.encode(signature),
            });
        }
        "qualification-host-report-v2" => {
            let raw = fixed_host_report_version(&request, 2)?;
            let mut message = HOST_REPORT_PURPOSE_V2.as_bytes().to_vec();
            message.push(0);
            message.extend_from_slice(&raw);
            let signature = provider.sign(&reference, &message)?;
            result = json!({
                "schema_version": 2,
                "purpose": HOST_REPORT_PURPOSE_V2,
                "host_id": request.host_id.as_ref().ok_or(UNAVAILABLE)?,
                "signer_id": request.signer_id.as_ref().ok_or(UNAVAILABLE)?,
                "report_sha256": format!("sha256:{}", digest(&raw)),
                "report_base64url": URL.encode(&raw),
                "signature_base64url": URL.encode(signature),
            });
        }
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
