// SPDX-License-Identifier: MIT
//! Zero-crate Rust SDK for Baccarat Live Platform B2B Operator Seamless Wallet API (v1.5.1).

pub mod crypto;
mod curl_ffi;
pub mod json;

pub use crate::json::Json;

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::io::Read as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SANDBOX_BASE_URL: &str = "https://api.lt.cniia.cloud";
pub const MAX_DETAIL_WINDOW_MS: i64 = 604_800_000;
pub const MAX_PAGE_SIZE: i64 = 20_000;
pub const MAX_WEBHOOK_BODY_BYTES: usize = 1_048_576;
const LEDGER_SCALE: i128 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Sandbox,
    Production,
}

pub mod status_code {
    pub const SC_OK: &str = "SC_OK";
    pub const SC_INVALID_REQUEST: &str = "SC_INVALID_REQUEST";
    pub const SC_AUTHENTICATION_FAILED: &str = "SC_AUTHENTICATION_FAILED";
    pub const SC_INVALID_SIGNATURE: &str = "SC_INVALID_SIGNATURE";
    pub const SC_INVALID_TOKEN: &str = "SC_INVALID_TOKEN";
    pub const SC_INVALID_GAME: &str = "SC_INVALID_GAME";
    pub const SC_USER_NOT_EXISTS: &str = "SC_USER_NOT_EXISTS";
    pub const SC_USER_DISABLED: &str = "SC_USER_DISABLED";
    pub const SC_WRONG_CURRENCY: &str = "SC_WRONG_CURRENCY";
    pub const SC_CURRENCY_NOT_SUPPORTED: &str = "SC_CURRENCY_NOT_SUPPORTED";
    pub const SC_INSUFFICIENT_FUNDS: &str = "SC_INSUFFICIENT_FUNDS";
    pub const SC_TRANSACTION_DUPLICATED: &str = "SC_TRANSACTION_DUPLICATED";
    pub const SC_TRANSACTION_NOT_EXISTS: &str = "SC_TRANSACTION_NOT_EXISTS";
    pub const SC_TRANSACTION_STILL_PROCESSING: &str = "SC_TRANSACTION_STILL_PROCESSING";
    pub const SC_OPERATOR_TIMEOUT: &str = "SC_OPERATOR_TIMEOUT";
    pub const SC_UNDER_MAINTENANCE: &str = "SC_UNDER_MAINTENANCE";
    pub const SC_GAME_DISABLED: &str = "SC_GAME_DISABLED";
    pub const SC_RATE_LIMITED: &str = "SC_RATE_LIMITED";
}

pub fn is_retryable_status(status: &str) -> bool {
    matches!(
        status.trim(),
        status_code::SC_TRANSACTION_STILL_PROCESSING
            | status_code::SC_OPERATOR_TIMEOUT
            | status_code::SC_RATE_LIMITED
    )
}

#[derive(Debug, Clone)]
pub enum SdkError {
    Config(String),
    Argument(String),
    Money(String),
    Transport(String),
    Api {
        trace_id: String,
        status: String,
        message: String,
        validation: Option<HashMap<String, String>>,
        http_status: u16,
    },
}

impl SdkError {
    pub fn is_retryable(&self) -> bool {
        match self {
            SdkError::Transport(_) => true,
            SdkError::Api { status, .. } => is_retryable_status(status),
            _ => false,
        }
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdkError::Config(m) | SdkError::Argument(m) | SdkError::Money(m) | SdkError::Transport(m) => {
                write!(f, "{}", m)
            }
            SdkError::Api { status, message, .. } => write!(f, "{}: {}", status, message),
        }
    }
}

impl std::error::Error for SdkError {}

// ── 1. Raw-Byte HMAC-SHA256 Signing & Timing-Safe Verification ──────────────

pub fn sign_body(raw_body: &[u8], hmac_secret: &str) -> Result<String, SdkError> {
    if hmac_secret.is_empty() {
        return Err(SdkError::Config("hmac_secret must be non-empty".into()));
    }
    // CRITICAL: Use raw UTF-8 bytes of hmac_secret directly — NEVER Base64-decode!
    let digest = crypto::hmac_sha256(hmac_secret.as_bytes(), raw_body);
    Ok(crypto::hex_encode(&digest))
}

pub fn verify_signature(raw_body: &[u8], signature_header: &str, hmac_secret: &str) -> bool {
    if hmac_secret.is_empty() {
        return false;
    }
    let trimmed = signature_header.trim();
    let Some(actual) = crypto::hex_decode_32(trimmed) else {
        return false;
    };
    let expected = crypto::hmac_sha256(hmac_secret.as_bytes(), raw_body);
    crypto::ct_eq(&actual, &expected)
}

pub fn verify_webhook_headers(
    api_key_header: &str,
    signature_header: &str,
    raw_body: &[u8],
    expected_api_key: &str,
    hmac_secret: &str,
) -> &'static str {
    let exp = expected_api_key.trim();
    let act = api_key_header.trim();
    if exp.is_empty() || act.is_empty() || !crypto::ct_eq(act.as_bytes(), exp.as_bytes()) {
        return status_code::SC_AUTHENTICATION_FAILED;
    }
    if !verify_signature(raw_body, signature_header, hmac_secret) {
        return status_code::SC_INVALID_SIGNATURE;
    }
    status_code::SC_OK
}

// ── 2. Exact Decimal <-> Ledger Units (i128, handles display_exponent 0..=18) ─

pub fn decimal_to_ledger_units(raw: &str, display_exponent: i32, allow_negative: bool) -> Result<i128, SdkError> {
    if !(0..=18).contains(&display_exponent) {
        return Err(SdkError::Money(format!("display_exponent out of range: {}", display_exponent)));
    }
    let s = raw.trim();
    if s.is_empty() {
        return Err(SdkError::Money("empty decimal amount".into()));
    }
    let (neg, rest) = if let Some(stripped) = s.strip_prefix('-') {
        (true, stripped)
    } else {
        (false, s)
    };
    let (whole_str, frac_str) = if let Some((w, f)) = rest.split_once('.') {
        if f.is_empty() {
            return Err(SdkError::Money("trailing dot in decimal".into()));
        }
        (w, f)
    } else {
        (rest, "")
    };
    if whole_str.is_empty()
        || !whole_str.bytes().all(|b| b.is_ascii_digit())
        || !frac_str.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(SdkError::Money(format!("malformed decimal amount: {}", raw)));
    }
    let scale_digits = (display_exponent as usize) + 3;
    let trimmed_frac = frac_str.trim_end_matches('0');
    if trimmed_frac.len() > scale_digits {
        return Err(SdkError::Money("decimal precision exceeded".into()));
    }
    let mut padded_frac = String::from(trimmed_frac);
    while padded_frac.len() < scale_digits {
        padded_frac.push('0');
    }
    let divisor = LEDGER_SCALE * 10_i128.pow(display_exponent as u32);
    let whole: i128 = whole_str.parse().map_err(|_| SdkError::Money("whole overflow".into()))?;
    let frac: i128 = if padded_frac.is_empty() {
        0
    } else {
        padded_frac.parse().map_err(|_| SdkError::Money("frac overflow".into()))?
    };
    let abs = whole
        .checked_mul(divisor)
        .and_then(|v| v.checked_add(frac))
        .ok_or_else(|| SdkError::Money("ledger units overflow".into()))?;
    if neg && abs > 0 {
        if !allow_negative {
            return Err(SdkError::Money("negative decimal forbidden".into()));
        }
        Ok(-abs)
    } else {
        Ok(abs)
    }
}

pub fn ledger_units_to_decimal(amount: i128, display_exponent: i32) -> Result<String, SdkError> {
    if !(0..=18).contains(&display_exponent) {
        return Err(SdkError::Money(format!("display_exponent out of range: {}", display_exponent)));
    }
    let neg = amount < 0;
    let abs = amount.unsigned_abs();
    let scale_digits = (display_exponent as usize) + 3;
    let divisor = 10_u128.pow(scale_digits as u32);
    let whole = abs / divisor;
    let frac = abs % divisor;
    let sign = if neg { "-" } else { "" };
    if display_exponent == 0 {
        if frac == 0 {
            return Ok(format!("{}{}", sign, whole));
        }
        let fs = format!("{:03}", frac);
        return Ok(format!("{}{}.{}", sign, whole, fs.trim_end_matches('0')));
    }
    let fs = format!("{:0width$}", frac, width = scale_digits);
    let exp = display_exponent as usize;
    let shown = &fs[..exp];
    let sub = fs[exp..].trim_end_matches('0');
    Ok(format!("{}{}.{}{}", sign, whole, shown, sub))
}

// ── 3. Canonical Idempotency Fingerprints ───────────────────────────────────

pub fn encode_tuple_fingerprint(domain: &str, fields: &[&str]) -> String {
    let mut canonical = format!("v1|{}", domain);
    for f in fields {
        canonical.push('|');
        canonical.push_str(&f.len().to_string());
        canonical.push(':');
        canonical.push_str(f);
    }
    crypto::hex_encode(&crypto::sha256(canonical.as_bytes()))
}

pub fn bet_fingerprint(p: &Json) -> String {
    let f0 = p.get("transactionId").to_scalar_string();
    let f1 = p.get("username").to_scalar_string();
    let f2 = p.get("betId").to_scalar_string();
    let f3 = p.get("externalTransactionId").to_scalar_string();
    let f4 = p.get("roundId").to_scalar_string();
    let f5 = p.get("currency").to_scalar_string();
    let f6 = p.get("gameCode").to_scalar_string();
    let f7 = p.get("amount").to_scalar_string();
    encode_tuple_fingerprint("wallet/bet", &[&f0, &f1, &f2, &f3, &f4, &f5, &f6, &f7])
}

pub fn bet_result_fingerprint(p: &Json) -> String {
    let vals = [
        p.get("transactionId").to_scalar_string(),
        p.get("username").to_scalar_string(),
        p.get("betId").to_scalar_string(),
        p.get("externalTransactionId").to_scalar_string(),
        p.get("roundId").to_scalar_string(),
        p.get("currency").to_scalar_string(),
        p.get("gameCode").to_scalar_string(),
        p.get("betAmount").to_scalar_string(),
        p.get("winAmount").to_scalar_string(),
        p.get("effectiveTurnover").to_scalar_string(),
        p.get("winLoss").to_scalar_string(),
        p.get("jackpotAmount").to_scalar_string(),
        p.get("resultType").to_scalar_string(),
        p.get("isFreespin").to_scalar_string(),
        p.get("isEndRound").to_scalar_string(),
        p.get("betTime").to_scalar_string(),
    ];
    let refs: Vec<&str> = vals.iter().map(String::as_str).collect();
    encode_tuple_fingerprint("wallet/bet_result", &refs)
}

pub fn rollback_fingerprint(p: &Json) -> String {
    let f0 = p.get("transactionId").to_scalar_string();
    let f1 = p.get("username").to_scalar_string();
    let f2 = p.get("betId").to_scalar_string();
    let f3 = p.get("externalTransactionId").to_scalar_string();
    let f4 = p.get("roundId").to_scalar_string();
    let f5 = p.get("currency").to_scalar_string();
    let f6 = p.get("gameCode").to_scalar_string();
    let f7 = p.get("amount").to_scalar_string();
    encode_tuple_fingerprint("wallet/rollback", &[&f0, &f1, &f2, &f3, &f4, &f5, &f6, &f7])
}

pub fn adjustment_fingerprint(p: &Json) -> String {
    let vals = [
        p.get("transactionId").to_scalar_string(),
        p.get("username").to_scalar_string(),
        p.get("betId").to_scalar_string(),
        p.get("externalTransactionId").to_scalar_string(),
        p.get("roundId").to_scalar_string(),
        p.get("currency").to_scalar_string(),
        p.get("gameCode").to_scalar_string(),
        p.get("direction").to_scalar_string(),
        p.get("amount").to_scalar_string(),
        p.get("reasonCode").to_scalar_string(),
    ];
    let refs: Vec<&str> = vals.iter().map(String::as_str).collect();
    encode_tuple_fingerprint("wallet/adjustment", &refs)
}

// ── 4. Config, Pluggable HttpTransport & S2S Client ─────────────────────────

pub trait HttpTransport: Send + Sync {
    fn post_json(
        &self,
        url: &str,
        api_key: &str,
        signature: &str,
        raw_body: &[u8],
        timeout_ms: u64,
    ) -> Result<(u16, Vec<u8>), SdkError>;
}

pub struct LibCurlTransport;

impl HttpTransport for LibCurlTransport {
    fn post_json(
        &self,
        url: &str,
        api_key: &str,
        signature: &str,
        raw_body: &[u8],
        timeout_ms: u64,
    ) -> Result<(u16, Vec<u8>), SdkError> {
        curl_ffi::libcurl_post_json(url, api_key, signature, raw_body, timeout_ms).map_err(SdkError::Transport)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub api_key: String,
    pub hmac_secret: String,
    pub environment: Environment,
    pub base_url: Option<String>,
    pub timeout_ms: u64,
}

impl Config {
    pub fn resolved_base_url(&self) -> Result<String, SdkError> {
        if self.api_key.trim().is_empty() {
            return Err(SdkError::Config("api_key is required".into()));
        }
        if self.hmac_secret.is_empty() {
            return Err(SdkError::Config("hmac_secret is required".into()));
        }
        let raw = match self.base_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(u) => u,
            None if self.environment == Environment::Sandbox => SANDBOX_BASE_URL,
            None => return Err(SdkError::Config("base_url is required when environment is Production".into())),
        };
        let lower = raw.to_ascii_lowercase();
        if !lower.starts_with("http://") && !lower.starts_with("https://") {
            return Err(SdkError::Config("base_url must start with http:// or https://".into()));
        }
        if self.timeout_ms == 0 {
            return Err(SdkError::Config("timeout_ms must be > 0".into()));
        }
        Ok(raw.trim_end_matches('/').to_string())
    }
}

fn os_random_seed() -> [u8; 16] {
    static SEED: OnceLock<[u8; 16]> = OnceLock::new();
    *SEED.get_or_init(|| {
        let mut buf = [0u8; 16];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut buf).is_ok() {
                return buf;
            }
        }
        let rs1 = RandomState::new();
        let rs2 = RandomState::new();
        let mut h1 = rs1.build_hasher();
        h1.write_u32(std::process::id());
        let mut h2 = rs2.build_hasher();
        h2.write_u64(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        );
        buf[..8].copy_from_slice(&h1.finish().to_le_bytes());
        buf[8..].copy_from_slice(&h2.finish().to_le_bytes());
        buf
    })
}

fn next_trace_uuid() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut material = Vec::with_capacity(48);
    material.extend_from_slice(&os_random_seed());
    material.extend_from_slice(&std::process::id().to_le_bytes());
    material.extend_from_slice(&nanos.to_le_bytes());
    material.extend_from_slice(&n.to_le_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&crypto::sha256(&material)[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

pub struct Client {
    api_key: String,
    hmac_secret: String,
    base_url: String,
    timeout_ms: u64,
    transport: Arc<dyn HttpTransport>,
}

impl Client {
    pub fn new(config: Config) -> Result<Self, SdkError> {
        Self::with_transport(config, Arc::new(LibCurlTransport))
    }

    pub fn with_transport(config: Config, transport: Arc<dyn HttpTransport>) -> Result<Self, SdkError> {
        let base_url = config.resolved_base_url()?;
        Ok(Self {
            api_key: config.api_key.trim().to_string(),
            hmac_secret: config.hmac_secret,
            base_url,
            timeout_ms: config.timeout_ms,
            transport,
        })
    }

    pub fn post_signed(&self, route_path: &str, mut payload: Json) -> Result<Json, SdkError> {
        if !payload.is_object() {
            payload = Json::object();
        }
        let trace_id = payload
            .get("traceId")
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(next_trace_uuid);
        payload.set("traceId", Json::Str(trace_id.clone()));

        let raw_json = payload.dump();
        let raw_bytes = raw_json.as_bytes();
        let sig = sign_body(raw_bytes, &self.hmac_secret)?;
        let url = format!("{}{}", self.base_url, route_path);

        let (http_status, resp_bytes) =
            self.transport
                .post_json(&url, &self.api_key, &sig, raw_bytes, self.timeout_ms)?;

        let resp_str = String::from_utf8_lossy(&resp_bytes);
        let parsed = Json::parse(&resp_str)
            .ok()
            .filter(Json::is_object)
            .ok_or_else(|| SdkError::Api {
                trace_id: trace_id.clone(),
                status: if http_status >= 500 || http_status == 408 || http_status == 429 {
                    status_code::SC_OPERATOR_TIMEOUT.into()
                } else {
                    status_code::SC_INVALID_REQUEST.into()
                },
                message: format!("Non-JSON-object HTTP {}", http_status),
                validation: None,
                http_status,
            })?;

        let st = parsed.get("status").as_str().unwrap_or(status_code::SC_INVALID_REQUEST);
        let eff_trace = parsed
            .get("traceId")
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(&trace_id)
            .to_string();

        if http_status != 200 || st != status_code::SC_OK {
            let validation = parsed.get("validation").as_object_entries().map(|entries| {
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_scalar_string()))
                    .collect::<HashMap<String, String>>()
            });
            return Err(SdkError::Api {
                trace_id: eff_trace,
                status: st.to_string(),
                message: parsed.get("message").as_str().unwrap_or("API error").to_string(),
                validation,
                http_status,
            });
        }

        let mut out = Json::object();
        out.set("traceId", Json::Str(eff_trace));
        out.set("status", Json::Str(status_code::SC_OK.into()));
        out.set("data", parsed.get("data").clone());
        Ok(out)
    }

    pub fn ping(&self, params: Json) -> Result<Json, SdkError> {
        self.post_signed("/operator/v1/ping", params)
    }

    pub fn create_game_url(&self, params: Json) -> Result<Json, SdkError> {
        self.post_signed("/operator/v1/game/url", params)
    }

    pub fn list_tables(&self, params: Json) -> Result<Json, SdkError> {
        self.post_signed("/operator/v1/game/tables", params)
    }

    pub fn terminate_sessions(&self, params: Json) -> Result<Json, SdkError> {
        self.post_signed("/operator/v1/game/terminate", params)
    }

    pub fn update_player_status(&self, params: Json) -> Result<Json, SdkError> {
        self.post_signed("/operator/v1/player/status", params)
    }

    pub fn update_player_limits(&self, params: Json) -> Result<Json, SdkError> {
        self.post_signed("/operator/v1/player/limits", params)
    }

    pub fn list_transactions(&self, params: Json) -> Result<Json, SdkError> {
        let Some(from) = params.get("fromTime").as_i64() else {
            return Err(SdkError::Argument("fromTime integer is required".into()));
        };
        let Some(to) = params.get("toTime").as_i64() else {
            return Err(SdkError::Argument("toTime integer is required".into()));
        };
        if from < 0 || to < from {
            return Err(SdkError::Argument("invalid [fromTime, toTime]".into()));
        }
        self.post_signed("/operator/v1/transaction/list", params)
    }

    pub fn list_all_transactions(&self, from_time: i64, to_time: i64, page_size: i64) -> Result<Vec<Json>, SdkError> {
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(SdkError::Argument(format!("page_size must be in 1..={}", MAX_PAGE_SIZE)));
        }
        let mut all = Vec::new();
        let mut page_no = 1_i64;
        loop {
            let mut p = Json::object();
            p.set("fromTime", Json::Int(from_time));
            p.set("toTime", Json::Int(to_time));
            p.set("pageNo", Json::Int(page_no));
            p.set("pageSize", Json::Int(page_size));
            let res = self.list_transactions(p)?;
            let data = res.get("data");
            let batch = data.get("transactions").as_array().unwrap_or(&[]);
            all.extend_from_slice(batch);
            let total = data.get("total").as_i64().unwrap_or(all.len() as i64).max(0) as usize;
            if all.len() >= total || batch.is_empty() {
                break;
            }
            page_no += 1;
        }
        Ok(all)
    }

    pub fn get_transaction_detail(&self, params: Json) -> Result<Json, SdkError> {
        let bet_id = params.get("betId").as_str().unwrap_or("").trim();
        if bet_id.is_empty() {
            return Err(SdkError::Argument("betId is required".into()));
        }
        if params.contains("fromTime") || params.contains("toTime") {
            let Some(from) = params.get("fromTime").as_i64() else {
                return Err(SdkError::Argument("fromTime integer is required when specified".into()));
            };
            let Some(to) = params.get("toTime").as_i64() else {
                return Err(SdkError::Argument("toTime integer is required when specified".into()));
            };
            if from < 0 || to < from || (to - from) > MAX_DETAIL_WINDOW_MS {
                return Err(SdkError::Argument(
                    "detail window must satisfy 0 <= toTime - fromTime <= 604800000".into(),
                ));
            }
        }
        self.post_signed("/operator/v1/transaction/detail", params)
    }

    pub fn list_unsettled_transactions(&self, params: Json) -> Result<Json, SdkError> {
        if params.contains("fromTime") || params.contains("toTime") {
            let Some(from) = params.get("fromTime").as_i64() else {
                return Err(SdkError::Argument("fromTime integer is required when specified".into()));
            };
            let Some(to) = params.get("toTime").as_i64() else {
                return Err(SdkError::Argument("toTime integer is required when specified".into()));
            };
            if from < 0 || to < from || (to - from) > MAX_DETAIL_WINDOW_MS {
                return Err(SdkError::Argument(
                    "unsettled window must satisfy 0 <= toTime - fromTime <= 604800000".into(),
                ));
            }
        }
        self.post_signed("/operator/v1/transaction/unsettled", params)
    }

    pub fn get_wallet_transaction_status(&self, params: Json) -> Result<Json, SdkError> {
        let tx_id = params.get("transactionId").as_str().unwrap_or("").trim();
        let bet_id = params.get("betId").as_str().unwrap_or("").trim();
        let username = params.get("username").as_str().unwrap_or("").trim();
        if tx_id.is_empty() && bet_id.is_empty() && username.is_empty() {
            return Err(SdkError::Argument("transactionId, betId, or username is required".into()));
        }
        let user_only = !username.is_empty() && tx_id.is_empty() && bet_id.is_empty();
        let has_window = params.contains("fromTime") || params.contains("toTime");
        if user_only || has_window {
            let Some(from) = params.get("fromTime").as_i64() else {
                return Err(SdkError::Argument("fromTime integer is required".into()));
            };
            let Some(to) = params.get("toTime").as_i64() else {
                return Err(SdkError::Argument("toTime integer is required".into()));
            };
            if from < 0 || to < from || (user_only && (to - from) > 86_400_000) {
                return Err(SdkError::Argument(
                    if user_only {
                        "username query window must satisfy 0 <= toTime - fromTime <= 86400000"
                    } else {
                        "invalid [fromTime, toTime] window"
                    }
                    .into(),
                ));
            }
        }
        self.post_signed("/operator/v1/wallet/transaction-status", params)
    }
}

// ── 5. Seamless Wallet Pluggable WalletHandler, WebhookDispatcher & InMemoryWallet ─

pub trait WalletHandler: Send + Sync {
    fn on_balance(&self, req: &Json) -> Json;
    fn on_bet(&self, req: &Json) -> Json;
    fn on_bet_result(&self, req: &Json) -> Json;
    fn on_rollback(&self, req: &Json) -> Json;
    fn on_adjustment(&self, req: &Json) -> Json {
        InMemoryWallet::err_env(
            req.get("traceId").as_str().unwrap_or(""),
            status_code::SC_INVALID_REQUEST,
            "on_adjustment not implemented",
        )
    }
}

struct Acct {
    currency: String,
    exponent: i32,
    units: i128,
    tokens: HashSet<String>,
    disabled: bool,
}

struct TxRec {
    kind: &'static str,
    fp: String,
    empty: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BetState {
    Deducted,
    Settled,
    RolledBack,
}

struct BetRec {
    username: String,
    currency: String,
    stake: i128,
    state: BetState,
}

struct WalletState {
    accounts: HashMap<String, Acct>,
    transactions: HashMap<String, TxRec>,
    deducted_bets: HashMap<String, BetRec>,
}

pub struct InMemoryWallet {
    inner: Mutex<WalletState>,
}

impl Default for InMemoryWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryWallet {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(WalletState {
                accounts: HashMap::new(),
                transactions: HashMap::new(),
                deducted_bets: HashMap::new(),
            }),
        }
    }

    pub fn add_account(
        &self,
        username: &str,
        currency: &str,
        balance: &str,
        exponent: i32,
        tokens: &[&str],
    ) -> Result<(), SdkError> {
        let units = decimal_to_ledger_units(balance, exponent, false)?;
        let mut st = self.inner.lock().unwrap();
        st.accounts.insert(
            username.to_string(),
            Acct {
                currency: currency.trim().to_ascii_uppercase(),
                exponent,
                units,
                tokens: tokens.iter().map(|s| (*s).to_string()).collect(),
                disabled: false,
            },
        );
        Ok(())
    }

    pub fn set_disabled(&self, username: &str, disabled: bool) {
        let mut st = self.inner.lock().unwrap();
        if let Some(a) = st.accounts.get_mut(username) {
            a.disabled = disabled;
        }
    }

    fn err_env(trace_id: &str, status: &str, msg: &str) -> Json {
        let mut r = Json::object();
        r.set("traceId", Json::Str(trace_id.into()));
        r.set("status", Json::Str(status.into()));
        r.set("message", Json::Str(msg.into()));
        r
    }

    fn ok_env(trace_id: &str, username: &str, acct: &Acct) -> Json {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let bal = ledger_units_to_decimal(acct.units, acct.exponent).unwrap_or_else(|_| "0.00".into());
        let mut data = Json::object();
        data.set("username", Json::Str(username.into()));
        data.set("currency", Json::Str(acct.currency.clone()));
        data.set("balance", Json::Str(bal));
        data.set("timestamp", Json::Int(ts));
        let mut r = Json::object();
        r.set("traceId", Json::Str(trace_id.into()));
        r.set("status", Json::Str(status_code::SC_OK.into()));
        r.set("data", data);
        r
    }
}

impl WalletHandler for InMemoryWallet {
    fn on_balance(&self, req: &Json) -> Json {
        let st = self.inner.lock().unwrap();
        let tid = req.get("traceId").as_str().unwrap_or("");
        let u = req.get("username").as_str().unwrap_or("").trim();
        let cur = req.get("currency").as_str().unwrap_or("").trim().to_ascii_uppercase();
        if u.is_empty() || cur.is_empty() {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "username and currency required");
        }
        let Some(a) = st.accounts.get(u) else {
            return Self::err_env(tid, status_code::SC_USER_NOT_EXISTS, "User missing");
        };
        if a.currency != cur {
            return Self::err_env(tid, status_code::SC_WRONG_CURRENCY, "Wrong currency");
        }
        if a.disabled {
            return Self::err_env(tid, status_code::SC_USER_DISABLED, "Disabled");
        }
        if !a.tokens.is_empty() && !a.tokens.contains(req.get("token").as_str().unwrap_or("")) {
            return Self::err_env(tid, status_code::SC_INVALID_TOKEN, "Invalid token");
        }
        Self::ok_env(tid, u, a)
    }

    fn on_bet(&self, req: &Json) -> Json {
        let mut st = self.inner.lock().unwrap();
        let tid = req.get("traceId").as_str().unwrap_or("");
        let tx_id = req.get("transactionId").as_str().unwrap_or("").trim().to_string();
        let bet_id = req.get("betId").as_str().unwrap_or("").trim().to_string();
        let u = req.get("username").as_str().unwrap_or("").trim();
        let cur = req.get("currency").as_str().unwrap_or("").trim().to_ascii_uppercase();
        let amt_str = req.get("amount").as_str().unwrap_or("");
        if tx_id.is_empty() || bet_id.is_empty() || u.is_empty() || cur.is_empty() || amt_str.is_empty() {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Missing required bet fields");
        }
        let fp = bet_fingerprint(req);

        let (exp, disabled, tok_ok, cur_ok, units_now) = match st.accounts.get(u) {
            None => return Self::err_env(tid, status_code::SC_USER_NOT_EXISTS, "User missing"),
            Some(a) => (
                a.exponent,
                a.disabled,
                a.tokens.is_empty() || a.tokens.contains(req.get("token").as_str().unwrap_or("")),
                a.currency == cur,
                a.units,
            ),
        };
        if !cur_ok {
            return Self::err_env(tid, status_code::SC_WRONG_CURRENCY, "Wrong currency");
        }
        if let Some(prior) = st.transactions.get(&tx_id) {
            if prior.kind != "BET" || prior.fp != fp {
                return Self::err_env(tid, status_code::SC_TRANSACTION_DUPLICATED, "Conflict");
            }
            return Self::ok_env(tid, u, st.accounts.get(u).unwrap());
        }
        if st.deducted_bets.contains_key(&bet_id) {
            return Self::err_env(tid, status_code::SC_TRANSACTION_DUPLICATED, "Duplicate betId");
        }
        if disabled {
            return Self::err_env(tid, status_code::SC_USER_DISABLED, "Disabled");
        }
        if !tok_ok {
            return Self::err_env(tid, status_code::SC_INVALID_TOKEN, "Invalid token");
        }
        let Ok(stake) = decimal_to_ledger_units(amt_str, exp, false) else {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Bad amount");
        };
        if stake <= 0 {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Bet amount must be positive");
        }
        if units_now < stake {
            return Self::err_env(tid, status_code::SC_INSUFFICIENT_FUNDS, "Insufficient funds");
        }
        st.accounts.get_mut(u).unwrap().units -= stake;
        st.transactions.insert(
            tx_id,
            TxRec {
                kind: "BET",
                fp,
                empty: false,
            },
        );
        st.deducted_bets.insert(
            bet_id,
            BetRec {
                username: u.to_string(),
                currency: cur,
                stake,
                state: BetState::Deducted,
            },
        );
        Self::ok_env(tid, u, st.accounts.get(u).unwrap())
    }

    fn on_bet_result(&self, req: &Json) -> Json {
        let mut st = self.inner.lock().unwrap();
        let tid = req.get("traceId").as_str().unwrap_or("");
        let tx_id = req.get("transactionId").as_str().unwrap_or("").trim().to_string();
        let bet_id = req.get("betId").as_str().unwrap_or("").trim().to_string();
        let u = req.get("username").as_str().unwrap_or("").trim();
        let cur = req.get("currency").as_str().unwrap_or("").trim().to_ascii_uppercase();
        let win_str = req.get("winAmount").as_str().unwrap_or("");
        let bet_amt_str = req.get("betAmount").as_str().unwrap_or("");
        if tx_id.is_empty()
            || bet_id.is_empty()
            || u.is_empty()
            || cur.is_empty()
            || win_str.is_empty()
            || bet_amt_str.is_empty()
        {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Missing required bet_result fields");
        }
        let fp = bet_result_fingerprint(req);

        let exp = match st.accounts.get(u) {
            None => return Self::err_env(tid, status_code::SC_USER_NOT_EXISTS, "User missing"),
            Some(a) if a.currency != cur => return Self::err_env(tid, status_code::SC_WRONG_CURRENCY, "Wrong currency"),
            Some(a) => a.exponent,
        };
        if let Some(prior) = st.transactions.get(&tx_id) {
            if prior.kind != "SETTLE" || prior.fp != fp {
                return Self::err_env(tid, status_code::SC_TRANSACTION_DUPLICATED, "Conflict");
            }
            return Self::ok_env(tid, u, st.accounts.get(u).unwrap());
        }
        let (Ok(bet_units), Ok(win)) = (
            decimal_to_ledger_units(bet_amt_str, exp, false),
            decimal_to_ledger_units(win_str, exp, false),
        ) else {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Bad bet_result amount");
        };
        let Some(orig) = st.deducted_bets.get_mut(&bet_id) else {
            return Self::err_env(tid, status_code::SC_TRANSACTION_NOT_EXISTS, "Original betId missing");
        };
        if orig.username != u || orig.currency != cur || orig.stake != bet_units {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "bet_result mismatch");
        }
        if orig.state != BetState::Deducted {
            return Self::err_env(tid, status_code::SC_TRANSACTION_DUPLICATED, "betId already finalized");
        }
        orig.state = BetState::Settled;
        let acct = st.accounts.get_mut(u).unwrap();
        let Some(next_units) = acct.units.checked_add(win) else {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Balance overflow");
        };
        acct.units = next_units;
        st.transactions.insert(
            tx_id,
            TxRec {
                kind: "SETTLE",
                fp,
                empty: false,
            },
        );
        Self::ok_env(tid, u, st.accounts.get(u).unwrap())
    }

    fn on_rollback(&self, req: &Json) -> Json {
        let mut st = self.inner.lock().unwrap();
        let tid = req.get("traceId").as_str().unwrap_or("");
        let tx_id = req.get("transactionId").as_str().unwrap_or("").trim().to_string();
        let bet_id = req.get("betId").as_str().unwrap_or("").trim().to_string();
        let u = req.get("username").as_str().unwrap_or("").trim();
        let cur = req.get("currency").as_str().unwrap_or("").trim().to_ascii_uppercase();
        let amt_str = req.get("amount").as_str().unwrap_or("");
        if tx_id.is_empty() || bet_id.is_empty() || u.is_empty() || cur.is_empty() || amt_str.is_empty() {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Missing required rollback fields");
        }
        let fp = rollback_fingerprint(req);

        let exp = match st.accounts.get(u) {
            None => return Self::err_env(tid, status_code::SC_USER_NOT_EXISTS, "User missing"),
            Some(a) if a.currency != cur => return Self::err_env(tid, status_code::SC_WRONG_CURRENCY, "Wrong currency"),
            Some(a) => a.exponent,
        };
        if let Some(prior) = st.transactions.get(&tx_id) {
            if prior.kind != "ROLLBACK" || prior.fp != fp {
                return Self::err_env(tid, status_code::SC_TRANSACTION_DUPLICATED, "Conflict");
            }
            if prior.empty {
                return Self::err_env(tid, status_code::SC_TRANSACTION_NOT_EXISTS, "Never deducted");
            }
            return Self::ok_env(tid, u, st.accounts.get(u).unwrap());
        }
        let Ok(refund) = decimal_to_ledger_units(amt_str, exp, false) else {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Bad amount");
        };
        if refund <= 0 {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Rollback amount must be positive");
        }
        let Some(orig) = st.deducted_bets.get_mut(&bet_id) else {
            st.transactions.insert(
                tx_id,
                TxRec {
                    kind: "ROLLBACK",
                    fp,
                    empty: true,
                },
            );
            return Self::err_env(tid, status_code::SC_TRANSACTION_NOT_EXISTS, "Never deducted");
        };
        if orig.username != u || orig.currency != cur || orig.stake != refund {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Rollback mismatch");
        }
        if orig.state != BetState::Deducted {
            return Self::err_env(tid, status_code::SC_TRANSACTION_DUPLICATED, "betId already finalized");
        }
        orig.state = BetState::RolledBack;
        let acct = st.accounts.get_mut(u).unwrap();
        let Some(next_units) = acct.units.checked_add(refund) else {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Balance overflow");
        };
        acct.units = next_units;
        st.transactions.insert(
            tx_id,
            TxRec {
                kind: "ROLLBACK",
                fp,
                empty: false,
            },
        );
        Self::ok_env(tid, u, st.accounts.get(u).unwrap())
    }

    fn on_adjustment(&self, req: &Json) -> Json {
        let mut st = self.inner.lock().unwrap();
        let tid = req.get("traceId").as_str().unwrap_or("");
        let tx_id = req.get("transactionId").as_str().unwrap_or("").trim().to_string();
        let bet_id = req.get("betId").as_str().unwrap_or("").trim().to_string();
        let u = req.get("username").as_str().unwrap_or("").trim();
        let cur = req.get("currency").as_str().unwrap_or("").trim().to_ascii_uppercase();
        let dir = req.get("direction").as_str().unwrap_or("").trim().to_ascii_uppercase();
        let reason = req.get("reasonCode").as_str().unwrap_or("").trim();
        let amt_str = req.get("amount").as_str().unwrap_or("");
        if tx_id.is_empty()
            || bet_id.is_empty()
            || u.is_empty()
            || cur.is_empty()
            || reason.is_empty()
            || amt_str.is_empty()
            || (dir != "CREDIT" && dir != "DEBIT")
        {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Missing or invalid adjustment fields");
        }
        let fp = adjustment_fingerprint(req);

        let exp = match st.accounts.get(u) {
            None => return Self::err_env(tid, status_code::SC_USER_NOT_EXISTS, "User missing"),
            Some(a) if a.currency != cur => return Self::err_env(tid, status_code::SC_WRONG_CURRENCY, "Wrong currency"),
            Some(a) => a.exponent,
        };
        if let Some(prior) = st.transactions.get(&tx_id) {
            if prior.kind != "ADJUSTMENT" || prior.fp != fp {
                return Self::err_env(tid, status_code::SC_TRANSACTION_DUPLICATED, "Conflict");
            }
            return Self::ok_env(tid, u, st.accounts.get(u).unwrap());
        }
        let Ok(adj_units) = decimal_to_ledger_units(amt_str, exp, false) else {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Bad amount");
        };
        if adj_units <= 0 {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Adjustment amount must be positive");
        }
        let Some(orig) = st.deducted_bets.get(&bet_id) else {
            return Self::err_env(tid, status_code::SC_TRANSACTION_NOT_EXISTS, "Original betId missing");
        };
        if orig.username != u || orig.currency != cur {
            return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Adjustment mismatch");
        }
        let acct = st.accounts.get_mut(u).unwrap();
        if dir == "DEBIT" {
            if acct.units < adj_units {
                return Self::err_env(tid, status_code::SC_INSUFFICIENT_FUNDS, "Insufficient funds");
            }
            acct.units -= adj_units;
        } else {
            let Some(next_units) = acct.units.checked_add(adj_units) else {
                return Self::err_env(tid, status_code::SC_INVALID_REQUEST, "Balance overflow");
            };
            acct.units = next_units;
        }
        st.transactions.insert(
            tx_id,
            TxRec {
                kind: "ADJUSTMENT",
                fp,
                empty: false,
            },
        );
        Self::ok_env(tid, u, st.accounts.get(u).unwrap())
    }
}

impl InMemoryWallet {
    pub fn on_balance(&self, req: &Json) -> Json {
        <Self as WalletHandler>::on_balance(self, req)
    }

    pub fn on_bet(&self, req: &Json) -> Json {
        <Self as WalletHandler>::on_bet(self, req)
    }

    pub fn on_bet_result(&self, req: &Json) -> Json {
        <Self as WalletHandler>::on_bet_result(self, req)
    }

    pub fn on_rollback(&self, req: &Json) -> Json {
        <Self as WalletHandler>::on_rollback(self, req)
    }

    pub fn on_adjustment(&self, req: &Json) -> Json {
        <Self as WalletHandler>::on_adjustment(self, req)
    }
}

fn extract_trace_hint(raw_body: &[u8]) -> String {
    let head = &raw_body[..raw_body.len().min(1024)];
    let Ok(s) = std::str::from_utf8(head) else {
        return String::new();
    };
    let Some(idx) = s.find("\"traceId\"") else {
        return String::new();
    };
    let rest = &s[idx + 9..];
    let Some(colon) = rest.find(':') else {
        return String::new();
    };
    let after_colon = rest[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return String::new();
    }
    let val_rest = &after_colon[1..];
    let Some(end_q) = val_rest.find('"') else {
        return String::new();
    };
    let candidate = &val_rest[..end_q];
    if candidate.len() <= 128
        && candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        candidate.to_string()
    } else {
        String::new()
    }
}

pub struct WebhookDispatcher<'a> {
    api_key: String,
    hmac_secret: String,
    wallet: &'a dyn WalletHandler,
}

impl<'a> WebhookDispatcher<'a> {
    pub fn new(config: &Config, wallet: &'a dyn WalletHandler) -> Self {
        Self {
            api_key: config.api_key.trim().to_string(),
            hmac_secret: config.hmac_secret.clone(),
            wallet,
        }
    }

    pub fn try_new(config: &Config, wallet: &'a dyn WalletHandler) -> Result<Self, SdkError> {
        if config.api_key.trim().is_empty() {
            return Err(SdkError::Config("api_key is required".into()));
        }
        if config.hmac_secret.is_empty() {
            return Err(SdkError::Config("hmac_secret is required".into()));
        }
        Ok(Self::new(config, wallet))
    }

    pub fn handle(&self, route_path: &str, api_key_header: &str, signature_header: &str, raw_body: &[u8]) -> Json {
        if raw_body.len() > MAX_WEBHOOK_BODY_BYTES {
            return InMemoryWallet::err_env("", status_code::SC_INVALID_REQUEST, "Request body exceeds 1 MiB limit");
        }

        // Verify X-API-Key & X-Signature over raw bytes BEFORE JSON parsing!
        let auth = verify_webhook_headers(api_key_header, signature_header, raw_body, &self.api_key, &self.hmac_secret);
        if auth != status_code::SC_OK {
            return InMemoryWallet::err_env(&extract_trace_hint(raw_body), auth, "Auth/signature failed");
        }

        let Some(body_obj) = std::str::from_utf8(raw_body)
            .ok()
            .and_then(|s| Json::parse(s).ok())
            .filter(Json::is_object)
        else {
            return InMemoryWallet::err_env("", status_code::SC_INVALID_REQUEST, "Invalid JSON object");
        };
        let trace_id: String = body_obj
            .get("traceId")
            .as_str()
            .map(str::trim)
            .unwrap_or("")
            .chars()
            .take(128)
            .collect();

        let clean = route_path.split('?').next().unwrap_or("").trim_end_matches('/');
        if clean.ends_with("/wallet/balance") {
            self.wallet.on_balance(&body_obj)
        } else if clean.ends_with("/wallet/bet") {
            self.wallet.on_bet(&body_obj)
        } else if clean.ends_with("/wallet/bet_result") {
            self.wallet.on_bet_result(&body_obj)
        } else if clean.ends_with("/wallet/rollback") {
            self.wallet.on_rollback(&body_obj)
        } else if clean.ends_with("/wallet/adjustment") {
            self.wallet.on_adjustment(&body_obj)
        } else {
            InMemoryWallet::err_env(&trace_id, status_code::SC_INVALID_REQUEST, "Unknown route")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    fn load_vectors() -> Json {
        let raw = std::fs::read_to_string("../test-vectors.json").expect("read ../test-vectors.json");
        Json::parse(&raw).expect("parse test-vectors.json")
    }

    #[test]
    fn cross_language_golden_vectors() {
        let doc = load_vectors();

        for v in doc.get("hmacVectors").as_array().unwrap() {
            let name = v.get("name").as_str().unwrap();
            let raw = v.get("rawBody").as_str().unwrap();
            let sec = v.get("secret").as_str().unwrap();
            let sig = v.get("signature").as_str().unwrap();
            assert_eq!(raw.len() as i64, v.get("utf8ByteLength").as_i64().unwrap(), "{}:len", name);
            assert_eq!(sign_body(raw.as_bytes(), sec).unwrap(), sig, "{}:sign", name);
            assert!(verify_signature(raw.as_bytes(), sig, sec), "{}:verify", name);
            if v.contains("wrongBase64DecodedSignature") {
                let wrong = v.get("wrongBase64DecodedSignature").as_str().unwrap();
                assert!(!verify_signature(raw.as_bytes(), wrong, sec), "{}:wrongB64", name);
            }
        }

        for h in doc.get("headerVerificationVectors").as_array().unwrap() {
            let got = verify_webhook_headers(
                h.get("apiKeyHeader").as_str().unwrap(),
                h.get("signatureHeader").as_str().unwrap(),
                h.get("rawBody").as_str().unwrap().as_bytes(),
                h.get("expectedApiKey").as_str().unwrap(),
                h.get("hmacSecret").as_str().unwrap(),
            );
            assert_eq!(got, h.get("expectedStatus").as_str().unwrap());
        }

        let idem = doc.get("idempotencyVectors");
        let bet = idem.get("bet");
        assert_eq!(bet_fingerprint(bet.get("initial")), bet.get("expectedFingerprint").as_str().unwrap());
        assert_eq!(bet_fingerprint(bet.get("retrySameBusiness")), bet.get("expectedFingerprint").as_str().unwrap());
        assert_eq!(bet_fingerprint(bet.get("conflictDifferentAmount")), bet.get("conflictFingerprint").as_str().unwrap());

        let stl = idem.get("betResult");
        assert_eq!(bet_result_fingerprint(stl.get("initial")), stl.get("expectedFingerprint").as_str().unwrap());
        assert_eq!(bet_result_fingerprint(stl.get("retrySameBusiness")), stl.get("expectedFingerprint").as_str().unwrap());
        assert_eq!(bet_result_fingerprint(stl.get("conflictDifferentWinAmount")), stl.get("conflictFingerprint").as_str().unwrap());

        let rb = idem.get("rollback");
        assert_eq!(rollback_fingerprint(rb.get("initial")), rb.get("expectedFingerprint").as_str().unwrap());
        assert_eq!(rollback_fingerprint(rb.get("retrySameBusiness")), rb.get("expectedFingerprint").as_str().unwrap());
        assert_eq!(rollback_fingerprint(rb.get("conflictDifferentAmount")), rb.get("conflictFingerprint").as_str().unwrap());

        let adj = idem.get("adjustment");
        assert_eq!(adjustment_fingerprint(adj.get("initial")), adj.get("expectedFingerprint").as_str().unwrap());
        assert_eq!(adjustment_fingerprint(adj.get("retrySameBusiness")), adj.get("expectedFingerprint").as_str().unwrap());
        assert_eq!(adjustment_fingerprint(adj.get("conflictDifferentDirection")), adj.get("conflictFingerprint").as_str().unwrap());

        for m in doc.get("moneyVectors").get("valid").as_array().unwrap() {
            let exp = m.get("displayExponent").as_i64().unwrap() as i32;
            let units = decimal_to_ledger_units(
                m.get("raw").as_str().unwrap(),
                exp,
                m.get("allowNegative").as_bool().unwrap(),
            )
            .unwrap();
            assert_eq!(units.to_string(), m.get("expectedUnits").as_str().unwrap());
            assert_eq!(
                ledger_units_to_decimal(units, exp).unwrap(),
                m.get("expectedFormatted").as_str().unwrap()
            );
        }
        for inv in doc.get("moneyVectors").get("invalid").as_array().unwrap() {
            assert!(
                decimal_to_ledger_units(
                    inv.get("raw").as_str().unwrap(),
                    inv.get("displayExponent").as_i64().unwrap() as i32,
                    inv.get("allowNegative").as_bool().unwrap()
                )
                .is_err(),
                "expected {} to fail",
                inv.get("name").as_str().unwrap()
            );
        }
        for sc in doc.get("statusCodes").as_array().unwrap() {
            assert_eq!(
                is_retryable_status(sc.get("code").as_str().unwrap()),
                sc.get("retryable").as_bool().unwrap()
            );
        }
    }

    #[test]
    fn s2s_libcurl_loopback_and_webhook_lifecycle() {
        let doc = load_vectors();
        let api_key = "ak_0123456789abcdef0123456789abcdef";
        let secret = "dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        let srv_handle = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(mut s) = stream else { break };
                let mut req_buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let mut header_end = None;
                let mut content_len = 0usize;
                loop {
                    let n = s.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    req_buf.extend_from_slice(&tmp[..n]);
                    if header_end.is_none() {
                        if let Some(idx) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(idx);
                            let head_str = String::from_utf8_lossy(&req_buf[..idx]);
                            for line in head_str.lines() {
                                if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                                    content_len = rest.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                    if let Some(idx) = header_end {
                        if req_buf.len() >= idx + 4 + content_len {
                            break;
                        }
                    }
                }
                let Some(idx) = header_end else { continue };
                let head_str = String::from_utf8_lossy(&req_buf[..idx]);
                let raw_body = &req_buf[idx + 4..idx + 4 + content_len];
                let mut lines = head_str.lines();
                let first_line = lines.next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("");
                let mut x_key = "";
                let mut x_sig = "";
                for line in lines {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("x-api-key") {
                            x_key = v;
                        } else if k.eq_ignore_ascii_case("x-signature") {
                            x_sig = v;
                        }
                    }
                }

                let st = verify_webhook_headers(x_key, x_sig, raw_body, api_key, secret);
                let body = Json::parse(&String::from_utf8_lossy(raw_body)).unwrap();
                let mut resp = Json::object();
                resp.set("traceId", body.get("traceId").clone());
                let mut status_line = "200 OK";
                if st != status_code::SC_OK {
                    resp.set("status", Json::Str(st.into()));
                    resp.set("message", Json::Str("bad auth".into()));
                } else {
                    resp.set("status", Json::Str("SC_OK".into()));
                    match path {
                        "/operator/v1/game/tables" => {
                            let mut t = Json::object();
                            t.set("tableId", Json::Str("T-A2".into()));
                            t.set("currency", Json::Str("USD".into()));
                            let mut data = Json::object();
                            data.set("tables", Json::Arr(vec![t]));
                            data.set("pageNo", Json::Int(1));
                            data.set("pageSize", Json::Int(50));
                            data.set("total", Json::Int(1));
                            resp.set("data", data);
                        }
                        "/operator/v1/game/url" => {
                            if body.get("currency").as_str() != Some("USD") {
                                resp.set("status", Json::Str("SC_WRONG_CURRENCY".into()));
                                resp.set("message", Json::Str("USD required".into()));
                            } else {
                                let tok = format!("b2bt_{}", "a".repeat(48));
                                let mut data = Json::object();
                                data.set("gameUrl", Json::Str(format!("https://play.lt.cniia.cloud/?token={}", tok)));
                                data.set("token", Json::Str(tok));
                                resp.set("data", data);
                            }
                        }
                        "/operator/v1/game/terminate" => {
                            let mut data = Json::object();
                            data.set("username", body.get("username").clone());
                            data.set("terminatedSessions", Json::Int(1));
                            data.set("revokedLaunchTokens", Json::Int(0));
                            resp.set("data", data);
                        }
                        "/operator/v1/player/status" => {
                            if body.get("username").as_str() == Some("locked_user") {
                                status_line = "403 Forbidden";
                                resp.set("status", Json::Str("SC_USER_DISABLED".into()));
                                resp.set("message", Json::Str("PLATFORM_RISK_LOCKED".into()));
                            } else if body.get("username").as_str() == Some("capped_user")
                                && body.get("bettingEnabled").as_bool() == Some(true)
                                && body.get("resetPnlWindow").as_bool() != Some(true)
                            {
                                status_line = "409 Conflict";
                                resp.set("status", Json::Str("SC_INVALID_REQUEST".into()));
                                resp.set("message", Json::Str("PNL_CAP_BREACHED_RESET_REQUIRED".into()));
                            } else {
                                let mut data = Json::object();
                                data.set("username", body.get("username").clone());
                                data.set("status", Json::Str("ACTIVE".into()));
                                data.set("bettingEnabled", Json::Bool(true));
                                data.set("rgRestricted", Json::Bool(false));
                                data.set("revokedSessions", Json::Int(0));
                                data.set("revokedLaunchTokens", Json::Int(0));
                                resp.set("data", data);
                            }
                        }
                        "/operator/v1/wallet/transaction-status" => {
                            let mut row = Json::object();
                            row.set("transactionId", Json::Str("bet_rs_1".into()));
                            row.set("username", body.get("username").clone());
                            row.set("status", Json::Str("COMPLETED".into()));
                            let mut data = Json::object();
                            data.set("transactions", Json::Arr(vec![row]));
                            resp.set("data", data);
                        }
                        "/operator/v1/transaction/list" => {
                            let pno = body.get("pageNo").as_i64().unwrap_or(1);
                            let mut r1 = Json::object();
                            r1.set("betId", Json::Str("b2btkt1".into()));
                            let mut r2 = Json::object();
                            r2.set("betId", Json::Str("b2btkt2".into()));
                            let mut r3 = Json::object();
                            r3.set("betId", Json::Str("b2btkt3".into()));
                            let mut data = Json::object();
                            data.set("transactions", Json::Arr(if pno == 1 { vec![r1, r2] } else { vec![r3] }));
                            data.set("pageNo", Json::Int(pno));
                            data.set("pageSize", Json::Int(2));
                            data.set("total", Json::Int(3));
                            resp.set("data", data);
                        }
                        _ => {
                            let mut rr = Json::object();
                            rr.set("outcome", Json::Str("PLAYER".into()));
                            rr.set("playerPoints", Json::Int(9));
                            rr.set("bankerPoints", Json::Int(1));
                            let mut data = Json::object();
                            data.set("betId", body.get("betId").clone());
                            data.set("status", Json::Int(1));
                            data.set("roundResult", rr);
                            resp.set("data", data);
                        }
                    }
                }
                let out_str = resp.dump();
                let http_msg = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    status_line,
                    out_str.len(),
                    out_str
                );
                let _ = s.write_all(http_msg.as_bytes());
            }
        });

        let cfg = Config {
            api_key: api_key.into(),
            hmac_secret: secret.into(),
            environment: Environment::Production,
            base_url: Some(format!("http://127.0.0.1:{}", port)),
            timeout_ms: 5000,
        };
        let client = Client::new(cfg.clone()).unwrap();

        let mut tbl_p = Json::object();
        tbl_p.set("currency", Json::Str("USD".into()));
        let tbl = client.list_tables(tbl_p).unwrap();
        assert_eq!(
            tbl.get("data").get("tables").as_array().unwrap()[0].get("tableId").as_str(),
            Some("T-A2")
        );

        let mut url_p = Json::object();
        url_p.set("username", Json::Str("player_9527".into()));
        url_p.set("tableId", Json::Str("T-A2".into()));
        url_p.set("platform", Json::Str("H5".into()));
        url_p.set("currency", Json::Str("USD".into()));
        url_p.set("lobbyUrl", Json::Str("https://merchant.example.com/lobby".into()));
        url_p.set("ipAddress", Json::Str("203.0.113.42".into()));
        let launch = client.create_game_url(url_p.clone()).unwrap();
        assert!(launch.get("data").get("token").as_str().unwrap().starts_with("b2bt_"));

        url_p.set("currency", Json::Str("JPY".into()));
        let err = client.create_game_url(url_p).unwrap_err();
        assert!(matches!(err, SdkError::Api { ref status, .. } if status == "SC_WRONG_CURRENCY"));
        assert!(!err.is_retryable());

        assert_eq!(client.list_all_transactions(1000, 2000, 2).unwrap().len(), 3);

        let mut det_p = Json::object();
        det_p.set("betId", Json::Str("b2btkt1".into()));
        det_p.set("fromTime", Json::Int(1000));
        det_p.set("toTime", Json::Int(2000));
        let det = client.get_transaction_detail(det_p).unwrap();
        assert_eq!(det.get("data").get("roundResult").get("outcome").as_str(), Some("PLAYER"));

        let mut ps_ok_p = Json::object();
        ps_ok_p.set("username", Json::Str("capped_user".into()));
        ps_ok_p.set("action", Json::Str("SET".into()));
        ps_ok_p.set("bettingEnabled", Json::Bool(true));
        ps_ok_p.set("resetPnlWindow", Json::Bool(true));
        let ps_ok = client.update_player_status(ps_ok_p).unwrap();
        assert_eq!(ps_ok.get("data").get("bettingEnabled").as_bool(), Some(true));

        let mut ps_403 = Json::object();
        ps_403.set("username", Json::Str("locked_user".into()));
        ps_403.set("action", Json::Str("SET".into()));
        ps_403.set("status", Json::Str("ACTIVE".into()));
        let err_403 = client.update_player_status(ps_403).unwrap_err();
        assert!(matches!(err_403, SdkError::Api { http_status: 403, ref status, ref message, .. } if status == "SC_USER_DISABLED" && message == "PLATFORM_RISK_LOCKED"));
        assert!(!err_403.is_retryable());

        let mut ps_409 = Json::object();
        ps_409.set("username", Json::Str("capped_user".into()));
        ps_409.set("action", Json::Str("SET".into()));
        ps_409.set("bettingEnabled", Json::Bool(true));
        let err_409 = client.update_player_status(ps_409).unwrap_err();
        assert!(matches!(err_409, SdkError::Api { http_status: 409, ref status, ref message, .. } if status == "SC_INVALID_REQUEST" && message == "PNL_CAP_BREACHED_RESET_REQUIRED"));
        assert!(!err_409.is_retryable());

        let mut wts_p = Json::object();
        wts_p.set("username", Json::Str("player_9527".into()));
        wts_p.set("fromTime", Json::Int(0));
        wts_p.set("toTime", Json::Int(86_400_000));
        let wts = client.get_wallet_transaction_status(wts_p).unwrap();
        assert_eq!(wts.get("data").get("transactions").as_array().unwrap()[0].get("username").as_str(), Some("player_9527"));

        assert!(matches!(client.get_wallet_transaction_status(Json::object()), Err(SdkError::Argument(_))));
        let mut wts_user_no_win = Json::object();
        wts_user_no_win.set("username", Json::Str("player_9527".into()));
        assert!(matches!(client.get_wallet_transaction_status(wts_user_no_win), Err(SdkError::Argument(_))));
        let mut wts_over24 = Json::object();
        wts_over24.set("username", Json::Str("player_9527".into()));
        wts_over24.set("fromTime", Json::Int(0));
        wts_over24.set("toTime", Json::Int(86_400_001));
        assert!(matches!(client.get_wallet_transaction_status(wts_over24), Err(SdkError::Argument(_))));
        let mut wts_partial = Json::object();
        wts_partial.set("transactionId", Json::Str("bet_1".into()));
        wts_partial.set("fromTime", Json::Int(1000));
        assert!(matches!(client.get_wallet_transaction_status(wts_partial), Err(SdkError::Argument(_))));
        let mut wts_inv = Json::object();
        wts_inv.set("betId", Json::Str("b2btkt1".into()));
        wts_inv.set("fromTime", Json::Int(2000));
        wts_inv.set("toTime", Json::Int(1000));
        assert!(matches!(client.get_wallet_transaction_status(wts_inv), Err(SdkError::Argument(_))));
        let mut wts_null = Json::object();
        wts_null.set("transactionId", Json::Str("bet_1".into()));
        wts_null.set("fromTime", Json::Null);
        assert!(matches!(client.get_wallet_transaction_status(wts_null), Err(SdkError::Argument(_))));
        let mut un_null = Json::object();
        un_null.set("fromTime", Json::Null);
        assert!(matches!(client.list_unsettled_transactions(un_null), Err(SdkError::Argument(_))));

        stop.store(true, Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        let _ = srv_handle.join();

        // WebhookDispatcher + InMemoryWallet lifecycle + CR-01..CR-10 adversarial checks
        let tok = "b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819";
        let wallet = InMemoryWallet::new();
        wallet.add_account("player_9527", "USD", "1000.00", 2, &[tok]).unwrap();
        let disp = WebhookDispatcher::try_new(&cfg, &wallet).unwrap();
        let send = |route: &str, p: &Json| -> Json {
            let raw = p.dump();
            disp.handle(route, api_key, &sign_body(raw.as_bytes(), secret).unwrap(), raw.as_bytes())
        };

        let mut bal_p = Json::object();
        bal_p.set("traceId", Json::Str("t1".into()));
        bal_p.set("username", Json::Str("player_9527".into()));
        bal_p.set("currency", Json::Str("USD".into()));
        bal_p.set("token", Json::Str(tok.into()));
        assert_eq!(send("/wallet/balance", &bal_p).get("data").get("balance").as_str(), Some("1000.00"));

        let idem = doc.get("idempotencyVectors");
        assert_eq!(send("/wallet/bet", idem.get("bet").get("initial")).get("data").get("balance").as_str(), Some("900.00"));
        assert_eq!(send("/wallet/bet", idem.get("bet").get("retrySameBusiness")).get("data").get("balance").as_str(), Some("900.00"));
        assert_eq!(send("/wallet/bet", idem.get("bet").get("conflictDifferentAmount")).get("status").as_str(), Some("SC_TRANSACTION_DUPLICATED"));

        wallet.set_disabled("player_9527", true);
        assert_eq!(send("/wallet/bet_result", idem.get("betResult").get("initial")).get("data").get("balance").as_str(), Some("1100.00"));
        assert_eq!(send("/wallet/adjustment", idem.get("adjustment").get("initial")).get("data").get("balance").as_str(), Some("1120.00"));
        assert_eq!(send("/wallet/adjustment", idem.get("adjustment").get("retrySameBusiness")).get("data").get("balance").as_str(), Some("1120.00"));
        assert_eq!(send("/wallet/adjustment", idem.get("adjustment").get("conflictDifferentDirection")).get("status").as_str(), Some("SC_TRANSACTION_DUPLICATED"));
        let mut debit_adj = idem.get("adjustment").get("initial").clone();
        debit_adj.set("transactionId", Json::Str("adj_debit_rs".into()));
        debit_adj.set("direction", Json::Str("DEBIT".into()));
        assert_eq!(send("/wallet/adjustment", &debit_adj).get("data").get("balance").as_str(), Some("1100.00"));

        // CR-03: Rollback after already-settled betId rejected!
        assert_eq!(send("/wallet/rollback", idem.get("rollback").get("initial")).get("status").as_str(), Some("SC_TRANSACTION_DUPLICATED"));

        let mut unknown_rb = idem.get("rollback").get("initial").clone();
        unknown_rb.set("transactionId", Json::Str("rb_b2btkt000000000000000000000000".into()));
        unknown_rb.set("betId", Json::Str("b2btkt000000000000000000000000".into()));
        unknown_rb.set("externalTransactionId", Json::Str("b2btkt000000000000000000000000".into()));
        assert_eq!(send("/wallet/rollback", &unknown_rb).get("status").as_str(), Some("SC_TRANSACTION_NOT_EXISTS"));

        // CR-01 & CR-07: Pre-auth deep nesting rejected; signed >64 depth rejected; bad surrogate \uD83D\u0041 does NOT underflow/panic!
        assert_eq!(
            disp.handle("/wallet/bet", "bad", "bad", "[".repeat(50_000).as_bytes()).get("status").as_str(),
            Some("SC_AUTHENTICATION_FAILED")
        );
        let deep_signed = format!("{{\"a\":{}{}}}", "[".repeat(80), "]".repeat(80));
        assert_eq!(
            disp.handle("/wallet/bet", api_key, &sign_body(deep_signed.as_bytes(), secret).unwrap(), deep_signed.as_bytes())
                .get("status")
                .as_str(),
            Some("SC_INVALID_REQUEST")
        );
        assert!(Json::parse("{\"bad\":\"\\uD83D\\u0041\"}").is_err());
        assert_eq!(Json::parse("{\"ok\":\"\\uD83C\\uDFB2\"}").unwrap().get("ok").as_str(), Some("🎲"));
    }
}
