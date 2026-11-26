# SPDX-License-Identifier: MIT
"""Zero-dependency Python 3 SDK for Baccarat Live Platform B2B Operator Seamless Wallet API (v1.5.5)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, Union

SANDBOX_BASE_URL = "https://api.lt.cniia.cloud"
MAX_DETAIL_WINDOW_MS = 604_800_000  # 7 days in ms
MAX_PAGE_SIZE = 20_000
MAX_WEBHOOK_BODY_BYTES = 1_048_576  # 1 MiB
MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024  # 16 MiB
LEDGER_SCALE = 1000

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DECIMAL_RE = re.compile(r"^(-?)(\d+)(?:\.(\d+))?$")
_TRACE_HINT_RE = re.compile(rb'"traceId"\s*:\s*"([A-Za-z0-9_.:-]{1,128})"')


class _UnsetType:
    def __repr__(self) -> str:
        return "UNSET"


UNSET: Any = _UnsetType()


class Environment:
    SANDBOX = "SANDBOX"
    PRODUCTION = "PRODUCTION"


class StatusCode:
    SC_OK = "SC_OK"
    SC_INVALID_REQUEST = "SC_INVALID_REQUEST"
    SC_AUTHENTICATION_FAILED = "SC_AUTHENTICATION_FAILED"
    SC_INVALID_SIGNATURE = "SC_INVALID_SIGNATURE"
    SC_INVALID_TOKEN = "SC_INVALID_TOKEN"
    SC_INVALID_GAME = "SC_INVALID_GAME"
    SC_USER_NOT_EXISTS = "SC_USER_NOT_EXISTS"
    SC_USER_DISABLED = "SC_USER_DISABLED"
    SC_WRONG_CURRENCY = "SC_WRONG_CURRENCY"
    SC_CURRENCY_NOT_SUPPORTED = "SC_CURRENCY_NOT_SUPPORTED"
    SC_INSUFFICIENT_FUNDS = "SC_INSUFFICIENT_FUNDS"
    SC_TRANSACTION_DUPLICATED = "SC_TRANSACTION_DUPLICATED"
    SC_TRANSACTION_NOT_EXISTS = "SC_TRANSACTION_NOT_EXISTS"
    SC_TRANSACTION_STILL_PROCESSING = "SC_TRANSACTION_STILL_PROCESSING"
    SC_OPERATOR_TIMEOUT = "SC_OPERATOR_TIMEOUT"
    SC_UNDER_MAINTENANCE = "SC_UNDER_MAINTENANCE"
    SC_GAME_DISABLED = "SC_GAME_DISABLED"
    SC_RATE_LIMITED = "SC_RATE_LIMITED"


_RETRYABLE_STATUSES = frozenset(
    {
        StatusCode.SC_TRANSACTION_STILL_PROCESSING,
        StatusCode.SC_OPERATOR_TIMEOUT,
        StatusCode.SC_RATE_LIMITED,
    }
)


def is_retryable_status(status: str) -> bool:
    return (status or "").strip() in _RETRYABLE_STATUSES


class BaccaratSdkError(Exception):
    def __init__(self, message: str, code: str = "SDK_ERROR") -> None:
        super().__init__(message)
        self.code = code


class BaccaratApiError(BaccaratSdkError):
    def __init__(
        self,
        status: str,
        message: str = "",
        trace_id: str = "",
        validation: Optional[Dict[str, str]] = None,
        http_status: int = 200,
    ) -> None:
        msg = message or f"B2B API error: {status}"
        super().__init__(msg, status)
        self.message = msg
        self.trace_id = trace_id
        self.status = status
        self.validation = validation
        self.http_status = http_status

    def is_retryable(self) -> bool:
        return is_retryable_status(self.status)


# ── 1. Raw-Byte HMAC-SHA256 Signing & Timing-Safe Verification ──────────────


def _to_utf8_bytes(raw: Union[bytes, bytearray, str]) -> bytes:
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, bytearray):
        return bytes(raw)
    return str(raw).encode("utf-8")


def sign_body(raw_body: Union[bytes, bytearray, str], hmac_secret: str) -> str:
    if not isinstance(hmac_secret, str) or len(hmac_secret) == 0:
        raise BaccaratSdkError("hmac_secret must be a non-empty string", "INVALID_CONFIG")
    # CRITICAL: Use raw UTF-8 bytes of hmac_secret string directly — NEVER Base64-decode!
    return hmac.new(hmac_secret.encode("utf-8"), _to_utf8_bytes(raw_body), hashlib.sha256).hexdigest()


def verify_signature(
    raw_body: Union[bytes, bytearray, str],
    signature_header: Optional[str],
    hmac_secret: str,
) -> bool:
    if not isinstance(hmac_secret, str) or not hmac_secret or not isinstance(signature_header, str):
        return False
    trimmed = signature_header.strip()
    if not _HEX64_RE.match(trimmed):
        return False
    expected_bytes = bytes.fromhex(sign_body(raw_body, hmac_secret))
    actual_bytes = bytes.fromhex(trimmed.lower())
    return hmac.compare_digest(actual_bytes, expected_bytes)


def verify_webhook_headers(
    api_key_header: Optional[str],
    signature_header: Optional[str],
    raw_body: Union[bytes, bytearray, str],
    expected_api_key: str,
    hmac_secret: str,
) -> str:
    expected_key = (expected_api_key or "").strip()
    actual_key = api_key_header.strip() if isinstance(api_key_header, str) else ""
    if not expected_key or not actual_key or not hmac.compare_digest(
        actual_key.encode("utf-8"), expected_key.encode("utf-8")
    ):
        return StatusCode.SC_AUTHENTICATION_FAILED
    if not verify_signature(raw_body, signature_header, hmac_secret):
        return StatusCode.SC_INVALID_SIGNATURE
    return StatusCode.SC_OK


# ── 2. Exact Decimal & Ledger Unit Utilities (Arbitrary-Precision Python int) ──


def decimal_to_ledger_units(
    raw: Union[str, int],
    display_exponent: int,
    allow_negative: bool = False,
) -> int:
    if isinstance(display_exponent, bool) or not isinstance(display_exponent, int) or not (0 <= display_exponent <= 18):
        raise BaccaratSdkError(f"display_exponent out of range: {display_exponent}", "INVALID_DISPLAY_EXPONENT")
    if isinstance(raw, bool):
        raise BaccaratSdkError("boolean is not a decimal amount", "INVALID_DECIMAL_AMOUNT")
    text = str(raw).strip() if isinstance(raw, (str, int)) else ""
    m = _DECIMAL_RE.match(text)
    if not m:
        raise BaccaratSdkError(f"malformed decimal amount: {raw}", "INVALID_DECIMAL_AMOUNT")
    negative = m.group(1) == "-"
    whole_part = m.group(2)
    raw_frac = m.group(3) or ""
    scale_digits = display_exponent + 3
    trimmed_frac = raw_frac.rstrip("0")
    if len(trimmed_frac) > scale_digits:
        raise BaccaratSdkError(
            f"decimal amount {text} exceeds max precision ({scale_digits} decimals)",
            "DECIMAL_PRECISION_EXCEEDED",
        )
    divisor = LEDGER_SCALE * (10**display_exponent)
    frac_padded = trimmed_frac.ljust(scale_digits, "0")
    abs_val = int(whole_part) * divisor + (int(frac_padded) if frac_padded else 0)
    if negative and abs_val > 0:
        if not allow_negative:
            raise BaccaratSdkError(f"negative decimal amount forbidden: {text}", "NEGATIVE_DECIMAL_FORBIDDEN")
        return -abs_val
    return abs_val


def ledger_units_to_decimal(amount: int, display_exponent: int) -> str:
    if isinstance(display_exponent, bool) or not isinstance(display_exponent, int) or not (0 <= display_exponent <= 18):
        raise BaccaratSdkError(f"display_exponent out of range: {display_exponent}", "INVALID_DISPLAY_EXPONENT")
    negative = amount < 0
    abs_val = -amount if negative else amount
    divisor = LEDGER_SCALE * (10**display_exponent)
    whole, frac = divmod(abs_val, divisor)
    sign = "-" if negative else ""
    if display_exponent == 0:
        sub = "" if frac == 0 else "." + f"{frac:03d}".rstrip("0")
        return f"{sign}{whole}{sub}"
    frac_str = f"{frac:0{display_exponent + 3}d}"
    shown = frac_str[:display_exponent]
    sub = frac_str[display_exponent:].rstrip("0")
    return f"{sign}{whole}.{shown}{sub}"


# ── 3. Canonical Idempotency Fingerprints ───────────────────────────────────


def encode_tuple_fingerprint(domain: str, fields: List[Any]) -> str:
    parts = [f"v1|{domain}"]
    for val in fields:
        s = "" if val is None else str(val)
        byte_len = len(s.encode("utf-8"))
        parts.append(f"{byte_len}:{s}")
    canonical = "|".join(parts)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def bet_fingerprint(payload: Dict[str, Any]) -> str:
    return encode_tuple_fingerprint(
        "wallet/bet",
        [
            payload.get("transactionId", ""),
            payload.get("username", ""),
            payload.get("betId", ""),
            payload.get("externalTransactionId", ""),
            payload.get("roundId", ""),
            payload.get("currency", ""),
            payload.get("gameCode", ""),
            payload.get("amount", ""),
        ],
    )


def bet_result_fingerprint(payload: Dict[str, Any]) -> str:
    return encode_tuple_fingerprint(
        "wallet/bet_result",
        [
            payload.get("transactionId", ""),
            payload.get("username", ""),
            payload.get("betId", ""),
            payload.get("externalTransactionId", ""),
            payload.get("roundId", ""),
            payload.get("currency", ""),
            payload.get("gameCode", ""),
            payload.get("betAmount", ""),
            payload.get("winAmount", ""),
            payload.get("effectiveTurnover", ""),
            payload.get("winLoss", ""),
            payload.get("jackpotAmount", ""),
            payload.get("resultType", ""),
            "" if payload.get("isFreespin") is None else str(payload.get("isFreespin")),
            "" if payload.get("isEndRound") is None else str(payload.get("isEndRound")),
            "" if payload.get("betTime") is None else str(payload.get("betTime")),
        ],
    )


def rollback_fingerprint(payload: Dict[str, Any]) -> str:
    return encode_tuple_fingerprint(
        "wallet/rollback",
        [
            payload.get("transactionId", ""),
            payload.get("username", ""),
            payload.get("betId", ""),
            payload.get("externalTransactionId", ""),
            payload.get("roundId", ""),
            payload.get("currency", ""),
            payload.get("gameCode", ""),
            payload.get("amount", ""),
        ],
    )


def adjustment_fingerprint(payload: Dict[str, Any]) -> str:
    return encode_tuple_fingerprint(
        "wallet/adjustment",
        [
            payload.get("transactionId", ""),
            payload.get("username", ""),
            payload.get("betId", ""),
            payload.get("externalTransactionId", ""),
            payload.get("roundId", ""),
            payload.get("currency", ""),
            payload.get("gameCode", ""),
            payload.get("direction", ""),
            payload.get("amount", ""),
            payload.get("reasonCode", ""),
        ],
    )


# ── 4. Configuration & S2S Client (/operator/v1/*) ──────────────────────────


@dataclass(frozen=True)
class Config:
    api_key: str
    hmac_secret: str
    environment: str = Environment.PRODUCTION
    base_url: Optional[str] = None
    timeout_ms: int = 8000
    send_timestamp: bool = False
    resolved_base_url: str = field(init=False)

    def __post_init__(self) -> None:
        trimmed_key = (self.api_key or "").strip() if isinstance(self.api_key, str) else ""
        if not trimmed_key:
            raise BaccaratSdkError("api_key is required", "INVALID_CONFIG")
        if not isinstance(self.hmac_secret, str) or not self.hmac_secret:
            raise BaccaratSdkError("hmac_secret is required", "INVALID_CONFIG")
        raw_url = (self.base_url or "").strip() if isinstance(self.base_url, str) else ""
        if not raw_url:
            if self.environment == Environment.SANDBOX:
                raw_url = SANDBOX_BASE_URL
            else:
                raise BaccaratSdkError(
                    "base_url is required when environment is PRODUCTION",
                    "INVALID_CONFIG",
                )
        if not raw_url.lower().startswith(("http://", "https://")):
            raise BaccaratSdkError(f"base_url must start with http:// or https://: {raw_url}", "INVALID_CONFIG")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int) or self.timeout_ms <= 0:
            raise BaccaratSdkError("timeout_ms must be a positive integer", "INVALID_CONFIG")
        object.__setattr__(self, "api_key", trimmed_key)
        object.__setattr__(self, "resolved_base_url", raw_url.rstrip("/"))


TransportFn = Callable[[str, Dict[str, str], bytes, int], Tuple[int, str]]


def _fallback_status_for_http(http_status: int) -> str:
    if http_status == 429:
        return StatusCode.SC_RATE_LIMITED
    if http_status >= 500 or http_status == 408:
        return StatusCode.SC_OPERATOR_TIMEOUT
    return StatusCode.SC_INVALID_REQUEST


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _default_transport(url: str, headers: Dict[str, str], raw_body: bytes, timeout_ms: int) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=raw_body, headers=headers, method="POST")
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=timeout_ms / 1000.0) as resp:
            chunk = resp.read(MAX_HTTP_RESPONSE_BYTES + 1)
            if len(chunk) > MAX_HTTP_RESPONSE_BYTES:
                raise BaccaratApiError(
                    status=StatusCode.SC_INVALID_REQUEST,
                    message="Gateway response exceeded 16 MiB limit",
                    http_status=resp.status,
                )
            return resp.status, chunk.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        try:
            raw = err.read(MAX_HTTP_RESPONSE_BYTES + 1) if err.fp else b""
        except Exception as read_exc:
            raise BaccaratSdkError(
                f"Network error reading HTTP {err.code} body: {read_exc}",
                StatusCode.SC_OPERATOR_TIMEOUT,
            ) from read_exc
        finally:
            err.close()
        if len(raw) > MAX_HTTP_RESPONSE_BYTES:
            raise BaccaratApiError(
                status=StatusCode.SC_INVALID_REQUEST,
                message="Gateway response exceeded 16 MiB limit",
                http_status=err.code,
            )
        return err.code, raw.decode("utf-8", errors="replace")
    except BaccaratSdkError:
        raise
    except Exception as exc:
        raise BaccaratSdkError(f"Network error: {exc}", StatusCode.SC_OPERATOR_TIMEOUT) from exc


class Client:
    def __init__(self, config: Config, transport: TransportFn = _default_transport) -> None:
        self.config = config
        self._transport = transport

    def _post_signed(self, route_path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(payload)
        raw_trace = body.get("traceId")
        trace_id = (
            raw_trace.strip()
            if isinstance(raw_trace, str) and raw_trace.strip()
            else (str(raw_trace).strip() if raw_trace is not None and str(raw_trace).strip() else str(uuid.uuid4()))
        )
        body["traceId"] = trace_id

        raw_bytes = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        sig = sign_body(raw_bytes, self.config.hmac_secret)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": self.config.api_key,
            "X-Signature": sig,
        }
        if self.config.send_timestamp:
            headers["X-Timestamp"] = str(int(time.time() * 1000))
        try:
            http_status, resp_text = self._transport(
                f"{self.config.resolved_base_url}{route_path}",
                headers,
                raw_bytes,
                self.config.timeout_ms,
            )
        except BaccaratApiError as exc:
            if not exc.trace_id:
                exc.trace_id = trace_id
            raise
        try:
            parsed = json.loads(resp_text)
        except Exception as exc:
            raise BaccaratApiError(
                status=_fallback_status_for_http(http_status),
                message=f"Non-JSON HTTP {http_status}",
                trace_id=trace_id,
                http_status=http_status,
            ) from exc

        if not isinstance(parsed, dict):
            raise BaccaratApiError(
                status=_fallback_status_for_http(http_status),
                message="Malformed envelope",
                trace_id=trace_id,
                http_status=http_status,
            )

        raw_status = parsed.get("status")
        resp_status = raw_status.strip() if isinstance(raw_status, str) else ""
        if http_status != 200 or resp_status != StatusCode.SC_OK:
            raise BaccaratApiError(
                status=resp_status or _fallback_status_for_http(http_status),
                message=str(parsed.get("message") or f"HTTP {http_status}"),
                trace_id=str(parsed.get("traceId") or trace_id),
                validation=parsed.get("validation"),
                http_status=http_status,
            )
        return {
            "traceId": str(parsed.get("traceId") or trace_id),
            "status": StatusCode.SC_OK,
            "data": parsed.get("data"),
        }

    def ping(self, *, trace_id: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/ping", payload)

    def create_game_url(
        self,
        *,
        username: str,
        platform: str,
        currency: str,
        lobby_url: str,
        ip_address: str,
        table_id: Optional[str] = None,
        entry_mode: Optional[str] = None,
        language: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "username": username,
            "platform": platform,
            "currency": currency,
            "lobbyUrl": lobby_url,
            "ipAddress": ip_address,
        }
        if table_id is not None:
            payload["tableId"] = table_id
        if entry_mode is not None:
            payload["entryMode"] = entry_mode
        if language is not None:
            payload["language"] = language
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/game/url", payload)

    def list_tables(
        self,
        *,
        currency: Optional[str] = None,
        page_no: Optional[int] = None,
        page_size: Optional[int] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if currency is not None:
            payload["currency"] = currency
        if page_no is not None:
            payload["pageNo"] = page_no
        if page_size is not None:
            payload["pageSize"] = page_size
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/game/tables", payload)

    def terminate_sessions(
        self,
        *,
        username: Optional[str] = None,
        scope: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if username is not None:
            payload["username"] = username
        if scope is not None:
            payload["scope"] = scope
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/game/terminate", payload)

    def update_player_status(
        self,
        *,
        username: str,
        action: Optional[str] = None,
        status: Optional[str] = None,
        betting_enabled: Optional[bool] = None,
        reset_pnl_window: Optional[bool] = None,
        reason: Any = UNSET,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"username": username}
        if action is not None:
            payload["action"] = action
        if status is not None:
            payload["status"] = status
        if betting_enabled is not None:
            payload["bettingEnabled"] = betting_enabled
        if reset_pnl_window is not None:
            payload["resetPnlWindow"] = reset_pnl_window
        if reason is not UNSET:
            payload["reason"] = reason
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/player/status", payload)

    def update_player_limits(
        self,
        *,
        username: str,
        currency: str,
        action: Optional[str] = None,
        min_bet: Any = UNSET,
        max_bet: Any = UNSET,
        max_table_round: Any = UNSET,
        max_user_day: Any = UNSET,
        max_loss_per_day: Any = UNSET,
        custom_chips: Any = UNSET,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"username": username, "currency": currency}
        if action is not None:
            payload["action"] = action
        if min_bet is not UNSET:
            payload["minBet"] = min_bet
        if max_bet is not UNSET:
            payload["maxBet"] = max_bet
        if max_table_round is not UNSET:
            payload["maxTableRound"] = max_table_round
        if max_user_day is not UNSET:
            payload["maxUserDay"] = max_user_day
        if max_loss_per_day is not UNSET:
            payload["maxLossPerDay"] = max_loss_per_day
        if custom_chips is not UNSET:
            payload["customChips"] = custom_chips
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/player/limits", payload)

    def list_transactions(
        self,
        *,
        from_time: int,
        to_time: int,
        time_type: Optional[str] = None,
        status: Optional[Union[int, str]] = None,
        username: Optional[str] = None,
        table_id: Optional[str] = None,
        round_id: Optional[str] = None,
        page_no: Optional[int] = None,
        page_size: Optional[int] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if isinstance(from_time, bool) or isinstance(to_time, bool) or not isinstance(from_time, int) or not isinstance(to_time, int) or from_time < 0 or to_time < from_time:
            raise BaccaratSdkError("Invalid [from_time, to_time] window", "INVALID_ARGUMENT")
        payload: Dict[str, Any] = {"fromTime": from_time, "toTime": to_time}
        if time_type is not None:
            payload["timeType"] = time_type
        if status is not None:
            payload["status"] = status
        if username is not None:
            payload["username"] = username
        if table_id is not None:
            payload["tableId"] = table_id
        if round_id is not None:
            payload["roundId"] = round_id
        if page_no is not None:
            payload["pageNo"] = page_no
        if page_size is not None:
            payload["pageSize"] = page_size
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/transaction/list", payload)

    def list_all_transactions(
        self,
        *,
        from_time: int,
        to_time: int,
        page_size: int = 2000,
        time_type: Optional[str] = None,
        status: Optional[Union[int, str]] = None,
        username: Optional[str] = None,
        table_id: Optional[str] = None,
        round_id: Optional[str] = None,
        rate_limit_max_retries: int = 3,
        rate_limit_backoff_sec: float = 1.0,
    ) -> List[Dict[str, Any]]:
        if isinstance(page_size, bool) or not isinstance(page_size, int) or not (1 <= page_size <= MAX_PAGE_SIZE):
            raise BaccaratSdkError(f"page_size must be in 1..{MAX_PAGE_SIZE}", "INVALID_ARGUMENT")
        max_retries = rate_limit_max_retries if isinstance(rate_limit_max_retries, int) and rate_limit_max_retries >= 0 else 3
        backoff = rate_limit_backoff_sec if rate_limit_backoff_sec >= 0 else 1.0
        rows: List[Dict[str, Any]] = []
        page_no = 1
        while True:
            attempt = 0
            while True:
                try:
                    res = self.list_transactions(
                        from_time=from_time,
                        to_time=to_time,
                        time_type=time_type,
                        status=status,
                        username=username,
                        table_id=table_id,
                        round_id=round_id,
                        page_no=page_no,
                        page_size=page_size,
                    )
                    break
                except BaccaratApiError as exc:
                    if exc.status == StatusCode.SC_RATE_LIMITED and attempt < max_retries:
                        attempt += 1
                        wait_s = backoff * attempt
                        if wait_s > 0:
                            time.sleep(wait_s)
                        continue
                    raise
            data = res.get("data") or {}
            batch = data.get("transactions") or []
            rows.extend(batch)
            total = int(data.get("total") or len(rows))
            if len(rows) >= total or not batch:
                break
            page_no += 1
        return rows

    def get_transaction_detail(
        self,
        *,
        bet_id: str,
        from_time: Optional[int] = None,
        to_time: Optional[int] = None,
        language: Optional[str] = None,
        detail_url_ttl_sec: Optional[int] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not isinstance(bet_id, str) or not bet_id.strip():
            raise BaccaratSdkError("bet_id is required", "INVALID_ARGUMENT")
        payload: Dict[str, Any] = {"betId": bet_id}
        if from_time is not None or to_time is not None:
            if isinstance(from_time, bool) or isinstance(to_time, bool) or not isinstance(from_time, int) or not isinstance(to_time, int):
                raise BaccaratSdkError("from_time and to_time must both be ints when specified", "INVALID_ARGUMENT")
            span = to_time - from_time
            if from_time < 0 or span < 0 or span > MAX_DETAIL_WINDOW_MS:
                raise BaccaratSdkError("Detail query window must satisfy 0 <= to_time - from_time <= 604800000", "INVALID_ARGUMENT")
            payload["fromTime"] = from_time
            payload["toTime"] = to_time
        if language is not None:
            payload["language"] = language
        if detail_url_ttl_sec is not None:
            payload["detailUrlTtlSec"] = detail_url_ttl_sec
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/transaction/detail", payload)

    def list_unsettled_transactions(
        self,
        *,
        from_time: Optional[int] = None,
        to_time: Optional[int] = None,
        username: Optional[str] = None,
        table_id: Optional[str] = None,
        page_no: Optional[int] = None,
        page_size: Optional[int] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if from_time is not None or to_time is not None:
            if isinstance(from_time, bool) or isinstance(to_time, bool) or not isinstance(from_time, int) or not isinstance(to_time, int):
                raise BaccaratSdkError("from_time and to_time must both be ints when specified", "INVALID_ARGUMENT")
            span = to_time - from_time
            if from_time < 0 or span < 0 or span > MAX_DETAIL_WINDOW_MS:
                raise BaccaratSdkError("Unsettled query window must satisfy 0 <= to_time - from_time <= 604800000", "INVALID_ARGUMENT")
            payload["fromTime"] = from_time
            payload["toTime"] = to_time
        if username is not None:
            payload["username"] = username
        if table_id is not None:
            payload["tableId"] = table_id
        if page_no is not None:
            payload["pageNo"] = page_no
        if page_size is not None:
            payload["pageSize"] = page_size
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/transaction/unsettled", payload)

    def get_wallet_transaction_status(
        self,
        *,
        transaction_id: Optional[str] = None,
        bet_id: Optional[str] = None,
        username: Optional[str] = None,
        from_time: Optional[int] = None,
        to_time: Optional[int] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tx_s = (transaction_id or "").strip() if isinstance(transaction_id, str) else ""
        bet_s = (bet_id or "").strip() if isinstance(bet_id, str) else ""
        user_s = (username or "").strip() if isinstance(username, str) else ""
        if not tx_s and not bet_s and not user_s:
            raise BaccaratSdkError("At least one of transaction_id, bet_id, or username is required", "INVALID_ARGUMENT")
        payload: Dict[str, Any] = {}
        if tx_s:
            payload["transactionId"] = tx_s
        if bet_s:
            payload["betId"] = bet_s
        if user_s:
            payload["username"] = user_s
        user_only = bool(user_s and not tx_s and not bet_s)
        has_window = from_time is not None or to_time is not None
        if user_only or has_window:
            if isinstance(from_time, bool) or isinstance(to_time, bool) or not isinstance(from_time, int) or not isinstance(to_time, int):
                raise BaccaratSdkError("from_time and to_time must both be ints when querying by username alone or specifying a window", "INVALID_ARGUMENT")
            span = to_time - from_time
            if from_time < 0 or span < 0 or (user_only and span > 86_400_000):
                raise BaccaratSdkError(
                    "Username query window must satisfy 0 <= to_time - from_time <= 86400000 (24 hours)"
                    if user_only
                    else "Invalid [from_time, to_time] window",
                    "INVALID_ARGUMENT",
                )
            payload["fromTime"] = from_time
            payload["toTime"] = to_time
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/wallet/transaction-status", payload)


# ── 5. Seamless Wallet Webhook Dispatcher & Reference In-Memory Wallet ──────


def wallet_ok(
    trace_id: str,
    username: str,
    currency: str,
    balance: str,
    timestamp: Optional[int] = None,
) -> Dict[str, Any]:
    ts = int(time.time() * 1000) if timestamp is None else int(timestamp)
    return {
        "traceId": trace_id or "",
        "status": StatusCode.SC_OK,
        "data": {
            "username": username,
            "currency": currency,
            "balance": balance,
            "timestamp": ts,
        },
    }


def wallet_error(trace_id: str, status: str, message: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "traceId": trace_id or "",
        "status": status,
    }
    if message:
        out["message"] = message
    return out


class WalletHandler(Protocol):
    def on_balance(self, req: Dict[str, Any]) -> Dict[str, Any]: ...
    def on_bet(self, req: Dict[str, Any]) -> Dict[str, Any]: ...
    def on_bet_result(self, req: Dict[str, Any]) -> Dict[str, Any]: ...
    def on_rollback(self, req: Dict[str, Any]) -> Dict[str, Any]: ...
    def on_adjustment(self, req: Dict[str, Any]) -> Dict[str, Any]: ...


def _non_empty_str(val: Any) -> Optional[str]:
    if isinstance(val, str):
        s = val.strip()
        return s if s else None
    return None


class InMemoryWallet:
    def __init__(self, initial_accounts: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self._lock = threading.Lock()
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.transactions: Dict[str, Dict[str, Any]] = {}
        self.deducted_bets: Dict[str, Dict[str, Any]] = {}
        for username, info in (initial_accounts or {}).items():
            exponent = int(info.get("exponent", 2))
            self.accounts[username] = {
                "currency": str(info["currency"]).strip().upper(),
                "exponent": exponent,
                "balance_units": decimal_to_ledger_units(str(info.get("balance", "0.00")), exponent),
                "tokens": set(info.get("tokens") or []),
                "disabled": bool(info.get("disabled", False)),
            }

    def set_disabled(self, username: str, disabled: bool) -> None:
        with self._lock:
            if username in self.accounts:
                self.accounts[username]["disabled"] = disabled

    def _ok(self, trace_id: str, username: str, acct: Dict[str, Any]) -> Dict[str, Any]:
        return wallet_ok(
            trace_id,
            username,
            acct["currency"],
            ledger_units_to_decimal(acct["balance_units"], acct["exponent"]),
        )

    def _check_acct(self, username: str, currency: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        acct = self.accounts.get(username)
        if acct is None:
            return None, StatusCode.SC_USER_NOT_EXISTS
        if acct["currency"] != currency.strip().upper():
            return None, StatusCode.SC_WRONG_CURRENCY
        return acct, None

    def on_balance(self, req: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            return self._on_balance_unlocked(req)

    def _on_balance_unlocked(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = req.get("traceId") if isinstance(req.get("traceId"), str) else ""
        username = _non_empty_str(req.get("username"))
        currency = _non_empty_str(req.get("currency"))
        if not username or not currency:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "username and currency are required"}
        acct, err = self._check_acct(username, currency)
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        if acct["disabled"]:
            return {"traceId": trace_id, "status": StatusCode.SC_USER_DISABLED, "message": "User disabled"}
        if acct["tokens"] and req.get("token") not in acct["tokens"]:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_TOKEN, "message": "Invalid token"}
        return self._ok(trace_id, username, acct)

    def on_bet(self, req: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            return self._on_bet_unlocked(req)

    def _on_bet_unlocked(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = req.get("traceId") if isinstance(req.get("traceId"), str) else ""
        tx_id = _non_empty_str(req.get("transactionId"))
        bet_id = _non_empty_str(req.get("betId"))
        username = _non_empty_str(req.get("username"))
        currency = _non_empty_str(req.get("currency"))
        if not tx_id or not bet_id or not username or not currency or req.get("amount") is None:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Missing required bet fields"}
        acct, err = self._check_acct(username, currency)
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        fp = bet_fingerprint(req)
        prior = self.transactions.get(tx_id)
        if prior:
            if prior["type"] != "BET" or prior["fp"] != fp:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": "Conflicting bet payload"}
            return self._ok(trace_id, username, acct)
        if bet_id in self.deducted_bets:
            return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": "Duplicate betId"}
        if acct["disabled"]:
            return {"traceId": trace_id, "status": StatusCode.SC_USER_DISABLED, "message": "User disabled"}
        if acct["tokens"] and req.get("token") not in acct["tokens"]:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_TOKEN, "message": "Invalid token"}
        stake = decimal_to_ledger_units(req["amount"], acct["exponent"])
        if stake <= 0:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Bet amount must be positive"}
        if acct["balance_units"] < stake:
            return {"traceId": trace_id, "status": StatusCode.SC_INSUFFICIENT_FUNDS, "message": "Insufficient funds"}
        acct["balance_units"] -= stake
        self.transactions[tx_id] = {"type": "BET", "fp": fp, "empty": False}
        self.deducted_bets[bet_id] = {
            "tx_id": tx_id,
            "username": username,
            "currency": acct["currency"],
            "stake": stake,
            "state": "DEDUCTED",
        }
        return self._ok(trace_id, username, acct)

    def on_bet_result(self, req: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            return self._on_bet_result_unlocked(req)

    def _on_bet_result_unlocked(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = req.get("traceId") if isinstance(req.get("traceId"), str) else ""
        tx_id = _non_empty_str(req.get("transactionId"))
        bet_id = _non_empty_str(req.get("betId"))
        username = _non_empty_str(req.get("username"))
        currency = _non_empty_str(req.get("currency"))
        if not tx_id or not bet_id or not username or not currency or req.get("winAmount") is None or req.get("betAmount") is None:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Missing required bet_result fields"}
        acct, err = self._check_acct(username, currency)
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        fp = bet_result_fingerprint(req)
        prior = self.transactions.get(tx_id)
        if prior:
            if prior["type"] != "SETTLE" or prior["fp"] != fp:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": "Conflicting bet_result payload"}
            return self._ok(trace_id, username, acct)
        # Honor already-deducted betId even if player later logged out or was disabled
        orig = self.deducted_bets.get(bet_id)
        if orig is None:
            return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_NOT_EXISTS, "message": "Original betId not found"}
        bet_units = decimal_to_ledger_units(req["betAmount"], acct["exponent"])
        win_units = decimal_to_ledger_units(req["winAmount"], acct["exponent"])
        if orig["username"] != username or orig["currency"] != acct["currency"] or orig["stake"] != bet_units:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "bet_result does not match original bet"}
        if orig["state"] != "DEDUCTED":
            return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": f"betId already {orig['state']}"}
        acct["balance_units"] += win_units
        orig["state"] = "SETTLED"
        self.transactions[tx_id] = {"type": "SETTLE", "fp": fp, "empty": False}
        return self._ok(trace_id, username, acct)

    def on_rollback(self, req: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            return self._on_rollback_unlocked(req)

    def _on_rollback_unlocked(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = req.get("traceId") if isinstance(req.get("traceId"), str) else ""
        tx_id = _non_empty_str(req.get("transactionId"))
        bet_id = _non_empty_str(req.get("betId"))
        username = _non_empty_str(req.get("username"))
        currency = _non_empty_str(req.get("currency"))
        if not tx_id or not bet_id or not username or not currency or req.get("amount") is None:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Missing required rollback fields"}
        acct, err = self._check_acct(username, currency)
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        fp = rollback_fingerprint(req)
        prior = self.transactions.get(tx_id)
        if prior:
            if prior["type"] != "ROLLBACK" or prior["fp"] != fp:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": "Conflicting rollback payload"}
            if prior["empty"]:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_NOT_EXISTS, "message": "Original betId never deducted"}
            return self._ok(trace_id, username, acct)
        refund = decimal_to_ledger_units(req["amount"], acct["exponent"])
        if refund <= 0:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Rollback amount must be positive"}
        orig = self.deducted_bets.get(bet_id)
        if orig is None:
            self.transactions[tx_id] = {"type": "ROLLBACK", "fp": fp, "empty": True}
            return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_NOT_EXISTS, "message": "Original betId never deducted"}
        if orig["username"] != username or orig["currency"] != acct["currency"] or orig["stake"] != refund:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Rollback does not match original bet"}
        if orig["state"] != "DEDUCTED":
            return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": f"betId already {orig['state']}"}
        acct["balance_units"] += refund
        orig["state"] = "ROLLED_BACK"
        self.transactions[tx_id] = {"type": "ROLLBACK", "fp": fp, "empty": False}
        return self._ok(trace_id, username, acct)

    def on_adjustment(self, req: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            return self._on_adjustment_unlocked(req)

    def _on_adjustment_unlocked(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = req.get("traceId") if isinstance(req.get("traceId"), str) else ""
        tx_id = _non_empty_str(req.get("transactionId"))
        bet_id = _non_empty_str(req.get("betId"))
        username = _non_empty_str(req.get("username"))
        currency = _non_empty_str(req.get("currency"))
        direction_raw = _non_empty_str(req.get("direction"))
        direction = direction_raw.upper() if direction_raw else ""
        reason_code = _non_empty_str(req.get("reasonCode"))
        if not tx_id or not bet_id or not username or not currency or not reason_code or req.get("amount") is None or direction not in ("CREDIT", "DEBIT"):
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Missing or invalid adjustment fields"}
        acct, err = self._check_acct(username, currency)
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        fp = adjustment_fingerprint(req)
        prior = self.transactions.get(tx_id)
        if prior:
            if prior["type"] != "ADJUSTMENT" or prior["fp"] != fp:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": "Conflicting adjustment payload"}
            return self._ok(trace_id, username, acct)
        orig = self.deducted_bets.get(bet_id)
        if orig is None:
            return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_NOT_EXISTS, "message": "Original betId not found"}
        if orig["username"] != username or orig["currency"] != acct["currency"]:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Adjustment does not match original bet"}
        adj_units = decimal_to_ledger_units(req["amount"], acct["exponent"])
        if adj_units <= 0:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Adjustment amount must be positive"}
        if direction == "DEBIT":
            if acct["balance_units"] < adj_units:
                return {"traceId": trace_id, "status": StatusCode.SC_INSUFFICIENT_FUNDS, "message": "Insufficient funds"}
            acct["balance_units"] -= adj_units
        else:
            acct["balance_units"] += adj_units
        self.transactions[tx_id] = {"type": "ADJUSTMENT", "fp": fp, "empty": False}
        return self._ok(trace_id, username, acct)


def _extract_trace_hint(raw_bytes: bytes) -> str:
    m = _TRACE_HINT_RE.search(raw_bytes[:1024])
    return m.group(1).decode("ascii", errors="ignore") if m else ""


class WebhookDispatcher:
    def __init__(self, config: Optional[Config], wallet: WalletHandler, *, api_key: Optional[str] = None, hmac_secret: Optional[str] = None) -> None:
        if wallet is None:
            raise BaccaratSdkError("wallet handler is required", "INVALID_CONFIG")
        resolved_key = (config.api_key if config is not None else (api_key or "")).strip()
        resolved_secret = config.hmac_secret if config is not None else (hmac_secret or "")
        if not resolved_key or not resolved_secret:
            raise BaccaratSdkError("api_key and hmac_secret are required", "INVALID_CONFIG")
        self.config = config
        self.api_key = resolved_key
        self.hmac_secret = resolved_secret
        self.wallet = wallet

    @classmethod
    def from_credentials(cls, api_key: str, hmac_secret: str, wallet: WalletHandler) -> "WebhookDispatcher":
        return cls(None, wallet, api_key=api_key, hmac_secret=hmac_secret)

    def handle(
        self,
        route_path: str,
        api_key_header: Optional[str],
        signature_header: Optional[str],
        raw_body: Union[bytes, bytearray, str],
    ) -> Tuple[int, Dict[str, Any]]:
        if isinstance(raw_body, (dict, list)):
            trace_hint = raw_body.get("traceId") if isinstance(raw_body, dict) and isinstance(raw_body.get("traceId"), str) else ""
            return 200, {
                "traceId": trace_hint.strip()[:128],
                "status": StatusCode.SC_INVALID_REQUEST,
                "message": "raw_body must be raw bytes or str, not parsed dict/list",
            }
        raw_bytes = _to_utf8_bytes(raw_body)
        if len(raw_bytes) > MAX_WEBHOOK_BODY_BYTES:
            return 200, {"traceId": "", "status": StatusCode.SC_INVALID_REQUEST, "message": "Request body exceeds 1 MiB limit"}

        # Verify X-API-Key & X-Signature over raw bytes BEFORE JSON parsing!
        auth_status = verify_webhook_headers(
            api_key_header,
            signature_header,
            raw_bytes,
            self.api_key,
            self.hmac_secret,
        )
        if auth_status != StatusCode.SC_OK:
            return 200, {
                "traceId": _extract_trace_hint(raw_bytes),
                "status": auth_status,
                "message": "Authentication/signature check failed",
            }

        trace_id = ""
        parsed: Optional[Dict[str, Any]] = None
        try:
            candidate = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(candidate, dict):
                parsed = candidate
                if isinstance(candidate.get("traceId"), str):
                    trace_id = candidate["traceId"].strip()[:128]
        except Exception:
            parsed = None

        if parsed is None:
            return 200, {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Malformed JSON object"}

        clean = (route_path or "").split("?", 1)[0].rstrip("/")
        try:
            if clean.endswith("/wallet/balance"):
                return 200, self.wallet.on_balance(parsed)
            if clean.endswith("/wallet/bet"):
                return 200, self.wallet.on_bet(parsed)
            if clean.endswith("/wallet/bet_result"):
                return 200, self.wallet.on_bet_result(parsed)
            if clean.endswith("/wallet/rollback"):
                return 200, self.wallet.on_rollback(parsed)
            if clean.endswith("/wallet/adjustment"):
                adj_fn = getattr(self.wallet, "on_adjustment", None)
                if not callable(adj_fn):
                    return 200, {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "on_adjustment not implemented"}
                return 200, adj_fn(parsed)
            return 200, {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": f"Unknown route {clean}"}
        except BaccaratSdkError as exc:
            st = exc.code if isinstance(exc.code, str) and exc.code.startswith("SC_") else StatusCode.SC_INVALID_REQUEST
            return 200, {"traceId": trace_id, "status": st, "message": str(exc)}
        except Exception:
            return 200, {
                "traceId": trace_id,
                "status": StatusCode.SC_OPERATOR_TIMEOUT,
                "message": "Temporary wallet handler error",
            }


__all__ = [
    "SANDBOX_BASE_URL",
    "MAX_DETAIL_WINDOW_MS",
    "MAX_PAGE_SIZE",
    "MAX_WEBHOOK_BODY_BYTES",
    "MAX_HTTP_RESPONSE_BYTES",
    "LEDGER_SCALE",
    "UNSET",
    "Environment",
    "StatusCode",
    "is_retryable_status",
    "BaccaratSdkError",
    "BaccaratApiError",
    "sign_body",
    "verify_signature",
    "verify_webhook_headers",
    "decimal_to_ledger_units",
    "ledger_units_to_decimal",
    "encode_tuple_fingerprint",
    "bet_fingerprint",
    "bet_result_fingerprint",
    "rollback_fingerprint",
    "adjustment_fingerprint",
    "Config",
    "TransportFn",
    "Client",
    "wallet_ok",
    "wallet_error",
    "WalletHandler",
    "InMemoryWallet",
    "WebhookDispatcher",
]
