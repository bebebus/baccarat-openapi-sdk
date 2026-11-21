# SPDX-License-Identifier: MIT
"""Zero-dependency Python 3 SDK for Baccarat Live Platform B2B Operator Seamless Wallet API (v1.2.0)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

SANDBOX_BASE_URL = "https://api.lt.cniia.cloud"
MAX_DETAIL_WINDOW_MS = 604_800_000  # 7 days in ms
LEDGER_SCALE = 1000

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DECIMAL_RE = re.compile(r"^(-?)(\d+)(?:\.(\d+))?$")


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


_RETRYABLE_STATUSES = frozenset(
    {StatusCode.SC_TRANSACTION_STILL_PROCESSING, StatusCode.SC_OPERATOR_TIMEOUT}
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
        super().__init__(message or f"B2B API error: {status}", status)
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
            payload["transactionId"],
            payload["username"],
            payload["betId"],
            payload["externalTransactionId"],
            payload["roundId"],
            payload["currency"],
            payload["gameCode"],
            payload["amount"],
        ],
    )


def bet_result_fingerprint(payload: Dict[str, Any]) -> str:
    return encode_tuple_fingerprint(
        "wallet/bet_result",
        [
            payload["transactionId"],
            payload["username"],
            payload["betId"],
            payload["externalTransactionId"],
            payload["roundId"],
            payload["currency"],
            payload["gameCode"],
            payload["betAmount"],
            payload["winAmount"],
            payload["effectiveTurnover"],
            payload["winLoss"],
            payload["jackpotAmount"],
            payload["resultType"],
            str(payload["isFreespin"]),
            str(payload["isEndRound"]),
            str(payload["betTime"]),
        ],
    )


def rollback_fingerprint(payload: Dict[str, Any]) -> str:
    return encode_tuple_fingerprint(
        "wallet/rollback",
        [
            payload["transactionId"],
            payload["username"],
            payload["betId"],
            payload["externalTransactionId"],
            payload["roundId"],
            payload["currency"],
            payload["gameCode"],
            payload["amount"],
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
    resolved_base_url: str = field(init=False)

    def __post_init__(self) -> None:
        trimmed_key = (self.api_key or "").strip()
        if not trimmed_key:
            raise BaccaratSdkError("api_key is required", "INVALID_CONFIG")
        if not self.hmac_secret:
            raise BaccaratSdkError("hmac_secret is required", "INVALID_CONFIG")
        raw_url = (self.base_url or "").strip()
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
        if self.timeout_ms <= 0:
            raise BaccaratSdkError("timeout_ms must be positive", "INVALID_CONFIG")
        object.__setattr__(self, "api_key", trimmed_key)
        object.__setattr__(self, "resolved_base_url", raw_url.rstrip("/"))


TransportFn = Callable[[str, Dict[str, str], bytes, int], Tuple[int, str]]


def _default_transport(url: str, headers: Dict[str, str], raw_body: bytes, timeout_ms: int) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=raw_body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000.0) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace") if err.fp else ""
        return err.code, body
    except Exception as exc:
        raise BaccaratSdkError(f"Network error: {exc}", StatusCode.SC_OPERATOR_TIMEOUT) from exc


class Client:
    def __init__(self, config: Config, transport: TransportFn = _default_transport) -> None:
        self.config = config
        self._transport = transport

    def _post_signed(self, route_path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(payload)
        trace_id = str(body.get("traceId") or "").strip() or str(uuid.uuid4())
        body["traceId"] = trace_id

        raw_bytes = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        sig = sign_body(raw_bytes, self.config.hmac_secret)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": self.config.api_key,
            "X-Signature": sig,
        }
        http_status, resp_text = self._transport(
            f"{self.config.resolved_base_url}{route_path}",
            headers,
            raw_bytes,
            self.config.timeout_ms,
        )
        try:
            parsed = json.loads(resp_text)
        except Exception as exc:
            status = (
                StatusCode.SC_OPERATOR_TIMEOUT
                if http_status >= 500 or http_status in (408, 429)
                else StatusCode.SC_INVALID_REQUEST
            )
            raise BaccaratApiError(status=status, message=f"Non-JSON HTTP {http_status}", trace_id=trace_id, http_status=http_status) from exc

        if not isinstance(parsed, dict):
            raise BaccaratApiError(status=StatusCode.SC_INVALID_REQUEST, message="Malformed envelope", trace_id=trace_id, http_status=http_status)

        if http_status != 200 or parsed.get("status") != StatusCode.SC_OK:
            raise BaccaratApiError(
                status=str(parsed.get("status") or StatusCode.SC_INVALID_REQUEST),
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

    def create_game_url(
        self,
        *,
        username: str,
        table_id: str,
        platform: str,
        currency: str,
        lobby_url: str,
        ip_address: str,
        language: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "username": username,
            "tableId": table_id,
            "platform": platform,
            "currency": currency,
            "lobbyUrl": lobby_url,
            "ipAddress": ip_address,
        }
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

    def terminate_sessions(self, *, username: str, trace_id: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"username": username}
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/game/terminate", payload)

    def list_transactions(
        self,
        *,
        from_time: int,
        to_time: int,
        page_no: Optional[int] = None,
        page_size: Optional[int] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if isinstance(from_time, bool) or isinstance(to_time, bool) or from_time < 0 or to_time < from_time:
            raise BaccaratSdkError("Invalid [from_time, to_time] window", "INVALID_ARGUMENT")
        payload: Dict[str, Any] = {"fromTime": from_time, "toTime": to_time}
        if page_no is not None:
            payload["pageNo"] = page_no
        if page_size is not None:
            payload["pageSize"] = page_size
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/transaction/list", payload)

    def list_all_transactions(self, *, from_time: int, to_time: int, page_size: int = 2000) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        page_no = 1
        while True:
            res = self.list_transactions(from_time=from_time, to_time=to_time, page_no=page_no, page_size=page_size)
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
        from_time: int,
        to_time: int,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        span = to_time - from_time
        if not bet_id or isinstance(from_time, bool) or isinstance(to_time, bool) or from_time < 0 or span < 0 or span > MAX_DETAIL_WINDOW_MS:
            raise BaccaratSdkError("Detail query window must satisfy 0 <= to_time - from_time <= 604800000", "INVALID_ARGUMENT")
        payload: Dict[str, Any] = {"betId": bet_id, "fromTime": from_time, "toTime": to_time}
        if trace_id is not None:
            payload["traceId"] = trace_id
        return self._post_signed("/operator/v1/transaction/detail", payload)


# ── 5. Seamless Wallet Webhook Dispatcher & Reference In-Memory Wallet ──────


class InMemoryWallet:
    def __init__(self, initial_accounts: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.transactions: Dict[str, Dict[str, Any]] = {}
        self.deducted_bets: Dict[str, int] = {}
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
        if username in self.accounts:
            self.accounts[username]["disabled"] = disabled

    def _ok(self, trace_id: str, username: str, acct: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "traceId": trace_id,
            "status": StatusCode.SC_OK,
            "data": {
                "username": username,
                "currency": acct["currency"],
                "balance": ledger_units_to_decimal(acct["balance_units"], acct["exponent"]),
                "timestamp": int(time.time() * 1000),
            },
        }

    def _check_acct(self, username: str, currency: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        acct = self.accounts.get(username)
        if acct is None:
            return None, StatusCode.SC_USER_NOT_EXISTS
        if acct["currency"] != str(currency or "").strip().upper():
            return None, StatusCode.SC_WRONG_CURRENCY
        return acct, None

    def on_balance(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = str(req.get("traceId", ""))
        acct, err = self._check_acct(req.get("username", ""), req.get("currency", ""))
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        if acct["disabled"]:
            return {"traceId": trace_id, "status": StatusCode.SC_USER_DISABLED, "message": "User disabled"}
        if acct["tokens"] and req.get("token") not in acct["tokens"]:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_TOKEN, "message": "Invalid token"}
        return self._ok(trace_id, req["username"], acct)

    def on_bet(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = str(req.get("traceId", ""))
        acct, err = self._check_acct(req.get("username", ""), req.get("currency", ""))
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        fp = bet_fingerprint(req)
        prior = self.transactions.get(req["transactionId"])
        if prior:
            if prior["fp"] != fp:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": "Conflicting bet payload"}
            return self._ok(trace_id, req["username"], acct)
        if acct["disabled"]:
            return {"traceId": trace_id, "status": StatusCode.SC_USER_DISABLED, "message": "User disabled"}
        if acct["tokens"] and req.get("token") not in acct["tokens"]:
            return {"traceId": trace_id, "status": StatusCode.SC_INVALID_TOKEN, "message": "Invalid token"}
        stake = decimal_to_ledger_units(req["amount"], acct["exponent"])
        if acct["balance_units"] < stake:
            return {"traceId": trace_id, "status": StatusCode.SC_INSUFFICIENT_FUNDS, "message": "Insufficient funds"}
        acct["balance_units"] -= stake
        self.transactions[req["transactionId"]] = {"fp": fp, "empty": False}
        self.deducted_bets[req["betId"]] = stake
        return self._ok(trace_id, req["username"], acct)

    def on_bet_result(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = str(req.get("traceId", ""))
        acct, err = self._check_acct(req.get("username", ""), req.get("currency", ""))
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        fp = bet_result_fingerprint(req)
        prior = self.transactions.get(req["transactionId"])
        if prior:
            if prior["fp"] != fp:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": "Conflicting bet_result payload"}
            return self._ok(trace_id, req["username"], acct)
        # Honor already-deducted betId even if player later logged out or was disabled
        if req["betId"] not in self.deducted_bets:
            return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_NOT_EXISTS, "message": "Original betId not found"}
        win_units = decimal_to_ledger_units(req["winAmount"], acct["exponent"])
        acct["balance_units"] += win_units
        self.transactions[req["transactionId"]] = {"fp": fp, "empty": False}
        return self._ok(trace_id, req["username"], acct)

    def on_rollback(self, req: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = str(req.get("traceId", ""))
        acct, err = self._check_acct(req.get("username", ""), req.get("currency", ""))
        if err or acct is None:
            return {"traceId": trace_id, "status": err or StatusCode.SC_USER_NOT_EXISTS, "message": "Account/currency check failed"}
        fp = rollback_fingerprint(req)
        prior = self.transactions.get(req["transactionId"])
        if prior:
            if prior["fp"] != fp:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_DUPLICATED, "message": "Conflicting rollback payload"}
            if prior["empty"]:
                return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_NOT_EXISTS, "message": "Original betId never deducted"}
            return self._ok(trace_id, req["username"], acct)
        if req["betId"] not in self.deducted_bets:
            self.transactions[req["transactionId"]] = {"fp": fp, "empty": True}
            return {"traceId": trace_id, "status": StatusCode.SC_TRANSACTION_NOT_EXISTS, "message": "Original betId never deducted"}
        refund = decimal_to_ledger_units(req["amount"], acct["exponent"])
        acct["balance_units"] += refund
        self.transactions[req["transactionId"]] = {"fp": fp, "empty": False}
        return self._ok(trace_id, req["username"], acct)


class WebhookDispatcher:
    def __init__(self, config: Config, wallet: InMemoryWallet) -> None:
        self.config = config
        self.wallet = wallet

    def handle(
        self,
        route_path: str,
        api_key_header: Optional[str],
        signature_header: Optional[str],
        raw_body: Union[bytes, bytearray, str],
    ) -> Tuple[int, Dict[str, Any]]:
        raw_bytes = _to_utf8_bytes(raw_body)
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

        auth_status = verify_webhook_headers(
            api_key_header,
            signature_header,
            raw_bytes,
            self.config.api_key,
            self.config.hmac_secret,
        )
        if auth_status != StatusCode.SC_OK:
            return 200, {"traceId": trace_id, "status": auth_status, "message": "Authentication/signature check failed"}

        if parsed is None:
            return 200, {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": "Malformed JSON object"}

        clean = route_path.split("?", 1)[0].rstrip("/")
        if clean.endswith("/wallet/balance"):
            return 200, self.wallet.on_balance(parsed)
        if clean.endswith("/wallet/bet"):
            return 200, self.wallet.on_bet(parsed)
        if clean.endswith("/wallet/bet_result"):
            return 200, self.wallet.on_bet_result(parsed)
        if clean.endswith("/wallet/rollback"):
            return 200, self.wallet.on_rollback(parsed)
        return 200, {"traceId": trace_id, "status": StatusCode.SC_INVALID_REQUEST, "message": f"Unknown route {clean}"}
