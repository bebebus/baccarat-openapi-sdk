# SPDX-License-Identifier: MIT
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from baccarat_sdk import (
    BaccaratApiError,
    BaccaratSdkError,
    Client,
    Config,
    Environment,
    InMemoryWallet,
    StatusCode,
    UNSET,
    WebhookDispatcher,
    adjustment_fingerprint,
    bet_fingerprint,
    bet_result_fingerprint,
    decimal_to_ledger_units,
    is_retryable_status,
    ledger_units_to_decimal,
    rollback_fingerprint,
    sign_body,
    verify_signature,
    verify_webhook_headers,
    wallet_error,
    wallet_ok,
)

VECTORS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../test-vectors.json"))
with open(VECTORS_PATH, "r", encoding="utf-8") as fh:
    VECTORS = json.load(fh)


class TestBaccaratPythonSdk(unittest.TestCase):
    def test_hmac_and_header_vectors(self) -> None:
        for v in VECTORS["hmacVectors"]:
            self.assertEqual(len(v["rawBody"].encode("utf-8")), v["utf8ByteLength"])
            self.assertEqual(sign_body(v["rawBody"], v["secret"]), v["signature"], v["name"])
            self.assertTrue(verify_signature(v["rawBody"], v["signature"], v["secret"]))
            if "wrongBase64DecodedSignature" in v:
                self.assertFalse(verify_signature(v["rawBody"], v["wrongBase64DecodedSignature"], v["secret"]))

        for h in VECTORS["headerVerificationVectors"]:
            actual = verify_webhook_headers(
                h["apiKeyHeader"],
                h["signatureHeader"],
                h["rawBody"],
                h["expectedApiKey"],
                h["hmacSecret"],
            )
            self.assertEqual(actual, h["expectedStatus"], h["name"])

    def test_idempotency_fingerprints(self) -> None:
        idem = VECTORS["idempotencyVectors"]
        self.assertEqual(bet_fingerprint(idem["bet"]["initial"]), idem["bet"]["expectedFingerprint"])
        self.assertEqual(bet_fingerprint(idem["bet"]["retrySameBusiness"]), idem["bet"]["expectedFingerprint"])
        self.assertEqual(bet_fingerprint(idem["bet"]["conflictDifferentAmount"]), idem["bet"]["conflictFingerprint"])

        self.assertEqual(bet_result_fingerprint(idem["betResult"]["initial"]), idem["betResult"]["expectedFingerprint"])
        self.assertEqual(bet_result_fingerprint(idem["betResult"]["retrySameBusiness"]), idem["betResult"]["expectedFingerprint"])
        self.assertEqual(bet_result_fingerprint(idem["betResult"]["conflictDifferentWinAmount"]), idem["betResult"]["conflictFingerprint"])

        self.assertEqual(rollback_fingerprint(idem["rollback"]["initial"]), idem["rollback"]["expectedFingerprint"])
        self.assertEqual(rollback_fingerprint(idem["rollback"]["retrySameBusiness"]), idem["rollback"]["expectedFingerprint"])
        self.assertEqual(rollback_fingerprint(idem["rollback"]["conflictDifferentAmount"]), idem["rollback"]["conflictFingerprint"])

        self.assertEqual(adjustment_fingerprint(idem["adjustment"]["initial"]), idem["adjustment"]["expectedFingerprint"])
        self.assertEqual(adjustment_fingerprint(idem["adjustment"]["retrySameBusiness"]), idem["adjustment"]["expectedFingerprint"])
        self.assertEqual(adjustment_fingerprint(idem["adjustment"]["conflictDifferentDirection"]), idem["adjustment"]["conflictFingerprint"])

    def test_money_and_status_vectors(self) -> None:
        for m in VECTORS["moneyVectors"]["valid"]:
            units = decimal_to_ledger_units(m["raw"], m["displayExponent"], m["allowNegative"])
            self.assertEqual(str(units), m["expectedUnits"], m["name"])
            self.assertEqual(ledger_units_to_decimal(units, m["displayExponent"]), m["expectedFormatted"], m["name"])

        for inv in VECTORS["moneyVectors"]["invalid"]:
            with self.assertRaises(BaccaratSdkError, msg=inv["name"]):
                decimal_to_ledger_units(inv["raw"], inv["displayExponent"], inv["allowNegative"])

        for sc in VECTORS["statusCodes"]:
            self.assertEqual(is_retryable_status(sc["code"]), sc["retryable"], sc["code"])

    def test_s2s_client_loopback_and_webhook_lifecycle(self) -> None:
        api_key = "ak_0123456789abcdef0123456789abcdef"
        secret = "dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s"

        class MockS2sHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                st = verify_webhook_headers(
                    self.headers.get("X-API-Key"),
                    self.headers.get("X-Signature"),
                    raw,
                    api_key,
                    secret,
                )
                body = json.loads(raw.decode("utf-8"))
                status_code = 200
                if st != StatusCode.SC_OK:
                    resp = {"traceId": body.get("traceId", ""), "status": st, "message": "auth error"}
                elif self.path == "/operator/v1/game/tables":
                    resp = {"traceId": body["traceId"], "status": "SC_OK", "data": {"tables": [{"tableId": "T-A2", "currency": "USD"}], "pageNo": 1, "pageSize": 50, "total": 1}}
                elif self.path == "/operator/v1/game/url":
                    if body["currency"] != "USD":
                        resp = {"traceId": body["traceId"], "status": "SC_WRONG_CURRENCY", "message": "mismatch"}
                    else:
                        tok = "b2bt_" + ("b" * 48)
                        resp = {"traceId": body["traceId"], "status": "SC_OK", "data": {"gameUrl": f"https://play.lt.cniia.cloud/?token={tok}", "token": tok}}
                elif self.path == "/operator/v1/game/terminate":
                    resp = {"traceId": body["traceId"], "status": "SC_OK", "data": {"username": body["username"], "terminatedSessions": 1, "revokedLaunchTokens": 0}}
                elif self.path == "/operator/v1/player/status":
                    if body.get("username") == "locked_user":
                        status_code = 403
                        resp = {"traceId": body["traceId"], "status": "SC_USER_DISABLED", "message": "PLATFORM_RISK_LOCKED"}
                    elif body.get("username") == "capped_user" and body.get("bettingEnabled") is True and body.get("resetPnlWindow") is not True:
                        status_code = 409
                        resp = {"traceId": body["traceId"], "status": "SC_INVALID_REQUEST", "message": "PNL_CAP_BREACHED_RESET_REQUIRED"}
                    else:
                        resp = {"traceId": body["traceId"], "status": "SC_OK", "data": {"username": body["username"], "status": body.get("status", "ACTIVE"), "bettingEnabled": body.get("bettingEnabled", True), "rgRestricted": False, "statusReason": None, "revokedSessions": 0, "revokedLaunchTokens": 0}}
                elif self.path == "/operator/v1/wallet/transaction-status":
                    resp = {"traceId": body["traceId"], "status": "SC_OK", "data": {"transactions": [{"transactionId": body.get("transactionId", "bet_py_1"), "username": body.get("username", "player_9527"), "status": "COMPLETED"}]}}
                elif self.path == "/operator/v1/transaction/list":
                    rows = [{"betId": "b2btkt1"}, {"betId": "b2btkt2"}] if body.get("pageNo", 1) == 1 else [{"betId": "b2btkt3"}]
                    resp = {"traceId": body["traceId"], "status": "SC_OK", "data": {"transactions": rows, "pageNo": body.get("pageNo", 1), "pageSize": 2, "total": 3}}
                else:
                    resp = {"traceId": body["traceId"], "status": "SC_OK", "data": {"betId": body["betId"], "status": 1, "roundResult": {"outcome": "BANKER", "playerPoints": 4, "bankerPoints": 7, "playerPair": False, "bankerPair": False, "natural": False}}}

                out = json.dumps(resp).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), MockS2sHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            cfg = Config(api_key=api_key, hmac_secret=secret, base_url=f"http://127.0.0.1:{port}")
            client = Client(cfg)

            self.assertEqual(client.list_tables(currency="USD")["data"]["tables"][0]["tableId"], "T-A2")
            launch = client.create_game_url(
                username="player_9527",
                table_id="T-A2",
                platform="H5",
                currency="USD",
                lobby_url="https://merchant.example.com/lobby",
                ip_address="203.0.113.42",
            )
            self.assertTrue(launch["data"]["token"].startswith("b2bt_"))

            with self.assertRaises(BaccaratApiError) as ctx:
                client.create_game_url(
                    username="player_9527",
                    table_id="T-A2",
                    platform="H5",
                    currency="CNY",
                    lobby_url="https://merchant.example.com/lobby",
                    ip_address="203.0.113.42",
                )
            self.assertEqual(ctx.exception.status, "SC_WRONG_CURRENCY")
            self.assertFalse(ctx.exception.is_retryable())

            self.assertEqual(client.terminate_sessions(username="player_9527")["data"]["terminatedSessions"], 1)
            all_tx = client.list_all_transactions(from_time=1000, to_time=2000, page_size=2)
            self.assertEqual(len(all_tx), 3)
            detail = client.get_transaction_detail(bet_id="b2btkt1", from_time=1000, to_time=2000)
            self.assertEqual(detail["data"]["roundResult"]["outcome"], "BANKER")

            ps_ok = client.update_player_status(username="capped_user", action="SET", betting_enabled=True, reset_pnl_window=True)
            self.assertTrue(ps_ok["data"]["bettingEnabled"])
            with self.assertRaises(BaccaratApiError) as ctx_403:
                client.update_player_status(username="locked_user", action="SET", status="ACTIVE")
            self.assertEqual(ctx_403.exception.http_status, 403)
            self.assertEqual(ctx_403.exception.status, "SC_USER_DISABLED")
            self.assertEqual(ctx_403.exception.message, "PLATFORM_RISK_LOCKED")
            self.assertFalse(ctx_403.exception.is_retryable())
            with self.assertRaises(BaccaratApiError) as ctx_409:
                client.update_player_status(username="capped_user", action="SET", betting_enabled=True)
            self.assertEqual(ctx_409.exception.http_status, 409)
            self.assertEqual(ctx_409.exception.status, "SC_INVALID_REQUEST")
            self.assertEqual(ctx_409.exception.message, "PNL_CAP_BREACHED_RESET_REQUIRED")
            self.assertFalse(ctx_409.exception.is_retryable())

            wts_user = client.get_wallet_transaction_status(username="player_9527", from_time=0, to_time=86_400_000)
            self.assertEqual(wts_user["data"]["transactions"][0]["username"], "player_9527")
            with self.assertRaises(BaccaratSdkError):
                client.get_wallet_transaction_status()
            with self.assertRaises(BaccaratSdkError):
                client.get_wallet_transaction_status(username="player_9527")
            with self.assertRaises(BaccaratSdkError):
                client.get_wallet_transaction_status(username="player_9527", from_time=0, to_time=86_400_001)
            with self.assertRaises(BaccaratSdkError):
                client.get_wallet_transaction_status(transaction_id="bet_1", from_time=1000)
            with self.assertRaises(BaccaratSdkError):
                client.get_wallet_transaction_status(bet_id="b2btkt1", from_time=2000, to_time=1000)
            with self.assertRaises(BaccaratSdkError):
                client.list_unsettled_transactions(from_time=1000)

            with self.assertRaises(BaccaratSdkError):
                client.get_transaction_detail(bet_id="b2btkt1", from_time=0, to_time=604_800_001)
        finally:
            httpd.shutdown()
            httpd.server_close()

        # Webhook lifecycle
        tok = "b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819"
        wallet = InMemoryWallet({"player_9527": {"currency": "USD", "balance": "1000.00", "exponent": 2, "tokens": [tok]}})
        disp = WebhookDispatcher(Config(api_key=api_key, hmac_secret=secret, environment=Environment.SANDBOX), wallet)

        def call(route: str, obj: dict) -> dict:
            raw = json.dumps(obj, ensure_ascii=False)
            _, body = disp.handle(route, api_key, sign_body(raw, secret), raw)
            return body

        self.assertEqual(call("/wallet/balance", {"traceId": "t1", "username": "player_9527", "currency": "USD", "token": tok})["data"]["balance"], "1000.00")
        self.assertEqual(call("/wallet/bet", VECTORS["idempotencyVectors"]["bet"]["initial"])["data"]["balance"], "900.00")
        self.assertEqual(call("/wallet/bet", VECTORS["idempotencyVectors"]["bet"]["retrySameBusiness"])["data"]["balance"], "900.00")
        self.assertEqual(call("/wallet/bet", VECTORS["idempotencyVectors"]["bet"]["conflictDifferentAmount"])["status"], "SC_TRANSACTION_DUPLICATED")

        wallet.set_disabled("player_9527", True)
        self.assertEqual(call("/wallet/bet_result", VECTORS["idempotencyVectors"]["betResult"]["initial"])["data"]["balance"], "1100.00")
        self.assertEqual(call("/wallet/adjustment", VECTORS["idempotencyVectors"]["adjustment"]["initial"])["data"]["balance"], "1120.00")
        self.assertEqual(call("/wallet/adjustment", VECTORS["idempotencyVectors"]["adjustment"]["retrySameBusiness"])["data"]["balance"], "1120.00")
        self.assertEqual(call("/wallet/adjustment", VECTORS["idempotencyVectors"]["adjustment"]["conflictDifferentDirection"])["status"], "SC_TRANSACTION_DUPLICATED")
        debit_adj = dict(VECTORS["idempotencyVectors"]["adjustment"]["initial"], transactionId="adj_debit_py", direction="DEBIT", amount="20.00")
        self.assertEqual(call("/wallet/adjustment", debit_adj)["data"]["balance"], "1100.00")
        unknown_rb = dict(
            VECTORS["idempotencyVectors"]["rollback"]["initial"],
            transactionId="rb_b2btkt000000000000000000000000",
            betId="b2btkt000000000000000000000000",
            externalTransactionId="b2btkt000000000000000000000000",
        )
        self.assertEqual(call("/wallet/rollback", unknown_rb)["status"], "SC_TRANSACTION_NOT_EXISTS")

        # CR-01..CR-10 adversarial regressions:
        # 1. Rollback after settled betId must be rejected (no double credit)
        self.assertEqual(call("/wallet/rollback", VECTORS["idempotencyVectors"]["rollback"]["initial"])["status"], "SC_TRANSACTION_DUPLICATED")
        # 2. Malformed decimal or missing field inside signed webhook returns HTTP 200 + SC_INVALID_REQUEST (never raises KeyError/BaccaratSdkError)
        bad_bet = dict(VECTORS["idempotencyVectors"]["bet"]["initial"], transactionId="bet_bad_amt", betId="b2btkt_bad", amount="not_a_number")
        wallet.set_disabled("player_9527", False)
        self.assertEqual(call("/wallet/bet", bad_bet)["status"], "SC_INVALID_REQUEST")
        self.assertEqual(call("/wallet/bet", {"traceId": "t_empty"})["status"], "SC_INVALID_REQUEST")
        # 3. Zero-stake bet rejected
        zero_bet = dict(VECTORS["idempotencyVectors"]["bet"]["initial"], transactionId="bet_zero", betId="b2btkt_zero", amount="0.00")
        self.assertEqual(call("/wallet/bet", zero_bet)["status"], "SC_INVALID_REQUEST")
        # 4. Pre-auth deep nesting rejected before JSON parse; timeout_ms=True rejected
        st_code, unauth_body = disp.handle("/wallet/bet", "bad_key", "bad_sig", b"[" * 50_000)
        self.assertEqual(st_code, 200)
        self.assertEqual(unauth_body["status"], "SC_AUTHENTICATION_FAILED")
        with self.assertRaises(BaccaratSdkError):
            Config(api_key=api_key, hmac_secret=secret, environment=Environment.SANDBOX, timeout_ms=True)  # type: ignore[arg-type]

        # 5. Regressions: send_timestamp, non-JSON/JSON missing-status 429 & 503 (M1), list_all_transactions retry + filters,
        #    WebhookDispatcher.from_credentials, dict/list rejection (m6), and 3xx redirect blocking (M7)
        captured_headers: list[dict[str, str]] = []
        p1_calls = {"n": 0}

        def mock_transport(url: str, headers: dict[str, str], raw_body: bytes, _timeout: int) -> tuple[int, str]:
            captured_headers.append(headers)
            body = json.loads(raw_body.decode("utf-8"))
            if url.endswith("/operator/v1/ping"):
                if body.get("traceId") == "m1_json_429":
                    return 429, json.dumps({"statusCode": 429, "message": "Too Many Requests"})
                if body.get("traceId") == "m1_json_503":
                    return 503, json.dumps({"error": "unavailable"})
                if body.get("traceId") == "m1_empty_429":
                    return 429, json.dumps({"status": "", "message": "Empty status"})
                return 429, "Too Many Requests"
            if body.get("pageNo") == 1 and p1_calls["n"] == 0:
                p1_calls["n"] += 1
                return 200, json.dumps({"traceId": body["traceId"], "status": "SC_RATE_LIMITED", "message": "slow down"})
            rows = [{"betId": "b1"}, {"betId": "b2"}] if body.get("pageNo") == 1 else [{"betId": "b3"}]
            return 200, json.dumps({"traceId": body["traceId"], "status": "SC_OK", "data": {"transactions": rows, "pageNo": body["pageNo"], "pageSize": 2, "total": 3}})

        ts_client = Client(
            Config(api_key=api_key, hmac_secret=secret, environment=Environment.SANDBOX, send_timestamp=True),
            transport=mock_transport,
        )
        with self.assertRaises(BaccaratApiError) as ctx_429:
            ts_client.ping()
        self.assertEqual(ctx_429.exception.http_status, 429)
        self.assertEqual(ctx_429.exception.status, StatusCode.SC_RATE_LIMITED)
        self.assertTrue(ctx_429.exception.is_retryable())
        self.assertRegex(captured_headers[0]["X-Timestamp"], r"^\d{13}$")

        with self.assertRaises(BaccaratApiError) as ctx_m1_429:
            ts_client.ping(trace_id="m1_json_429")
        self.assertEqual(ctx_m1_429.exception.http_status, 429)
        self.assertEqual(ctx_m1_429.exception.status, StatusCode.SC_RATE_LIMITED)
        self.assertTrue(ctx_m1_429.exception.is_retryable())

        with self.assertRaises(BaccaratApiError) as ctx_m1_503:
            ts_client.ping(trace_id="m1_json_503")
        self.assertEqual(ctx_m1_503.exception.http_status, 503)
        self.assertEqual(ctx_m1_503.exception.status, StatusCode.SC_OPERATOR_TIMEOUT)
        self.assertTrue(ctx_m1_503.exception.is_retryable())

        with self.assertRaises(BaccaratApiError) as ctx_m1_empty:
            ts_client.ping(trace_id="m1_empty_429")
        self.assertEqual(ctx_m1_empty.exception.http_status, 429)
        self.assertEqual(ctx_m1_empty.exception.status, StatusCode.SC_RATE_LIMITED)
        self.assertTrue(ctx_m1_empty.exception.is_retryable())

        retried = ts_client.list_all_transactions(
            from_time=1000,
            to_time=2000,
            page_size=2,
            username="player_9527",
            rate_limit_backoff_sec=0.0,
        )
        self.assertEqual(len(retried), 3)
        self.assertEqual(p1_calls["n"], 1)

        cred_disp = WebhookDispatcher.from_credentials(api_key, secret, wallet)
        bal_raw = json.dumps({"traceId": "t_cred", "username": "player_9527", "currency": "USD", "token": tok})
        st_c, b_c = cred_disp.handle("/wallet/balance", api_key, sign_body(bal_raw, secret), bal_raw)
        self.assertEqual(st_c, 200)
        self.assertEqual(b_c["status"], StatusCode.SC_OK)

        # m6: dict / list passed to WebhookDispatcher.handle must be rejected with SC_INVALID_REQUEST
        st_dict, b_dict = cred_disp.handle("/wallet/bet", api_key, "0" * 64, {"traceId": "t_dict", "amount": "10.00"})  # type: ignore[arg-type]
        self.assertEqual(st_dict, 200)
        self.assertEqual(b_dict["status"], StatusCode.SC_INVALID_REQUEST)
        self.assertEqual(b_dict["traceId"], "t_dict")
        st_list, b_list = cred_disp.handle("/wallet/bet", api_key, "0" * 64, [1, 2, 3])  # type: ignore[arg-type]
        self.assertEqual(st_list, 200)
        self.assertEqual(b_list["status"], StatusCode.SC_INVALID_REQUEST)

        # M7: default transport must NOT follow 3xx redirects (no credential leak)
        redirect_followed = {"hit": False}

        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                if self.path == "/leaked":
                    redirect_followed["hit"] = True
                    self.send_response(200)
                    self.end_headers()
                    return
                body = json.loads(raw.decode("utf-8"))
                if body.get("traceId") == "oversized_500":
                    oversized = b"x" * (16 * 1024 * 1024 + 1)
                    self.send_response(500)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(oversized)))
                    self.end_headers()
                    try:
                        self.wfile.write(oversized)
                    except BrokenPipeError:
                        pass
                    return
                self.send_response(307)
                self.send_header("Location", "/leaked")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                redirect_followed["hit"] = True
                self.send_response(200)
                self.end_headers()

        redir_srv = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redir_port = redir_srv.server_address[1]
        rt = threading.Thread(target=redir_srv.serve_forever, daemon=True)
        rt.start()
        try:
            redir_client = Client(Config(api_key=api_key, hmac_secret=secret, base_url=f"http://127.0.0.1:{redir_port}"))
            with self.assertRaises(BaccaratApiError) as ctx_redir:
                redir_client.ping()
            self.assertEqual(ctx_redir.exception.http_status, 307)
            self.assertEqual(ctx_redir.exception.status, StatusCode.SC_INVALID_REQUEST)
            self.assertFalse(redirect_followed["hit"])

            # >16 MiB HTTP 500 error body must raise non-retryable SC_INVALID_REQUEST with trace_id attached
            with self.assertRaises(BaccaratApiError) as ctx_500_big:
                redir_client.ping(trace_id="oversized_500")
            self.assertEqual(ctx_500_big.exception.http_status, 500)
            self.assertEqual(ctx_500_big.exception.status, StatusCode.SC_INVALID_REQUEST)
            self.assertEqual(ctx_500_big.exception.code, StatusCode.SC_INVALID_REQUEST)
            self.assertEqual(ctx_500_big.exception.trace_id, "oversized_500")
            self.assertFalse(ctx_500_big.exception.is_retryable())
        finally:
            redir_srv.shutdown()
            redir_srv.server_close()

        # 6. v1.5.7 regressions: deadlock & internal SdkError safety, HTTPError read failure, UNSET/None null clearing, wallet helpers
        class DeadlockWallet:
            def on_balance(self, req: dict) -> dict:
                raise BaccaratSdkError("explicit sdk err", StatusCode.SC_INSUFFICIENT_FUNDS)

            def on_bet(self, req: dict) -> dict:
                decimal_to_ledger_units(req.get("amount", "bad_amt"), 2)
                return wallet_ok(req.get("traceId", ""), "p1", "USD", "100.00")

            def on_bet_result(self, req: dict) -> dict:
                if req.get("mode") == "bad_balance":
                    return wallet_ok(req.get("traceId", ""), "p1", "USD", "-1.00")
                if req.get("mode") == "nan_balance":
                    return wallet_ok(req.get("traceId", ""), "p1", "USD", "NaN")
                raise RuntimeError("ERROR: deadlock detected (40P01) on table wallets")

            def on_rollback(self, req: dict) -> dict:
                return wallet_ok(req.get("traceId", ""), "p1", "USD", "100.00", timestamp=1700000000000)

            def on_adjustment(self, req: dict) -> dict:
                return wallet_error(req.get("traceId", ""), StatusCode.SC_INSUFFICIENT_FUNDS, "low funds")

        dl_disp = WebhookDispatcher.from_credentials(api_key, secret, DeadlockWallet())
        dl_raw = json.dumps({"traceId": "t_py_dl", "transactionId": "stl_1"}).encode("utf-8")
        st_dl, body_dl = dl_disp.handle("/wallet/bet_result", api_key, sign_body(dl_raw, secret), dl_raw)
        self.assertEqual(st_dl, 200)
        self.assertEqual(body_dl["traceId"], "t_py_dl")
        self.assertEqual(body_dl["status"], StatusCode.SC_OPERATOR_TIMEOUT)
        self.assertEqual(body_dl["message"], "Temporary wallet handler error")
        self.assertNotIn("40P01", body_dl["message"])
        self.assertNotIn("deadlock", body_dl["message"])

        for mode in ("bad_balance", "nan_balance"):
            bb_raw = json.dumps({"traceId": f"t_py_{mode}", "mode": mode}).encode("utf-8")
            st_bb, body_bb = dl_disp.handle("/wallet/bet_result", api_key, sign_body(bb_raw, secret), bb_raw)
            self.assertEqual(st_bb, 200)
            self.assertEqual(body_bb["traceId"], f"t_py_{mode}")
            self.assertEqual(body_bb["status"], StatusCode.SC_OPERATOR_TIMEOUT)
            self.assertEqual(body_bb["message"], "Temporary wallet handler error")
            self.assertNotIn("wallet_ok", body_bb["message"])
            self.assertNotIn("INVALID_ARGUMENT", body_bb["message"])

        for bad_amt in ("not_a_number", "1.123456", "-5.00"):
            bd_raw = json.dumps({"traceId": "t_py_bad_dec", "amount": bad_amt}).encode("utf-8")
            st_bd, body_bd = dl_disp.handle("/wallet/bet", api_key, sign_body(bd_raw, secret), bd_raw)
            self.assertEqual(st_bd, 200)
            self.assertEqual(body_bd["traceId"], "t_py_bad_dec")
            self.assertEqual(body_bd["status"], StatusCode.SC_INVALID_REQUEST)

        sdk_raw = json.dumps({"traceId": "t_py_sdk"}).encode("utf-8")
        st_sdk, body_sdk = dl_disp.handle("/wallet/balance", api_key, sign_body(sdk_raw, secret), sdk_raw)
        self.assertEqual(st_sdk, 200)
        self.assertEqual(body_sdk["status"], StatusCode.SC_INSUFFICIENT_FUNDS)

        ok_res = wallet_ok("t_ok", "player_1", "JPY", "0")
        self.assertEqual(ok_res["status"], StatusCode.SC_OK)
        self.assertEqual(ok_res["data"]["balance"], "0")
        self.assertIsInstance(ok_res["data"]["timestamp"], int)
        err_res = wallet_error("t_err", StatusCode.SC_USER_DISABLED, "disabled")
        self.assertEqual(err_res, {"traceId": "t_err", "status": StatusCode.SC_USER_DISABLED, "message": "disabled"})

        for bad_bal in ("", "   ", "-1.00", "abc", "10.", ".5", "10.00\n"):
            with self.assertRaises(BaccaratSdkError) as ctx_bal:
                wallet_ok("t_bad", "player_1", "USD", bad_bal)
            self.assertEqual(ctx_bal.exception.code, "INVALID_ARGUMENT")
        for bad_st in ("", "   ", StatusCode.SC_OK, " SC_OK ", "sc_ok", "Sc_Ok", " sc_ok "):
            with self.assertRaises(BaccaratSdkError) as ctx_st:
                wallet_error("t_bad", bad_st, "oops")
            self.assertEqual(ctx_st.exception.code, "INVALID_ARGUMENT")

        # Explicit None -> JSON null vs omitted UNSET on update_player_status / update_player_limits
        sent_payloads: list[dict] = []

        def capture_transport(url: str, _hdrs: dict[str, str], raw: bytes, _t: int) -> tuple[int, str]:
            body = json.loads(raw.decode("utf-8"))
            sent_payloads.append(body)
            return 200, json.dumps({"traceId": body["traceId"], "status": "SC_OK", "data": {}})

        cap_client = Client(
            Config(api_key=api_key, hmac_secret=secret, environment=Environment.SANDBOX),
            transport=capture_transport,
        )
        cap_client.update_player_status(username="p1", action="SET", status="ACTIVE")
        self.assertNotIn("reason", sent_payloads[-1])
        cap_client.update_player_status(username="p1", action="SET", status="ACTIVE", reason=None)
        self.assertIn("reason", sent_payloads[-1])
        self.assertIsNone(sent_payloads[-1]["reason"])

        cap_client.update_player_limits(username="p1", currency="USD", action="SET", min_bet=UNSET)
        for k in ("minBet", "maxBet", "maxTableRound", "maxUserDay", "maxLossPerDay", "customChips"):
            self.assertNotIn(k, sent_payloads[-1])
        cap_client.update_player_limits(
            username="p1",
            currency="USD",
            action="SET",
            min_bet=None,
            max_bet=None,
            max_table_round=None,
            max_user_day=None,
            max_loss_per_day=None,
            custom_chips=None,
        )
        for k in ("minBet", "maxBet", "maxTableRound", "maxUserDay", "maxLossPerDay", "customChips"):
            self.assertIn(k, sent_payloads[-1])
            self.assertIsNone(sent_payloads[-1][k])

        # Simulated mid-body HTTPError read failure raises retryable BaccaratSdkError(SC_OPERATOR_TIMEOUT)
        import io
        import urllib.error
        from unittest import mock
        import baccarat_sdk as _sdk_mod

        closed_flag = {"closed": False}

        class BrokenHttpError(urllib.error.HTTPError):
            def read(self, amt: int = -1) -> bytes:
                raise ConnectionResetError("connection reset mid-body")

            def close(self) -> None:
                closed_flag["closed"] = True

        broken_err = BrokenHttpError("http://127.0.0.1/operator/v1/ping", 502, "Bad Gateway", {}, io.BytesIO(b"x"))  # type: ignore[arg-type]
        with mock.patch.object(_sdk_mod._NO_REDIRECT_OPENER, "open", side_effect=broken_err):
            default_client = Client(Config(api_key=api_key, hmac_secret=secret, base_url="http://127.0.0.1:9"))
            with self.assertRaises(BaccaratSdkError) as ctx_read_err:
                default_client.ping(trace_id="t_httperr_read")
            self.assertNotIsInstance(ctx_read_err.exception, BaccaratApiError)
            self.assertEqual(ctx_read_err.exception.code, StatusCode.SC_OPERATOR_TIMEOUT)
            self.assertTrue(is_retryable_status(ctx_read_err.exception.code))
            self.assertTrue(closed_flag["closed"])


if __name__ == "__main__":
    unittest.main()
