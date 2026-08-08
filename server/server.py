"""ModelLock authorization server (stdlib only: http.server + sqlite3 + hmac).

Run:
    python3 server/server.py --db /path/to/model_lock.db --port 8787

Environment:
    MODELOCK_ADMIN_KEY   artist admin key (if unset, a random one is printed)
    MODELOCK_SECRET      token signing secret (if unset, random per process)
    MODELOCK_TOKEN_TTL   session TTL seconds (default 43200 = 12 h)
    MODELOCK_MAX_DEVICES default device limit per code (default 1)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS models (
    model_id   TEXT PRIMARY KEY,
    title      TEXT NOT NULL DEFAULT '',
    artist_note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS codes (
    code        TEXT PRIMARY KEY,
    model_id    TEXT NOT NULL,
    max_devices INTEGER NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'active',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    code       TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    pubkey_spki TEXT NOT NULL,
    hwids      TEXT NOT NULL DEFAULT '{}',
    bound_at   TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (code, device_id)
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    code       TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str, what: str = "base64") -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError(f"invalid {what}") from exc


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code


class Store:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def _row(self, sql: str, args: Tuple = ()) -> Optional[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, args).fetchone()

    def _all(self, sql: str, args: Tuple = ()) -> list:
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def _exec(self, sql: str, args: Tuple = ()) -> None:
        with self.lock:
            self.conn.execute(sql, args)
            self.conn.commit()

    # ---- codes ----
    def create_codes(self, model_id: str, count: int, max_devices: int, note: str) -> list:
        now = utcnow()
        codes = []
        with self.lock:
            for _ in range(count):
                code = "ML-" + secrets.token_hex(8).upper()
                self.conn.execute(
                    "INSERT INTO codes(code, model_id, max_devices, status, note, created_at) "
                    "VALUES (?,?,?, 'active', ?, ?)",
                    (code, model_id, max_devices, note, now),
                )
                codes.append(code)
            self.conn.commit()
        return codes

    def get_code(self, code: str) -> Optional[sqlite3.Row]:
        return self._row("SELECT * FROM codes WHERE code = ?", (code,))

    def list_codes(self, model_id: Optional[str]) -> list:
        if model_id:
            return self._all("SELECT * FROM codes WHERE model_id = ? ORDER BY created_at", (model_id,))
        return self._all("SELECT * FROM codes ORDER BY created_at")

    def set_code_status(self, code: str, status: str) -> None:
        self._exec("UPDATE codes SET status = ? WHERE code = ?", (status, code))

    # ---- devices ----
    def get_device(self, code: str, device_id: str) -> Optional[sqlite3.Row]:
        return self._row(
            "SELECT * FROM devices WHERE code = ? AND device_id = ?", (code, device_id)
        )

    def list_devices(self, code: str) -> list:
        return self._all("SELECT * FROM devices WHERE code = ?", (code,))

    def bind_device(self, code: str, device_id: str, spki: str, hwids: str) -> None:
        now = utcnow()
        self._exec(
            "INSERT OR REPLACE INTO devices(code, device_id, pubkey_spki, hwids, bound_at, last_seen, revoked) "
            "VALUES (?,?,?,?,?,?,0)",
            (code, device_id, spki, hwids, now, now),
        )

    def touch_device(self, code: str, device_id: str) -> None:
        self._exec(
            "UPDATE devices SET last_seen = ? WHERE code = ? AND device_id = ?",
            (utcnow(), code, device_id),
        )

    def revoke_device(self, code: str, device_id: Optional[str]) -> int:
        if device_id:
            self._exec(
                "UPDATE devices SET revoked = 1 WHERE code = ? AND device_id = ?",
                (code, device_id),
            )
        else:
            self._exec("UPDATE devices SET revoked = 1 WHERE code = ?", (code,))
        return 0

    # ---- sessions ----
    def create_session(self, token: str, code: str, device_id: str, expires_at: int) -> None:
        self._exec(
            "INSERT OR REPLACE INTO sessions(token, code, device_id, expires_at, created_at) VALUES (?,?,?,?,?)",
            (token, code, device_id, expires_at, utcnow()),
        )

    def get_session(self, token: str) -> Optional[sqlite3.Row]:
        return self._row("SELECT * FROM sessions WHERE token = ?", (token,))

    def delete_session(self, token: str) -> None:
        self._exec("DELETE FROM sessions WHERE token = ?", (token,))

    def purge_expired(self, now: int) -> None:
        self._exec("DELETE FROM sessions WHERE expires_at < ?", (now,))


class TokenCodec:
    def __init__(self, secret: bytes):
        self.secret = secret

    def issue(self, code: str, device_id: str, ttl: int) -> Tuple[str, int]:
        exp = int(time.time()) + ttl
        payload = b64e(json.dumps(
            {"code": code, "device_id": device_id, "exp": exp, "n": secrets.token_hex(8)},
            separators=(",", ":"),
        ).encode("utf-8"))
        sig = hmac.new(self.secret, payload.encode("ascii"), hashlib.sha256).digest()
        return f"{payload}.{b64e(sig)}", exp

    def verify(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload_b64, sig_b64 = token.split(".", 1)
            expected = hmac.new(self.secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, b64d(sig_b64, "signature")):
                return None
            payload = json.loads(b64d(payload_b64, "payload").decode("utf-8"))
            if int(payload.get("exp", 0)) < int(time.time()):
                return None
            return payload
        except Exception:
            return None


def validate_device_key(spki_b64: str) -> str:
    """Validate an RSA-2048 SPKI and return its normalized b64 form."""
    der = b64d(spki_b64, "pubkey_spki")
    try:
        pub = serialization.load_der_public_key(der)
    except Exception as exc:
        raise ApiError(400, "BAD_PUBKEY", "invalid public key") from exc
    if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size != 2048:
        raise ApiError(400, "BAD_PUBKEY", "expected RSA-2048 public key")
    return b64e(der)


class ModelLockServer:
    def __init__(self, store: Store, admin_key: str, secret: bytes, token_ttl: int):
        self.store = store
        self.admin_key = admin_key
        self.tokens = TokenCodec(secret)
        self.token_ttl = token_ttl

    # ---------- admin ----------
    def admin_create_codes(self, body: Dict) -> Dict:
        self._require_admin(body)
        model_id = str(body.get("model_id", "")).strip()
        if not model_id:
            raise ApiError(400, "BAD_REQUEST", "model_id is required")
        count = int(body.get("count", 1))
        if not 1 <= count <= 1000:
            raise ApiError(400, "BAD_REQUEST", "count must be 1..1000")
        max_devices = int(body.get("max_devices", 1))
        if not 1 <= max_devices <= 5:
            raise ApiError(400, "BAD_REQUEST", "max_devices must be 1..5")
        note = str(body.get("note", ""))
        codes = self.store.create_codes(model_id, count, max_devices, note)
        return {"ok": True, "model_id": model_id, "codes": codes}

    def admin_list(self, body: Dict) -> Dict:
        self._require_admin(body)
        model_id = str(body.get("model_id", "")).strip() or None
        out = []
        for row in self.store.list_codes(model_id):
            devices = [dict(d) for d in self.store.list_devices(row["code"])]
            out.append({**dict(row), "devices": devices})
        return {"ok": True, "codes": out}

    def admin_unbind(self, body: Dict) -> Dict:
        self._require_admin(body)
        code = str(body.get("code", "")).strip()
        if not code:
            raise ApiError(400, "BAD_REQUEST", "code is required")
        device_id = str(body.get("device_id", "")).strip() or None
        action = str(body.get("action", "unbind"))
        if action == "unbind":
            if device_id:
                self.store.revoke_device(code, device_id)
                self.store._exec("DELETE FROM sessions WHERE code = ? AND device_id = ?", (code, device_id))
            else:
                self.store.revoke_device(code, None)
                self.store._exec("DELETE FROM sessions WHERE code = ?", (code,))
        elif action == "revoke":
            self.store.set_code_status(code, "revoked")
            self.store._exec("DELETE FROM sessions WHERE code = ?", (code,))
        else:
            raise ApiError(400, "BAD_REQUEST", "action must be unbind or revoke")
        return {"ok": True}

    def _require_admin(self, body: Dict) -> None:
        supplied = str(body.get("admin_key", ""))
        if not hmac.compare_digest(supplied, self.admin_key):
            raise ApiError(403, "FORBIDDEN", "invalid admin key")

    # ---------- client ----------
    def activate(self, body: Dict) -> Dict:
        code = str(body.get("code", "")).strip()
        device_id = str(body.get("device_id", "")).strip()
        spki = validate_device_key(str(body.get("pubkey_spki", "")))
        hwids = body.get("hwids") or {}
        if not code or not device_id:
            raise ApiError(400, "BAD_REQUEST", "code and device_id are required")
        row = self.store.get_code(code)
        if row is None:
            raise ApiError(404, "CODE_NOT_FOUND", "activation code not found")
        if row["status"] != "active":
            raise ApiError(403, "CODE_REVOKED", "activation code is revoked")

        existing = self.store.get_device(code, device_id)
        if existing is not None:
            if existing["revoked"]:
                raise ApiError(403, "DEVICE_REVOKED", "this device is revoked for the code")
            self.store.touch_device(code, device_id)
        else:
            bound = [d for d in self.store.list_devices(code) if not d["revoked"]]
            if len(bound) >= row["max_devices"]:
                raise ApiError(403, "DEVICE_MISMATCH", "code already bound to another device")
            self.store.bind_device(code, device_id, spki, json.dumps(hwids, ensure_ascii=False))

        token, exp = self.tokens.issue(code, device_id, self.token_ttl)
        self.store.create_session(token, code, device_id, exp)
        return {
            "ok": True,
            "token": token,
            "expires_at": exp,
            "model_id": row["model_id"],
            "device_id": device_id,
        }

    def refresh(self, body: Dict) -> Dict:
        payload = self._require_token(body)
        token, exp = self.tokens.issue(payload["code"], payload["device_id"], self.token_ttl)
        self.store.create_session(token, payload["code"], payload["device_id"], exp)
        return {"ok": True, "token": token, "expires_at": exp}

    def status(self, body: Dict) -> Dict:
        payload = self._require_token(body)
        row = self.store.get_code(payload["code"])
        return {
            "ok": True,
            "model_id": row["model_id"] if row else None,
            "device_id": payload["device_id"],
            "expires_at": payload["exp"],
        }

    def _require_token(self, body: Dict) -> Dict:
        token = str(body.get("token", ""))
        payload = self.tokens.verify(token)
        if payload is None:
            raise ApiError(401, "BAD_TOKEN", "invalid or expired token")
        session = self.store.get_session(token)
        if session is None:
            raise ApiError(401, "BAD_TOKEN", "session was revoked")
        device = self.store.get_device(payload["code"], payload["device_id"])
        if device is None or device["revoked"]:
            raise ApiError(403, "DEVICE_REVOKED", "device access revoked")
        code = self.store.get_code(payload["code"])
        if code is None or code["status"] != "active":
            raise ApiError(403, "CODE_REVOKED", "activation code revoked")
        self.store.touch_device(payload["code"], payload["device_id"])
        return payload


def make_handler(api: ModelLockServer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ModelLock/0.1"

        def _send(self, status: int, obj: Dict) -> None:
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self) -> Dict:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0 or length > 1024 * 1024:
                raise ApiError(400, "BAD_REQUEST", "invalid body size")
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception as exc:
                raise ApiError(400, "BAD_REQUEST", "invalid JSON") from exc
            if not isinstance(data, dict):
                raise ApiError(400, "BAD_REQUEST", "expected JSON object")
            return data

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send(200, {"ok": True, "time": utcnow()})
                return
            self._send(404, {"ok": False, "code": "NOT_FOUND"})

        def do_POST(self) -> None:
            try:
                body = self._read_json()
                if self.path == "/api/admin/codes":
                    out = api.admin_create_codes(body)
                elif self.path == "/api/admin/list":
                    out = api.admin_list(body)
                elif self.path == "/api/admin/unbind":
                    out = api.admin_unbind(body)
                elif self.path == "/api/activate":
                    out = api.activate(body)
                elif self.path == "/api/refresh":
                    out = api.refresh(body)
                elif self.path == "/api/status":
                    out = api.status(body)
                else:
                    raise ApiError(404, "NOT_FOUND", "unknown endpoint")
                self._send(200, out)
            except ApiError as exc:
                self._send(exc.status, {"ok": False, "code": exc.code, "message": str(exc)})
            except Exception as exc:  # pragma: no cover - defensive
                self._send(500, {"ok": False, "code": "INTERNAL", "message": str(exc)})

        def log_message(self, fmt, *args):  # quieter logs
            sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ModelLock authorization server")
    parser.add_argument("--db", default=os.environ.get("MODELOCK_DB", "model_lock.db"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MODELOCK_PORT", "8787")))
    args = parser.parse_args(argv)

    admin_key = os.environ.get("MODELOCK_ADMIN_KEY") or ("MLADMIN-" + secrets.token_hex(12))
    secret = os.environ.get("MODELOCK_SECRET") or secrets.token_bytes(32)
    ttl = int(os.environ.get("MODELOCK_TOKEN_TTL", "43200"))

    store = Store(args.db)
    api = ModelLockServer(store, admin_key, secret, ttl)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(api))
    print(f"ModelLock server listening on http://{args.host}:{args.port}")
    print(f"Admin key: {admin_key}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
