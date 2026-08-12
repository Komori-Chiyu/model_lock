"""Offline activation-code ledger (artist side, local SQLite)."""

from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path
from typing import List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS codes (
    code       TEXT PRIMARY KEY,
    model_id   TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active',
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""


class LedgerError(Exception):
    pass


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def gen_codes(self, model_id: str, key_id: str, note: str = "", count: int = 1) -> List[str]:
        import time
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        codes = []
        with self.conn:
            for _ in range(count):
                code = "ML-" + secrets.token_hex(8).upper()
                self.conn.execute(
                    "INSERT INTO codes(code, model_id, key_id, status, note, created_at) "
                    "VALUES (?,?,?,'active',?,?)",
                    (code, model_id, key_id, note, now),
                )
                codes.append(code)
        return codes

    def get(self, code: str) -> Optional[sqlite3.Row]:
        self.conn.row_factory = sqlite3.Row
        row = self.conn.execute("SELECT * FROM codes WHERE code = ?", (code,)).fetchone()
        return row

    def mark_used(self, code: str) -> None:
        with self.conn:
            self.conn.execute("UPDATE codes SET status='used' WHERE code = ?", (code,))

    def list_codes(
        self,
        model_id: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> List[sqlite3.Row]:
        """列出授权码；start/end 为 "YYYY-MM-DD"（含端点），按 created_at 过滤。"""
        self.conn.row_factory = sqlite3.Row
        conds, args = [], []
        if model_id:
            conds.append("model_id = ?")
            args.append(model_id)
        if start:
            conds.append("created_at >= ?")
            args.append(start)
        if end:
            from datetime import date, timedelta

            end_day = date.fromisoformat(end) + timedelta(days=1)
            conds.append("created_at < ?")
            args.append(end_day.isoformat())
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        return self.conn.execute(
            f"SELECT * FROM codes{where} ORDER BY created_at", args
        ).fetchall()

    def validate_and_consume(self, code: str, key_id: str) -> None:
        row = self.get(code)
        if row is None:
            raise LedgerError("activation code not found in ledger")
        if row["status"] != "active":
            raise LedgerError("activation code is not active")
        if row["key_id"].lower() != key_id.lower():
            raise LedgerError("activation code is bound to a different buyer key")
        self.mark_used(code)
