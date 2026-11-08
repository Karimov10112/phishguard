"""Tahlil natijalari va karantin holatini saqlash (SQLite).

Jadval `analyses`:
    id, created_at, subject, from_addr, verdict, risk, status, feedback, result_json
status: delivered (Inbox) | quarantined (karantin) | blocked (bloklangan) | released (chiqarilgan) | deleted
feedback: NULL | correct | false_positive | false_negative  — modelni qayta o‘qitish uchun (diplom, 3.5-band)
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    subject TEXT,
    from_addr TEXT,
    verdict TEXT NOT NULL,
    risk REAL NOT NULL,
    status TEXT NOT NULL,
    feedback TEXT,
    source TEXT DEFAULT 'web',
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_analyses_created ON analyses(created_at);
CREATE INDEX IF NOT EXISTS ix_analyses_verdict ON analyses(verdict);
"""

STATUS_BY_VERDICT = {"CLEAN": "delivered", "SUSPICIOUS": "quarantined", "PHISHING": "blocked"}
STATUS_UZ = {"delivered": "Inbox’ga yetkazildi", "quarantined": "Karantinda", "blocked": "Bloklangan",
             "released": "Karantindan chiqarilgan", "deleted": "O‘chirilgan"}
FEEDBACK_UZ = {"correct": "To‘g‘ri baholangan", "false_positive": "Xato: aslida xavfsiz", "false_negative": "Xato: aslida phishing"}


class Storage:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        with _lock:
            conn = sqlite3.connect(self.path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def save(self, result: dict, source: str = "web") -> str:
        status = STATUS_BY_VERDICT[result["verdict"]]
        with self._conn() as c:
            c.execute("INSERT INTO analyses (id, created_at, subject, from_addr, verdict, risk, status, source, result_json) "
                      "VALUES (?,?,?,?,?,?,?,?,?)",
                      (result["id"], result["created_at"], result.get("subject", ""), result.get("from_addr", ""),
                       result["verdict"], result["risk_score"], status, source, json.dumps(result, ensure_ascii=False)))
        return result["id"]

    def get(self, aid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM analyses WHERE id=?", (aid,)).fetchone()
        if not row:
            return None
        res = json.loads(row["result_json"])
        res.update({"status": row["status"], "feedback": row["feedback"], "source": row["source"]})
        return res

    def list(self, verdict: str | None = None, q: str | None = None, statuses: tuple | None = None,
             limit: int = 200, offset: int = 0) -> list[dict]:
        sql, args = "SELECT id, created_at, subject, from_addr, verdict, risk, status, feedback, source FROM analyses WHERE 1=1", []
        if verdict:
            sql += " AND verdict=?"
            args.append(verdict)
        if statuses:
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            args += list(statuses)
        if q:
            sql += " AND (subject LIKE ? OR from_addr LIKE ?)"
            args += [f"%{q}%", f"%{q}%"]
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    def set_status(self, aid: str, status: str) -> bool:
        if status not in STATUS_UZ:
            raise ValueError(status)
        with self._conn() as c:
            return c.execute("UPDATE analyses SET status=? WHERE id=?", (status, aid)).rowcount > 0

    def set_feedback(self, aid: str, feedback: str) -> bool:
        if feedback not in FEEDBACK_UZ:
            raise ValueError(feedback)
        with self._conn() as c:
            return c.execute("UPDATE analyses SET feedback=? WHERE id=?", (feedback, aid)).rowcount > 0

    def stats(self) -> dict:
        with self._conn() as c:
            by_verdict = {r["verdict"]: r["n"] for r in c.execute("SELECT verdict, COUNT(*) n FROM analyses GROUP BY verdict")}
            by_status = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM analyses GROUP BY status")}
            fb = {r["feedback"]: r["n"] for r in c.execute("SELECT feedback, COUNT(*) n FROM analyses WHERE feedback IS NOT NULL GROUP BY feedback")}
            hist = [0] * 10
            for r in c.execute("SELECT risk FROM analyses"):
                hist[min(int(r["risk"] * 10), 9)] += 1
            daily = [dict(r) for r in c.execute(
                "SELECT substr(created_at,1,10) d, COUNT(*) n, SUM(verdict!='CLEAN') bad FROM analyses GROUP BY d ORDER BY d DESC LIMIT 14")]
        total = sum(by_verdict.values())
        return {"total": total, "by_verdict": by_verdict, "by_status": by_status, "feedback": fb,
                "risk_hist": hist, "daily": list(reversed(daily))}

    def feedback_rows(self) -> list[dict]:
        """Qayta o‘qitish uchun: tahlilchi tasdiqlagan belgilar bilan xatlar matni."""
        out = []
        with self._conn() as c:
            for r in c.execute("SELECT result_json, verdict, feedback FROM analyses WHERE feedback IS NOT NULL"):
                res = json.loads(r["result_json"])
                if r["feedback"] == "correct":
                    label = 0 if r["verdict"] == "CLEAN" else 1
                else:
                    label = 0 if r["feedback"] == "false_positive" else 1
                out.append({"text": f"{res.get('subject', '')}\n{res.get('body_excerpt', '')}", "label": label})
        return out
