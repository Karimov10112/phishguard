"""SMTP kontent-filtr (Postfix after-queue content filter) — diplom ishi, 3.5-band “SMTP proxy sifatida joylashtirish”.

Ishlash tartibi:
    Internet → Postfix (25) → PhishGuard filtr (127.0.0.1:10025) → Postfix qayta qabul (127.0.0.1:10026) → Inbox
Har bir xat tahlil qilinadi va qarorga ko‘ra:
    CLEAN       → X-PhishGuard-* sarlavhalari qo‘shilib, yetkaziladi;
    SUSPICIOUS  → mavzuga “[SHUBHALI]” belgisi va ogohlantirish sarlavhasi qo‘shilib, yetkaziladi (pochta qoidasi bilan karantin papkasiga);
    PHISHING    → yetkazilmaydi, quarantine/ papkasiga .eml sifatida saqlanadi, SOC uchun jurnalga yoziladi.

Ishga tushirish:
    pip install aiosmtpd
    python integrations/smtp_filter.py --listen 127.0.0.1:10025 --relay 127.0.0.1:10026

Postfix sozlamasi (master.cf) namunasi README.md faylida keltirilgan.
"""
from __future__ import annotations

import argparse
import asyncio
import email
import logging
import os
import smtplib
import sys
from email import policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from phishguard.analyzer import analyze  # noqa: E402
from phishguard.storage import Storage  # noqa: E402

log = logging.getLogger("phishguard.smtp")


class PhishGuardHandler:
    def __init__(self, relay_host: str, relay_port: int, quarantine_dir: str, store: Storage | None):
        self.relay = (relay_host, relay_port)
        self.qdir = quarantine_dir
        self.store = store
        os.makedirs(self.qdir, exist_ok=True)

    async def handle_DATA(self, server, session, envelope):  # noqa: N802 — aiosmtpd interfeysi
        raw: bytes = envelope.original_content or envelope.content
        try:
            res = await asyncio.get_running_loop().run_in_executor(None, analyze, raw)
        except Exception as e:  # noqa: BLE001 — filtr xatosi pochtani to‘xtatmasligi kerak
            log.exception("Tahlil xatosi, xat o‘zgarishsiz yetkaziladi: %s", e)
            return self._relay(envelope.mail_from, envelope.rcpt_tos, raw)
        if self.store:
            self.store.save(res, source="smtp")
        verdict, score = res["verdict"], res["risk_score"]
        log.info("%s from=%s subj=%r risk=%.3f verdict=%s", res["id"], res["from_addr"], res["subject"], score, verdict)

        if verdict == "PHISHING":
            path = os.path.join(self.qdir, f"{res['id']}.eml")
            with open(path, "wb") as f:
                f.write(raw)
            log.warning("SOC OGOHLANTIRISH: phishing bloklandi %s (risk=%.3f) → %s", res["from_addr"], score, path)
            return "250 OK: xat PhishGuard tomonidan karantinga olindi"

        msg = email.message_from_bytes(raw, policy=policy.default)
        msg["X-PhishGuard-Score"] = f"{score:.3f}"
        msg["X-PhishGuard-Verdict"] = verdict
        msg["X-PhishGuard-Id"] = res["id"]
        if verdict == "SUSPICIOUS":
            subj = str(msg.get("Subject", ""))
            del msg["Subject"]
            msg["Subject"] = f"[SHUBHALI] {subj}"
            msg["X-PhishGuard-Warning"] = "Ushbu xat shubhali deb topildi. Havolalarni bosmang va ma'lumot yubormang."
        return self._relay(envelope.mail_from, envelope.rcpt_tos, msg.as_bytes())

    def _relay(self, mail_from, rcpt_tos, data: bytes) -> str:
        try:
            with smtplib.SMTP(*self.relay, timeout=30) as s:
                s.sendmail(mail_from, rcpt_tos, data)
            return "250 OK"
        except Exception as e:  # noqa: BLE001
            log.error("Qayta yuborishda xato: %s", e)
            return "451 4.3.0 Vaqtinchalik xato, keyinroq qayta urinib ko‘ring"


def main() -> None:
    from aiosmtpd.controller import Controller  # noqa: PLC0415

    ap = argparse.ArgumentParser(description="PhishGuard SMTP kontent-filtri")
    ap.add_argument("--listen", default="127.0.0.1:10025")
    ap.add_argument("--relay", default="127.0.0.1:10026")
    ap.add_argument("--quarantine", default=os.path.join(ROOT, "quarantine"))
    ap.add_argument("--db", default=os.path.join(ROOT, "instance", "phishguard.db"), help="tahlillarni veb-ilova bazasiga yozish")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    lh, lp = args.listen.rsplit(":", 1)
    rh, rp = args.relay.rsplit(":", 1)
    handler = PhishGuardHandler(rh, int(rp), args.quarantine, Storage(args.db) if args.db else None)
    ctrl = Controller(handler, hostname=lh, port=int(lp))
    ctrl.start()
    log.info("PhishGuard SMTP filtr ishga tushdi: %s → %s", args.listen, args.relay)
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ctrl.stop()


if __name__ == "__main__":
    main()
