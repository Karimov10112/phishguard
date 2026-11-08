"""Domen va jo‘natuvchi tekshiruvi — S_Domain komponenti (diplom ishi, 3.4-band).

Tekshiriladi: bepul pochta xizmati, brendga o‘xshatilgan domen, Reply-To / Return-Path nomuvofiqligi,
jo‘natuvchi nomi bilan domen mos kelmasligi, SPF / DKIM / DMARC natijalari va shubhali TLD.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .email_parser import ParsedEmail
from .reputation import (FREE_MAIL, MEDIUM_TLDS, SUSPICIOUS_TLDS, blacklist, brand_impersonation, registered_domain,
                         trusted_domains)

ROLE_WORDS = re.compile(r"(?i)\b(support|security|service|admin|administrator|helpdesk|it|billing|account|team|"
                        r"bank|ceo|cfo|director|hr|payroll|xavfsizlik|qo‘llab|bank|direktor|rahbar|служба|поддержка|банк)\b")


@dataclass
class DomainReport:
    domain: str
    score: float
    reasons: list[str] = field(default_factory=list)
    auth: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"domain": self.domain, "score": round(self.score, 3), "reasons": self.reasons, "auth": self.auth}


def _auth_result(text: str, mech: str) -> str:
    m = re.search(rf"(?i)\b{mech}\s*=\s*([a-z]+)", text or "")
    return m.group(1).lower() if m else ""


def analyze_sender(pe: ParsedEmail) -> DomainReport:
    domain = pe.from_domain
    reasons: list[str] = []
    score = 0.0

    def add(points: float, why: str) -> None:
        nonlocal score
        score += points
        reasons.append(why)

    auth_text = f"{pe.auth_results} {pe.received_spf}"
    spf = _auth_result(auth_text, "spf") or (re.match(r"\s*(pass|fail|softfail|neutral|none)", pe.received_spf or "", re.I) or [None, ""])[1].lower()
    dkim = _auth_result(auth_text, "dkim")
    dmarc = _auth_result(auth_text, "dmarc")
    auth = {"spf": spf or "—", "dkim": dkim or ("signature" if pe.has_dkim_signature else "—"), "dmarc": dmarc or "—"}

    if not domain:
        return DomainReport("", 0.0, ["Jo‘natuvchi manzili ko‘rsatilmagan — domen tekshiruvi o‘tkazilmadi"], auth)

    reg = registered_domain(domain)
    bl_urls, bl_hosts = blacklist()
    if domain in bl_hosts or reg in bl_hosts:
        return DomainReport(domain, 1.0, ["Jo‘natuvchi domeni qora ro‘yxatda"], auth)
    if reg in trusted_domains() or domain in trusted_domains():
        if spf not in ("fail", "softfail") and dmarc != "fail":
            return DomainReport(domain, 0.0, ["Tashkilotning ishonchli domenlar ro‘yxatida"], auth)

    if reg in FREE_MAIL:
        add(0.30, f"Bepul pochta xizmati ({reg}) — korporativ xatlar odatda bunday manzildan yuborilmaydi")
        if pe.from_name and ROLE_WORDS.search(pe.from_name):
            add(0.30, f"Jo‘natuvchi nomi “{pe.from_name}” rasmiy tashkilotga o‘xshatilgan, lekin manzil bepul pochtada")
    brand = brand_impersonation(domain)
    if brand:
        add(0.50, f"Jo‘natuvchi domeni “{brand}” brendiga o‘xshatilgan, lekin rasmiy emas")
    elif pe.from_name:
        nb = brand_impersonation(re.sub(r"[^a-z0-9.-]", "", pe.from_name.lower().replace(" ", "")) + ".invalid")
        if nb and reg not in FREE_MAIL:
            add(0.30, f"Jo‘natuvchi nomida “{nb}” brendi, lekin domen boshqa ({reg})")
    if domain.startswith("xn--") or ".xn--" in domain:
        add(0.40, "Punycode (xn--) domen")
    tld = domain.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        add(0.15, f"Shubhali TLD: .{tld}")
    elif tld in MEDIUM_TLDS:
        add(0.10, f"Phishingda ko‘p uchraydigan domen zonasi: .{tld}")
    if pe.reply_to and registered_domain(pe.reply_to.rsplit("@", 1)[-1]) != reg:
        add(0.30, f"Javob manzili (Reply-To: {pe.reply_to}) boshqa domenga yo‘naltirilgan")
    if pe.return_path and "@" in pe.return_path and registered_domain(pe.return_path.rsplit("@", 1)[-1]) != reg:
        add(0.10, f"Return-Path ({pe.return_path}) jo‘natuvchi domeniga mos emas")

    if spf in ("fail", "softfail"):
        add(0.30, f"SPF tekshiruvidan o‘tmagan (spf={spf})")
    if dkim == "fail":
        add(0.25, "DKIM imzosi yaroqsiz (dkim=fail)")
    if dmarc == "fail":
        add(0.35, "DMARC siyosatiga mos emas (dmarc=fail)")
    if spf == "pass" and dkim == "pass" and score > 0:
        reasons.append("Eslatma: SPF/DKIM “pass” — bu faqat jo‘natuvchini tasdiqlaydi, xat mazmuni xavfsizligini emas")

    return DomainReport(domain, min(score, 1.0), reasons, auth)
