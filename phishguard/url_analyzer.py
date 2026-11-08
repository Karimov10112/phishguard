"""URL tekshiruvi moduli — S_URL komponenti (diplom ishi, 3.4-band).

Xabardagi har bir havola qoidalar asosida baholanadi; S_URL — eng xavfli havolaning bali (0..1).
Qora ro‘yxat (OpenPhish / PhishTank feed) bo‘yicha mos kelish darhol 1.0 beradi.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from .reputation import (MEDIUM_TLDS, SUSPICIOUS_TLDS, URL_SHORTENERS, blacklist, brand_impersonation, host_of, is_ip,
                         registered_domain, trusted_domains)

SENSITIVE_WORDS = re.compile(r"(?i)(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|"
                             r"banking|password|wallet|webscr|cmd=|wp-admin|wp-content|invoice|billing|restore|unlock)")
DOMAIN_IN_TEXT = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")


@dataclass
class UrlReport:
    url: str
    host: str
    score: float
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"url": self.url, "host": self.host, "score": round(self.score, 3), "reasons": self.reasons}


def analyze_url(url: str, display_text: str = "") -> UrlReport:
    raw = (url or "").strip()
    low = raw.lower()
    host = host_of(raw)
    reasons: list[str] = []
    score = 0.0

    def add(points: float, why: str) -> None:
        nonlocal score
        score += points
        reasons.append(why)

    if low.startswith(("javascript:", "data:", "vbscript:")):
        return UrlReport(raw, host, 1.0, ["Havola skript yoki ma’lumot sxemasidan foydalanadi (javascript:/data:)"])
    if low.startswith("mailto:") or not host:
        return UrlReport(raw, host, 0.0, [])

    bl_urls, bl_hosts = blacklist()
    if low.rstrip("/") in bl_urls or host in bl_hosts or registered_domain(host) in bl_hosts:
        return UrlReport(raw, host, 1.0, ["Qora ro‘yxatda bor (OpenPhish / PhishTank)"])
    if registered_domain(host) in trusted_domains() or host in trusted_domains():
        return UrlReport(raw, host, 0.0, ["Tashkilotning ishonchli domenlar ro‘yxatida"])

    if is_ip(host):
        add(0.45, "Domen o‘rniga IP-manzil ishlatilgan")
    if host in URL_SHORTENERS or registered_domain(host) in URL_SHORTENERS:
        add(0.30, "Havola qisqartiruvchi xizmat orqali yashirilgan")
    if host.startswith("xn--") or ".xn--" in host:
        add(0.40, "Punycode (xn--) domen — boshqa alifbodagi o‘xshash harflar bo‘lishi mumkin")
    if "@" in (urlsplit(raw).netloc if "://" in raw else ""):
        add(0.40, "URL ichida “@” belgisi — haqiqiy manzil yashirilgan")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        add(0.20, f"Shubhali yuqori darajali domen: .{tld}")
    elif tld in MEDIUM_TLDS:
        add(0.10, f"Phishingda ko‘p uchraydigan domen zonasi: .{tld}")
    if host.count(".") >= 4:
        add(0.15, "Juda ko‘p subdomen")
    brand = brand_impersonation(host)
    if brand:
        add(0.45, f"Domen “{brand}” brendiga o‘xshatilgan, lekin rasmiy domen emas")
    port = None
    try:
        port = urlsplit(raw if "://" in raw else "http://" + raw).port
    except ValueError:
        pass
    if port and port not in (80, 443):
        add(0.15, f"Nostandart port: {port}")
    path = unquote(raw.split(host, 1)[-1]) if host in low else ""
    if SENSITIVE_WORDS.search(path) or SENSITIVE_WORDS.search(host.replace(registered_domain(host), "")):
        add(0.15, "Manzilda kirish/tasdiqlash bilan bog‘liq so‘zlar (login, verify, account...)")
    if low.startswith("http://") and SENSITIVE_WORDS.search(low):
        add(0.10, "Shifrlanmagan HTTP orqali ma’lumot so‘raladi")
    if len(raw) > 120:
        add(0.10, "Haddan tashqari uzun URL")
    if raw.count("//") > 1 and "://" in raw:
        add(0.10, "URL ichida qayta yo‘naltirish (ikkinchi “//”)")

    # Ko‘rinadigan matn boshqa domenni ko‘rsatsa (masalan, matn: paypal.com, havola: evil.xyz)
    if display_text:
        m = DOMAIN_IN_TEXT.search(display_text)
        if m:
            shown = registered_domain(m.group(1).lower())
            if shown and "." in shown and shown != registered_domain(host) and not display_text.strip().lower().startswith(("[rasm]",)):
                add(0.50, f"Havola matni “{m.group(1)}” ni ko‘rsatadi, lekin aslida {host} ga olib boradi")

    return UrlReport(raw, host, min(score, 1.0), reasons)


def analyze_links(links: list[dict]) -> tuple[float, list[UrlReport]]:
    """S_URL: barcha havolalar ichidagi eng yuqori xavf bali va har bir havola bo‘yicha hisobot."""
    reports = [analyze_url(l.get("href", ""), l.get("text", "")) for l in links[:50]]
    reports = [r for r in reports if r.host or r.score > 0]
    s_url = max((r.score for r in reports), default=0.0)
    # Bir nechta shubhali havola bo‘lsa, xavf biroz oshadi
    risky = sum(1 for r in reports if r.score >= 0.3)
    if risky >= 3:
        s_url = min(1.0, s_url + 0.1)
    reports.sort(key=lambda r: r.score, reverse=True)
    return round(s_url, 3), reports
