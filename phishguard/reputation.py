"""Domen va URL reputatsiyasi uchun umumiy ma’lumotlar va yordamchi funksiyalar."""
from __future__ import annotations

import ipaddress
import os
import re
from functools import lru_cache
from urllib.parse import urlsplit

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com",
    "gmx.net", "mail.com", "zoho.com", "yandex.ru", "yandex.com", "ya.ru", "mail.ru", "inbox.ru", "list.ru",
    "bk.ru", "rambler.ru", "tutanota.com",
}

URL_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "tiny.cc", "s.id", "t.ly", "clck.ru", "qps.ru", "bitly.com", "lnkd.in", "v.gd",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work", "click", "country", "kim", "loan", "men",
    "racing", "review", "stream", "download", "win", "bid", "party", "date", "faith", "cricket", "science",
    "accountant", "rest", "icu", "cyou", "buzz", "monster", "sbs", "cfd", "lol", "quest",
}

# Qonuniy maqsadlarda ham ishlatiladi, lekin phishingda tez-tez uchraydi — kichikroq ball
MEDIUM_TLDS = {"online", "site", "info", "live", "shop", "store", "website", "space", "fun", "pw", "cc", "ws", "su", "app", "link"}

# Taniqli brendlar va ularning rasmiy domenlari (xalqaro va O‘zbekiston)
BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"],
    "office365": ["office.com", "microsoft.com"], "outlook": ["outlook.com", "live.com"], "google": ["google.com", "gmail.com", "youtube.com"],
    "apple": ["apple.com", "icloud.com"], "icloud": ["icloud.com", "apple.com"], "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"], "facebook": ["facebook.com", "fb.com", "meta.com"], "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"], "telegram": ["telegram.org", "t.me"], "linkedin": ["linkedin.com"], "dhl": ["dhl.com"],
    "fedex": ["fedex.com"], "ups": ["ups.com"], "docusign": ["docusign.com", "docusign.net"], "dropbox": ["dropbox.com"],
    "wellsfargo": ["wellsfargo.com"], "chase": ["chase.com"], "bankofamerica": ["bankofamerica.com"], "binance": ["binance.com"],
    "coinbase": ["coinbase.com"], "steam": ["steampowered.com", "steamcommunity.com"],
    # O‘zbekiston
    "uzcard": ["uzcard.uz"], "humo": ["humocard.uz", "humo.uz"], "payme": ["payme.uz", "paycom.uz"], "click": ["click.uz"],
    "kapitalbank": ["kapitalbank.uz"], "hamkorbank": ["hamkorbank.uz"], "ipakyulibank": ["ipakyulibank.uz"],
    "agrobank": ["agrobank.uz"], "xalqbank": ["xb.uz"], "nbu": ["nbu.uz"], "anorbank": ["anorbank.uz"], "tbc": ["tbcbank.uz"],
    "soliq": ["soliq.uz"], "mygov": ["my.gov.uz", "gov.uz"], "beeline": ["beeline.uz"], "ucell": ["ucell.uz"],
    "uzmobile": ["uztelecom.uz", "uzmobile.uz"], "uzum": ["uzum.uz", "uzumbank.uz"], "olx": ["olx.uz", "olx.com"],
}
BRAND_DOMAINS = sorted({d for ds in BRANDS.values() for d in ds})
# Oddiy so‘z bo‘lishi mumkin bo‘lgan brend nomlari — faqat alohida token sifatida tekshiriladi
# Juda keng tarqalgan so‘z — faqat yozilishi o‘xshash domen orqali tekshiriladi
NO_TOKEN_BRANDS = {"click"}
GENERIC_BRANDS = {"click", "steam", "apple", "chase", "humo", "soliq", "outlook", "google", "telegram"}


def host_of(url: str) -> str:
    url = (url or "").strip()
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    return host.lower().strip(".")


def registered_domain(host: str) -> str:
    """Soddalashtirilgan ro‘yxatdan o‘tgan domen (eTLD+1). Masalan: login.paypal.com.evil.xyz → evil.xyz."""
    host = (host or "").lower().strip(".")
    if not host or is_ip(host):
        return host
    parts = host.split(".")
    two_level = {"co.uk", "com.au", "co.jp", "com.br", "gov.uz", "com.tr", "co.in", "org.uk", "ac.uk", "edu.uz", "com.ru", "org.ru"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_impersonation(host: str) -> str | None:
    """Domen taniqli brendga o‘xshatilgan, lekin rasmiy emasligini aniqlaydi. Brend nomini qaytaradi."""
    host = (host or "").lower()
    if not host or is_ip(host):
        return None
    reg = registered_domain(host)
    if reg in BRAND_DOMAINS or any(host == d or host.endswith("." + d) for d in BRAND_DOMAINS):
        return None
    reg_label = reg.split(".")[0]
    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    for brand, domains in BRANDS.items():
        # 1) brend nomi subdomen/domen tarkibida (paypal.com.secure-login.xyz, paypal-security.com)
        if len(brand) >= 4 and brand not in NO_TOKEN_BRANDS and brand in tokens:
            return brand
        if brand not in GENERIC_BRANDS and len(brand) >= 5 and any(
                t != brand and (t.startswith(brand) or t.endswith(brand)) for t in tokens):
            return brand
        # 2) yozilishi o‘xshash domen (paypa1.com, rnicrosoft.com)
        for d in domains:
            d_label = d.split(".")[0]
            if len(d_label) >= 5 and reg_label != d_label and levenshtein(reg_label, d_label) <= 2:
                return brand
            if reg_label.replace("rn", "m").replace("1", "l").replace("0", "o") == d_label and reg_label != d_label:
                return brand
    return None


def _load_list(name: str) -> set[str]:
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}


@lru_cache(maxsize=1)
def blacklist() -> tuple[frozenset, frozenset]:
    """Mahalliy qora ro‘yxat: to‘liq URL'lar va domenlar (data/blacklist.txt, OpenPhish/PhishTank feed)."""
    items = _load_list("blacklist.txt")
    urls = frozenset(i for i in items if "/" in i)
    hosts = frozenset(i for i in items if "/" not in i)
    return urls, hosts


@lru_cache(maxsize=1)
def trusted_domains() -> frozenset:
    """Tashkilot ishonchli deb belgilagan domenlar (data/trusted_domains.txt)."""
    return frozenset(_load_list("trusted_domains.txt"))


def reload_lists() -> None:
    blacklist.cache_clear()
    trusted_domains.cache_clear()
