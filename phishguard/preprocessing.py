"""Matnni dastlabki ishlov berish moduli (diplom ishi, 2.2-band va A-ilova).

Bosqichlar:
  1. HTML tozalash — teglar, CSS va JavaScript olib tashlanadi, havolalar alohida saqlanadi;
  2. Unicode normalizatsiyasi — ko‘rinishi o‘xshash (homoglyph) kirill/yunon harflari lotinga o‘tkaziladi;
  3. Statistik modellar uchun: kichik harflar, URL/e-pochta/sonlarni maxsus tokenlarga almashtirish.
Transformer (semantik) modeli uchun faqat 1–2-bosqichlar qo‘llaniladi.
"""
from __future__ import annotations

import html
import re
import unicodedata

from bs4 import BeautifulSoup

# Ko‘rinishi lotin harfiga o‘xshash kirill va yunon belgilar (homoglyph)
HOMOGLYPHS = {
    # kirill
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I",
    # yunon
    "ο": "o", "α": "a", "ρ": "p", "ι": "i", "Ο": "O",
    "Α": "A", "Β": "B", "Ε": "E", "Κ": "K", "Μ": "M",
}
_HOMO_TABLE = str.maketrans(HOMOGLYPHS)
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()\[\]]+")
EMAIL_RE = re.compile(r"(?i)\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
NUM_RE = re.compile(r"\b\d[\d.,]*\b")
NON_ALPHA_RE = re.compile(r"[^a-zЀ-ӿ‘’'\s]")
SPACES_RE = re.compile(r"\s+")
APOS_RE = re.compile(r"[\u2018\u2019\u02bb\u02bc`\u00b4]")  # o‘, g‘, tutuq belgisining turli yozilishi → '


def unify_apostrophes(text: str) -> str:
    return APOS_RE.sub("'", text or "")


def looks_like_html(text: str) -> bool:
    return bool(re.search(r"(?i)<\s*(html|body|div|p|a|table|br|span|font)\b", text or ""))


def clean_html(raw: str) -> tuple[str, list[dict]]:
    """HTML dan ko‘rinadigan matnni va havolalarni (href + ko‘rinadigan matn) ajratadi."""
    if not raw:
        return "", []
    if not looks_like_html(raw):
        return html.unescape(raw), []
    soup = BeautifulSoup(raw, "html.parser")
    for tag in soup(["script", "style", "noscript", "head", "title", "meta"]):
        tag.decompose()
    links = []
    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        if href:
            links.append({"href": href, "text": a.get_text(" ", strip=True)})
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        if src.startswith("http"):
            links.append({"href": src, "text": "[rasm]", "image": True})
    text = soup.get_text(separator=" ")
    return text, links


def normalize_unicode(text: str) -> str:
    """NFKC normalizatsiya, ko‘rinmas belgilarni olib tashlash va homoglyphlarni almashtirish."""
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH)

    def _fix(m: re.Match) -> str:
        word = m.group(0)
        # Faqat aralash yozuvli so‘zlar (masalan, "pаypal": lotin + kirill "а") tuzatiladi;
        # sof ruscha matn o‘zgarmaydi.
        if _has_latin(word) and any(ch in HOMOGLYPHS for ch in word):
            return word.translate(_HOMO_TABLE)
        return word

    return re.sub(r"\w+", _fix, text)


def _has_latin(word: str) -> bool:
    return any("a" <= ch.lower() <= "z" for ch in word)


def count_homoglyphs(text: str) -> int:
    """Lotin so‘zlari ichiga aralashtirilgan kirill/yunon belgilar sonini hisoblaydi."""
    n = 0
    for word in re.findall(r"\w+", text or ""):
        if _has_latin(word):
            n += sum(1 for ch in word if ch in HOMOGLYPHS)
    return n


def normalize_for_ml(text: str) -> str:
    """Statistik modellar (TF-IDF + XGBoost) uchun to‘liq tozalash.

    O‘quv dataseti va real xatlar bir xil ko‘rinishga keltiriladi:
    URL → `urltoken`, e-pochta → `emailtoken`, son → `numtoken`.
    """
    text, _ = clean_html(text or "")
    text = unify_apostrophes(normalize_unicode(text))
    text = text.lower()
    text = URL_RE.sub(" urltoken ", text)
    text = EMAIL_RE.sub(" emailtoken ", text)
    text = NUM_RE.sub(" numtoken ", text)
    text = NON_ALPHA_RE.sub(" ", text)
    return SPACES_RE.sub(" ", text).strip()


def normalize_for_semantic(text: str) -> str:
    """Semantik model uchun minimal tozalash: HTML va homoglyph normalizatsiyasi."""
    text, _ = clean_html(text or "")
    text = unify_apostrophes(normalize_unicode(text))
    text = URL_RE.sub(" urltoken ", text)
    return SPACES_RE.sub(" ", text).strip()
