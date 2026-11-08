"""Elektron xatni tahlil qilish (Parser moduli, diplom ishi 3.2-jadval).

Kirish sifatida quyidagilar qabul qilinadi:
  * xom MIME xabar (.eml fayl yoki sarlavhalari bilan nusxa ko‘chirilgan matn);
  * oddiy matn (faqat xat tanasi) — bu holda sarlavhalar bo‘sh qoladi.
Natijada sarlavha, matn, havolalar, biriktirmalar va autentifikatsiya natijalari ajratiladi.
"""
from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import getaddresses, parseaddr

from .preprocessing import URL_RE, clean_html

HEADER_LINE_RE = re.compile(r"^(From|To|Subject|Date|Reply-To|Return-Path|Received|Message-ID|MIME-Version|Content-Type|Authentication-Results|DKIM-Signature|Received-SPF|X-[\w-]+):", re.I | re.M)


@dataclass
class ParsedEmail:
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    links: list[dict] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    auth_results: str = ""
    received_spf: str = ""
    has_dkim_signature: bool = False
    has_headers: bool = False
    message_id: str = ""

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""

    @property
    def full_text(self) -> str:
        """Model uchun matn: mavzu + tana (HTML tozalangan)."""
        body = self.body_text
        if not body and self.body_html:
            body, _ = clean_html(self.body_html)
        return f"{self.subject}\n{body}".strip()

    def to_dict(self) -> dict:
        return {
            "subject": self.subject, "from_name": self.from_name, "from_addr": self.from_addr,
            "reply_to": self.reply_to, "return_path": self.return_path, "to": self.to,
            "links": self.links, "attachments": self.attachments, "auth_results": self.auth_results,
            "received_spf": self.received_spf, "has_dkim_signature": self.has_dkim_signature,
            "has_headers": self.has_headers, "message_id": self.message_id,
        }


def _looks_like_mime(raw: str) -> bool:
    head = raw.lstrip()[:4000]
    return len(HEADER_LINE_RE.findall(head)) >= 2 and bool(re.search(r"(?im)^(from|subject):", head))


def parse_email(raw: str | bytes, subject: str = "", sender: str = "") -> ParsedEmail:
    """Xom xat yoki oddiy matnni ParsedEmail obyektiga aylantiradi."""
    if isinstance(raw, bytes):
        msg = email.message_from_bytes(raw, policy=policy.default)
        return _from_message(msg)
    raw = raw or ""
    if _looks_like_mime(raw):
        msg = email.message_from_string(raw.lstrip(), policy=policy.default)
        pe = _from_message(msg)
        if subject and not pe.subject:
            pe.subject = subject
        return pe
    # Oddiy matn: faqat tana
    pe = ParsedEmail(subject=subject.strip())
    if sender:
        pe.from_name, pe.from_addr = parseaddr(sender)
        pe.from_addr = pe.from_addr.lower()
    if re.search(r"(?i)<\s*(html|body|div|p|a|table)\b", raw):
        pe.body_html = raw
        pe.body_text, pe.links = clean_html(raw)
    else:
        pe.body_text = raw
    _add_text_links(pe)
    return pe


def _from_message(msg) -> ParsedEmail:
    pe = ParsedEmail(has_headers=True)
    pe.subject = str(msg.get("Subject", "") or "").strip()
    pe.from_name, addr = parseaddr(str(msg.get("From", "") or ""))
    pe.from_addr = addr.lower()
    pe.reply_to = parseaddr(str(msg.get("Reply-To", "") or ""))[1].lower()
    pe.return_path = parseaddr(str(msg.get("Return-Path", "") or ""))[1].lower()
    pe.to = [a for _, a in getaddresses(msg.get_all("To", []) or [])]
    pe.auth_results = " ".join(str(h) for h in (msg.get_all("Authentication-Results", []) or []))
    pe.received_spf = " ".join(str(h) for h in (msg.get_all("Received-SPF", []) or []))
    pe.has_dkim_signature = msg.get("DKIM-Signature") is not None
    pe.message_id = str(msg.get("Message-ID", "") or "")

    texts, htmls = [], []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.is_multipart():
            continue
        disp = (part.get_content_disposition() or "").lower()
        fname = part.get_filename()
        if disp == "attachment" or (fname and disp != "inline"):
            if fname:
                pe.attachments.append(fname)
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:  # noqa: BLE001 — buzilgan kodlash
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            htmls.append(content)
        elif ctype == "text/plain":
            texts.append(content)
    pe.body_html = "\n".join(htmls)
    html_text, html_links = clean_html(pe.body_html) if pe.body_html else ("", [])
    pe.body_text = "\n".join(texts) or html_text
    pe.links = html_links
    _add_text_links(pe)
    return pe


def _add_text_links(pe: ParsedEmail) -> None:
    known = {l["href"] for l in pe.links}
    for m in URL_RE.finditer(pe.body_text or ""):
        url = m.group(0).rstrip(".,;:!?")
        if url not in known:
            pe.links.append({"href": url, "text": url})
            known.add(url)
