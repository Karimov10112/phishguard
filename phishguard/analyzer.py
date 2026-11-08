"""Tahlil konveyeri (Data Pipeline, diplom ishi 3.1-rasm):

  1. Kiruvchi xat (SMTP / veb-forma / API)  →  2. Parsing (MIME)  →  3. NLP dastlabki ishlov
  →  4. Klassifikatorlar: XGBoost (P_ML) va semantik model (P_BERT), domen (S_Domain), URL (S_URL)
  →  5. Gibrid Risk Score va karantin qarori
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime

from .domain_analyzer import analyze_sender
from .email_parser import ParsedEmail, parse_email
from .lexicons import DRIVERS, driver_hits
from .models import get_ml_model, get_semantic_model
from .preprocessing import count_homoglyphs, normalize_unicode
from .reputation import FREE_MAIL, registered_domain
from .risk import HIGH_THRESHOLD, LOW_THRESHOLD, VERDICTS, WEIGHTS, decide, risk_score
from .url_analyzer import analyze_links

DANGEROUS_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".com", ".pif", ".jar", ".msi", ".hta", ".iso",
                 ".img", ".lnk", ".html", ".htm", ".docm", ".xlsm", ".pptm", ".ps1", ".wsf")
ARCHIVE_EXT = (".zip", ".rar", ".7z", ".gz", ".tar", ".cab")


def _attachment_risk(names: list[str]) -> tuple[float, list[str]]:
    score, reasons = 0.0, []
    for n in names:
        low = n.lower()
        if low.endswith(DANGEROUS_EXT):
            score = max(score, 0.7)
            reasons.append(f"Xavfli biriktirma turi: {n}")
        elif low.endswith(ARCHIVE_EXT):
            score = max(score, 0.3)
            reasons.append(f"Arxiv biriktirma (ichida zararli fayl bo‘lishi mumkin): {n}")
        if low.count(".") >= 2 and low.rsplit(".", 1)[-1] in {"exe", "js", "scr", "vbs", "bat"}:
            score = max(score, 0.9)
            reasons.append(f"Ikki kengaytmali fayl nomi (masalan, .pdf.exe): {n}")
    return score, reasons


def analyze(raw: str | bytes, subject: str = "", sender: str = "") -> dict:
    t0 = time.perf_counter()
    pe: ParsedEmail = parse_email(raw, subject=subject, sender=sender)
    text = pe.full_text
    if not text.strip() and not pe.links:
        raise ValueError("Xat matni bo‘sh — tahlil uchun matn kiriting")

    p_ml, ml_explain = get_ml_model().predict(text)
    sem = get_semantic_model()
    p_bert = sem.predict(text)
    dom = analyze_sender(pe)
    s_url, url_reports = analyze_links(pe.links)
    att_score, att_reasons = _attachment_risk(pe.attachments)
    s_url_eff = max(s_url, att_score)

    drivers = driver_hits(normalize_unicode(text))

    # Korrelyatsiya qoidalari (SIEM uslubida): alohida zaif belgilar birgalikda kuchli xavf bildiradi
    dom_score, dom_reasons = dom.score, list(dom.reasons)
    if "credentials" in drivers and pe.links:
        external = [r for r in url_reports if r.host and r.score < 1.0
                    and registered_domain(r.host) != registered_domain(pe.from_domain or "-")]
        if external:
            s_url_eff = max(s_url_eff, min(1.0, external[0].score + 0.35))
            external[0].reasons.append(
                "Xat parol yoki shaxsiy ma’lumot so‘raydi va tashqi saytga yo‘naltiradi (credential harvesting)")
    if registered_domain(pe.from_domain or "") in FREE_MAIL and "financial" in drivers and (
            "urgency" in drivers or "secrecy" in drivers):
        dom_score = min(1.0, dom_score + 0.30)
        dom_reasons.append("BEC belgisi: bepul pochtadan pul o‘tkazish so‘rovi + shoshilinchlik/maxfiylik talabi")

    score = risk_score(p_ml, p_bert, dom_score, s_url_eff)
    verdict = decide(score)
    homoglyphs = count_homoglyphs(text)

    components = []
    for key, title, value, desc in (
        ("ml", "P_ML — XGBoost", p_ml, "TF-IDF (1–2 gramm) belgilari asosida statistik klassifikator"),
        ("bert", "P_BERT — semantik niyat", p_bert, sem.title),
        ("domain", "S_Domain — jo‘natuvchi domeni", dom_score, "Domen reputatsiyasi, SPF/DKIM/DMARC, Reply-To"),
        ("url", "S_URL — havolalar va fayllar", s_url_eff, "IP, qisqartiruvchi, brendga o‘xshash domen, qora ro‘yxat"),
    ):
        components.append({"key": key, "title": title, "value": round(value, 3), "weight": WEIGHTS[key],
                           "weighted": round(WEIGHTS[key] * value, 3), "desc": desc})

    warnings = []
    if homoglyphs:
        warnings.append(f"Matnda {homoglyphs} ta ko‘rinishi o‘xshash (homoglyph) belgi topildi — filtrni aldash urinishi")
    warnings += att_reasons
    if not pe.has_headers:
        warnings.append("Faqat xat matni kiritildi: sarlavhalar (SPF/DKIM, Reply-To) bo‘lmagani uchun domen tekshiruvi cheklangan. "
                        "To‘liq tahlil uchun .eml faylni yuklang.")

    v = VERDICTS[verdict]
    return {
        "id": uuid.uuid4().hex[:12],
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "subject": pe.subject or "(mavzusiz)",
        "from_name": pe.from_name, "from_addr": pe.from_addr,
        "risk_score": round(score, 3),
        "verdict": verdict, "verdict_label": v["label"], "action": v["action"], "action_uz": v["action_uz"],
        "color": v["color"],
        "thresholds": {"low": LOW_THRESHOLD, "high": HIGH_THRESHOLD},
        "components": components,
        "ml_explain": ml_explain,
        "drivers": [{"key": k, "name": DRIVERS[k]["name"], "hits": h} for k, h in drivers.items()],
        "domain": {**dom.to_dict(), "score": round(dom_score, 3), "reasons": dom_reasons},
        "urls": [r.to_dict() for r in url_reports],
        "attachments": pe.attachments,
        "warnings": warnings,
        "email": pe.to_dict(),
        "body_excerpt": (pe.body_text or "")[:6000],
        "semantic_engine": getattr(sem, "kind", "lightweight"),
        "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
    }
