"""Gibrid Risk Score algoritmi va karantin qoidalari (diplom ishi, 3.4-band, 3.6-formula, C-ilova).

    Risk Score = w1·P_ML + w2·P_BERT + w3·S_Domain + w4·S_URL,   w1+w2+w3+w4 = 1

Karantin moduli:
    Risk < 0.40           → CLEAN       (Inbox)
    0.40 ≤ Risk < 0.70    → SUSPICIOUS  (karantin + ogohlantiruvchi banner, havolalar faolsizlantiriladi)
    Risk ≥ 0.70           → PHISHING    (blok + SOC xabarnomasi)
"""
from __future__ import annotations

WEIGHTS = {"ml": 0.35, "bert": 0.35, "domain": 0.15, "url": 0.15}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

LOW_THRESHOLD = 0.40
HIGH_THRESHOLD = 0.70

VERDICTS = {
    "CLEAN": {"label": "Xavfsiz", "action": "deliver_to_inbox", "action_uz": "Inbox qutisiga yetkaziladi", "color": "green"},
    "SUSPICIOUS": {"label": "Shubhali", "action": "quarantine_with_banner",
                   "action_uz": "Karantinga olinadi, havolalar faolsizlantiriladi, ogohlantiruvchi banner qo‘shiladi", "color": "amber"},
    "PHISHING": {"label": "Phishing", "action": "block_and_notify_soc",
                 "action_uz": "To‘liq bloklanadi, SOC markaziga ogohlantirish yuboriladi", "color": "red"},
}


def _clip(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def risk_score(p_ml: float, p_bert: float, s_domain: float, s_url: float, weights: dict | None = None) -> float:
    w = weights or WEIGHTS
    return (w["ml"] * _clip(p_ml) + w["bert"] * _clip(p_bert)
            + w["domain"] * _clip(s_domain) + w["url"] * _clip(s_url))


def decide(score: float) -> str:
    score = round(score, 6)  # suzuvchi nuqta xatolarining oldini olish (0.7 → 0.69999...)
    if score < LOW_THRESHOLD:
        return "CLEAN"
    if score < HIGH_THRESHOLD:
        return "SUSPICIOUS"
    return "PHISHING"
