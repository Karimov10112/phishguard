"""Ijtimoiy muhandislik drayverlari va ularning lingvistik indikatorlari (diplom ishi, 1.3-jadval).

Har bir drayver uchun inglizcha, o‘zbekcha va ruscha tipik iboralar keltirilgan.
Ular semantik modulda qo‘shimcha belgilar sifatida va natijani tushuntirishda ishlatiladi.
"""
from __future__ import annotations

import re

DRIVERS: dict[str, dict] = {
    "urgency": {
        "name": "Shoshilinchlik (Urgency)",
        "patterns": [
            r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bact now\b", r"\bwithin \d+ (hours?|days?)\b",
            r"\bexpires? (today|soon)\b", r"\blast (chance|warning|notice)\b", r"\bas soon as possible\b", r"\basap\b",
            r"\bdeadline\b", r"\btime[- ]sensitive\b", r"\bfinal notice\b",
            r"\bshoshilinch\b", r"\bzudlik bilan\b", r"\bdarhol\b", r"\bbugun(oq)?\b.*\bmuddat", r"\b\d+ soat ichida\b",
            r"\boxirgi (ogohlantirish|imkoniyat)\b",
            r"\b(close|end) of (business|day)\b", r"\bby (eod|cob)\b", r"\bkechgacha\b", r"\bish kuni oxirigacha\b", r"\bдо конца дня\b",
            r"\bright (now|away)\b", r"\bwithin the hour\b", r"\btoday\b.{0,40}\b(transfer|payment|wire|pay)\b", r"\bbefore \d{1,2}\s?(am|pm)\b",
            r"\bhozir(oq)?\b.{0,30}\b(o‘tkaz|to‘la)", r"\bbugun(oq)?\b.{0,40}\b(o‘tkaz|to‘lov)", r"\bсегодня\b.{0,40}\b(перевест|оплат)",
            r"\bсрочно\b", r"\bнемедленно\b", r"\bв течение \d+ (часов|часа|дней)\b", r"\bпоследн(ее|ий) (предупреждение|шанс)\b",
        ],
    },
    "fear": {
        "name": "Qo‘rquv (Fear)",
        "patterns": [
            r"\b(account|card) (has been |is |will be )?(suspended|locked|blocked|closed|disabled|terminated)\b",
            r"\bunauthori[sz]ed (access|login|activity|transaction)\b", r"\bsuspicious (activity|login|sign[- ]in)\b",
            r"\bsecurity (alert|breach|warning)\b", r"\bpermanently (deleted|closed)\b", r"\blegal action\b",
            r"\bhisob(ingiz)? (bloklan|to‘xtatil|yopil)", r"\bkarta(ngiz)? bloklan", r"\bshubhali (kirish|faollik|amaliyot)\b",
            r"\bruxsatsiz kirish\b", r"\bsud(ga)? (ishi|murojaat)",
            r"\bаккаунт (заблокирован|приостановлен)\b", r"\bкарта заблокирована\b", r"\bподозрительн(ая|ый) (активность|вход)\b",
            r"\bнесанкционированн",
        ],
    },
    "authority": {
        "name": "Vakolat (Authority)",
        "patterns": [
            r"\bfrom the (ceo|cfo|director|president)\b", r"\b(ceo|cfo) (request|asked)\b", r"\bas per (management|company) (decision|policy)\b",
            r"\bit (department|support|helpdesk|team)\b", r"\bsecurity team\b", r"\badministrator\b", r"\bcompliance department\b",
            r"\brahbariyat (topshirig|qarori)", r"\bdirektor(ning)? (topshirig|buyrug)", r"\bAT bo‘limi\b", r"\btizim administratori\b",
            r"\bсогласно (решению|распоряжению) руководства\b", r"\bслужба безопасности\b", r"\bгенеральн(ый|ого) директор",
        ],
    },
    "financial": {
        "name": "Moliyaviy manfaat (Financial gain)",
        "patterns": [
            r"\byou('ve| have) won\b", r"\b(lottery|jackpot|prize|reward|bonus)\b", r"\brefund\b", r"\bwire transfer\b",
            r"\binvoice (attached|overdue|payment)\b", r"\bpayment (failed|declined|pending|required)\b", r"\bgift card\b",
            r"\bbank (details|account details)\b", r"\bbitcoin\b|\bcrypto(currency)?\b", r"\bunclaimed (funds|money)\b",
            r"\bbeneficiary\b", r"\bsettlement of\b", r"\bavans\b", r"\bjo‘natish kerak\b", r"\bmln so‘m\b",
            r"\b(handle|make|process|arrange) (a |the )?(payment|transfer)\b", r"\baccount number\b", r"\b(buy|purchase) (some )?gift cards?\b",
            r"\bdollar o‘tkaz", r"\bso‘m (pul )?o‘tkaz", r"\brekvizit", r"\bhisob raqam", r"\bsovg‘a kartalari\b",
            r"\bреквизит", r"\bоплатите\b",
            r"\byutib oldingiz\b", r"\bsovrin\b", r"\bpul o‘tkaz", r"\bto‘lov(ni)? (amalga oshiring|tasdiqlang)\b", r"\bkeshbek\b",
            r"\bвы выиграли\b", r"\bприз\b", r"\bвозврат средств\b", r"\bперевод(ите)? (деньги|средства)\b", r"\bкомпенсаци",
        ],
    },
    "credentials": {
        "name": "Ma’lumot so‘rash (Credential request)",
        "patterns": [
            r"\b(verify|confirm|update|validate) (your )?(account|identity|password|details|information|payment)\b",
            r"\b(enter|provide|send) (your )?(password|pin|ssn|cvv|login|credentials|card number)\b", r"\breset (your )?password\b",
            r"\bsign(ing)? ?in with your\b", r"\b(corporate|company|email|network|work) credentials\b", r"\blog ?in with your\b",
            r"\bkelgan SMS kod", r"\bkirish kodi(ni)?\b", r"\bпо ссылке\b", r"\bкод из смс\b",
            r"\bclick (here|the link|below)\b", r"\blog ?in (here|now|to verify)\b", r"\bsign in to (verify|confirm|restore)\b",
            r"\b(parol|login|pin|karta raqami)(ingiz)?ni (kiriting|yuboring|tasdiqlang)\b", r"\bhavola(ga|ni) bosing\b",
            r"\bma’lumotlar(ingiz)?ni (yangilang|tasdiqlang)\b", r"\bSMS kod(ni)?\b",
            r"\bподтвердите (данные|аккаунт|личность)\b", r"\bвведите (пароль|код|данные карты)\b", r"\bперейдите по ссылке\b",
        ],
    },
    "secrecy": {
        "name": "Maxfiylik (Secrecy)",
        "patterns": [
            r"\bkeep (this|it) (confidential|secret|between us)\b", r"\bdo not (discuss|tell|share|mention)\b", r"\bstrictly confidential\b",
            r"\bdon[’]?t (mention|tell|discuss|share)\b", r"\bkeep (this|it) between us\b", r"\bsensitive (acquisition|matter|deal|project)\b",
            r"\b(treat|keep) (this|it) (as )?(private|confidential|quiet)\b", r"\bprivate for now\b",
            r"\b(boshqalarga|hech kimga) (hozircha )?(bildirmang|aytmang)\b", r"\bпока (никому|не говорите)\b",
            r"\bdon[’]?t call me\b", r"\bcan[’]?t (talk|take calls)\b",
            r"\bhech kimga (aytmang|gapirmang|bildirmang)\b", r"\bmaxfiy saqlang\b", r"\boramizda qolsin\b", r"\btelefon(im)? (ishlamayapti|ko‘tara olmayman)\b",
            r"\bне могу говорить\b", r"\bникому не (говорите|сообщайте)\b", r"\bконфиденциально\b",
        ],
    },
}

_COMPILED = {k: [re.compile(p, re.IGNORECASE) for p in v["patterns"]] for k, v in DRIVERS.items()}

# Inkor konteksti: “biz hech qachon parolingizni so‘ramaymiz” kabi xavfsizlik eslatmalari drayver hisoblanmaydi
NEGATION = re.compile(r"(?i)(\bnever\b|\bwill not\b|\bwon[’]?t\b|\bdo not need to\b|\bdon[’]?t need to\b|\bhech qachon\b|"
                      r"\bhech kim\b|\bникогда\b|\bне (запрашива|просим|нужно))")
NEGATION_AFTER = re.compile(r"(?i)^.{0,60}?(so‘ramaymiz|so‘ramaydi|so‘ramaydilar|bermang|не запрашива|не сообщайте)")
DRIVER_KEYS = list(DRIVERS.keys())


_APOS = str.maketrans({"'": "’", "`": "’", "ʼ": "’", "ʻ": "‘", "´": "’"})


def normalize_apostrophes(text: str) -> str:
    """o' / g' → o‘ / g‘, qolgan apostroflar → ’ (lug‘at iboralari bilan bir xil ko‘rinishga keltirish)."""
    text = (text or "").translate(_APOS)
    return re.sub(r"(?i)([og])’", lambda m: m.group(1) + "‘", text)


def driver_hits(text: str) -> dict[str, list[str]]:
    """Har bir drayver bo‘yicha matnda topilgan iboralar ro‘yxati."""
    text = normalize_apostrophes(text)
    found: dict[str, list[str]] = {}
    for key, pats in _COMPILED.items():
        hits = []
        for p in pats:
            for m in p.finditer(text):
                before = text[max(0, m.start() - 60):m.start()]
                sentence_start = max(before.rfind("."), before.rfind("!"), before.rfind("?"), before.rfind("\n"))
                before = before[sentence_start + 1:]
                if key in ("credentials", "financial", "fear") and (
                        NEGATION.search(before) or NEGATION_AFTER.search(text[m.end():m.end() + 70])):
                    continue
                frag = m.group(0).strip()
                if frag and frag.lower() not in (h.lower() for h in hits):
                    hits.append(frag)
        if hits:
            found[key] = hits[:5]
    return found


def driver_vector(text: str) -> list[float]:
    """Drayverlar bo‘yicha sonli belgilar (0..1) — semantik model kirishi uchun."""
    hits = driver_hits(text)
    return [min(len(hits.get(k, [])), 3) / 3.0 for k in DRIVER_KEYS]
