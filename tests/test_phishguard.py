"""PhishGuard avtomatik testlari:  python -m pytest -q"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from phishguard.domain_analyzer import analyze_sender  # noqa: E402
from phishguard.email_parser import parse_email  # noqa: E402
from phishguard.lexicons import driver_hits  # noqa: E402
from phishguard.preprocessing import clean_html, count_homoglyphs, normalize_for_ml, normalize_unicode  # noqa: E402
from phishguard.reputation import brand_impersonation, registered_domain  # noqa: E402
from phishguard.risk import WEIGHTS, decide, risk_score  # noqa: E402
from phishguard.url_analyzer import analyze_url  # noqa: E402

MODELS_READY = os.path.exists(os.path.join(ROOT, "models", "ml_model.joblib"))


# ---------------------------------------------------------------- Risk Score (diplom, 3.5-jadval)
def test_weights_sum_to_one():
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


@pytest.mark.parametrize("vals, expected_score, expected", [
    ((0.05, 0.08, 0.10, 0.00), 0.060, "CLEAN"),
    ((0.62, 0.55, 0.40, 0.30), 0.514, "SUSPICIOUS"),
    ((0.78, 0.92, 0.70, 0.00), 0.700, "PHISHING"),     # BEC misoli — aynan chegarada
    ((0.95, 0.96, 0.60, 1.00), 0.908, "PHISHING"),
])
def test_risk_examples_from_thesis(vals, expected_score, expected):
    s = risk_score(*vals)
    assert round(s, 3) == expected_score
    assert decide(s) == expected


def test_decide_thresholds():
    assert decide(0.3999) == "CLEAN"
    assert decide(0.40) == "SUSPICIOUS"
    assert decide(0.6999) == "SUSPICIOUS"
    assert decide(0.70) == "PHISHING"


def test_risk_clips_inputs():
    assert risk_score(2, 2, 2, 2) == pytest.approx(1.0)
    assert risk_score(-1, -1, -1, -1) == 0.0


# ---------------------------------------------------------------- preprocessing
def test_homoglyph_normalization():
    fake = "pаypаl"  # kirillcha "а"
    assert normalize_unicode(fake) == "paypal"
    assert count_homoglyphs(fake) == 2
    assert normalize_unicode("Привет мир") == "Привет мир"  # sof ruscha matn o‘zgarmaydi


def test_clean_html_extracts_links():
    text, links = clean_html('<html><body><script>x()</script><p>Hi <a href="http://evil.xyz">paypal.com</a></p></body></html>')
    assert "x()" not in text and "Hi" in text
    assert links[0]["href"] == "http://evil.xyz" and links[0]["text"] == "paypal.com"


def test_normalize_for_ml_tokens():
    out = normalize_for_ml("Visit https://a.com/x NOW, call 998 90 123 45 67 or mail a@b.uz")
    assert "urltoken" in out and "emailtoken" in out and "numtoken" in out
    assert out == out.lower()


# ---------------------------------------------------------------- reputation / URL / domain
@pytest.mark.parametrize("host, brand", [
    ("paypal.com", None), ("www.paypal.com", None), ("paypal-security.com", "paypal"),
    ("login.paypal.com.secure-verify.xyz", "paypal"), ("paypa1.com", "paypal"), ("rnicrosoft.com", "microsoft"),
    ("click.mailchimp.com", None), ("uzcard.uz", None), ("uzcard-verify.top", "uzcard"),
])
def test_brand_impersonation(host, brand):
    assert brand_impersonation(host) == brand


def test_registered_domain():
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("login.paypal.com.evil.xyz") == "evil.xyz"


def test_url_ip_and_shortener():
    assert analyze_url("http://185.22.11.4/login.php").score >= 0.45
    assert analyze_url("https://bit.ly/abc").score >= 0.3
    assert analyze_url("javascript:alert(1)").score == 1.0


def test_url_text_mismatch():
    r = analyze_url("http://evil.xyz/a", display_text="https://www.paypal.com/verify")
    assert r.score >= 0.5 and any("ko‘rsatadi" in x for x in r.reasons)


def test_url_benign():
    assert analyze_url("https://northwind.com/wiki/page").score == 0.0


def test_parse_mime_and_domain_checks():
    raw = ("From: PayPal Security <service@paypa1-security.com>\nTo: a@b.uz\nSubject: Alert\nReply-To: x@gmail.com\n"
           "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail\nContent-Type: text/plain\n\nVerify your account.")
    pe = parse_email(raw)
    assert pe.has_headers and pe.from_domain == "paypa1-security.com" and pe.subject == "Alert"
    rep = analyze_sender(pe)
    assert rep.auth["spf"] == "fail" and rep.auth["dmarc"] == "fail"
    assert rep.score >= 0.7


def test_plain_text_input_has_no_headers():
    pe = parse_email("Hello, see you tomorrow at https://example.com/x", subject="Hi", sender="Ann <ann@example.com>")
    assert not pe.has_headers and pe.from_addr == "ann@example.com" and pe.links[0]["href"].startswith("https://example.com")


# ---------------------------------------------------------------- lexicons
def test_driver_hits_multilang():
    assert "urgency" in driver_hits("Please act now, your account expires today")
    assert "fear" in driver_hits("Kartangiz bloklandi, shubhali faollik aniqlandi")
    assert "secrecy" in driver_hits("Hech kimga aytmang")
    assert "credentials" in driver_hits("Подтвердите данные карты по ссылке")


def test_driver_negation():
    assert driver_hits("Biz hech qachon karta ma’lumotlari yoki SMS kodni so‘ramaymiz.") == {}


# ---------------------------------------------------------------- end-to-end (o‘qitilgan model kerak)
@pytest.mark.skipif(not MODELS_READY, reason="modellar o‘qitilmagan")
def test_samples_classified_correctly():
    from phishguard.analyzer import analyze
    d = os.path.join(ROOT, "samples")
    for fn in sorted(x for x in os.listdir(d) if x.endswith(".eml")):
        with open(os.path.join(d, fn), "rb") as f:
            r = analyze(f.read())
        if fn.startswith("phishing"):
            assert r["verdict"] != "CLEAN", fn
        else:
            assert r["verdict"] == "CLEAN", fn


@pytest.mark.skipif(not MODELS_READY, reason="modellar o‘qitilmagan")
def test_web_and_api(tmp_path):
    from app import create_app
    app = create_app(str(tmp_path / "t.db"))
    c = app.test_client()
    assert c.get("/").status_code == 200
    r = c.post("/api/v1/score", json={"p_ml": 0.78, "p_bert": 0.92, "s_domain": 0.70, "s_url": 0.0})
    assert r.get_json() == {"message_id": None, "risk_score": 0.7, "verdict": "PHISHING", "action": "block_and_notify_soc"}
    assert c.post("/api/v1/score", json={"p_ml": 2}).status_code == 400
    r = c.post("/api/v1/analyze", json={"text": "Verify your account within 24 hours: http://paypa1-login.xyz/a",
                                        "sender": "PayPal <x@paypa1.com>"})
    body = r.get_json()
    assert r.status_code == 200 and body["verdict"] in ("SUSPICIOUS", "PHISHING")
    assert c.get(f"/result/{body['id']}").status_code == 200
    assert c.get("/dashboard").status_code == 200
    # CSRF himoyasi
    assert c.post("/analyze", data={"csrf": "x", "body": "hi"}).status_code == 400
