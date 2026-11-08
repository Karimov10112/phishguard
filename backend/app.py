"""PhishGuard veb-ilovasi (Flask).

Ishga tushirish:
    pip install -r requirements.txt
    python app.py                 # http://127.0.0.1:5000

Muhit o‘zgaruvchilari (ixtiyoriy):
    PHISHGUARD_API_KEY   — REST API uchun kalit (X-API-Key sarlavhasi); berilmasa API ochiq
    PHISHGUARD_DB        — SQLite fayl yo‘li (standart: instance/phishguard.db)
    PHISHGUARD_SECRET    — sessiya kaliti
    PORT                 — port (standart 5000)
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import sys
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for)
from markupsafe import Markup, escape

from phishguard import __version__
from phishguard.analyzer import analyze
from phishguard.lexicons import normalize_apostrophes
from phishguard.models import ModelNotTrained, get_metrics, get_semantic_model
from phishguard.reputation import reload_lists
from phishguard.risk import HIGH_THRESHOLD, LOW_THRESHOLD, VERDICTS, WEIGHTS, decide, risk_score
from phishguard.storage import FEEDBACK_UZ, STATUS_UZ, Storage

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__, template_folder=os.path.join(FRONTEND_DIR, "templates"),
                static_folder=os.path.join(FRONTEND_DIR, "static"))
    app.config.update(
        SECRET_KEY=os.environ.get("PHISHGUARD_SECRET") or secrets.token_hex(16),
        MAX_CONTENT_LENGTH=3 * 1024 * 1024,  # 3 MB
        JSON_AS_ASCII=False,
    )
    app.json.ensure_ascii = False
    store = Storage(db_path or os.environ.get("PHISHGUARD_DB") or os.path.join(BASE_DIR, "instance", "phishguard.db"))
    app.extensions["store"] = store
    api_key = os.environ.get("PHISHGUARD_API_KEY")

    # ------------------------------------------------------------------ yordamchilar
    @app.context_processor
    def inject_globals():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf"], "VERDICTS": VERDICTS, "STATUS_UZ": STATUS_UZ, "FEEDBACK_UZ": FEEDBACK_UZ,
                "WEIGHTS": WEIGHTS, "LOW": LOW_THRESHOLD, "HIGH": HIGH_THRESHOLD, "version": __version__}

    def check_csrf():
        if request.form.get("csrf") != session.get("csrf"):
            abort(400, "CSRF tekshiruvi muvaffaqiyatsiz — sahifani yangilab, qayta urinib ko‘ring")

    def require_api_key(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if api_key and request.headers.get("X-API-Key") != api_key:
                return jsonify({"error": "unauthorized", "message": "X-API-Key noto‘g‘ri yoki berilmagan"}), 401
            return fn(*a, **kw)
        return wrapper

    @app.template_filter("pct")
    def pct(v):
        return f"{float(v) * 100:.1f}%"

    @app.template_filter("dt")
    def dt(v):
        return (v or "").replace("T", " ")[:16]

    @app.template_filter("highlight")
    def highlight(text: str, drivers: list) -> Markup:
        """Xat matnida ijtimoiy muhandislik iboralarini ajratib ko‘rsatadi; havolalar bosilmaydigan bo‘ladi."""
        text = normalize_apostrophes(text or "")
        safe = str(escape(text))
        phrases = sorted({h for d in drivers or [] for h in d.get("hits", [])}, key=len, reverse=True)
        if phrases:
            pattern = "|".join(re.escape(str(escape(ph))) for ph in phrases)
            safe = re.sub(f"(?i)({pattern})", r'<mark class="hit">\1</mark>', safe)
        safe = re.sub(r"(?i)\b((?:https?://|www\.)[^\s<]+)", r'<span class="url-defanged" title="Havola xavfsizlik uchun faolsizlantirilgan">\1</span>', safe)
        return Markup(safe.replace("\n", "<br>"))

    def sample_files() -> list[dict]:
        out = []
        titles = {}
        tpath = os.path.join(SAMPLES_DIR, "titles.json")
        if os.path.exists(tpath):
            with open(tpath, encoding="utf-8") as fh:
                titles = json.load(fh)
        if os.path.isdir(SAMPLES_DIR):
            for fn in sorted(os.listdir(SAMPLES_DIR)):
                if fn.endswith(".eml"):
                    title = titles.get(fn) or fn[:-4].split("_", 2)[-1].replace("_", " ")
                    out.append({"file": fn, "title": title, "kind": fn.split("_", 1)[0]})
        return out

    def run_analysis(raw, subject="", sender="", source="web") -> dict:
        res = analyze(raw, subject=subject, sender=sender)
        store.save(res, source=source)
        return res

    # ------------------------------------------------------------------ sahifalar
    @app.get("/")
    def index():
        return render_template("index.html", samples=sample_files(), engine=_engine_name())

    @app.post("/analyze")
    def analyze_view():
        check_csrf()
        f = request.files.get("eml")
        subject = request.form.get("subject", "").strip()
        sender = request.form.get("sender", "").strip()
        body = request.form.get("body", "")
        try:
            if f and f.filename:
                raw = f.read()
                if not raw.strip():
                    raise ValueError("Yuklangan fayl bo‘sh")
                res = run_analysis(raw, source="eml")
            else:
                if not body.strip():
                    raise ValueError("Xat matnini kiriting yoki .eml faylni yuklang")
                res = run_analysis(body, subject=subject, sender=sender)
        except ModelNotTrained as e:
            flash(str(e), "error")
            return redirect(url_for("index"))
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("index"))
        return redirect(url_for("result", aid=res["id"]))

    @app.get("/sample/<name>")
    def sample(name):
        if not re.fullmatch(r"[\w.-]+\.eml", name):
            abort(404)
        path = os.path.join(SAMPLES_DIR, name)
        if not os.path.exists(path):
            abort(404)
        with open(path, "rb") as fh:
            res = run_analysis(fh.read(), source="sample")
        return redirect(url_for("result", aid=res["id"]))

    @app.get("/result/<aid>")
    def result(aid):
        res = store.get(aid)
        if not res:
            abort(404)
        return render_template("result.html", r=res)

    @app.get("/result/<aid>.json")
    def result_json(aid):
        res = store.get(aid)
        if not res:
            abort(404)
        return Response(json.dumps(res, ensure_ascii=False, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=phishguard_{aid}.json"})

    @app.post("/result/<aid>/status")
    def set_status(aid):
        check_csrf()
        status = request.form.get("status", "")
        if status not in ("released", "deleted", "quarantined", "blocked") or not store.set_status(aid, status):
            abort(400)
        flash(f"Holat o‘zgartirildi: {STATUS_UZ[status]}", "ok")
        return redirect(request.form.get("next") or url_for("result", aid=aid))

    @app.post("/result/<aid>/feedback")
    def set_feedback(aid):
        check_csrf()
        fb = request.form.get("feedback", "")
        if fb not in FEEDBACK_UZ or not store.set_feedback(aid, fb):
            abort(400)
        flash("Rahmat! Fikringiz modelni qayta o‘qitish uchun saqlandi.", "ok")
        return redirect(url_for("result", aid=aid))

    @app.get("/history")
    def history():
        verdict = request.args.get("verdict") or None
        if verdict and verdict not in VERDICTS:
            verdict = None
        q = (request.args.get("q") or "").strip() or None
        rows = store.list(verdict=verdict, q=q, limit=300)
        return render_template("history.html", rows=rows, verdict=verdict, q=q or "")

    @app.get("/quarantine")
    def quarantine():
        rows = store.list(statuses=("quarantined", "blocked"), limit=300)
        handled = store.list(statuses=("released", "deleted"), limit=50)
        return render_template("quarantine.html", rows=rows, handled=handled)

    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard.html", s=store.stats(), m=get_metrics(), engine=_engine_name())

    @app.get("/feedback.csv")
    def feedback_csv():
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["text", "label"])
        w.writeheader()
        w.writerows(store.feedback_rows())
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=feedback_dataset.csv"})

    @app.get("/api")
    def api_docs():
        return render_template("api.html", api_key_required=bool(api_key))

    @app.get("/about")
    def about():
        return render_template("about.html", m=get_metrics(), engine=_engine_name())

    # ------------------------------------------------------------------ REST API
    @app.get("/api/v1/health")
    def api_health():
        m = get_metrics()
        return jsonify({"status": "ok", "version": __version__, "model_trained_at": m.get("trained_at"),
                        "semantic_engine": _engine_name()})

    @app.post("/api/v1/analyze")
    @require_api_key
    def api_analyze():
        """Xom xat (.eml) yoki matnni tahlil qiladi. JSON: {"raw": "..."} yoki {"text": "...", "subject": "...", "sender": "..."}.
        Multipart: file=<.eml>."""
        try:
            if request.files.get("file"):
                res = run_analysis(request.files["file"].read(), source="api")
            else:
                data = request.get_json(silent=True) or {}
                raw = data.get("raw") or data.get("text") or ""
                if not str(raw).strip():
                    return jsonify({"error": "bad_request", "message": "“raw” yoki “text” maydoni bo‘sh"}), 400
                res = run_analysis(str(raw), subject=str(data.get("subject", "")), sender=str(data.get("sender", "")), source="api")
        except ModelNotTrained as e:
            return jsonify({"error": "model_not_trained", "message": str(e)}), 503
        except ValueError as e:
            return jsonify({"error": "bad_request", "message": str(e)}), 400
        keys = ("id", "created_at", "subject", "from_addr", "risk_score", "verdict", "action", "components",
                "drivers", "domain", "urls", "warnings", "elapsed_ms")
        return jsonify({k: res[k] for k in keys})

    @app.post("/api/v1/score")
    @require_api_key
    def api_score():
        """Komponent ballaridan Risk Score hisoblash (diplom ishi, 3.1-band so‘rov/javob namunasi)."""
        data = request.get_json(silent=True) or {}
        try:
            vals = {k: float(data[k]) for k in ("p_ml", "p_bert", "s_domain", "s_url")}
        except (KeyError, TypeError, ValueError):
            return jsonify({"error": "bad_request", "message": "p_ml, p_bert, s_domain, s_url (0..1) talab qilinadi"}), 400
        if any(not 0.0 <= v <= 1.0 for v in vals.values()):
            return jsonify({"error": "bad_request", "message": "qiymatlar 0 va 1 oralig‘ida bo‘lishi kerak"}), 400
        score = risk_score(vals["p_ml"], vals["p_bert"], vals["s_domain"], vals["s_url"])
        verdict = decide(score)
        return jsonify({"message_id": data.get("message_id"), "risk_score": round(score, 3), "verdict": verdict,
                        "action": VERDICTS[verdict]["action"]})

    @app.get("/api/v1/results/<aid>")
    @require_api_key
    def api_result(aid):
        res = store.get(aid)
        return (jsonify(res), 200) if res else (jsonify({"error": "not_found"}), 404)

    @app.post("/admin/reload-lists")
    def reload_lists_view():
        check_csrf()
        reload_lists()
        flash("Qora va ishonchli ro‘yxatlar qayta yuklandi", "ok")
        return redirect(url_for("dashboard"))

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "not_found"}), 404
        return render_template("error.html", code=404, message="Sahifa topilmadi"), 404

    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "bad_request", "message": str(e.description)}), 400
        return render_template("error.html", code=400, message=e.description), 400

    @app.errorhandler(413)
    def too_large(e):
        return render_template("error.html", code=413, message="Fayl hajmi 3 MB dan oshmasligi kerak"), 413

    return app


def _engine_name() -> str:
    try:
        return get_semantic_model().title
    except ModelNotTrained:
        return "o‘qitilmagan"


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)
