"""Modellarni o‘qitish va baholash skripti (diplom ishi, 2.1–2.4 va 3.3-bandlar, B-ilova).

Ishlatish:
    python train/train_models.py --data data/Phishing_Email.csv
    python train/train_models.py --data data/Phishing_Email.csv data/boshqa_dataset.csv

Qo‘llab-quvvatlanadigan CSV ustunlari (avtomatik aniqlanadi):
    matn:  "Email Text", "text", "text_combined", "body", "Message" (+ ixtiyoriy "subject"/"Subject")
    belgi: "Email Type", "label", "Spam/Ham", "class"  (phishing/spam/1 → 1; safe/ham/0 → 0)

Natijalar:
    models/ml_model.joblib        — TF-IDF (1–2 gramm) + XGBoost  (P_ML)
    models/semantic_model.joblib  — belgi n-gramm TF-IDF + psixolingvistik belgilar + Logistic Regression (P_BERT zaxira modeli)
    models/metrics.json           — barcha modellar metrikalari, xatoliklar matritsasi, ROC egri chiziqlari
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import BernoulliNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from phishguard.lexicons import driver_vector  # noqa: E402
from phishguard.preprocessing import normalize_for_ml, normalize_for_semantic  # noqa: E402

TEXT_COLS = ["Email Text", "text", "text_combined", "body", "Body", "Message", "message", "content"]
SUBJECT_COLS = ["subject", "Subject"]
LABEL_COLS = ["Email Type", "label", "Label", "Spam/Ham", "class", "Class", "is_phishing"]
POSITIVE = {"phishing email", "phishing", "spam", "1", "1.0", "true", "malicious", "fraud"}
NEGATIVE = {"safe email", "safe", "ham", "legitimate", "legit", "0", "0.0", "false", "benign"}

RANDOM_STATE = 42


def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    tcol = next((c for c in TEXT_COLS if c in df.columns), None)
    lcol = next((c for c in LABEL_COLS if c in df.columns), None)
    if not tcol or not lcol:
        raise SystemExit(f"{path}: matn yoki belgi ustuni topilmadi. Ustunlar: {list(df.columns)}")
    scol = next((c for c in SUBJECT_COLS if c in df.columns and c != tcol), None)
    text = df[tcol].fillna("").astype(str)
    if scol:
        text = df[scol].fillna("").astype(str) + "\n" + text
    lab = df[lcol].astype(str).str.strip().str.lower()
    y = lab.map(lambda v: 1 if v in POSITIVE else (0 if v in NEGATIVE else -1))
    out = pd.DataFrame({"text": text, "label": y, "source": os.path.basename(path)})
    bad = (out.label == -1).sum()
    if bad:
        print(f"  ! {bad} ta yozuvning belgisi noma’lum — tashlab yuborildi")
    return out[out.label >= 0]


def prepare(df: pd.DataFrame) -> pd.DataFrame:
    n0 = len(df)
    df = df.copy()
    df["text"] = df["text"].str.slice(0, 20000)
    df["ml_text"] = df["text"].map(normalize_for_ml)
    df = df[df["ml_text"].str.split().str.len() >= 3]          # bo‘sh / “empty” yozuvlar
    df = df.drop_duplicates(subset="ml_text")                   # ma’lumot sizib chiqishining (data leakage) oldini olish
    df["sem_text"] = df["text"].map(normalize_for_semantic).str.slice(0, 5000)
    print(f"  Tozalash: {n0} → {len(df)} yozuv (bo‘sh va takroriy xatlar olib tashlandi)")
    return df.reset_index(drop=True)


def metrics(y_true, y_pred, y_score, seconds_per_1k: float) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr_c, tpr_c, _ = roc_curve(y_true, y_score)
    idx = np.unique(np.linspace(0, len(fpr_c) - 1, min(60, len(fpr_c))).astype(int))
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "fpr": round(fp / (fp + tn) if (fp + tn) else 0.0, 4),
        "roc_auc": round(roc_auc_score(y_true, y_score), 4),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "seconds_per_1000": round(seconds_per_1k, 4),
        "roc": {"fpr": [round(float(x), 4) for x in fpr_c[idx]], "tpr": [round(float(x), 4) for x in tpr_c[idx]]},
    }


def timed_predict(fn, X, n_rows):
    t = time.perf_counter()
    out = fn(X)
    return out, (time.perf_counter() - t) / max(n_rows, 1) * 1000


def semantic_features(vec, texts):
    drv = csr_matrix(np.array([driver_vector(t) for t in texts]) * 2.0)
    return hstack([vec.transform(texts), drv]).tocsr()


def main() -> None:
    ap = argparse.ArgumentParser(description="PhishGuard modellarini o‘qitish")
    ap.add_argument("--data", nargs="+", default=[os.path.join(ROOT, "data", "Phishing_Email.csv")])
    ap.add_argument("--out", default=os.path.join(ROOT, "models"))
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--quick", action="store_true", help="tezkor rejim (kamroq daraxt) — sinash uchun")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    print("1) Ma’lumotlarni yuklash")
    frames = []
    for p in args.data:
        d = load_dataset(p)
        print(f"  {p}: {len(d)} yozuv (phishing: {int(d.label.sum())}, xavfsiz: {int((d.label == 0).sum())})")
        frames.append(d)
    df = prepare(pd.concat(frames, ignore_index=True))

    print("2) Stratifikatsiyalangan bo‘lish (80/20)")
    tr, te = train_test_split(df, test_size=args.test_size, stratify=df.label, random_state=RANDOM_STATE)
    y_tr, y_te = tr.label.values, te.label.values
    print(f"  o‘quv: {len(tr)}, test: {len(te)}")

    print("3) TF-IDF (1–2 gramm, 10 000 belgi)")
    vec = TfidfVectorizer(ngram_range=(1, 2), max_features=10_000, min_df=2, sublinear_tf=True)
    X_tr = vec.fit_transform(tr.ml_text)
    X_te = vec.transform(te.ml_text)
    X_tr_bin, X_te_bin = (X_tr > 0).astype(np.float32), (X_te > 0).astype(np.float32)

    results: dict[str, dict] = {}
    n_est = 120 if args.quick else 300

    print("4) Modellarni o‘qitish va baholash")
    # Bernoulli Naive Bayes
    nb = BernoulliNB(alpha=1.0).fit(X_tr_bin, y_tr)
    proba, s = timed_predict(lambda X: nb.predict_proba(X)[:, 1], X_te_bin, len(te))
    results["Bernoulli Naive Bayes"] = metrics(y_te, (proba >= 0.5).astype(int), proba, s)

    # Linear SVM
    svm = LinearSVC(C=1.0, class_weight="balanced").fit(X_tr, y_tr)
    dec, s = timed_predict(svm.decision_function, X_te, len(te))
    results["Linear SVM"] = metrics(y_te, (dec >= 0).astype(int), dec, s)

    # Random Forest
    rf = RandomForestClassifier(n_estimators=n_est, max_features="sqrt", min_samples_leaf=2, n_jobs=-1,
                                random_state=RANDOM_STATE).fit(X_tr, y_tr)
    proba, s = timed_predict(lambda X: rf.predict_proba(X)[:, 1], X_te, len(te))
    results["Random Forest"] = metrics(y_te, (proba >= 0.5).astype(int), proba, s)

    # XGBoost — asosiy tezkor klassifikator (P_ML)
    xgb = XGBClassifier(n_estimators=n_est, max_depth=6, learning_rate=0.1, reg_alpha=0.1, reg_lambda=1.0,
                        subsample=0.8, colsample_bytree=0.8, eval_metric="logloss", n_jobs=-1,
                        tree_method="hist", random_state=RANDOM_STATE)
    xgb.fit(X_tr, y_tr)
    proba_xgb, s = timed_predict(lambda X: xgb.predict_proba(X)[:, 1], X_te, len(te))
    results["XGBoost"] = metrics(y_te, (proba_xgb >= 0.5).astype(int), proba_xgb, s)

    # Semantik niyat modeli (P_BERT zaxira varianti)
    sem_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=60_000, min_df=3,
                              sublinear_tf=True, lowercase=True)
    sem_vec.fit(tr.sem_text)
    S_tr, S_te = semantic_features(sem_vec, tr.sem_text), semantic_features(sem_vec, te.sem_text)
    sem = LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced").fit(S_tr, y_tr)
    proba_sem, s = timed_predict(lambda X: sem.predict_proba(X)[:, 1], S_te, len(te))
    results["Semantik model (P_BERT)"] = metrics(y_te, (proba_sem >= 0.5).astype(int), proba_sem, s)

    # Gibrid: matn komponentlari (domen/URL komponentlari datasetda yo‘q — ular qoidaviy)
    hyb = (0.5 * proba_xgb + 0.5 * proba_sem)
    results["Gibrid (XGBoost + semantik)"] = metrics(y_te, (hyb >= 0.5).astype(int), hyb,
                                                    results["XGBoost"]["seconds_per_1000"] + results["Semantik model (P_BERT)"]["seconds_per_1000"])

    # Har bir manba (dataset) bo‘yicha alohida natijalar
    per_source = {}
    for src in sorted(te.source.unique()):
        mask = (te.source == src).values
        if mask.sum() < 20 or len(set(y_te[mask])) < 2:
            continue
        per_source[src] = {
            "n_test": int(mask.sum()),
            "XGBoost": metrics(y_te[mask], (proba_xgb[mask] >= 0.5).astype(int), proba_xgb[mask], 0),
            "Semantik model (P_BERT)": metrics(y_te[mask], (proba_sem[mask] >= 0.5).astype(int), proba_sem[mask], 0),
            "Gibrid (XGBoost + semantik)": metrics(y_te[mask], (hyb[mask] >= 0.5).astype(int), hyb[mask], 0),
        }
        for k in ("XGBoost", "Semantik model (P_BERT)", "Gibrid (XGBoost + semantik)"):
            per_source[src][k].pop("roc", None)
        print(f"  [{src}] n={mask.sum()}  XGB F1={per_source[src]['XGBoost']['f1']:.4f}  "
              f"Sem F1={per_source[src]['Semantik model (P_BERT)']['f1']:.4f}  Gibrid F1={per_source[src]['Gibrid (XGBoost + semantik)']['f1']:.4f}")

    for name, m in results.items():
        print(f"  {name:32s} Acc={m['accuracy']:.4f} P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f} FPR={m['fpr']:.4f} AUC={m['roc_auc']:.4f} t/1k={m['seconds_per_1000']:.3f}s")

    # Eng muhim belgilar (XGBoost)
    names = np.array(vec.get_feature_names_out())
    imp = xgb.feature_importances_
    top = [{"feature": names[i], "importance": round(float(imp[i]), 5)} for i in np.argsort(imp)[::-1][:25]]

    print("5) Saqlash")
    trained_at = datetime.now().isoformat(timespec="seconds")
    joblib.dump({"vectorizer": vec, "model": xgb, "trained_at": trained_at, "version": 1},
                os.path.join(args.out, "ml_model.joblib"), compress=3)
    joblib.dump({"vectorizer": sem_vec, "model": sem, "trained_at": trained_at, "version": 1, "driver_weight": 2.0},
                os.path.join(args.out, "semantic_model.joblib"), compress=3)
    info = {
        "trained_at": trained_at,
        "datasets": [os.path.basename(p) for p in args.data],
        "n_total": int(len(df)), "n_train": int(len(tr)), "n_test": int(len(te)),
        "n_phishing": int(df.label.sum()), "n_safe": int((df.label == 0).sum()),
        "models": results, "per_source": per_source, "top_features": top,
        "params": {"tfidf": "1–2 gramm, 10 000 belgi, sublinear_tf", "xgboost": f"n_estimators={n_est}, max_depth=6, "
                   "learning_rate=0.1, reg_alpha=0.1, reg_lambda=1.0, subsample=0.8",
                   "semantic": "char_wb 3–5 gramm (60 000) + 6 psixolingvistik belgi, LogisticRegression C=4"},
    }
    with open(os.path.join(args.out, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=1)
    print(f"  Saqlandi: {args.out}")


if __name__ == "__main__":
    main()
