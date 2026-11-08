"""O‘qitilgan modellarni yuklash va ishlatish: P_ML (TF-IDF + XGBoost) va P_BERT (semantik niyat).

P_BERT uchun ikki variant mavjud:
  1. RoBERTa (fine-tuned) — agar `models/roberta/` papkasi va `transformers` + `torch` o‘rnatilgan bo‘lsa
     (train/train_roberta.py yordamida GPU’da o‘qitiladi, diplom ishi D-ilova);
  2. Zaxira semantik model — belgi n-grammalari + psixolingvistik belgilar + Logistic Regression.
     Oddiy kompyuterda GPU’siz ishlaydi va standart holatda shu ishlatiladi.
"""
from __future__ import annotations

import json
import os
import threading
from functools import lru_cache

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack

from .lexicons import driver_vector
from .preprocessing import normalize_for_ml, normalize_for_semantic

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
_lock = threading.Lock()


class ModelNotTrained(RuntimeError):
    pass


class MLModel:
    """TF-IDF (1–2 gramm) + XGBoost — tezkor statistik klassifikator."""

    def __init__(self, path: str):
        bundle = joblib.load(path)
        self.vec = bundle["vectorizer"]
        self.model = bundle["model"]
        self.trained_at = bundle.get("trained_at", "")
        self.names = np.array(self.vec.get_feature_names_out())

    def predict(self, text: str) -> tuple[float, list[dict]]:
        X = self.vec.transform([normalize_for_ml(text)])
        with _lock:
            p = float(self.model.predict_proba(X)[0, 1])
            explain = self._explain(X)
        return p, explain

    def _explain(self, X) -> list[dict]:
        """XGBoost SHAP hissalari (pred_contribs) bo‘yicha qarorga eng ko‘p ta’sir qilgan so‘zlar."""
        try:
            import xgboost as xgb
            contrib = self.model.get_booster().predict(xgb.DMatrix(X), pred_contribs=True)[0][:-1]
        except Exception:  # noqa: BLE001
            return []
        present = X.nonzero()[1]
        items = [(self.names[i], float(contrib[i])) for i in present if abs(contrib[i]) > 1e-4]
        items.sort(key=lambda t: abs(t[1]), reverse=True)
        return [{"feature": f, "contribution": round(c, 3)} for f, c in items[:10]]


class SemanticModel:
    """Zaxira semantik model: belgi n-gramm TF-IDF + drayver belgilari + Logistic Regression."""
    kind = "lightweight"
    title = "Semantik model (belgi n-gramm + psixolingvistik belgilar)"

    def __init__(self, path: str):
        bundle = joblib.load(path)
        self.vec = bundle["vectorizer"]
        self.model = bundle["model"]
        self.w = bundle.get("driver_weight", 2.0)

    def predict(self, text: str) -> float:
        t = normalize_for_semantic(text)[:5000]
        X = hstack([self.vec.transform([t]), csr_matrix(np.array([driver_vector(t)]) * self.w)]).tocsr()
        return float(self.model.predict_proba(X)[0, 1])


class RobertaModel:
    """Fine-tuned RoBERTa (ixtiyoriy). `models/roberta/` papkasida saqlangan bo‘lishi kerak."""
    kind = "roberta"
    title = "RoBERTa (fine-tuned transformer)"

    def __init__(self, path: str):
        from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: PLC0415
        import torch  # noqa: PLC0415
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(path)
        self.model = AutoModelForSequenceClassification.from_pretrained(path).eval()

    def predict(self, text: str) -> float:
        enc = self.tok(normalize_for_semantic(text), truncation=True, max_length=512, return_tensors="pt")
        with self.torch.no_grad():
            logits = self.model(**enc).logits
        return float(self.torch.softmax(logits, dim=-1)[0, 1])


@lru_cache(maxsize=1)
def get_ml_model() -> MLModel:
    path = os.path.join(MODELS_DIR, "ml_model.joblib")
    if not os.path.exists(path):
        raise ModelNotTrained("models/ml_model.joblib topilmadi. Avval: python train/train_models.py")
    try:
        return MLModel(path)
    except Exception as e:  # noqa: BLE001 — masalan, scikit-learn/xgboost versiyasi mos kelmasa
        raise ModelNotTrained(f"Modelni yuklab bo‘lmadi ({type(e).__name__}: {e}). "
                              "Kutubxona versiyalari farq qilishi mumkin — modelni qayta o‘qiting: python train/train_models.py") from e


@lru_cache(maxsize=1)
def get_semantic_model():
    rob = os.path.join(MODELS_DIR, "roberta")
    if os.path.isdir(rob) and os.environ.get("PHISHGUARD_DISABLE_ROBERTA") != "1":
        try:
            return RobertaModel(rob)
        except Exception as e:  # noqa: BLE001
            print(f"[PhishGuard] RoBERTa yuklanmadi ({e}); zaxira semantik model ishlatiladi")
    path = os.path.join(MODELS_DIR, "semantic_model.joblib")
    if not os.path.exists(path):
        raise ModelNotTrained("models/semantic_model.joblib topilmadi. Avval: python train/train_models.py")
    try:
        return SemanticModel(path)
    except Exception as e:  # noqa: BLE001
        raise ModelNotTrained(f"Semantik modelni yuklab bo‘lmadi ({type(e).__name__}: {e}). "
                              "Modelni qayta o‘qiting: python train/train_models.py") from e


@lru_cache(maxsize=1)
def get_metrics() -> dict:
    path = os.path.join(MODELS_DIR, "metrics.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def reload_models() -> None:
    get_ml_model.cache_clear()
    get_semantic_model.cache_clear()
    get_metrics.cache_clear()
