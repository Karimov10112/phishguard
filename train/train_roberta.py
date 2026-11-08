"""RoBERTa modelini phishing aniqlashga fine-tuning qilish (ixtiyoriy, GPU talab etiladi) — diplom ishi, D-ilova.

O‘rnatish:   pip install torch transformers datasets accelerate
Ishlatish:   python train/train_roberta.py --data data/Phishing_Email.csv data/augment_multilang.csv
Natija:      models/roberta/  — tizim keyingi ishga tushishda P_BERT uchun avtomatik RoBERTa’dan foydalanadi.
             (O‘chirish uchun: PHISHGUARD_DISABLE_ROBERTA=1)

Ko‘p tilli xatlar (o‘zbek, rus) uchun --base xlm-roberta-base tavsiya etiladi.
Google Colab’da (bepul GPU) ishga tushirish mumkin: papkani yuklab, shu buyruqni bajaring.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "train"))

from train_models import load_dataset, prepare  # noqa: E402


def main() -> None:
    import numpy as np
    import pandas as pd
    import torch
    from datasets import Dataset
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding, Trainer,
                              TrainingArguments)

    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="+", default=[os.path.join(ROOT, "data", "Phishing_Email.csv")])
    ap.add_argument("--base", default="roberta-base")
    ap.add_argument("--epochs", type=float, default=3)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--out", default=os.path.join(ROOT, "models", "roberta"))
    args = ap.parse_args()
    if not torch.cuda.is_available():
        print("Ogohlantirish: GPU topilmadi — o‘qitish juda sekin bo‘ladi (Google Colab GPU tavsiya etiladi).")

    df = prepare(pd.concat([load_dataset(p) for p in args.data], ignore_index=True))
    tr, te = train_test_split(df, test_size=0.2, stratify=df.label, random_state=42)
    tr, va = train_test_split(tr, test_size=0.1, stratify=tr.label, random_state=42)

    tok = AutoTokenizer.from_pretrained(args.base)
    model = AutoModelForSequenceClassification.from_pretrained(args.base, num_labels=2)

    def to_ds(d):
        ds = Dataset.from_dict({"text": d.sem_text.tolist(), "label": d.label.tolist()})
        return ds.map(lambda b: tok(b["text"], truncation=True, max_length=args.max_length), batched=True)

    train_ds, val_ds, test_ds = to_ds(tr), to_ds(va), to_ds(te)

    def compute_metrics(p):
        logits, labels = p
        prob = torch.softmax(torch.tensor(logits), dim=-1)[:, 1].numpy()
        pred = (prob >= 0.5).astype(int)
        fp = int(((pred == 1) & (labels == 0)).sum())
        tn = int(((pred == 0) & (labels == 0)).sum())
        return {"f1": f1_score(labels, pred), "precision": precision_score(labels, pred), "recall": recall_score(labels, pred),
                "fpr": fp / max(fp + tn, 1), "roc_auc": roc_auc_score(labels, prob)}

    targs = TrainingArguments(
        output_dir=os.path.join(ROOT, "train", "roberta_runs"), num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch, per_device_eval_batch_size=args.batch * 2,
        learning_rate=2e-5, weight_decay=0.01, warmup_ratio=0.06,
        eval_strategy="epoch", save_strategy="epoch", load_best_model_at_end=True, metric_for_best_model="f1",
        fp16=torch.cuda.is_available(), report_to=[], logging_steps=50, save_total_limit=1,
    )
    trainer = Trainer(model=model, args=targs, train_dataset=train_ds, eval_dataset=val_ds,
                      data_collator=DataCollatorWithPadding(tok), compute_metrics=compute_metrics)
    trainer.train()
    res = trainer.evaluate(test_ds)
    print("Test natijalari:", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})
    os.makedirs(args.out, exist_ok=True)
    trainer.save_model(args.out)
    tok.save_pretrained(args.out)
    with open(os.path.join(args.out, "test_metrics.json"), "w", encoding="utf-8") as f:
        json.dump({k: float(v) for k, v in res.items() if isinstance(v, (int, float, np.floating))}, f, indent=1)
    print(f"Saqlandi: {args.out}")


if __name__ == "__main__":
    main()
