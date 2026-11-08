"""O‘quv datasetini yuklab olish: Kaggle “Phishing Email Detection” (Phishing_Email.csv, 18 650 xat).

Ishlatish:  python train/download_data.py
Agar internet orqali yuklab bo‘lmasa, faylni qo‘lda yuklab, data/Phishing_Email.csv sifatida saqlang:
  https://www.kaggle.com/datasets/subhajournal/phishingemails
  https://huggingface.co/datasets/zefang-liu/phishing-email-dataset
"""
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEST = os.path.join(ROOT, "data", "Phishing_Email.csv")
MIRRORS = [
    "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv",
    "https://raw.githubusercontent.com/stannou/email-phishing-detection/main/Phishing_Email.csv",
]


def main() -> int:
    if os.path.exists(DEST) and os.path.getsize(DEST) > 1_000_000:
        print(f"Dataset allaqachon mavjud: {DEST}")
        return 0
    os.makedirs(os.path.dirname(DEST), exist_ok=True)
    for url in MIRRORS:
        try:
            print(f"Yuklanmoqda: {url}")
            urllib.request.urlretrieve(url, DEST)  # noqa: S310
            if os.path.getsize(DEST) > 1_000_000:
                print(f"Saqlandi: {DEST} ({os.path.getsize(DEST) / 1e6:.1f} MB)")
                return 0
        except Exception as e:  # noqa: BLE001
            print(f"  xato: {e}")
    print("Datasetni yuklab bo‘lmadi. Uni qo‘lda yuklab, data/Phishing_Email.csv sifatida saqlang.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
