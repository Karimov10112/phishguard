#!/usr/bin/env bash
# Linux / macOS uchun ishga tushirish
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
if ! python -c "from phishguard.analyzer import analyze; analyze('Hello team, meeting at 10am tomorrow.')" 2>/dev/null; then
  echo "Model yuklanmadi — qayta o‘qitiladi (3–5 daqiqa)..."
  python train/download_data.py
  python train/generate_augmentation.py --n 4000
  python train/train_models.py --data data/Phishing_Email.csv data/augment_multilang.csv
fi
echo "Ilova: http://127.0.0.1:5000"
python backend/app.py
