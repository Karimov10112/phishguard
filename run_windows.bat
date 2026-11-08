@echo off
chcp 65001 >nul
cd /d %~dp0
if not exist .venv (
  echo [1/4] Virtual muhit yaratilmoqda...
  python -m venv .venv || (echo Python topilmadi. python.org dan Python 3.10+ o'rnating & pause & exit /b 1)
)
call .venv\Scripts\activate
echo [2/4] Kutubxonalar o'rnatilmoqda...
pip install -q -r requirements.txt
echo [3/4] Model tekshirilmoqda...
python -c "from phishguard.analyzer import analyze; analyze('Hello team, meeting at 10am tomorrow.')" 2>nul
if errorlevel 1 (
  echo Model yuklanmadi - qayta o'qitiladi, 3-5 daqiqa...
  python train\download_data.py
  python train\generate_augmentation.py --n 4000
  python train\train_models.py --data data\Phishing_Email.csv data\augment_multilang.csv
)
echo [4/4] Ilova ishga tushmoqda: http://127.0.0.1:5000
start "" http://127.0.0.1:5000
python backend\app.py
pause
