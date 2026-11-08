# PhishGuard — Machine Learning yordamida phishing xabarlarini aniqlash tizimi

Diplom loyihasining dasturiy qismi: elektron xatlarni NLP va mashinaviy o‘rgatish yordamida tahlil qilib,
**gibrid Risk Score** hisoblaydigan va **uch darajali karantin** qarorini chiqaradigan veb-ilova, REST API va SMTP filtr.

```
Risk Score = 0.35·P_ML + 0.35·P_BERT + 0.15·S_Domain + 0.15·S_URL

Risk < 0.40         → CLEAN       (Inbox)
0.40 ≤ Risk < 0.70  → SUSPICIOUS  (karantin + banner, havolalar faolsizlantiriladi)
Risk ≥ 0.70         → PHISHING    (blok + SOC xabarnomasi)
```

## 1. Tez ishga tushirish

**Windows:** `run_windows.bat` faylini ikki marta bosing. U virtual muhit yaratadi, kutubxonalarni o‘rnatadi
va brauzerda http://127.0.0.1:5000 ni ochadi. Python 3.10 yoki undan yangi versiya kerak (python.org).
O‘rnatishda “Add Python to PATH” belgisini qo‘ying.

**Linux / macOS:** `./run.sh`

**Lokal launcher:** `./run_local` (Linux/macOS yoki Git Bash)

**Qo‘lda:**
```bash
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python backend\app.py           # http://127.0.0.1:5000
```

O‘qitilgan modellar `models/` papkasida tayyor turibdi. Agar sizdagi scikit-learn yoki XGBoost versiyasi
boshqacha bo‘lsa va model yuklanmasa, ishga tushirish skripti modelni avtomatik qayta o‘qitadi. Buni
qo‘lda ham qilish mumkin (3-bo‘lim).

### Render va GitHub’ga joylash

Loyiha Render uchun tayyorlangan: `render.yaml` Flask ilovasini `gunicorn` orqali ishga tushiradi,
`/api/v1/health` esa health-check sifatida ishlatiladi.

1. Loyihani GitHub’da yangi repository’ga yuklang:

   ```bash
   git init
   git add .
   git commit -m "Deploy PhishGuard to Render"
   git branch -M main
   git remote add origin https://github.com/<USERNAME>/<REPOSITORY>.git
   git push -u origin main
   ```

2. Render Dashboard → **New** → **Blueprint** bo‘limidan GitHub repository’ni tanlang.
   Render `render.yaml` ni avtomatik topadi va web service yaratadi.
3. Deploy tugagach, Render bergan URL orqali ilovani oching. API uchun ixtiyoriy ravishda
   `PHISHGUARD_API_KEY` environment variable’ini Render sozlamalarida qo‘shish mumkin.

Render’ning bepul web service fayl tizimi doimiy emas: `instance/phishguard.db` dagi tarix
restart yoki redeploy’dan keyin yo‘qolishi mumkin. Doimiy tarix kerak bo‘lsa, Render Persistent
Disk yoki tashqi PostgreSQL storage ulash kerak.

### Hugging Face Spaces’da bepul deploy

Kredit karta talab qilinmaydigan bepul variant sifatida Docker Space ishlatish mumkin.
Loyihada buning uchun `Dockerfile` va `.dockerignore` tayyorlangan.

1. Hugging Face’da **Create new Space** ni tanlang.
2. Space SDK sifatida **Docker** va visibility sifatida **Public** yoki **Private** ni tanlang.
3. Space’ning **Settings → Repository secrets** bo‘limida GitHub token emas, kerak bo‘lsa
   faqat `PHISHGUARD_SECRET` va `PHISHGUARD_API_KEY` qiymatlarini qo‘shing.
4. Lokal loyihani Space repository’siga alohida remote orqali push qiling:

   ```bash
   git remote add hf https://huggingface.co/spaces/<USERNAME>/<SPACE_NAME>
   git push hf main
   ```

Space `Dockerfile` ni avtomatik build qiladi va ilovani 7860-portda ishga tushiradi.
Bepul CPU Space ishlatilmaganda uxlaydi; birinchi ochilishda yuklanishi biroz vaqt olishi mumkin.

## 2. Imkoniyatlar

| Sahifa | Vazifasi |
|---|---|
| **Tahlil** | Xat matnini kiritish yoki .eml faylni yuklash; 9 ta namunaviy xat (o‘zbek, rus, ingliz) |
| **Natija** | Risk Score, 4 komponent va formula, psixologik drayverlar, SHAP bo‘yicha muhim so‘zlar, domen va SPF/DKIM/DMARC tahlili, havolalar tahlili, ajratib ko‘rsatilgan matn, karantin amallari, tahlilchi fikri |
| **Tarix** | Barcha tahlillar, qidiruv va filtr |
| **Karantin** | SUSPICIOUS/PHISHING xatlarni chiqarish yoki o‘chirish |
| **Statistika va modellar** | 6 ta model taqqoslamasi (Accuracy, Precision, Recall, F1, FPR, ROC-AUC, tezlik), ROC egri chiziqlari, xatoliklar matritsasi, Risk Score taqsimoti |
| **REST API** | `/api/v1/analyze`, `/api/v1/score`, `/api/v1/health`, `/api/v1/results/<id>` |

## 3. Modellarni qayta o‘qitish

```bash
python train/download_data.py                        # Kaggle "Phishing Email Detection" (18 650 xat) → data/
python train/generate_augmentation.py --n 4000       # o‘zbek/rus/ingliz qo‘shimcha to‘plami → data/augment_multilang.csv
python train/train_models.py --data data/Phishing_Email.csv data/augment_multilang.csv
```

Skript 6 ta modelni o‘qitadi va test to‘plamida baholaydi: Bernoulli NB, Linear SVM, Random Forest,
XGBoost, semantik model va gibrid. Natijalar `models/metrics.json` ga yoziladi va “Statistika” sahifasida ko‘rinadi.
Boshqa CSV datasetlarni ham qo‘shish mumkin, ustunlar avtomatik aniqlanadi (`text`/`Email Text`/`body` + `label`/`Email Type`).

**Tahlilchi fikri asosida qayta o‘qitish:** Statistika → `feedback.csv` ni yuklab oling va `--data` ro‘yxatiga qo‘shing.

**RoBERTa (ixtiyoriy, GPU kerak):** `pip install torch transformers datasets accelerate`, so‘ng
`python train/train_roberta.py --data ...`. Natija `models/roberta/` papkasiga saqlanadi va tizim P_BERT uchun
uni avtomatik ishlatadi. Google Colab’ning bepul GPU’sida ishlatsa bo‘ladi. O‘zbekcha/ruscha xatlar uchun
`--base xlm-roberta-base` tavsiya etiladi.

## 4. Joriy natijalar (test to‘plami, 4 470 xat)

| Model | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| Bernoulli Naive Bayes | 97,2% | 0,946 | 0,980 | 0,963 | 3,3% | 0,994 |
| Linear SVM | 98,9% | 0,985 | 0,986 | 0,986 | 0,9% | 0,999 |
| Random Forest | 97,4% | 0,986 | 0,945 | 0,965 | 0,8% | 0,998 |
| XGBoost (P_ML) | 97,9% | 0,973 | 0,969 | 0,971 | 1,6% | 0,997 |
| Semantik model (P_BERT) | 99,2% | 0,986 | 0,991 | 0,989 | 0,8% | 0,999 |
| Gibrid (XGBoost + semantik) | 98,9% | 0,985 | 0,985 | 0,985 | 0,9% | 0,999 |

Faqat Kaggle datasetining test qismida: XGBoost F1 = 0,964, semantik model F1 = 0,985, gibrid F1 = 0,981.

## 5. Arxitektura va fayllar

```
backend/app.py               Flask backend, veb route’lar va REST API
frontend/templates/          Frontend HTML sahifalari
frontend/static/              Frontend CSS va JavaScript fayllari
phishguard/
  preprocessing.py           HTML tozalash, Unicode/homoglyph normalizatsiya, tokenlar
  email_parser.py            MIME parsing: sarlavha, matn, havolalar, biriktirmalar, SPF/DKIM/DMARC
  lexicons.py                6 ta ijtimoiy muhandislik drayveri (uz/ru/en), inkor konteksti
  models.py                  P_ML (TF-IDF + XGBoost, SHAP izohi), P_BERT (RoBERTa yoki zaxira model)
  domain_analyzer.py         S_Domain: bepul pochta, brend taqlidi, Reply-To, SPF/DKIM/DMARC
  url_analyzer.py            S_URL: IP, qisqartiruvchi, punycode, TLD, matn–havola nomuvofiqligi, qora ro‘yxat
  reputation.py              brendlar (xalqaro + O‘zbekiston), bepul pochta, TLD ro‘yxatlari
  risk.py                    Risk Score formulasi va karantin qoidalari
  analyzer.py                to‘liq konveyer + korrelyatsiya qoidalari (BEC, credential harvesting)
  storage.py                 SQLite: tarix, karantin holati, tahlilchi fikrlari
train/                       o‘qitish, dataset yuklash, qo‘shimcha to‘plam, RoBERTa
integrations/
  smtp_filter.py             Postfix uchun SMTP kontent-filtr (aiosmtpd)
  update_blacklist.py        OpenPhish/PhishTank feed’idan qora ro‘yxatni yangilash
samples/                     9 ta namunaviy .eml xat
tests/                       29 ta avtomatik test (python -m pytest -q)
```

## 6. Postfix bilan integratsiya (SMTP filtr)

```bash
pip install aiosmtpd
python integrations/smtp_filter.py --listen 127.0.0.1:10025 --relay 127.0.0.1:10026
```

`/etc/postfix/master.cf` namunasi:
```
smtp      inet  n  -  n  -  -  smtpd
  -o content_filter=phishguard:[127.0.0.1]:10025
phishguard unix -  -  n  -  4  smtp
  -o smtp_send_xforward_command=yes
127.0.0.1:10026 inet n - n - - smtpd
  -o content_filter=
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o mynetworks=127.0.0.0/8
```

Filtr har bir xatga `X-PhishGuard-Score` va `X-PhishGuard-Verdict` sarlavhalarini qo‘shadi. SUSPICIOUS xatlar
mavzusiga `[SHUBHALI]` belgisi qo‘yiladi. PHISHING xatlar yetkazilmaydi va `quarantine/` papkasiga saqlanadi.

## 7. Muhit o‘zgaruvchilari

| O‘zgaruvchi | Vazifasi |
|---|---|
| `PHISHGUARD_API_KEY` | REST API kaliti (`X-API-Key` sarlavhasi). Berilmasa API ochiq bo‘ladi |
| `PHISHGUARD_SECRET` | Sessiya kaliti (bir nechta jarayonda ishlatganda majburiy) |
| `PHISHGUARD_DB` | SQLite fayl yo‘li (standart: `instance/phishguard.db`) |
| `PHISHGUARD_DISABLE_ROBERTA=1` | `models/roberta` bo‘lsa ham zaxira semantik modelni ishlatish |
| `PORT`, `HOST` | Server porti va manzili |

## 8. Cheklovlar

- Ochiq dataset asosan 2000-yillarning inglizcha xatlaridan iborat. O‘zbekcha va ruscha xatlar uchun sintetik
  qo‘shimcha to‘plam ishlatilgan. Real korxonada tashkilotning o‘z xatlari bilan qayta o‘qitish tavsiya etiladi.
- Faqat matn kiritilsa, sarlavhalar bo‘lmaydi va SPF/DKIM/Reply-To tekshiruvi o‘tkazilmaydi. To‘liq tahlil uchun .eml yuklang.
- Rasm ichidagi matn va QR-kodlar (quishing) hozircha tahlil qilinmaydi.

## 9. Diplom himoyasi uchun asosiy ko‘rsatkichlar

Tizim natijani faqat bitta modelga emas, bir nechta mustaqil belgiga tayangan holda chiqaradi:
matn modeli, semantik model, jo‘natuvchi domeni va havolalar. Har bir xat uchun komponent ballari,
yakuniy Risk Score, topilgan psixologik drayverlar va qarorga ta’sir qilgan belgilar ko‘rsatiladi.
Modelni baholashda Accuracy, Precision, Recall, F1, FPR va ROC-AUC ishlatiladi; test natijalari
`Statistika va modellar` sahifasida ko‘rsatiladi.
