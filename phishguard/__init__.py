"""PhishGuard — Machine Learning yordamida phishing xabarlarini aniqlash tizimi.

Diplom loyihasi doirasida ishlab chiqilgan dasturiy majmua:
  * matnni dastlabki ishlov berish (HTML tozalash, Unicode homoglyph normalizatsiyasi);
  * TF-IDF + XGBoost klassifikatori (P_ML);
  * semantik niyat moduli (P_BERT) — RoBERTa yoki yengil zaxira modeli;
  * domen va URL tekshiruvlari (S_Domain, S_URL);
  * gibrid Risk Score va uch darajali karantin moduli.
"""

__version__ = "1.0.0"
