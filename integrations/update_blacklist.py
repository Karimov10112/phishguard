"""Qora ro‘yxatni OpenPhish ochiq feed’idan yangilash (diplom ishi, 3.5-band “dinamik yangilash”).

Ishlatish:   python integrations/update_blacklist.py            # har kuni cron orqali ishga tushirish tavsiya etiladi
Natija:      data/blacklist.txt (qo‘lda kiritilgan yozuvlar saqlanib qoladi)

Eslatma: PhishTank feed’i uchun bepul API kaliti kerak (https://phishtank.org/developer_info.php).
Kalit bo‘lsa: PHISHTANK_KEY=... python integrations/update_blacklist.py
"""
from __future__ import annotations

import csv
import io
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BL = os.path.join(ROOT, "data", "blacklist.txt")
OPENPHISH = "https://openphish.com/feed.txt"
MARK = "# --- avtomatik yangilangan yozuvlar (update_blacklist.py) ---"


def fetch(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-blacklist-updater/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — ishonchli manzil
        return r.read().decode("utf-8", errors="replace")


def main() -> int:
    manual = []
    if os.path.exists(BL):
        with open(BL, encoding="utf-8") as f:
            for line in f:
                if line.strip() == MARK:
                    break
                manual.append(line.rstrip("\n"))
    entries: set[str] = set()
    try:
        entries |= {u.strip().lower().rstrip("/") for u in fetch(OPENPHISH).splitlines() if u.strip().startswith("http")}
        print(f"OpenPhish: {len(entries)} ta URL")
    except Exception as e:  # noqa: BLE001
        print(f"OpenPhish yuklanmadi: {e}", file=sys.stderr)
    key = os.environ.get("PHISHTANK_KEY")
    if key:
        try:
            data = fetch(f"http://data.phishtank.com/data/{key}/online-valid.csv", timeout=120)
            n0 = len(entries)
            for row in csv.DictReader(io.StringIO(data)):
                if row.get("url"):
                    entries.add(row["url"].strip().lower().rstrip("/"))
            print(f"PhishTank: {len(entries) - n0} ta URL")
        except Exception as e:  # noqa: BLE001
            print(f"PhishTank yuklanmadi: {e}", file=sys.stderr)
    if not entries:
        print("Yangi yozuvlar yo‘q — fayl o‘zgartirilmadi")
        return 1
    with open(BL, "w", encoding="utf-8") as f:
        f.write("\n".join(manual).rstrip() + "\n" + MARK + "\n")
        f.write("\n".join(sorted(entries)) + "\n")
    print(f"Saqlandi: {BL} ({len(entries)} ta avtomatik yozuv). Ilovada: Statistika → “Qora ro‘yxatni yangilash”.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
