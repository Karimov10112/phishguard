"""Qo‘shimcha (sintetik) o‘quv to‘plamini yaratish — o‘zbek, rus va ingliz tillarida.

Nima uchun kerak: ochiq datasetlar (Enron, Kaggle Phishing_Email.csv) asosan 2000-yillarning inglizcha
spam xatlaridan iborat. Ularda zamonaviy BEC, bank kartasi bloklanishi, soliq qaytarimi, kuryerlik
xizmati kabi phishing turlari va o‘zbekcha/ruscha xatlar deyarli yo‘q (diplom ishi, 3.3-band, “domen siljishi”).
Ushbu skript shablonlar asosida turli xil phishing va oddiy korporativ xatlarni yaratadi.

Ishlatish:  python train/generate_augmentation.py --n 1500 --out data/augment_multilang.csv
Natija CSV: text, label (1 — phishing, 0 — xavfsiz), lang, category
"""
from __future__ import annotations

import argparse
import csv
import os
import random

R = random.Random(2026)

NAMES_EN = ["John", "Sarah", "Michael", "Emma", "David", "Olivia", "James", "Sophia", "Robert", "Anna", "Daniel", "Laura"]
NAMES_UZ = ["Aziz", "Dilshod", "Nodira", "Jasur", "Malika", "Sardor", "Gulnora", "Bekzod", "Shahnoza", "Otabek", "Madina", "Rustam"]
NAMES_RU = ["Алексей", "Мария", "Дмитрий", "Елена", "Сергей", "Ольга", "Иван", "Наталья", "Андрей", "Татьяна"]
COMPANIES = ["Artel", "Uzbektelecom", "Navoiy MMC", "TechSoft", "Global Logistics", "Orient Group", "Silk Road Trade",
             "Akfa", "UzAuto", "Sam Systems", "BrightPath", "Northwind"]
AMOUNTS = ["4 850", "12 300", "27 640", "48 500", "9 990", "15 000", "73 200", "6 420"]
SUMS = ["1 250 000", "3 400 000", "780 000", "5 000 000", "2 150 000", "990 000"]
BAD_TLDS = ["xyz", "top", "click", "online", "site", "info", "ru", "icu", "live", "co"]
BRANDS = [("PayPal", "paypal"), ("Microsoft 365", "microsoft"), ("Apple ID", "apple"), ("Amazon", "amazon"),
          ("Netflix", "netflix"), ("DHL", "dhl"), ("DocuSign", "docusign"), ("Google", "google")]
BRANDS_UZ = [("Uzcard", "uzcard"), ("Humo", "humo"), ("Payme", "payme"), ("Click", "click"), ("Kapitalbank", "kapitalbank"),
             ("Uzum Bank", "uzum"), ("Soliq qo‘mitasi", "soliq"), ("my.gov.uz", "mygov"), ("Ucell", "ucell"), ("Beeline", "beeline"),
             ("O‘zbekiston pochtasi", "pochta")]
BRANDS_RU = [("Сбербанк", "sber"), ("Госуслуги", "gosuslugi"), ("Почта России", "pochta"), ("Тинькофф", "tinkoff"),
             ("Wildberries", "wb"), ("Ozon", "ozon")]
LEGIT_DOMAINS = ["company.uz", "tatu.uz", "artel.uz", "corp.example.com", "northwind.com", "brightpath.io", "orient.uz"]


def phish_url(brand: str) -> str:
    style = R.randint(0, 5)
    tld = R.choice(BAD_TLDS)
    word = R.choice(["secure", "verify", "login", "account", "support", "update", "auth", "confirm"])
    if style == 0:
        return f"http://{brand}-{word}.{tld}/login"
    if style == 1:
        return f"https://{brand}.com.{word}-id.{tld}/session"
    if style == 2:
        return f"http://{R.randint(45, 210)}.{R.randint(1, 250)}.{R.randint(1, 250)}.{R.randint(1, 250)}/{brand}/{word}.php"
    if style == 3:
        return f"https://bit.ly/{''.join(R.choice('abcdefghjkmnpqrstuvwxyz23456789') for _ in range(7))}"
    if style == 4:
        return f"https://{word}-{brand}{R.randint(1, 99)}.{tld}/?id={R.randint(10000, 99999)}"
    return f"https://{brand}-{R.choice(['uz', 'online', 'portal', 'service'])}.{tld}/{word}"


def legit_url() -> str:
    d = R.choice(LEGIT_DOMAINS)
    path = R.choice(["intranet/news", "docs/policy", "calendar", "projects/q3", "hr/benefits", "it/status", "wiki/onboarding"])
    return f"https://{d}/{path}"


def uz_ascii(s: str) -> str:
    """Odamlar ko‘pincha o‘ va g‘ ni o' va g' deb yozadi — ikkala variant ham o‘qitishga kiradi."""
    return s.replace("‘", "'").replace("’", "'") if R.random() < 0.5 else s


def pick(*opts):
    return R.choice(opts)


# ----------------------------------------------------------------------------- PHISHING
BEC_EN = {
    "subject": ["Urgent request", "Quick favor", "Confidential", "Payment needed today", "Quick task", "Are you available?", "Need your help", "Request", "Time sensitive"],
    "open": ["Hi {n},", "Hello {n},", "{n},", "Hey {n},", "Good morning {n},"],
    "situation": ["I'm stuck in a conference.", "I am in a meeting and cannot talk.", "I'm travelling and can only use email.", "I'm in a board meeting right now.",
                  "I'm on a flight soon and can't take calls.", "My phone is not working at the moment.", "I'm with a client and can't step out."],
    "request": ["Can you handle a payment for me right now?", "I need you to process an urgent wire transfer of ${a} today.", "Please arrange a transfer of ${a} to a new vendor.",
                "I need a payment of ${a} sent to a supplier before 3pm.", "Can you take care of an invoice payment for me today?", "We need to pay a partner ${a} within the hour.",
                "I need you to buy some gift cards for a client.", "Please update the payment details for our supplier and send ${a}."],
    "secret": ["It's a sensitive acquisition, so don't mention it to the team.", "Keep this confidential until the deal is announced.", "Please do not discuss this with anyone.",
               "Don't mention it to anyone yet.", "This is strictly confidential.", "Keep this between us for now.", "Don't call me, just email.", ""],
    "next": ["I'll forward the account number in 5 minutes.", "I will send the bank details shortly.", "Reply and I'll send you the details.", "Let me know once done.",
             "Confirm when the transfer is complete.", "Reply as soon as possible.", "Send me the confirmation when it's done."],
    "sign": ["CEO", "CFO", "Managing Director", "President", "Director", "Sent from my iPhone"],
}
BEC_UZ = {
    "subject": ["Shoshilinch", "Shoshilinch topshiriq", "Maxfiy", "Bugun to‘lov kerak", "Iltimos, yordam bering", "Muhim"],
    "open": ["{n}, salom.", "Salom {n} aka.", "Assalomu alaykum, {n}.", "{n}, yaxshimisiz?", "{n} opa, salom."],
    "situation": ["Hozir yig‘ilishdaman, telefon ko‘tara olmayman.", "Men hozir xorijdaman, telefonim ishlamayapti.", "Mijoz bilan uchrashuvdaman, gaplasha olmayman.",
                  "Samolyotga chiqyapman, qo‘ng‘iroq qila olmayman.", "Hozir band bo‘lib turibman, faqat pochta orqali yozaman."],
    "request": ["Kompaniya nomidan hamkorga zudlik bilan {d} dollar o‘tkazish kerak.", "Yangi yetkazib beruvchiga bugunoq {s} so‘m pul o‘tkazish kerak.",
                "Bitta to‘lovni hozir amalga oshirib bera olasizmi?", "Shartnoma bo‘yicha {s} so‘m to‘lovni bugun o‘tkazing.", "Mijoz uchun sovg‘a kartalari sotib olish kerak."],
    "secret": ["Hech kimga gapirmang, keyin tushuntiraman.", "Bu masalani hech kimga aytmang, maxfiy saqlang.", "Buxgalteriyaga hozircha aytmang.", "Hozircha bu oramizda qolsin.", ""],
    "next": ["Rekvizitlarni hozir yuboraman.", "Hisob raqamini 5 daqiqada yuboraman.", "O‘tkazib bo‘lgach javob yozing.", "Bajarganingizdan keyin xabar bering.", "Zudlik bilan bajaring."],
    "sign": ["Direktor", "Rahbar", "Bosh direktor", "Moliya direktori", "iPhone’dan yuborildi"],
}
BEC_RU = {
    "subject": ["Срочно", "Конфиденциально", "Нужна помощь", "Срочный платеж"],
    "open": ["{n}, добрый день.", "{n}, привет.", "Здравствуйте, {n}."],
    "situation": ["Я на совещании, не могу говорить.", "Я в командировке, телефон не работает.", "Я на встрече с клиентом."],
    "request": ["Нужно срочно сегодня перевести средства новому поставщику.", "Оплатите, пожалуйста, счет партнеру прямо сейчас.", "Нужно сделать перевод {d} долларов в течение часа."],
    "secret": ["Никому не сообщайте об этом до завершения сделки.", "Это конфиденциально, никому не говорите.", "Пока не говорите бухгалтерии.", ""],
    "next": ["Реквизиты отправлю отдельно.", "Ответьте, когда будет готово.", "Сообщите, как только переведете."],
    "sign": ["генеральный директор", "финансовый директор", "руководитель"],
}


def bec_from(pool: dict, n: str, boss: str) -> str:
    a, s_, d = R.choice(AMOUNTS), R.choice(SUMS), str(R.randint(5, 60) * 1000)
    fill = lambda x: x.format(n=n, a=a, s=s_, d=d)  # noqa: E731
    parts = [fill(R.choice(pool["situation"])), fill(R.choice(pool["request"])), fill(R.choice(pool["secret"])), fill(R.choice(pool["next"]))]
    if R.random() < 0.3:
        parts[0], parts[1] = parts[1], parts[0]
    body = " ".join(p for p in parts if p)
    return f"{R.choice(pool['subject'])}\n{fill(R.choice(pool['open']))}\n{body}\n{boss}{chr(10) + R.choice(pool['sign']) if R.random() < 0.8 else ''}"


def ph_en() -> tuple[str, str]:
    cat = R.choice(["credential", "bec", "bec", "bec", "bec_bank", "giftcard", "delivery", "invoice", "it_password", "docshare", "prize", "payroll"])
    name, boss = R.choice(NAMES_EN), R.choice(NAMES_EN)
    brand, key = R.choice(BRANDS)
    url = phish_url(key)
    amt = R.choice(AMOUNTS)
    if cat == "credential":
        t = (f"{pick('Your account has been suspended', 'Unusual sign-in activity', 'Action required: verify your account', 'Security alert')}\n"
             f"Dear {pick('Customer', 'User', name)},\n"
             f"{pick('We detected unauthorized login', 'We noticed suspicious activity', 'We were unable to verify your information')} on your {brand} account. "
             f"{pick('Your account has been temporarily locked.', 'Access to your account has been limited.', 'Your account will be suspended.')} "
             f"To restore access, please {pick('verify your account', 'confirm your identity', 'update your payment details')} within {pick('24 hours', '48 hours', '12 hours')}: {url}\n"
             f"{pick('Failure to do so will result in permanent closure.', 'If you do not respond, your account will be permanently deleted.', '')}\n{brand} Security Team")
    elif cat == "bec":
        t = bec_from(BEC_EN, name, boss)
    elif cat == "bec_bank":
        t = (f"Updated banking information\nHello {name},\nPlease note that our bank account details have changed due to an audit. "
             f"All {pick('pending', 'outstanding')} invoices must be paid to the new account below starting today. "
             f"IBAN: GB{R.randint(10, 99)} {R.randint(1000, 9999)} {R.randint(1000, 9999)} {R.randint(1000, 9999)}\n"
             f"Kindly confirm once the payment of ${amt} has been sent. Do not use the old account.\nRegards,\n{boss}, Accounts Department, {R.choice(COMPANIES)}")
    elif cat == "giftcard":
        t = (f"Are you available?\n{name}, I need you to buy {pick('5', '8', '10')} {pick('Apple', 'Amazon', 'Google Play')} gift cards of $100 each for a client surprise. "
             f"Scratch the back, take pictures of the codes and send them to me {pick('immediately', 'right away', 'asap')}. I will reimburse you later. Keep it between us.\n{boss}")
    elif cat == "delivery":
        t = (f"{pick('Your parcel is on hold', 'Delivery failed', 'Package delivery notice')}\n"
             f"Dear customer, your {brand if key == 'dhl' else 'DHL'} package #{R.randint(10**8, 10**9)} could not be delivered due to unpaid customs fee of ${R.randint(1, 4)}.{R.randint(10, 99)}. "
             f"Please pay the fee {pick('within 48 hours', 'today')} to reschedule delivery: {url} Otherwise the parcel will be returned to sender.")
    elif cat == "invoice":
        t = (f"Invoice overdue - final notice\nHello,\nYour invoice INV-{R.randint(1000, 9999)} for ${amt} is overdue. "
             f"{pick('Please review the attached document', 'Open the secure document', 'Download the invoice')} and complete the payment immediately to avoid legal action: {url}\n"
             f"Payment department")
    elif cat == "it_password":
        t = (f"Password expiry notification\nDear {name},\nYour {pick('email', 'Office 365', 'corporate')} password expires today. "
             f"To keep using your mailbox, click here to keep your current password: {url}\n"
             f"{pick('If you ignore this message your mailbox will be disabled.', 'Unverified accounts will be deactivated within 24 hours.')}\nIT Helpdesk")
    elif cat == "docshare":
        t = (f"{boss} shared a document with you\n{boss} has shared \"{pick('Q3 Bonus Payments.pdf', 'Salary Review 2026.xlsx', 'Signed Contract.docx')}\" with you via {brand}. "
             f"Sign in with your email and password to view the document: {url}\nThis link expires in 24 hours.")
    elif cat == "prize":
        t = (f"Congratulations! You have won\nDear winner, your email was selected in our annual {pick('lottery', 'promotion', 'customer reward program')}. "
             f"You have won ${amt}! To claim your prize, provide your full name, bank details and card number at {url} within 72 hours.")
    else:
        t = (f"Payroll update required\nHi {name},\nWe are updating our payroll system. Please confirm your direct deposit information "
             f"by logging in here: {url} before Friday or your salary payment may be delayed.\nHR Department")
    return t, cat


def ph_uz() -> tuple[str, str]:
    cat = R.choice(["card", "bec", "bec", "bec", "tax", "delivery", "prize", "gov", "it_password", "telecom", "credit"])
    name, boss = R.choice(NAMES_UZ), R.choice(NAMES_UZ)
    brand, key = R.choice(BRANDS_UZ)
    url = phish_url(key)
    s = R.choice(SUMS)
    if cat == "card":
        t = (f"{pick('Kartangiz bloklandi', 'Diqqat! Shubhali amaliyot', 'Hisobingiz vaqtincha to‘xtatildi')}\n"
             f"Hurmatli mijoz! {brand} kartangizda {pick('shubhali faollik aniqlandi', 'ruxsatsiz kirish urinishi qayd etildi', 'xavfsizlik tekshiruvi talab qilinmoqda')}. "
             f"Kartangiz {pick('vaqtincha bloklandi', 'bloklanishi mumkin')}. {pick('24 soat', '12 soat', '48 soat')} ichida karta ma’lumotlaringizni tasdiqlang: {url} "
             f"{pick('Aks holda hisobingiz butunlay yopiladi.', 'Tasdiqlamasangiz, mablag‘laringiz muzlatiladi.', 'SMS kodni hech kimga bermang va havolaga bosing.')}")
    elif cat == "bec":
        t = bec_from(BEC_UZ, name, boss)
    elif cat == "tax":
        t = (f"Soliq qaytarimi\nHurmatli soliq to‘lovchi! Sizga {s} so‘m miqdorida ortiqcha to‘langan soliq qaytariladi. "
             f"Mablag‘ni olish uchun {pick('3 kun', '48 soat', 'bugun')} ichida karta raqamingiz va amal qilish muddatini kiriting: {url}\nSoliq qo‘mitasi")
    elif cat == "delivery":
        t = (f"Posilkangiz to‘xtatildi\nHurmatli mijoz, sizning №{R.randint(10**6, 10**7)} posilkangiz bojxona to‘lovi to‘lanmagani sababli omborda qoldi. "
             f"{R.randint(9, 39)} 000 so‘m to‘lovni {pick('bugun', '24 soat ichida')} amalga oshiring: {url} Aks holda jo‘natma qaytariladi.")
    elif cat == "prize":
        t = (f"Tabriklaymiz! Siz yutib oldingiz\nHurmatli foydalanuvchi, {brand} aksiyasida siz {pick('iPhone 16', 'Cobalt avtomobili', s + ' so‘m pul mukofoti')} yutib oldingiz! "
             f"Sovrinni olish uchun yetkazib berish to‘lovini to‘lang va karta ma’lumotlaringizni kiriting: {url}")
    elif cat == "gov":
        t = (f"Davlat to‘lovi bo‘yicha qarzdorlik\nHurmatli fuqaro! Sizning nomingizga {s} so‘m jarima rasmiylashtirilgan. "
             f"{pick('3 kun', '24 soat')} ichida to‘lanmasa, ish sudga oshiriladi va hisobingiz bloklanadi. To‘lov va tafsilotlar: {url}\nmy.gov.uz")
    elif cat == "it_password":
        t = (f"Parolingiz muddati tugadi\nHurmatli xodim! Korporativ pochta parolingiz bugun eskiradi. Pochtangiz o‘chirilmasligi uchun "
             f"havolaga bosing va joriy login hamda parolingizni kiriting: {url}\nAT bo‘limi, tizim administratori")
    elif cat == "telecom":
        t = (f"Raqamingiz bloklanadi\nHurmatli abonent! {brand} raqamingiz shaxsni tasdiqlash o‘tkazilmagani sababli {pick('bugun', '24 soat ichida')} bloklanadi. "
             f"Pasport ma’lumotlaringizni va SMS kodni kiriting: {url}")
    else:
        t = (f"Sizga kredit tasdiqlandi\nHurmatli mijoz! Sizga {s} so‘m miqdorida foizsiz kredit oldindan tasdiqlandi. "
             f"Mablag‘ni olish uchun sug‘urta to‘lovini to‘lang va karta ma’lumotlarini kiriting: {url} Taklif faqat bugun amal qiladi!")
    return uz_ascii(t), cat


def ph_ru() -> tuple[str, str]:
    cat = R.choice(["card", "bec", "bec", "delivery", "prize", "gov", "it_password"])
    name, boss = R.choice(NAMES_RU), R.choice(NAMES_RU)
    brand, key = R.choice(BRANDS_RU)
    url = phish_url(key)
    if cat == "card":
        t = (f"Ваша карта заблокирована\nУважаемый клиент! По вашей карте {brand} обнаружена подозрительная активность. "
             f"Карта временно заблокирована. Подтвердите данные карты в течение 24 часов: {url} Иначе счет будет закрыт.")
    elif cat == "bec":
        t = bec_from(BEC_RU, name, boss)
    elif cat == "delivery":
        t = (f"Посылка задержана\nВаша посылка №{R.randint(10**6, 10**7)} задержана на таможне. Оплатите пошлину {R.randint(150, 900)} руб. в течение 24 часов: {url}")
    elif cat == "prize":
        t = (f"Вы выиграли приз!\nПоздравляем! Вы стали победителем розыгрыша {brand}. Чтобы получить приз, оплатите доставку и введите данные карты: {url}")
    elif cat == "gov":
        t = (f"Задолженность по налогу\nУважаемый гражданин! За вами числится задолженность. В случае неоплаты в течение 3 дней дело будет передано в суд. Подробнее: {url}")
    else:
        t = (f"Срок действия пароля истекает\nУважаемый сотрудник! Срок действия вашего пароля истекает сегодня. Перейдите по ссылке и введите пароль, чтобы сохранить доступ: {url}\nСлужба поддержки")
    return t, cat


# ----------------------------------------------------------------------------- LEGIT
def ok_en() -> tuple[str, str]:
    cat = R.choice(["meeting", "project", "invoice_legit", "hr", "it_notice", "newsletter", "order", "order", "personal", "personal", "security_legit", "finance_legit", "paper"])
    name, other = R.choice(NAMES_EN), R.choice(NAMES_EN)
    comp = R.choice(COMPANIES)
    if cat == "meeting":
        t = (f"{pick('Meeting notes', 'Agenda for Thursday', 'Follow-up from our call')}\nHi {pick('team', name)},\n"
             f"{pick('Attached are the notes from yesterday', 'Here is the agenda for our next meeting', 'Thanks for the productive discussion today')}. "
             f"{pick('Please review the action items before Thursday.', 'Let me know if I missed anything.', 'Feel free to add topics to the shared document.')} "
             f"{pick('The meeting will be in room 3B at 10:00.', 'We will use the usual video link.', 'Lunch will be provided.')}\nBest regards,\n{other}")
    elif cat == "project":
        t = (f"Project status update\nHello {name},\nThe {pick('migration', 'website redesign', 'data warehouse', 'mobile app')} project is on track. "
             f"We completed {R.randint(60, 95)}% of the planned tasks this sprint. Remaining items: testing and documentation. "
             f"The detailed report is available on the project wiki: {legit_url()}\nThanks,\n{other}")
    elif cat == "invoice_legit":
        t = (f"Invoice for {pick('October', 'November', 'Q3')} services\nDear {name},\nPlease find attached invoice #{R.randint(1000, 9999)} for the consulting services provided under our contract. "
             f"Payment is due within 30 days in accordance with the agreement. If you have any questions, contact our accounting team.\nKind regards,\n{other}, {comp}")
    elif cat == "hr":
        t = (f"{pick('Updated holiday schedule', 'Annual training reminder', 'Welcome our new colleague')}\nDear colleagues,\n"
             f"{pick('The updated holiday schedule for next year is now available on the intranet.', 'The annual compliance training will be held next month; details will follow.', f'Please welcome {other}, who joins the marketing team this week.')} "
             f"{pick('No action is required at this time.', 'Questions can be directed to the HR team.', 'Have a great week!')}\nHR Department")
    elif cat == "it_notice":
        t = (f"Planned maintenance on Saturday\nHello all,\nThe mail server will undergo planned maintenance on Saturday from 22:00 to 02:00. "
             f"Email may be unavailable during this time. No action is required from you. Status updates: {legit_url()}\nIT Operations")
    elif cat == "newsletter":
        t = (f"{comp} monthly newsletter\nIn this issue: new office opening, employee of the month, and tips for working remotely. "
             f"Read the full newsletter on our website. You are receiving this because you subscribed to company news. Unsubscribe at any time.")
    elif cat == "order":
        t = (f"{pick('Order confirmation', 'Your order has shipped', 'Your package is on the way', 'Delivery update')} #{R.randint(100000, 999999)}\n"
             f"{pick('Thank you for your order!', 'Good news!', 'Hi ' + name + ',')} "
             f"{pick('Your items will be shipped within 3-5 business days.', 'Your order has shipped and is on its way.', 'Your package was handed to the courier today.')} "
             f"{pick('Track your package using the tracking number ' + str(R.randint(10**9, 10**10)) + ' on our website.', 'You can view your order history in your account at any time.', 'Estimated delivery: ' + pick('Friday', 'Monday', 'next week') + '.')} "
             f"{pick('This is an automated message.', 'Thank you for shopping with us.', '')}")
    elif cat == "personal":
        t = (f"{pick('Weekend plans', 'Thanks!', 'Lunch tomorrow?')}\nHey {name}, {pick('are we still on for lunch tomorrow?', 'thanks for helping me with the report yesterday.', 'how was the conference?')} "
             f"{pick('Let me know what works for you.', 'Talk soon.', 'See you on Monday.')}\n{other}")
    elif cat == "security_legit":
        t = (f"New sign-in to your account\nHi {name},\nWe noticed a new sign-in to your account from a Windows device. "
             f"If this was you, you don't need to do anything. If not, open the app directly and review your security settings. "
             f"We will never ask for your password by email.")
    elif cat == "paper":
        t = (f"{pick('Draft for review', 'Report draft', 'Comments on the draft', 'Thanks for the payment')}\nHi {name}, "
             f"{pick('attached is the draft of the report.', 'thanks for the payment of the invoice, we received it.', 'I left some comments on section 3.', 'here are the slides for Monday.')} "
             f"{pick('No rush, the deadline is next month.', 'Could you check it when you have time?', 'Looking forward to working together on the next phase.', 'Let me know your thoughts.')}\n{pick('Cheers', 'Best', 'Thanks')}, {other}")
    else:
        t = (f"Budget approval\nHi {name},\nThe budget for the {pick('marketing campaign', 'training program', 'new laptops')} has been approved by the finance committee. "
             f"Procurement will process the purchase order through the standard system next week.\nRegards,\n{other}, Finance")
    return t, cat


def ok_uz() -> tuple[str, str]:
    cat = R.choice(["meeting", "project", "hr", "it_notice", "study", "invoice_legit", "personal", "bank_legit", "event"])
    name, other = R.choice(NAMES_UZ), R.choice(NAMES_UZ)
    comp = R.choice(COMPANIES)
    if cat == "meeting":
        t = (f"{pick('Yig‘ilish haqida', 'Ertangi uchrashuv', 'Majlis kun tartibi')}\nAssalomu alaykum, {pick('hamkasblar', name)}! "
             f"Ertaga soat {R.randint(9, 16)}:00 da {pick('bo‘lim yig‘ilishi', 'loyiha muhokamasi', 'haftalik majlis')} bo‘ladi. "
             f"Kun tartibi: {pick('choraklik hisobot va yangi loyiha rejasi', 'byudjet masalalari', 'xodimlar malakasini oshirish')}. "
             f"{pick('Iltimos, taqdimotlaringizni tayyorlab keling.', 'Taklif va savollaringizni oldindan yuboring.', 'Kechikmaslikni so‘raymiz.')}\nHurmat bilan, {other}")
    elif cat == "project":
        t = (f"Loyiha holati\nSalom, {name}! Loyiha bo‘yicha ishlar rejadagidek davom etmoqda: rejalashtirilgan vazifalarning {R.randint(60, 95)} foizi bajarildi. "
             f"Keyingi bosqichda test va hujjatlashtirish qoladi. Batafsil hisobot ichki portalda: {legit_url()}\nRahmat, {other}")
    elif cat == "hr":
        t = (f"{pick('Bayram dam olish kunlari', 'Malaka oshirish kursi', 'Yangi hamkasbimiz')}\nHurmatli xodimlar! "
             f"{pick('Navro‘z bayrami munosabati bilan dam olish kunlari jadvali ichki portalda e’lon qilindi.', 'Keyingi oyda axborot xavfsizligi bo‘yicha o‘quv kursi o‘tkaziladi.', f'Bo‘limimizga yangi mutaxassis {other} qo‘shildi, unga omad tilaymiz.')} "
             f"{pick('Hech qanday harakat talab qilinmaydi.', 'Savollar bo‘lsa, kadrlar bo‘limiga murojaat qiling.', 'Barchangizga omad!')}\nKadrlar bo‘limi")
    elif cat == "it_notice":
        t = ("Rejalashtirilgan profilaktika ishlari\nHurmatli hamkasblar! Shanba kuni soat 22:00 dan 02:00 gacha pochta serverida profilaktika ishlari olib boriladi. "
             "Bu vaqtda pochta vaqtincha ishlamasligi mumkin. Sizdan hech qanday harakat talab qilinmaydi. AT bo‘limi hech qachon parolingizni so‘ramaydi.\nAT bo‘limi")
    elif cat == "study":
        t = (f"{pick('Dars jadvali o‘zgardi', 'Diplom himoyasi jadvali', 'Laboratoriya ishi')}\nHurmatli talabalar! "
             f"{pick('Keyingi haftadan boshlab dars jadvalida o‘zgarishlar bor, yangi jadval kafedra sahifasida.', 'Diplom himoyasi jadvali e’lon qilindi, o‘z vaqtingizni tekshiring.', 'Laboratoriya ishini juma kunigacha topshirishingiz kerak.')} "
             f"Savollar bo‘lsa, kafedraga murojaat qiling.\nKafedra mudiri {other}")
    elif cat == "invoice_legit":
        t = (f"Hisob-faktura\nAssalomu alaykum, {name}! Shartnoma bo‘yicha oktabr oyida ko‘rsatilgan xizmatlar uchun hisob-faktura ilova qilindi. "
             f"To‘lov shartnomaga muvofiq 30 kun ichida amalga oshiriladi. Savollar bo‘lsa, buxgalteriyamiz bilan bog‘laning.\nHurmat bilan, {other}, {comp}")
    elif cat == "personal":
        t = (f"{pick('Rahmat!', 'Tushlik', 'Dam olish kunlari')}\n{name}, salom! {pick('Kecha hisobotda yordam berganingiz uchun rahmat.', 'Ertaga tushlikka chiqamizmi?', 'Konferensiya qanday o‘tdi?')} "
             f"{pick('Keyin gaplashamiz.', 'Dushanba kuni ko‘rishamiz.', 'Javobingizni kutaman.')}\n{other}")
    elif cat == "bank_legit":
        t = ("Yangi qurilmadan kirish\nHurmatli mijoz! Ilovaga yangi qurilmadan kirish qayd etildi. Agar bu siz bo‘lsangiz, hech narsa qilish shart emas. "
             "Bank xodimlari hech qachon SMS kod yoki karta ma’lumotlaringizni so‘ramaydi. Savollar uchun rasmiy ilova yoki 1234 qisqa raqamiga murojaat qiling.")
    else:
        t = (f"Tadbirga taklif\nHurmatli hamkasblar! {pick('Juma', 'Shanba')} kuni soat 15:00 da universitet faollar zalida {pick('IT-konferensiya', 'ilmiy seminar', 'bitiruvchilar uchrashuvi')} bo‘lib o‘tadi. "
             f"Ishtirok etishingizni so‘raymiz.\nTashkiliy qo‘mita")
    return uz_ascii(t), cat


def ok_ru() -> tuple[str, str]:
    cat = R.choice(["meeting", "project", "it_notice", "invoice_legit", "personal", "report", "report", "hr"])
    name, other = R.choice(NAMES_RU), R.choice(NAMES_RU)
    if cat == "meeting":
        t = (f"Совещание в четверг\nКоллеги, добрый день! Совещание по проекту состоится в четверг в {R.randint(9, 16)}:00 в переговорной. "
             f"Повестка: итоги квартала и планы на следующий месяц. Просьба подготовить отчеты.\nС уважением, {other}")
    elif cat == "project":
        t = (f"Статус проекта\n{name}, привет! Работы по проекту идут по плану, выполнено {R.randint(60, 95)}% задач. Подробный отчет на внутреннем портале.\n{other}")
    elif cat == "it_notice":
        t = ("Плановые работы\nУважаемые коллеги! В субботу с 22:00 до 02:00 проводятся плановые работы на почтовом сервере. "
             "От вас никаких действий не требуется. Служба поддержки никогда не запрашивает пароль по почте.")
    elif cat == "invoice_legit":
        t = (f"Счет за услуги\nДобрый день, {name}! Направляем счет за услуги, оказанные в октябре по договору. Оплата в течение 30 дней согласно договору.\nС уважением, {other}")
    elif cat == "report":
        t = (f"{pick('Отчеты', 'Напоминание', 'Сроки сдачи')}\n{pick('Коллеги', name)}, {pick('напоминаю', 'напоминаем')}, что {pick('отчеты за месяц', 'планы на квартал', 'материалы к совещанию')} "
             f"нужно сдать до {pick('пятницы', 'понедельника', '15 числа')}. {pick('Шаблон лежит в общей папке.', 'Форма есть на портале.', 'Если есть вопросы, пишите.')} {pick('Спасибо!', 'Хорошего дня!', '')}")
    elif cat == "hr":
        t = (f"{pick('График отпусков', 'Обучение', 'Новый сотрудник')}\nУважаемые коллеги! {pick('График отпусков на следующий год опубликован на портале.', 'В следующем месяце пройдет обучение по информационной безопасности.', 'К нам присоединился новый сотрудник ' + other + '.')} "
             f"{pick('Никаких действий не требуется.', 'Вопросы можно задать отделу кадров.', '')}\nОтдел кадров")
    else:
        t = (f"Спасибо!\n{name}, {pick('спасибо за помощь с отчетом.', 'спасибо за презентацию.', 'отличная работа над проектом.')} {pick('Увидимся в понедельник.', 'До встречи.', '')}\n{other}")
    return t, cat


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1500, help="har bir sinf uchun yozuvlar soni")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "augment_multilang.csv"))
    args = ap.parse_args()
    rows, seen = [], set()
    gens = [(ph_en, 1, "en", 0.4), (ph_uz, 1, "uz", 0.4), (ph_ru, 1, "ru", 0.2),
            (ok_en, 0, "en", 0.4), (ok_uz, 0, "uz", 0.4), (ok_ru, 0, "ru", 0.2)]
    for fn, label, lang, share in gens:
        target = int(args.n * share)
        tries = 0
        made = 0
        while made < target and tries < target * 30:
            tries += 1
            text, cat = fn()
            if text in seen:
                continue
            seen.add(text)
            rows.append({"text": text, "label": label, "lang": lang, "category": cat})
            made += 1
    R.shuffle(rows)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["text", "label", "lang", "category"])
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} ta yozuv saqlandi: {args.out}")


if __name__ == "__main__":
    main()
