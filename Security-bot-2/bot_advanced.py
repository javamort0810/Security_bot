import logging, asyncio, re, ssl, socket, urllib.parse, datetime, hashlib, json
from typing import Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from telegram.constants import ParseMode
import httpx, whois
from config import BOT_TOKEN, VIRUSTOTAL_API_KEY, ADMIN_IDS

logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────
# HELPERS
# ────────────────────────────────────────────────

def extract_domain(url):
    url = url.strip()
    if not url.startswith(("http://","https://")): url = "https://" + url
    return urllib.parse.urlparse(url).netloc.lower().replace("www.","")

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://","https://")): url = "https://" + url
    return url

def is_telegram_bot(text):
    for p in [r"t\.me/(@?[\w]+bot[\w]*)",r"telegram\.me/(@?[\w]+bot[\w]*)",r"@([\w]+bot[\w]*)",r"^([\w]+bot[\w]*)$"]:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            u = m.group(1).lstrip("@")
            if "bot" in u.lower(): return u
    return None

def is_url(text):
    text = text.strip()
    return text.startswith(("http://","https://","www.")) or re.match(r"^[\w\-]+\.[a-zA-Z]{2,}",text)

# ────────────────────────────────────────────────
# САЙТЫ - ПРОДВИНУТЫЕ ПРОВЕРКИ
# ────────────────────────────────────────────────

async def check_ssl_advanced(domain):
    result = {"status":"❓","info":"","score":0,"details":{}}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
                
                # Получить информацию о сертификате
                expire_str = cert.get("notAfter", "")
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                
                if expire_str:
                    expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    days = (expire_date - datetime.datetime.utcnow()).days
                    
                    result["details"]["expire_days"] = days
                    result["details"]["issuer"] = issuer.get("organizationName", "Unknown")
                    result["details"]["cn"] = subject.get("commonName", "Unknown")
                    
                    if days > 90:
                        result.update({"status":"✅","score":35})
                        result["info"] = f"✅ SSL валиден\nИстекает: {days} дней ({expire_date.strftime('%d.%m.%Y')})\nИздатель: {result['details']['issuer']}"
                    elif days > 0:
                        result.update({"status":"⚠️","score":25})
                        result["info"] = f"⚠️ SSL истекает через {days} дней\nДата: {expire_date.strftime('%d.%m.%Y')}"
                    else:
                        result.update({"status":"🔴","score":5})
                        result["info"] = "❌ SSL СЕРТИФИКАТ ИСТЁК"
    except ssl.SSLError as e:
        result.update({"status":"🔴","info":f"❌ Ошибка SSL:\n{str(e)[:100]}"})
    except (socket.timeout, ConnectionRefusedError):
        result.update({"status":"⚠️","info":"⚠️ HTTPS недоступен (нет SSL)"})
    except Exception as e:
        result.update({"status":"❓","info":f"❓ Ошибка: {str(e)[:60]}"})
    return result

async def check_http_headers_advanced(url):
    result = {"status":"❓","present":[],"missing":[],"score":0,"details":{}}
    security_headers = {
        "Strict-Transport-Security":"HSTS (безопасность)",
        "X-Content-Type-Options":"X-Content-Type (MIME)",
        "X-Frame-Options":"X-Frame (клики)",
        "Content-Security-Policy":"CSP (скрипты)",
        "X-XSS-Protection":"XSS-Protection",
        "Referrer-Policy":"Referrer-Policy"
    }
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
            resp = await c.head(url)
            result["details"]["status_code"] = resp.status_code
            
            low = {k.lower() for k in resp.headers.keys()}
            for h, s in security_headers.items():
                if h.lower() in low:
                    result["present"].append(f"✅ {s}")
                else:
                    result["missing"].append(f"❌ {s}")
            
            n = len(result["present"])
            result.update({"status":"✅" if n>=5 else "⚠️" if n>=3 else "🔴","score":int(n/len(security_headers)*20)})
    except Exception as e:
        result["present"] = [f"❌ Ошибка: {str(e)[:60]}"]
    return result

async def check_whois_advanced(domain):
    result = {"status":"❓","info":"","score":0,"details":{}}
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        
        created = w.creation_date
        if isinstance(created, list): created = created[0]
        
        if created:
            days = (datetime.datetime.now() - created).days
            years = days // 365
            
            result["details"]["age_days"] = days
            result["details"]["created"] = created.strftime("%d.%m.%Y")
            result["details"]["registrar"] = str(getattr(w, "registrar", "Unknown"))[:100]
            
            if days > 1095:  # 3 года
                result.update({"status":"✅","score":35})
                result["info"] = f"✅ Проверенный домен\nВозраст: {years} лет {(days % 365) // 30} месяцев\nДата создания: {result['details']['created']}\nРегистратор: {result['details']['registrar']}"
            elif days > 365:
                result.update({"status":"✅","score":25})
                result["info"] = f"✅ Домен существует {years} год\nДата создания: {result['details']['created']}"
            elif days > 180:
                result.update({"status":"⚠️","score":15})
                result["info"] = f"⚠️ Молодой домен ({days} дней)\nДата создания: {result['details']['created']}"
            else:
                result.update({"status":"🔴","score":5})
                result["info"] = f"❌ НОВЫЙ ДОМЕН - {days} дней\n⚠️ Высокий риск мошенничества"
        else:
            result.update({"status":"⚠️","info":"⚠️ Дата создания не определена"})
    except Exception as e:
        result.update({"status":"❓","info":f"⚠️ WHOIS недоступен"})
    return result

async def check_dns_records(domain):
    result = {"status":"❓","info":"","score":5,"records":{}}
    try:
        import socket
        # Проверка A записи
        try:
            ip = socket.gethostbyname(domain)
            result["records"]["A"] = ip
            if not ip.startswith(("10.","172.","192.168.")): result["status"] = "✅"
        except: result["records"]["A"] = "Не найдена"
        
        # Проверка на наличие MX записей (легитимный домен обычно их имеет)
        try:
            import dns.resolver
            mx = dns.resolver.resolve(domain, 'MX')
            result["records"]["MX"] = f"Найдено {len(mx)} записей"
            result["status"] = "✅"
        except:
            result["records"]["MX"] = "Отсутствуют ⚠️"
            result["score"] -= 2
        
        result["info"] = f"A: {result['records'].get('A', '❌')}\nMX: {result['records'].get('MX', '❌')}"
    except Exception as e:
        result["info"] = "⚠️ Проверка DNS недоступна"
    return result

async def check_redirect_advanced(url):
    result = {"status":"✅","info":"","score":5,"details":{},"redirects":[]}
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
            resp = await c.get(url)
            result["details"]["final_url"] = str(resp.url)
            result["details"]["status"] = resp.status_code
            
            if len(resp.history) > 5:
                result.update({"status":"🔴","info":f"❌ ПОДОЗРИТЕЛЬНО: {len(resp.history)} редиректов!","score":-10})
            elif len(resp.history) > 3:
                result.update({"status":"⚠️","info":f"⚠️ Много редиректов ({len(resp.history)})","score":2})
                for i, r in enumerate(resp.history):
                    result["redirects"].append(f"{i+1}. {r.status_code} → {r.url}")
            elif len(resp.history) > 0:
                result["info"] = f"ℹ️ Один редирект → {result['details']['final_url'][:80]}"
                result["redirects"].append(f"→ {result['details']['final_url'][:80]}")
            else:
                result["info"] = "✅ Нет подозрительных редиректов"
                result["details"]["final_url"] = url
    except Exception as e:
        result.update({"status":"❓","info":f"⚠️ Ошибка проверки"})
    return result

async def check_phishing_advanced(domain, url):
    result = {"status":"✅","info":[],"score":10}
    flags = []
    
    # Список известных фишинг-ключевых слов
    high_risk_kw = ["paypal","apple","google","microsoft","amazon","netflix","bank","crypto","bitcoin","binance","wallet"]
    medium_risk_kw = ["login","signin","verify","account","secure","confirm","update"]
    
    legit_domains = {"paypal.com","apple.com","google.com","microsoft.com","amazon.com","netflix.com","telegram.org","binance.com"}
    
    d = domain.lower()
    
    # Проверка на известные фишинг-домены
    for kw in high_risk_kw:
        if kw in d and d not in legit_domains:
            flags.append(f"🔴 ОПАСНО: Содержит '{kw}' (фишинг)")
            result["score"] -= 20
    
    for kw in medium_risk_kw:
        if kw in d and d not in legit_domains:
            flags.append(f"⚠️ Подозрительно: Содержит '{kw}'")
            result["score"] -= 5
    
    # Проверка на IP вместо доменного имени
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        flags.append(f"🔴 IP-АДРЕС вместо домена (высокий риск)")
        result["score"] -= 25
    
    # Проверка на слишком много поддоменов
    parts = domain.split(".")
    if len(parts) > 5:
        flags.append(f"⚠️ Слишком много поддоменов ({len(parts)})")
        result["score"] -= 10
    
    # Проверка на замену символов
    if ("0" in d and "o" in d) or ("1" in d and "l" in d):
        flags.append(f"🔴 Возможна подделка символов (0/O, 1/l)")
        result["score"] -= 15
    
    # Проверка на очень длинный URL
    if len(url) > 200:
        flags.append(f"⚠️ Подозрительно длинный URL ({len(url)} символов)")
        result["score"] -= 5
    
    if flags:
        result["status"] = "🔴" if result["score"] < 0 else "⚠️"
        result["info"] = flags
    else:
        result["info"] = ["✅ Подозрительных признаков не найдено"]
        result["score"] = 10
    
    result["score"] = max(-50, min(10, result["score"]))
    return result

async def check_virustotal_advanced(url):
    result = {"status":"❓","info":"API не настроен","score":0,"details":{}}
    if not VIRUSTOTAL_API_KEY: return result
    
    try:
        h = {"x-apikey": VIRUSTOTAL_API_KEY}
        async with httpx.AsyncClient(timeout=25) as c:
            # Отправить URL на проверку
            r = await c.post("https://www.virustotal.com/api/v3/urls", headers=h, data={"url": url})
            if r.status_code == 200:
                aid = r.json().get("data", {}).get("id", "")
                await asyncio.sleep(5)
                
                # Получить результаты
                rep = await c.get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=h)
                if rep.status_code == 200:
                    s = rep.json().get("data", {}).get("attributes", {}).get("stats", {})
                    mal = s.get("malicious", 0)
                    sus = s.get("suspicious", 0)
                    undetected = s.get("undetected", 0)
                    tot = sum(s.values())
                    
                    result["details"]["total_vendors"] = tot
                    result["details"]["malicious"] = mal
                    result["details"]["suspicious"] = sus
                    result["details"]["undetected"] = undetected
                    
                    if mal > 0:
                        result.update({"status":"🔴","score":-50})
                        result["info"] = f"🔴 ОПАСНО!\n{mal} из {tot} антивирусов обнаружили МАЛВЕР"
                    elif sus > 0:
                        result.update({"status":"⚠️","score":-20})
                        result["info"] = f"⚠️ ПОДОЗРИТЕЛЬНО\n{sus} из {tot} антивирусов отметили как подозрительное"
                    elif mal == 0 and tot > 0:
                        result.update({"status":"✅","score":20})
                        result["info"] = f"✅ ЧИСТО\n0 из {tot} антивирусов обнаружили угрозы"
                    else:
                        result.update({"status":"✅","score":15})
                        result["info"] = f"✅ Проверка VirusTotal прошла"
    except Exception as e:
        result["info"] = "⚠️ Ошибка при проверке VirusTotal"
    return result

# ────────────────────────────────────────────────
# TELEGRAM БОТЫ - ПРОДВИНУТЫЕ ПРОВЕРКИ
# ────────────────────────────────────────────────

async def check_tg_bot_advanced(username):
    result = {
        "exists": False, "name": "", "username": username, 
        "warnings": [], "score": 30, "details": {}
    }
    
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
            resp = await c.get(f"https://t.me/{username}")
            
            if resp.status_code == 200:
                result["exists"] = True
                content = resp.text
                
                # Получить имя бота
                m = re.search(r"<title>(.*?)</title>", content)
                if m: result["name"] = m.group(1).strip()
                
                # Проверка на SCAM/FAKE метки
                if "scam" in content.lower():
                    result["warnings"].append("🔴 ОПАСНО: Помечен как SCAM на Telegram")
                    result["score"] -= 50
                    result["details"]["is_scam"] = True
                
                if "fake" in content.lower():
                    result["warnings"].append("🔴 ОПАСНО: Помечен как FAKE на Telegram")
                    result["score"] -= 50
                    result["details"]["is_fake"] = True
                
                # Анализ username
                uname_low = username.lower()
                
                # Высокий риск - известные мошеннические ключевые слова
                high_risk_kw = ["freemoney","earnmoney","makemoney","getcrypto","cryptomoney","freebitcoin","airdrop","claimrewards","getpaid","millionaire"]
                for kw in high_risk_kw:
                    if kw in uname_low:
                        result["warnings"].append(f"🔴 ОПАСНО: Username '{kw}' - типичный скам")
                        result["score"] -= 30
                
                # Средний риск - подозрительные слова
                medium_risk_kw = ["crypto","coin","bitcoin","ethereum","wallet","exchange","bank","invest","profit","bonus","gift","free"]
                for kw in medium_risk_kw:
                    if kw in uname_low and kw not in "official_verified_":
                        result["warnings"].append(f"⚠️ Подозрительно: Username содержит '{kw}'")
                        result["score"] -= 8
                
                # Проверка на проверку знаком ✓ в названии (обычно у скам-ботов)
                if "✓" in result["name"] or "☑" in result["name"]:
                    result["warnings"].append("⚠️ Использует проверочный знак в названии (подозрительно)")
                    result["score"] -= 10
                
                # Проверка на очень простое или короткое имя (часто скам)
                if len(result["name"]) < 3:
                    result["warnings"].append("⚠️ Слишком короткое имя")
                    result["score"] -= 5
                
                # Проверка на наличие ссылок на платежи в описании
                payment_keywords = ["pay","donate","click here","tap here","transfer money","send payment"]
                for kw in payment_keywords:
                    if kw in content.lower():
                        result["warnings"].append(f"⚠️ Содержит призывы к платежу")
                        result["score"] -= 10
                        break
                
                # Если всё ОК
                if not result["warnings"]:
                    result["score"] = 75
                    result["warnings"].append("✅ Явных признаков мошенничества не обнаружено")
            else:
                result["warnings"].append("⚠️ Бот не найден или заблокирован")
                result["score"] = -50
    except Exception as e:
        result["warnings"].append(f"❓ Ошибка при проверке")
        result["score"] = 0
    
    result["score"] = max(-50, min(100, result["score"]))
    return result

# ────────────────────────────────────────────────
# ВЕРДИКТ И ОЦЕНКИ
# ────────────────────────────────────────────────

def get_verdict(score):
    if score >= 75:
        return ("🟢 БЕЗОПАСНО", "Сайт выглядит надёжным")
    elif score >= 50:
        return ("🟡 УМЕРЕННЫЙ РИСК", "Будьте внимательны при вводе данных")
    elif score >= 25:
        return ("🟠 ВЫСОКИЙ РИСК", "Рекомендуем не доверять этому сайту")
    else:
        return ("🔴 ОПАСНО!", "Не вводите личные данные и пароли!")

def build_site_report_detailed(domain, r):
    # Расчёт итоговой оценки
    score = max(-50, min(100,
        r["ssl"].get("score", 0) +
        r["headers"].get("score", 0) +
        r["whois"].get("score", 0) +
        r["redirect"].get("score", 0) +
        r["phishing"].get("score", 0) +
        r["virustotal"].get("score", 0)
    ))
    
    verdict_emoji, verdict_text = get_verdict(score)
    
    lines = [
        f"🔍 *ДЕТАЛЬНЫЙ ОТЧЁТ БЕЗОПАСНОСТИ*",
        f"🌐 `{domain}`",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"",
        f"🔒 *SSL СЕРТИФИКАТ* {r['ssl']['status']}",
        f"{r['ssl'].get('info', '')}",
    ]
    
    lines += [
        f"",
        f"🌍 *WHOIS & ВОЗРАСТ ДОМЕНА* {r['whois']['status']}",
        f"{r['whois'].get('info', '')}",
    ]
    
    lines += [
        f"",
        f"🌐 *DNS ЗАПИСИ* {r['dns'].get('status', '❓')}",
        f"{r['dns'].get('info', 'Не проверены')}",
    ]
    
    lines += [
        f"",
        f"↪️ *РЕДИРЕКТЫ* {r['redirect']['status']}",
        f"{r['redirect'].get('info', 'Не найдены')}",
    ]
    if r["redirect"].get("redirects"):
        for rd in r["redirect"]["redirects"][:3]:
            lines.append(f"  {rd}")
    
    lines += [
        f"",
        f"🛡 *HTTP ЗАГОЛОВКИ БЕЗОПАСНОСТИ* {r['headers']['status']}",
    ]
    if r["headers"].get("present"):
        lines.append("  " + "\n  ".join(r["headers"]["present"]))
    if r["headers"].get("missing"):
        lines.append("  *Отсутствуют:*")
        lines.append("  " + "\n  ".join(r["headers"]["missing"][:3]))
    
    lines += [
        f"",
        f"🎣 *АНАЛИЗ ФИШИНГА* {r['phishing']['status']}",
    ]
    if r["phishing"].get("info"):
        for info in r["phishing"]["info"][:5]:
            lines.append(f"  {info}")
    
    lines += [
        f"",
        f"🦠 *VIRUSTOTAL ПРОВЕРКА* {r['virustotal']['status']}",
        f"{r['virustotal'].get('info', 'Не проверено')}",
    ]
    
    lines += [
        f"",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📊 *ИТОГОВАЯ ОЦЕНКА: {score}/100*",
        f"",
        f"{verdict_emoji}",
        f"_{verdict_text}_",
        f"",
        f"⏱ {datetime.datetime.now().strftime('%d.%m.%Y %H:%M')}",
    ]
    
    if score < 50:
        lines += [
            f"",
            f"⚠️ *РЕКОМЕНДАЦИИ:*",
            f"🚫 Не вводите пароли и пин-коды",
            f"🚫 Не совершайте финансовые операции",
            f"🚫 Не заполняйте формы с личными данными",
        ]
    
    return "\n".join(lines)

def build_bot_report_detailed(username, c):
    score = max(-50, min(100, c.get("score", 0)))
    verdict_emoji, verdict_text = get_verdict(score)
    
    lines = [
        f"🤖 *ДЕТАЛЬНЫЙ ОТЧЁТ О TELEGRAM БОТЕ*",
        f"👤 @{username}",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"",
    ]
    
    if c["exists"]:
        lines.append(f"✅ БОТ НАЙДЕН")
        if c.get("name"):
            lines.append(f"Название: *{c['name']}*")
    else:
        lines.append(f"❌ БОТ НЕ НАЙДЕН или ЗАБЛОКИРОВАН")
    
    lines += [
        f"",
        f"🔎 *РЕЗУЛЬТАТЫ АНАЛИЗА:*",
    ]
    
    if c.get("warnings"):
        for w in c["warnings"]:
            lines.append(f"  {w}")
    
    lines += [
        f"",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📊 *ОЦЕНКА БЕЗОПАСНОСТИ: {score}/100*",
        f"",
        f"{verdict_emoji}",
        f"_{verdict_text}_",
        f"",
        f"💡 *ПРАВИЛА БЕЗОПАСНОСТИ:*",
        f"  🚫 Никогда не отправляйте боту SMS-коды",
        f"  🚫 Не передавайте пароли и пин-коды",
        f"  🚫 Не заполняйте формы платежей без проверки",
        f"  ✅ Проверьте бота на официальном сайте",
        f"  ✅ Читайте отзывы других пользователей",
        f"",
        f"⏱ {datetime.datetime.now().strftime('%d.%m.%Y %H:%M')}",
    ]
    
    return "\n".join(lines)

# ────────────────────────────────────────────────
# HANDLERS
# ────────────────────────────────────────────────

async def start(update, context):
    kb = [
        [InlineKeyboardButton("🌐 Проверить сайт", callback_data="help_site")],
        [InlineKeyboardButton("🤖 Проверить Telegram-бот", callback_data="help_bot")],
        [InlineKeyboardButton("📊 Как работает оценка", callback_data="help_score")],
    ]
    await update.message.reply_text(
        "👋 *Привет! Я — ПРОДВИНУТЫЙ БОТ ПРОВЕРКИ БЕЗОПАСНОСТИ*\n\n"
        "🔍 *Что я проверяю для САЙТОВ:*\n"
        "🔒 SSL-сертификат (издатель, срок)\n"
        "🌍 WHOIS данные и возраст домена\n"
        "🌐 DNS записи (A, MX)\n"
        "🛡 HTTP заголовки безопасности\n"
        "🎣 Фишинг-анализ (высокий, средний риск)\n"
        "↪️ Цепочки редиректов\n"
        "🦠 VirusTotal (60+ антивирусов)\n\n"
        "🔍 *Что я проверяю для TELEGRAM БОТОВ:*\n"
        "🔴 Метки SCAM/FAKE на Telegram\n"
        "⚠️ Подозрительные ключевые слова в username\n"
        "🎣 Признаки мошенничества\n"
        "💰 Призывы к платежам\n\n"
        "➡️ *Просто отправьте мне ссылку или @username бота!*",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(kb)
    )

async def btn(update, context):
    q = update.callback_query
    await q.answer()
    if q.data == "help_site":
        await q.message.reply_text(
            "🌐 *Как проверить сайт*\n\n"
            "Отправьте URL:\n"
            "  `https://example.com`\n"
            "  `example.com`\n"
            "  `www.example.com`\n\n"
            "⏳ Проверка займёт 20-40 секунд",
            parse_mode=ParseMode.MARKDOWN
        )
    elif q.data == "help_bot":
        await q.message.reply_text(
            "🤖 *Как проверить Telegram-бот*\n\n"
            "Отправьте username бота:\n"
            "  `@somebot`\n"
            "  `t.me/somebot`\n"
            "  `somebot`\n\n"
            "Проверка выполняется мгновенно",
            parse_mode=ParseMode.MARKDOWN
        )
    elif q.data == "help_score":
        await q.message.reply_text(
            "📊 *СИСТЕМА ОЦЕНКИ БЕЗОПАСНОСТИ*\n\n"
            "Баллы начисляются за:\n"
            "🔒 SSL-сертификат — до 25 баллов\n"
            "🌍 Возраст домена — до 20 баллов\n"
            "🌐 DNS записи — до 5 баллов\n"
            "🛡 HTTP заголовки — до 20 баллов\n"
            "🎣 Фишинг-анализ — до 10 баллов\n"
            "↪️ Редиректы — до 5 баллов\n"
            "🦠 VirusTotal — до 20 баллов\n\n"
            "*ВЕРДИКТЫ:*\n"
            "🟢 75–100 = БЕЗОПАСНО\n"
            "🟡 50–74 = УМЕРЕННЫЙ РИСК\n"
            "🟠 25–49 = ВЫСОКИЙ РИСК\n"
            "🔴 0–24 = ОПАСНО",
            parse_mode=ParseMode.MARKDOWN
        )

async def analyze(update, context):
    text = update.message.text.strip()
    bot_u = is_telegram_bot(text)
    
    if bot_u:
        # ПРОВЕРКА TELEGRAM БОТА
        msg = await update.message.reply_text(f"🤖 Проверяю бота @{bot_u}...", parse_mode=ParseMode.MARKDOWN)
        try:
            check = await check_tg_bot_advanced(bot_u)
            report = build_bot_report_detailed(bot_u, check)
            await msg.edit_text(report, parse_mode=ParseMode.MARKDOWN)
        except Exception as e:
            await msg.edit_text(f"❌ Ошибка: {e}")
    
    elif is_url(text):
        # ПРОВЕРКА САЙТА
        url = normalize_url(text)
        domain = extract_domain(url)
        
        msg = await update.message.reply_text(
            f"🔍 *ПОЛНАЯ ПРОВЕРКА БЕЗОПАСНОСТИ*\n"
            f"🌐 `{domain}`\n\n"
            f"⏳ Это займёт 20-40 секунд...",
            parse_mode=ParseMode.MARKDOWN
        )
        
        try:
            # Запустить все проверки параллельно
            ssl_r, headers_r, whois_r, redirect_r, phish_r, vt_r, dns_r = await asyncio.gather(
                check_ssl_advanced(domain),
                check_http_headers_advanced(url),
                check_whois_advanced(domain),
                check_redirect_advanced(url),
                check_phishing_advanced(domain, url),
                check_virustotal_advanced(url),
                check_dns_records(domain),
            )
            
            r = {
                "ssl": ssl_r,
                "headers": headers_r,
                "whois": whois_r,
                "redirect": redirect_r,
                "phishing": phish_r,
                "virustotal": vt_r,
                "dns": dns_r,
            }
            
            report = build_site_report_detailed(domain, r)
            await msg.edit_text(report, parse_mode=ParseMode.MARKDOWN)
        except Exception as e:
            logger.exception("Analysis error")
            await msg.edit_text(f"❌ Ошибка при анализе: {e}")
    
    else:
        await update.message.reply_text(
            "❓ *Не могу распознать запрос*\n\n"
            "Отправьте:\n"
            "  🌐 Ссылку: `https://example.com`\n"
            "  🤖 Бота: `@somebot`",
            parse_mode=ParseMode.MARKDOWN
        )

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(btn))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze))
    logger.info("🚀 ПРОДВИНУТЫЙ БОТ ЗАПУЩЕН!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
