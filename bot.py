import asyncio
import configparser
from html import escape
import logging
from pathlib import Path
import time
from urllib.parse import quote, urlsplit

import requests
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, CommandHandler, filters

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

CONFIG_FILE = Path(__file__).with_name("secrets.ini")
settings = configparser.ConfigParser()

if not settings.read(CONFIG_FILE, encoding="utf-8"):
    raise RuntimeError("Create secrets.ini beside bot.py and add both credentials.")

TELEGRAM_TOKEN = settings.get("credentials", "telegram_token", fallback="").strip()
VT_API_KEY = settings.get("credentials", "vt_api_key", fallback="").strip()

if not TELEGRAM_TOKEN or TELEGRAM_TOKEN.startswith("paste-"):
    raise RuntimeError("Replace the Telegram token placeholder in secrets.ini.")
if not VT_API_KEY or VT_API_KEY.startswith("paste-"):
    raise RuntimeError("Replace the VirusTotal API key placeholder in secrets.ini.")

VT_API_BASE = "https://www.virustotal.com/api/v3"
ANALYSIS_WAIT_SECONDS = 30
ANALYSIS_POLL_INTERVAL = 2


def scan_url_with_virustotal(url):
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded",
    }
    response = requests.post(
        f"{VT_API_BASE}/urls",
        data={"url": url},
        headers=headers,
        timeout=(5, 15),
    )
    response.raise_for_status()

    submission = response.json()
    analysis_id = submission.get("data", {}).get("id")
    if not isinstance(analysis_id, str) or not analysis_id:
        raise ValueError("VirusTotal did not return an analysis ID.")

    deadline = time.monotonic() + ANALYSIS_WAIT_SECONDS
    while True:
        analysis_response = requests.get(
            f"{VT_API_BASE}/analyses/{quote(analysis_id, safe='')}",
            headers=headers,
            timeout=(5, 15),
        )
        analysis_response.raise_for_status()

        analysis = analysis_response.json().get("data", {}).get("attributes", {})
        status = analysis.get("status")
        if status == "completed":
            stats = analysis.get("stats")
            if not isinstance(stats, dict):
                raise ValueError("VirusTotal returned no analysis statistics.")
            results = analysis.get("results")
            if not isinstance(results, dict):
                raise ValueError("VirusTotal returned no engine results.")
            return stats, results, analysis_id
        if status not in ("queued", "in-progress"):
            raise ValueError(f"Unexpected VirusTotal analysis status: {status!r}")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, None, analysis_id
        time.sleep(min(ANALYSIS_POLL_INTERVAL, remaining))


def build_report(url, stats, results, analysis_id):
    def count(name):
        value = stats.get(name, 0)
        return value if isinstance(value, int) and value >= 0 else 0

    malicious = count("malicious")
    suspicious = count("suspicious")
    harmless = count("harmless")
    undetected = count("undetected")
    scanned = malicious + suspicious + harmless + undetected

    if malicious:
        verdict = f"🚨 <b>تحذير: تم تصنيف الرابط كضار من {malicious} محرك.</b>"
    elif suspicious:
        verdict = f"⚠️ <b>الرابط مشبوه بحسب {suspicious} محرك.</b>"
    elif scanned:
        verdict = (
            "✅ <b>لم يصنّف أي محرك الرابط كضار أو مشبوه ضمن النتائج المتاحة.</b>"
        )
    else:
        verdict = "ℹ️ <b>لم تتوفر نتائج كافية لإصدار حكم.</b>"

    lines = [
        "🛡️ <b>تقرير فحص VirusTotal</b>",
        f"🔗 <code>{escape(url[:240])}</code>",
        "",
        verdict,
        "",
        f"🔴 ضار: <b>{malicious}</b>",
        f"🟠 مشبوه: <b>{suspicious}</b>",
        f"🟢 غير ضار: <b>{harmless}</b>",
        f"⚪ لم يُكتشف: <b>{undetected}</b>",
    ]

    detections = []
    for engine_key, engine_result in results.items():s
        if not isinstance(engine_result, dict):
            continue
        category = engine_result.get("category")
        if category not in ("malicious", "suspicious"):
            continue
        engine_name = engine_result.get("engine_name") or engine_key
        detection_name = engine_result.get("result") or (
            "مصنّف كضار" if category == "malicious" else "مصنّف كمشبوه"
        )
        detections.append((category, str(engine_name), str(detection_name)))

    detections.sort(key=lambda item: (item[0] != "malicious", item[1].casefold()))
    if detections:
        lines.extend(["", "🔎 <b>تفاصيل المحركات المكتشفة:</b>"])
        for category, engine_name, detection_name in detections[:10]:
            icon = "🔴" if category == "malicious" else "🟠"
            lines.append(
                f"{icon} {escape(engine_name[:60])}: "
                f"<code>{escape(detection_name[:100])}</code>"
            )
        if len(detections) > 10:
            lines.append(f"… و {len(detections) - 10} محركات أخرى.")

    for key, label in (
        ("timeout", "انتهت مهلة الفحص"),
        ("confirmed-timeout", "انتهت المهلة المؤكدة"),
        ("failure", "تعذّر فحصه"),
        ("type-unsupported", "نوع غير مدعوم"),
    ):
        value = count(key)
        if value:
            lines.append(f"⏳ {label}: <b>{value}</b>")

    lines.extend(
        [
            "",
            f"🧾 معرّف التحليل: <code>{escape(analysis_id)}</code>",
            "ℹ️ النتائج تمثل آراء محركات الفحص وقت التحليل، ولا تضمن سلامة الرابط.",
        ]
    )
    return "\n".join(lines)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "أهلاً بك في بوت فحص الروابط 🛡️\n"
        "أرسل رابطاً كاملاً يبدأ بـ http:// أو https:// للحصول على تقرير المحركات.\n\n"
        "⚠️ قد تتم مشاركة الروابط المرسلة إلى VirusTotal مع الآخرين. "
        "لا ترسل روابط خاصة أو تتضمن كلمات مرور أو رموز دخول."
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    parsed_url = urlsplit(text)
    if parsed_url.scheme.lower() not in ("http", "https") or not parsed_url.netloc:
        await update.message.reply_text(
            "أرسل رابطاً كاملاً وصحيحاً يبدأ بـ http:// أو https://."
        )
        return

    progress = await update.message.reply_text(
        "🔍 جارٍ إرسال الرابط وتحليل نتائج المحركات...\n"
        "⚠️ لا ترسل روابط خاصة؛ قد تتم مشاركة الروابط مع مجتمع VirusTotal."
    )
    try:
        stats, results, analysis_id = await asyncio.to_thread(
            scan_url_with_virustotal, text
        )
        if stats is None:
            await progress.edit_text(
                "⏳ أُرسل الرابط، لكن التحليل لم يكتمل بعد.\n"
                f"🧾 معرّف التحليل: <code>{escape(analysis_id)}</code>\n"
                "أعد إرسال الرابط بعد قليل للحصول على النتيجة.",
                parse_mode="HTML",
            )
        else:
            await progress.edit_text(
                build_report(text, stats, results, analysis_id),
                parse_mode="HTML",
                disable_web_page_preview=True,
            )
    except requests.HTTPError as error:
        status_code = error.response.status_code if error.response else None
        logging.exception("VirusTotal returned an HTTP error")
        if status_code in (401, 403):
            message = "❌ مفتاح VirusTotal غير صالح أو لا يملك صلاحية الفحص."
        elif status_code == 429:
            message = "⏳ تم تجاوز حد الطلبات المسموح به في VirusTotal. حاول لاحقاً."
        else:
            message = f"❌ رفض VirusTotal الطلب (HTTP {status_code or 'غير معروف'})."
        await progress.edit_text(message)
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        logging.exception("VirusTotal scan failed")
        await progress.edit_text(
            "❌ تعذر إكمال الفحص. تحقق من اتصال الإنترنت ومفتاح VirusTotal ثم حاول مجدداً."
        )

if __name__ == "__main__":
    application = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
    print("🤖 البوت يعمل الآن ويستمع للرسائل...")
    application.run_polling()