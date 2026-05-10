#!/usr/bin/env python3
"""
EXIF Scrubber Bot — Open Source Core
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
A free, self-moderating Telegram bot that strips image metadata (EXIF).

Zero data stored. Images are processed entirely in memory and never
written to disk. Nothing is logged beyond anonymised processing counts.

Supports: JPEG, PNG, WEBP, HEIC
Requires: pip install aiogram Pillow pillow-heif
Env var:  EXIF_BOT_TOKEN

Built by Vendly Privacy Labs — https://vendlyprivacylabs.com
"""

import asyncio
import io
import json
import logging
import os
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pillow_heif
from PIL import Image
from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart
from aiogram.types import Message, BufferedInputFile

pillow_heif.register_heif_opener()

# ─── Config ───────────────────────────────────────────────────────────────────

BOT_TOKEN   = os.environ["EXIF_BOT_TOKEN"]  # Set in .env — never hardcode
MAX_BYTES   = 20 * 1024 * 1024              # 20 MB per image
WORKERS     = 4                              # PIL thread pool size
BANS_FILE   = Path("bans.json")             # Persists ban state across restarts

# Rate limiting
RATE_LIMIT  = 20   # max requests
RATE_WINDOW = 60   # per N seconds

# Escalating ban durations (seconds)
BAN_LEVELS = [
    3_600,        # level 1 — 1 hour
    86_400,       # level 2 — 24 hours
    604_800,      # level 3 — 7 days
    float("inf"), # level 4 — permanent
]

# ─── Logging ──────────────────────────────────────────────────────────────────
# We never log filenames, EXIF content, binary data or user-identifiable info.
# Only anonymised counters and error types are logged.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("exif_bot")

# ─── PIL safety ───────────────────────────────────────────────────────────────

# Hard cap on pixel count — prevents decompression bomb attacks
Image.MAX_IMAGE_PIXELS = 50_000_000  # ~7000×7000 px

executor = ThreadPoolExecutor(max_workers=WORKERS)

# ─── File validation ──────────────────────────────────────────────────────────

def validate_image_bytes(data: bytes) -> bool:
    """
    Validate file by magic bytes, not filename or extension.
    Attackers routinely fake extensions — always check the actual header.

    JPEG:  FF D8 FF
    PNG:   89 50 4E 47 0D 0A 1A 0A
    WEBP:  52 49 46 46 ... 57 45 42 50
    HEIC:  [4-byte box size] 66 74 79 70
    """
    if len(data) < 12:
        return False
    if data[:3] == b"\xff\xd8\xff":
        return True                           # JPEG
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return True                           # PNG
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return True                           # WEBP
    if data[4:8] == b"ftyp":
        return True                           # HEIC/HEIF (any box size)
    return False

# ─── Moderation ───────────────────────────────────────────────────────────────

_rate_windows: dict[int, deque] = defaultdict(lambda: deque(maxlen=RATE_LIMIT + 1))
_bans: dict[int, dict]          = {}
_violations: dict[int, int]     = defaultdict(int)


def _load_bans() -> None:
    if BANS_FILE.exists():
        try:
            data = json.loads(BANS_FILE.read_text())
            now  = time.time()
            for uid_str, ban in data.items():
                if ban["until"] == -1 or ban["until"] > now:
                    _bans[int(uid_str)] = ban
            log.info("Loaded %d active bans", len(_bans))
        except Exception as e:
            log.warning("Could not load bans file: %s", e)


def _save_bans() -> None:
    try:
        BANS_FILE.write_text(
            json.dumps({str(k): v for k, v in _bans.items()}, indent=2)
        )
    except Exception as e:
        log.warning("Could not save bans file: %s", e)


def _is_banned(user_id: int) -> tuple[bool, str]:
    ban = _bans.get(user_id)
    if not ban:
        return False, ""
    if ban["until"] == -1 or time.time() < ban["until"]:
        if ban["until"] == -1:
            duration_str = "permanently"
        else:
            remaining = int(ban["until"] - time.time())
            if remaining >= 86400:
                duration_str = f"for {remaining // 86400} more day(s)"
            elif remaining >= 3600:
                duration_str = f"for {remaining // 3600} more hour(s)"
            else:
                duration_str = f"for {remaining // 60} more minute(s)"
        return True, (
            f"⛔ You have been restricted {duration_str} due to excessive usage.\n\n"
            f"This is automated. Access resumes automatically."
        )
    del _bans[user_id]
    _violations[user_id] = 0
    _save_bans()
    return False, ""


def _record_violation(user_id: int) -> str:
    _violations[user_id] += 1
    current_level = _bans.get(user_id, {}).get("level", -1)
    new_level     = min(current_level + 1, len(BAN_LEVELS) - 1)
    duration      = BAN_LEVELS[new_level]
    until         = -1 if duration == float("inf") else time.time() + duration

    _bans[user_id] = {"until": until, "level": new_level}
    _save_bans()

    if until == -1:
        duration_str = "permanently"
    elif duration >= 86400:
        duration_str = f"for {int(duration // 86400)} day(s)"
    elif duration >= 3600:
        duration_str = f"for {int(duration // 3600)} hour(s)"
    else:
        duration_str = f"for {int(duration // 60)} minute(s)"

    log.warning("User restricted %s (level %d)", duration_str, new_level)
    return (
        f"⛔ Slow down. You've been restricted {duration_str} due to excessive usage.\n\n"
        f"This bot is a free tool — please use it fairly. Restrictions lift automatically."
    )


def _check_rate(user_id: int) -> bool:
    now    = time.time()
    window = _rate_windows[user_id]
    while window and now - window[0] > RATE_WINDOW:
        window.popleft()
    if len(window) >= RATE_LIMIT:
        return False
    window.append(now)
    return True


async def _cleanup_task() -> None:
    """Hourly cleanup — prunes expired rate windows and bans from memory."""
    while True:
        await asyncio.sleep(3600)
        now          = time.time()
        pruned_rates = 0
        pruned_bans  = 0

        for uid in list(_rate_windows):
            w = _rate_windows[uid]
            while w and now - w[0] > RATE_WINDOW:
                w.popleft()
            if not w:
                del _rate_windows[uid]
                pruned_rates += 1

        for uid in list(_bans):
            ban = _bans[uid]
            if ban["until"] != -1 and now >= ban["until"]:
                del _bans[uid]
                _violations[uid] = 0
                pruned_bans += 1

        if pruned_bans:
            _save_bans()

        log.info(
            "Cleanup: pruned %d rate windows, %d expired bans. Active: %d",
            pruned_rates, pruned_bans, len(_bans),
        )

# ─── Core scrub ───────────────────────────────────────────────────────────────
#
# HOW ZERO STORAGE WORKS:
# ─────────────────────────
# 1. Image bytes arrive from Telegram as an in-memory buffer
# 2. PIL opens the buffer directly — no file is written to disk
# 3. A brand new image is created from raw pixel data only
# 4. Output is written to a fresh in-memory BytesIO buffer
# 5. Clean bytes are sent back to Telegram
# 6. Both buffers are garbage collected — nothing persists
#
# There is no temp file, no upload directory, no database write.
# The image exists only for the duration of processing (~1 second).

def _scrub_sync(data: bytes) -> tuple[bytes, str]:
    """
    Strip all metadata via pixel rebuild.
    Opens the image, creates a fresh image object from raw pixel data only.
    No EXIF, XMP, IPTC or ICC profile from the original is carried over.
    """
    img = Image.open(io.BytesIO(data))
    fmt = (img.format or "JPEG").upper()

    if fmt in ("HEIF", "HEIC"):
        fmt = "JPEG"

    # Normalise colour mode for JPEG output
    if fmt == "JPEG" and img.mode in ("RGBA", "LA", "P"):
        bg = Image.new("RGB", img.size, (255, 255, 255))
        if img.mode == "P":
            img = img.convert("RGBA")
        if img.mode in ("RGBA", "LA"):
            bg.paste(img, mask=img.split()[-1])
        img = bg
    elif img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGB")

    # Pixel rebuild — creates a new image from raw pixel data only
    # Any EXIF, XMP, IPTC or ICC data is not carried over
    clean = Image.new(img.mode, img.size)
    clean.putdata(list(img.getdata()))

    buf = io.BytesIO()
    if fmt == "PNG":
        clean.save(buf, format="PNG", optimize=True)
        return buf.getvalue(), "png"
    elif fmt == "WEBP":
        clean.save(buf, format="WEBP", quality=92)
        return buf.getvalue(), "webp"
    else:
        clean.save(buf, format="JPEG", quality=95, optimize=True)
        return buf.getvalue(), "jpg"


async def scrub(data: bytes) -> tuple[bytes, str]:
    """Run CPU-bound scrub in thread pool to avoid blocking the event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, _scrub_sync, data)

# ─── Welcome message ──────────────────────────────────────────────────────────

WELCOME = (
    "🛡 <b>EXIF Scrubber — Protect Your Images</b>\n\n"
    "Every photo you take contains hidden metadata called <b>EXIF data</b>. This includes:\n"
    "📍 GPS location where the photo was taken\n"
    "📱 Device model and serial number\n"
    "🕐 Exact date and time of capture\n"
    "👤 Sometimes your name and software used\n\n"
    "<b>Why scrub before listing?</b>\n"
    "Leaving EXIF data in your photos is a privacy risk — anyone can extract "
    "your home address from a product photo taken at home.\n\n"
    "<b>How to use</b>\n"
    "1. Send any image (JPEG, PNG, WEBP or HEIC)\n"
    "2. Get it back fully clean in seconds\n"
    "3. Max file size: <b>20 MB</b>\n\n"
    "⚠️ <b>Important</b>\n"
    "When the bot returns your clean image, press and hold → "
    "<b>Save to Downloads</b> or <b>Save to Gallery</b>.\n\n"
    "<b>Do not screenshot it.</b> A screenshot creates a new photo using your camera "
    "app — it reattaches your device model, time, and location all over again.\n\n"
    "<i>Powered by Vendly Privacy Labs — vendlyprivacylabs.com</i>"
)

# ─── Handlers ─────────────────────────────────────────────────────────────────

dp = Dispatcher()


@dp.message(CommandStart())
async def send_welcome(msg: Message) -> None:
    await msg.answer(WELCOME, parse_mode="HTML")


@dp.message(F.photo | F.document)
async def handle_image(msg: Message, bot: Bot) -> None:
    if not msg.from_user:
        return
    user_id = msg.from_user.id

    banned, ban_msg = _is_banned(user_id)
    if banned:
        await msg.reply(ban_msg)
        return

    if not _check_rate(user_id):
        await msg.reply(_record_violation(user_id))
        return

    if msg.photo:
        file_id = msg.photo[-1].file_id
        fname   = "image.jpg"
    else:
        doc = msg.document
        if not doc.mime_type or not doc.mime_type.startswith("image/"):
            await msg.reply("⚠️ Please send an image file (JPEG, PNG, WEBP or HEIC).")
            return
        file_id = doc.file_id
        fname   = doc.file_name or "image.jpg"

    file_info = await bot.get_file(file_id)
    if file_info.file_size and file_info.file_size > MAX_BYTES:
        size_mb = file_info.file_size / (1024 * 1024)
        await msg.reply(
            f"⚠️ File too large ({size_mb:.1f} MB). Maximum is 20 MB.\n"
            "Try compressing the image first."
        )
        return

    processing = await msg.reply("⏳ Scrubbing...")

    try:
        # Downloaded directly to memory — never touches disk
        raw_bytes = (await bot.download(file_id)).read()

        if not validate_image_bytes(raw_bytes):
            await msg.reply("⚠️ Unrecognised format. Send a JPEG, PNG, WEBP or HEIC image.")
            return

        clean_bytes, ext = await scrub(raw_bytes)

        base        = os.path.splitext(fname)[0]
        clean_fname = f"{base}_clean.{ext}"

        await msg.reply_document(
            BufferedInputFile(clean_bytes, filename=clean_fname),
            caption=(
                "🛡 <b>Clean. Untraceable. Yours.</b>\n\n"
                "✅ All metadata stripped — no GPS, no device ID, no timestamps\n\n"
                "⚠️ <b>Download the file — do not screenshot it.</b>\n\n"
                "<i>Powered by Vendly Privacy Labs — vendlyprivacylabs.com</i>"
            ),
            parse_mode="HTML",
        )
        log.info("Scrubbed image (anonymised)")

    except Exception as e:
        log.exception("Scrub failed: %s", e)
        await msg.reply(
            "❌ Could not process that image. "
            "Make sure it's a valid JPEG, PNG, WEBP or HEIC file under 20 MB."
        )
    finally:
        try:
            await bot.delete_message(msg.chat.id, processing.message_id)
        except Exception:
            pass


@dp.message()
async def fallback(msg: Message) -> None:
    await msg.reply(
        "Send me an image and I'll strip all metadata from it. 🛡\n\n"
        "Type /start to learn more."
    )

# ─── Entry point ──────────────────────────────────────────────────────────────

async def main() -> None:
    _load_bans()
    log.info("Starting EXIF Scrubber Bot")
    bot = Bot(token=BOT_TOKEN)
    asyncio.create_task(_cleanup_task())
    try:
        await dp.start_polling(bot, allowed_updates=["message"])
    finally:
        executor.shutdown(wait=False)


if __name__ == "__main__":
    asyncio.run(main())
