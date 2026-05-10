# EXIF Scrubber Bot

A free, open source Telegram bot that strips hidden metadata from images and applies pixel-level transforms to break AI image fingerprinting.

**Zero data stored.** Images are processed entirely in memory and never written to disk or logged.

➡️ **Try it live: [@ExifStripBot](https://t.me/ExifStripBot)**
🌐 **Website: [vendlyprivacylabs.com](https://vendlyprivacylabs.com)**

---

## What it does

Every photo taken on a phone or camera contains hidden **EXIF metadata**:

- 📍 GPS coordinates (your home address if you photograph products at home)
- 📱 Device make, model and serial number
- 🕐 Exact date and time of capture
- 👤 Software, app and sometimes owner name

This bot removes all of it and applies transforms that break image fingerprinting — AI systems used by platforms like eBay, Vinted and Depop to detect the same photo across multiple listings.

---

## How zero storage works

```
User sends image
      ↓
Telegram delivers bytes to bot
      ↓
PIL opens bytes directly in memory (no file written to disk)
      ↓
7 pixel-level transforms applied in memory
      ↓
Pixel rebuild strips any remaining metadata
      ↓
Clean bytes sent back to user via Telegram
      ↓
Both buffers garbage collected — nothing persists
```

There is no upload directory, no database, no temp file, no log of image content. The image exists only for the 1–2 seconds it takes to process. You can verify this by reading `bot.py` — there is no file write operation anywhere in the processing pipeline.

---


---

## Supported formats

- JPEG
- PNG
- WEBP
- HEIC / HEIF

---

## Self-moderation

The bot requires zero admin intervention:

- **Rate limiting** — 20 images per 60 seconds per user
- **Escalating bans** — 1 hour → 24 hours → 7 days → permanent
- **Hourly cleanup** — expired bans and rate windows pruned from memory automatically
- **Ban persistence** — `bans.json` survives restarts

---

## Security

- Magic byte validation — file type checked by header, not extension
- `Image.MAX_IMAGE_PIXELS = 50_000_000` — decompression bomb protection
- Thread pool isolation — PIL processing never blocks the event loop
- No execute permissions needed — nothing written to disk
- Bot token loaded from environment variable only — never hardcoded

---

## Setup

**Requirements**
- Python 3.10+
- A Telegram bot token from [@BotFather](https://t.me/BotFather)

```bash
# Clone
git clone https://github.com/vendlyprivacylabs/exif-scrubber-bot
cd exif-scrubber-bot

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env and add your bot token

# Run
python bot.py
```

**As a systemd service (production)**

```ini
[Unit]
Description=EXIF Scrubber Bot
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/exif-bot
EnvironmentFile=/opt/exif-bot/.env
ExecStart=/opt/exif-bot/venv/bin/python bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `EXIF_BOT_TOKEN` | Your Telegram bot token from @BotFather |

---

## Built by

**Vendly Privacy Labs** — free privacy tools, zero data stored.

🌐 [vendlyprivacylabs.com](https://vendlyprivacylabs.com)
✈️ [@ExifStripBot](https://t.me/ExifStripBot)

---

## License

MIT — see [LICENSE](LICENSE)
