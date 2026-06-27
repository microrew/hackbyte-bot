import os
import io
import json
import asyncio
import logging
from pathlib import Path
from typing import Optional, List, Set

import aiohttp
import discord
from discord.ext import commands
from PIL import Image
import imagehash
import easyocr
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0"))

# ---- Tuning knobs ----
BASE_DIR = Path(__file__).parent
HASH_DB_FILE = BASE_DIR / "known_scam_hashes.json"
PHASH_DISTANCE_THRESHOLD = 6   # lower = stricter
DELETE_ON_SCORE = True
TIMEOUT_SECONDS = 10
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif")

SCAM_KEYWORDS = {
    "withdraw", "withdrawal", "bonus", "usdt", "crypto", "casino",
    "activate code", "activate", "mrbeast", "claim", "trx", "wallet",
    "deposit", "rewards", "kakeback", "keback", "bonus code",
}

SCAM_PHRASES = {
    "withdraw success",
    "activate code for bonus",
    "you have a question",
    "wallet balance",
    "crypto withdrawal",
    "bonus activated",
}

# ---- Discord setup ----
intents = discord.Intents.default()
intents.message_content = True
intents.guild_messages = True
intents.dm_messages = True

bot = commands.Bot(command_prefix="!", intents=intents)

logger = logging.getLogger("hackbyte")
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

# EasyOCR is heavy; create once.
ocr_reader: Optional[easyocr.Reader] = None

# Stored hashes as strings
known_hashes: Set[str] = set()

print(HASH_DB_FILE.resolve())

def load_hashes() -> None:
    global known_hashes
    if HASH_DB_FILE.exists():
        try:
            known_hashes = set(json.loads(HASH_DB_FILE.read_text()))
        except Exception:
            known_hashes = set()
    else:
        known_hashes = set()


def save_hashes() -> None:
    HASH_DB_FILE.write_text(json.dumps(sorted(known_hashes), indent=2))


def normalize_text(text: str) -> str:
    text = text.lower()
    text = text.replace("0", "o").replace("1", "i").replace("$", "s")
    text = " ".join(text.split())
    return text


def score_text(text: str) -> tuple[int, List[str]]:
    """
    Returns (score, matched_hits)
    """
    hits = []
    score = 0
    t = normalize_text(text)

    for phrase in SCAM_PHRASES:
        if phrase in t:
            hits.append(phrase)
            score += 4

    for kw in SCAM_KEYWORDS:
        if kw in t:
            hits.append(kw)
            score += 2

    # Simple aggressive boost for suspicious combinations
    if ("withdraw" in t and "bonus" in t) or ("usdt" in t and "withdraw" in t):
        score += 3
        hits.append("combo")
    return score, hits


def is_image_attachment(att: discord.Attachment) -> bool:
    ctype = (att.content_type or "").lower()
    if ctype.startswith("image/"):
        return True
    name = (att.filename or "").lower()
    return name.endswith(IMAGE_EXTS)


async def download_attachment(att: discord.Attachment) -> bytes:
    return await att.read()


def phash_from_bytes(data: bytes):
    img = Image.open(io.BytesIO(data)).convert("RGB")
    return imagehash.phash(img)


import numpy as np

async def ocr_image_bytes(data: bytes) -> str:
    global ocr_reader

    if ocr_reader is None:
        ocr_reader = easyocr.Reader(["en"], gpu=False)

    def _run():
        img = Image.open(io.BytesIO(data)).convert("RGB")

        # EasyOCR expects numpy array
        img = np.array(img)

        result = ocr_reader.readtext(
            img,
            detail=0,
            paragraph=True,
        )

        return " ".join(result)

    return await asyncio.to_thread(_run)

async def log_action(message: discord.Message, reason: str, details: str = ""):
    logger.info("Deleted message from %s in #%s | %s | %s",
                message.author, getattr(message.channel, "name", "dm"), reason, details)

    if LOG_CHANNEL_ID and isinstance(message.guild, discord.Guild):
        ch = message.guild.get_channel(LOG_CHANNEL_ID)
        if ch:
            try:
                await ch.send(
                    f"🛡️ Deleted suspicious image from **{message.author}** in {message.channel.mention}\n"
                    f"**Reason:** {reason}\n"
                    f"{details[:1500]}"
                )
            except Exception:
                pass


async def handle_attachment(message: discord.Message, att: discord.Attachment) -> bool:
    """
    Return True if message should be deleted.
    """
    try:
        data = await download_attachment(att)
    except Exception as e:
        logger.warning("Failed downloading attachment: %s", e)
        return False

    # 1) pHash check
    try:
        h = phash_from_bytes(data)
        h_str = str(h)
        for known in known_hashes:
            try:
                dist = h - imagehash.hex_to_hash(known)
                if dist <= PHASH_DISTANCE_THRESHOLD:
                    await log_action(message, "Known scam image hash", f"distance={dist}, file={att.filename}")
                    return True
            except Exception:
                continue
    except Exception as e:
        logger.warning("pHash failed: %s", e)

    # 2) OCR check
    text = await ocr_image_bytes(data)
    if text:
        score, hits = score_text(text)
        if score >= 4:
            await log_action(
                message,
                "OCR matched scam text",
                f"hits={hits}, file={att.filename}, text={text[:300]}"
            )
            # Save hash as known scam if this looks obviously bad
            try:
                known_hashes.add(str(phash_from_bytes(data)))
                save_hashes()
            except Exception:
                pass
            return True

    # 3) If this is a repeated same-style image, you can optionally store hash after manual review
    return False


@bot.event
async def on_ready():
    load_hashes()
    logger.info("Logged in as %s (%s)", bot.user, bot.user.id if bot.user else "?")
    logger.info("Loaded %d known hashes", len(known_hashes))


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    # Only inspect messages with attachments
    if not message.attachments:
        await bot.process_commands(message)
        return

    should_delete = False

    for att in message.attachments:
        if not is_image_attachment(att):
            continue

        if await handle_attachment(message, att):
            should_delete = True
            break

    if should_delete:
        try:
            await message.delete()
        except discord.Forbidden:
            logger.warning("No permission to delete message in %s", message.channel)
        except discord.NotFound:
            pass
        except discord.HTTPException as e:
            logger.warning("Delete failed: %s", e)

    await bot.process_commands(message)


@bot.command()
@commands.has_permissions(manage_messages=True)
async def train(ctx: commands.Context):
    """
    Reply to an image with !train to save its hash.
    """

    if ctx.message.reference is None:
        return await ctx.reply(
            "Reply to an image and type `!train`."
        )

    try:
        msg = await ctx.channel.fetch_message(
            ctx.message.reference.message_id
        )

        if not msg.attachments:
            return await ctx.reply("That message has no image.")

        att = next(
            (a for a in msg.attachments if is_image_attachment(a)),
            None
        )

        if att is None:
            return await ctx.reply("No image attachment found.")

        data = await att.read()

        h = str(phash_from_bytes(data))

        if h in known_hashes:
            return await ctx.reply(
                "I already know this scam image."
            )

        known_hashes.add(h)
        save_hashes()

        await ctx.reply(
            f"Learned new scam image!\n"
            f"Total hashes: **{len(known_hashes)}**"
        )

    except Exception as e:
        await ctx.reply(f"Failed: {e}")

@bot.command()
@commands.has_permissions(manage_messages=True)
async def clearscamhashes(ctx: commands.Context):
    known_hashes.clear()
    save_hashes()
    await ctx.reply("Cleared all saved scam hashes.")


if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN missing in .env")

bot.run(TOKEN)