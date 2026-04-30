#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NaiveProxy Telegram Bot | Production-Ready v2
Архитектура: FSM + SQLite(WAL) + APScheduler + AsyncIO
Новое: тарифы в БД, продвинутая реферальная система, диагностика панели
"""
from __future__ import annotations

import os, csv, io, json, re, sqlite3, asyncio, logging
import secrets, string, time, zipfile
from html import escape
from enum import Enum
from datetime import datetime, date, timedelta, timezone
from typing import Optional, List
from contextlib import contextmanager
from pathlib import Path
from collections import defaultdict
from functools import wraps
from dotenv import load_dotenv


class PaymentStatus(str, Enum):
    PENDING           = "pending"
    AWAITING_CONFIRM  = "awaiting_confirm"
    PROCESSING        = "processing"
    APPROVED          = "approved"
    REJECTED          = "rejected"
    CANCELLED         = "cancelled"

import qrcode

import httpx, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    ReplyKeyboardMarkup, KeyboardButton,
    InlineKeyboardMarkup, InlineKeyboardButton,
    CallbackQuery, Message,
)
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramRetryAfter, TelegramAPIError
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
import pytz

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГУРАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════
_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(_env, override=True)
load_dotenv(override=True)

BOT_TOKEN     = os.getenv("BOT_TOKEN",     "YOUR_BOT_TOKEN")
ADMIN_ID      = int(os.getenv("ADMIN_ID",  "0"))
PANEL_URL        = os.getenv("PANEL_URL",        "http://127.0.0.1:3000")
PANEL_USER       = os.getenv("PANEL_USER",       "admin")
PANEL_PASS       = os.getenv("PANEL_PASS",       "admin")
# PANEL_VERIFY_SSL=false в .env отключает проверку сертификата (для self-signed).
# По умолчанию — включена. Не отключай без необходимости (MITM-уязвимость).
PANEL_VERIFY_SSL = os.getenv("PANEL_VERIFY_SSL", "true").lower() not in ("0", "false", "no")
DOMAIN        = os.getenv("DOMAIN",        "vpn.example.com")
DB_PATH       = os.getenv("DB_PATH",       "/opt/vpn_bot/bot.db")
BACKUP_DIR    = os.getenv("BACKUP_DIR",    "/opt/vpn_bot/backups")
LOG_PATH      = os.getenv("LOG_PATH",      "/opt/vpn_bot/bot.log")
PAYMENT_PHONE = os.getenv("PAYMENT_PHONE", "+79000000000")
PAYMENT_BANK  = os.getenv("PAYMENT_BANK",  "Тинькофф / Сбер")
PAYMENT_NAME  = os.getenv("PAYMENT_NAME",  "Иван И.")
TIMEZONE      = os.getenv("TZ",            "Europe/Moscow")
TZ            = pytz.timezone(TIMEZONE)
TRIAL_HOURS   = int(os.getenv("TRIAL_HOURS", "48"))

# Дополнительные администраторы (через запятую в .env: EXTRA_ADMINS=123,456)
_extra = os.getenv("EXTRA_ADMINS", "")
EXTRA_ADMINS: set[int] = {int(x.strip()) for x in _extra.split(",") if x.strip().isdigit()}

# Тарифы по умолчанию — загружаются из БД при старте, это только fallback
DEFAULT_TARIFFS = {30: 400, 90: 1100, 180: 1500}

# Реферальная система: процент дней тарифа
REF_BONUS_PERCENT = float(os.getenv("REF_BONUS_PERCENT", "20"))

# Страницы списка пользователей
PAGE_SIZE = 10

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s]: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
    ],
)
logger = logging.getLogger("naive_bot")

# ══════════════════════════════════════════════════════════════════════════════
#  УТИЛИТЫ
# ══════════════════════════════════════════════════════════════════════════════
_background_tasks: set = set()
_bg_semaphore = asyncio.Semaphore(200)  # не более 200 фоновых задач одновременно
sync_lock = asyncio.Lock()

def fire_and_forget(coro):
    """Запускает корутину фоново. Не более 200 задач одновременно."""
    async def _guarded():
        async with _bg_semaphore:
            await coro
    task = asyncio.create_task(_guarded())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


class RateLimiter:
    def __init__(self): self._ts: dict[int, float] = defaultdict(float)
    def allow(self, uid: int, interval: float = 1.5) -> bool:
        now = time.time()
        # Чистим устаревшие записи раз в 1000 вызовов чтобы не копить память
        if len(self._ts) > 1000:
            cutoff = now - 3600  # записи старше 1 часа удаляем
            self._ts = {k: v for k, v in self._ts.items() if v > cutoff}
        if now - self._ts[uid] >= interval:
            self._ts[uid] = now
            return True
        return False

rate_limiter = RateLimiter()


def async_retry(max_retries=3, delay=1.0):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(1, max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        raise
                    await asyncio.sleep(delay * attempt)
        return wrapper
    return decorator


def handle_errors():
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.exception(f"Error in {func.__name__}: {e}")
                for arg in args:
                    if isinstance(arg, CallbackQuery):
                        try:
                            await arg.answer("❌ Внутренняя ошибка", show_alert=True)
                        except Exception:
                            pass
                        break
                    if isinstance(arg, Message):
                        try:
                            await arg.answer("❌ Произошла внутренняя ошибка. Попробуйте позже.")
                        except Exception:
                            pass
                        break
        return wrapper
    return decorator


async def safe_send(chat_id: int, text: str, **kwargs) -> bool:
    """
    Отправляет сообщение с retry + exponential backoff.
    - TelegramRetryAfter: ждёт сколько Telegram просит
    - Сетевые ошибки: 3 попытки с задержкой 1s, 3s, 7s
    - Заблокированный/удалённый пользователь: сразу False без retry
    """
    delays = [1, 3, 7]
    for attempt, delay in enumerate(delays):
        try:
            await bot.send_message(chat_id, text, **kwargs)
            return True
        except TelegramRetryAfter as e:
            await asyncio.sleep(e.retry_after + 1)
        except TelegramAPIError as e:
            err = str(e).lower()
            if any(x in err for x in ("bot was blocked", "user is deactivated", "chat not found", "forbidden")):
                logger.debug(f"safe_send: пользователь {chat_id} недоступен — {e}")
                return False
            # Сетевая / временная ошибка — ретраим с backoff
            logger.warning(f"safe_send attempt {attempt+1}/3: chat_id={chat_id} — {e}")
            if attempt < len(delays) - 1:
                await asyncio.sleep(delay)
        except Exception as e:
            logger.warning(f"safe_send unexpected error: chat_id={chat_id} — {e}")
            if attempt < len(delays) - 1:
                await asyncio.sleep(delay)
    return False


async def send_long(target, text: str, **kwargs) -> None:
    """Отправляет длинное сообщение частями по 4000 символов."""
    MAX = 4000
    first = True
    while text:
        chunk, text = text[:MAX], text[MAX:]
        kw = dict(kwargs) if first else {k: v for k, v in kwargs.items() if k != "reply_markup"}
        if hasattr(target, "answer"):
            await target.answer(chunk, **kw)
        else:
            await bot.send_message(target, chunk, **kw)
        first = False


def parse_date(value) -> Optional[date]:
    if not value: return None
    try: return date.fromisoformat(str(value).split(" ")[0].split("T")[0])
    except Exception: return None


def parse_datetime(value) -> Optional[datetime]:
    if not value: return None
    try:
        norm = str(value).replace("T", " ").split(".")[0].strip()
        fmt = "%Y-%m-%d %H:%M:%S" if " " in norm else "%Y-%m-%d"
        return datetime.strptime(norm, fmt)
    except Exception: return None


def days_left(end_str) -> int:
    d = parse_date(end_str)
    return max(0, (d - datetime.now(TZ).date()).days) if d else 0


def safe_html(val) -> str:
    return escape(str(val)) if val else ""


def gen_payment_code() -> str:
    return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))


def gen_ref_code(tg_id: int = 0) -> str:
    return secrets.token_hex(5)


def gen_password(length: int = 16) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits + "_-") for _ in range(length))


def make_naive_key(user: str, pwd: str) -> str:
    return f"naive+https://{user}:{pwd}@{DOMAIN}:443"


def _make_qr_bytes(text: str) -> bytes:
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


async def send_key_with_qr(target, key: str, caption: str, **kwargs):
    """
    Отправляет QR-код как фото с подписью ключа.
    target — Message (answer_photo) или int (bot.send_photo).
    Fallback на текст если QR не сгенерировался.
    """
    try:
        qr_bytes = await asyncio.get_running_loop().run_in_executor(None, _make_qr_bytes, key)
        photo    = types.BufferedInputFile(qr_bytes, filename="qr.png")
        if isinstance(target, int):
            await bot.send_photo(target, photo, caption=caption, **kwargs)
        else:
            await target.answer_photo(photo, caption=caption, **kwargs)
        return
    except Exception as e:
        logger.warning(f"QR generation failed: {e}")
    # Fallback — текст без QR
    if isinstance(target, int):
        await safe_send(target, caption, **kwargs)
    else:
        await target.answer(caption, **kwargs)


def fmt_traffic(b: int) -> str:
    if not b: return "0 B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"


def gen_proxy_username(tg_id: int, username: str = None, first_name: str = None) -> str:
    if username:
        base = re.sub(r"[^a-z0-9_]", "", username.lower())[:12]
        if base: return base
    if first_name:
        base = re.sub(r"[^a-z0-9_]", "", first_name.lower())[:12]
        if base: return base
    return f"u{tg_id}"


def _ensure_unique_proxy_user(conn: sqlite3.Connection, base: str) -> str:
    candidate = base
    i = 1
    while conn.execute("SELECT 1 FROM users WHERE proxy_user=?", (candidate,)).fetchone():
        candidate = f"{base}_{i}"
        i += 1
    return candidate


def safe_cb_int(data: str, pos: int = 1) -> Optional[int]:
    """Безопасно извлекает int из callback_data. Возвращает None при ошибке."""
    try:
        return int(data.split(":")[pos])
    except (IndexError, ValueError):
        return None


def calc_ref_bonus_days(tariff_days: int) -> int:
    """Считает бонусные дни реферала: REF_BONUS_PERCENT% от купленного тарифа, минимум 1 день."""
    return max(1, round(tariff_days * get_ref_bonus_pct() / 100))


def deactivate_user(conn, tg_id: int, source: str = "manual") -> None:
    """
    Единая функция деактивации пользователя в БД.
    Обнуляет proxy_user/pass/subscription_end, сбрасывает флаги, пишет историю.
    Вызывать внутри открытого with get_db() as conn.
    """
    row = conn.execute(
        "SELECT proxy_user, subscription_end FROM users WHERE tg_id=?", (tg_id,)
    ).fetchone()
    conn.execute(
        "UPDATE users SET is_active=0, proxy_user=NULL, proxy_pass=NULL, "
        "subscription_end=NULL, notified_1d=0, notified_3d=0, "
        "notified_7d=0, notified_remind=0 WHERE tg_id=?",
        (tg_id,),
    )
    if row and row["proxy_user"]:
        conn.execute(
            "INSERT INTO subscription_history "
            "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
            (tg_id, "expire", 0, row["subscription_end"] or "", "", source),
        )

# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════════════
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try: yield conn
    finally: conn.close()


def _col_exists(conn, table: str, column: str) -> bool:
    return any(r[1] == column for r in conn.execute(f"PRAGMA table_info({table})").fetchall())


def _run_init_db():
    with get_db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            tg_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, last_name TEXT,
            proxy_user TEXT UNIQUE, proxy_pass TEXT, subscription_end TIMESTAMP,
            traffic_up INTEGER DEFAULT 0, traffic_down INTEGER DEFAULT 0,
            referral_code TEXT UNIQUE, referred_by INTEGER,
            ref_balance INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 0, is_approved BOOLEAN DEFAULT 1,
            onboarded BOOLEAN DEFAULT 0,
            notified_1d BOOLEAN DEFAULT 0, notified_3d BOOLEAN DEFAULT 0,
            notified_remind BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tg_id INTEGER, amount INTEGER, duration INTEGER,
            payment_code TEXT UNIQUE, status TEXT DEFAULT 'pending',
            admin_msg_id INTEGER, panel_updated BOOLEAN DEFAULT 0,
            admin_reminded BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER, referred_id INTEGER,
            bonus_days INTEGER DEFAULT 0,
            payment_count INTEGER DEFAULT 0,
            total_bonus_given INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(referrer_id, referred_id)
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS trials (
            tg_id INTEGER PRIMARY KEY, proxy_user TEXT UNIQUE, proxy_pass TEXT,
            activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP,
            notified_24h BOOLEAN DEFAULT 0, notified_6h BOOLEAN DEFAULT 0,
            converted BOOLEAN DEFAULT 0, expired_processed BOOLEAN DEFAULT 0,
            panel_added BOOLEAN DEFAULT 0
        )""")

        # ── Тарифы в БД ──────────────────────────────────────────────────────
        conn.execute("""CREATE TABLE IF NOT EXISTS tariffs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            days INTEGER UNIQUE NOT NULL,
            price INTEGER NOT NULL,
            label TEXT,
            is_active BOOLEAN DEFAULT 1,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS bot_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS admins (
            tg_id INTEGER PRIMARY KEY,
            username TEXT,
            added_by INTEGER,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS subscription_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tg_id INTEGER,
            action TEXT,
            days INTEGER,
            old_end TEXT,
            new_end TEXT,
            source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS broadcast_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            audience TEXT,
            message_preview TEXT,
            sent INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS promo_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            discount_pct INTEGER DEFAULT 0,
            bonus_days INTEGER DEFAULT 0,
            max_uses INTEGER DEFAULT 1,
            used_count INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS promo_uses (
            promo_id INTEGER, tg_id INTEGER,
            used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(promo_id, tg_id)
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS pay_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS support_replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER, admin_id INTEGER,
            reply TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS polls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT, options TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS poll_votes (
            poll_id INTEGER, tg_id INTEGER, option_idx INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(poll_id, tg_id)
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tg_id INTEGER, message TEXT, status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # Индексы
        for idx in [
            "CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status)",
            "CREATE INDEX IF NOT EXISTS idx_users_proxy ON users(proxy_user)",
            "CREATE INDEX IF NOT EXISTS idx_users_sub_end ON users(subscription_end)",
            "CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)",
        ]:
            conn.execute(idx)

        # Миграции (идемпотентные)
        migrations = {
            "users.is_approved":      "ALTER TABLE users ADD COLUMN is_approved BOOLEAN DEFAULT 1",
            "users.onboarded":        "ALTER TABLE users ADD COLUMN onboarded BOOLEAN DEFAULT 0",
            "users.notified_remind":  "ALTER TABLE users ADD COLUMN notified_remind BOOLEAN DEFAULT 0",
            "users.traffic_up":       "ALTER TABLE users ADD COLUMN traffic_up INTEGER DEFAULT 0",
            "users.traffic_down":     "ALTER TABLE users ADD COLUMN traffic_down INTEGER DEFAULT 0",
            "users.ref_balance":      "ALTER TABLE users ADD COLUMN ref_balance INTEGER DEFAULT 0",
            "users.is_banned":        "ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT 0",
            "users.notified_7d":      "ALTER TABLE users ADD COLUMN notified_7d BOOLEAN DEFAULT 0",
            "payments.user_reminded": "ALTER TABLE payments ADD COLUMN user_reminded BOOLEAN DEFAULT 0",
            "users.last_tariff_days": "ALTER TABLE users ADD COLUMN last_tariff_days INTEGER DEFAULT 0",
            "payments.admin_reminded":"ALTER TABLE payments ADD COLUMN admin_reminded BOOLEAN DEFAULT 0",
            "payments.updated_at":    "ALTER TABLE payments ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            "referrals.bonus_days":         "ALTER TABLE referrals ADD COLUMN bonus_days INTEGER DEFAULT 0",
            "referrals.total_bonus_given":  "ALTER TABLE referrals ADD COLUMN total_bonus_given INTEGER DEFAULT 0",
            "referrals.payment_count":      "ALTER TABLE referrals ADD COLUMN payment_count INTEGER DEFAULT 0",
        }
        for col, sql in migrations.items():
            tbl, c = col.split(".")
            if not _col_exists(conn, tbl, c):
                conn.execute(sql)

        # Заполняем реквизиты по умолчанию если пусто
        defaults = {
            "phone": PAYMENT_PHONE,
            "bank":  PAYMENT_BANK,
            "name":  PAYMENT_NAME,
        }
        for k, v in defaults.items():
            conn.execute("INSERT OR IGNORE INTO pay_settings (key, value) VALUES (?,?)", (k, v))

        # Настройки бота по умолчанию
        bot_defaults = {
            "trial_hours":          str(TRIAL_HOURS),
            "ref_bonus_pct":        str(REF_BONUS_PERCENT),
            "notify_new_user":      "1",
            "welcome_text":         "",
            "maintenance":          "0",
            # Реферальная антинакрутка
            "ref_min_tariff_days":  "30",   # минимальный тариф для начисления бонуса
            "ref_account_age_days": "2",    # аккаунт реферала должен быть старше N дней
            "ref_max_bonus_month":  "30",   # максимум бонусных дней рефереру в месяц
            "ref_first_only":       "1",    # 1 = бонус только за первую оплату реферала
        }
        for k, v in bot_defaults.items():
            conn.execute("INSERT OR IGNORE INTO bot_settings (key, value) VALUES (?,?)", (k, v))

        # Заполняем тарифы по умолчанию если таблица пустая
        if not conn.execute("SELECT 1 FROM tariffs LIMIT 1").fetchone():
            for i, (days, price) in enumerate(DEFAULT_TARIFFS.items()):
                conn.execute(
                    "INSERT OR IGNORE INTO tariffs (days, price, sort_order) VALUES (?,?,?)",
                    (days, price, i),
                )

        # ── Бэкфилл для существующих пользователей ───────────────────────────
        # 1) Уже подключённые клиенты (proxy_user есть) — помечаем onboarded=1,
        #    чтобы они не получили онбординг при следующем продлении
        conn.execute(
            "UPDATE users SET onboarded=1 "
            "WHERE proxy_user IS NOT NULL AND onboarded=0"
        )

        # 2) Восстанавливаем last_tariff_days из истории подписок:
        #    берём последний платёж каждого пользователя (source LIKE 'payment:%')
        conn.execute("""
            UPDATE users SET last_tariff_days = (
                SELECT sh.days FROM subscription_history sh
                WHERE sh.tg_id = users.tg_id
                  AND sh.source LIKE 'payment:%'
                  AND sh.days > 0
                ORDER BY sh.id DESC LIMIT 1
            )
            WHERE last_tariff_days = 0
              AND EXISTS (
                  SELECT 1 FROM subscription_history sh2
                  WHERE sh2.tg_id = users.tg_id
                    AND sh2.source LIKE 'payment:%'
                    AND sh2.days > 0
              )
        """)

        conn.commit()
        logger.info("✅ DB инициализирована")


async def init_db():
    await asyncio.get_running_loop().run_in_executor(None, _run_init_db)


def get_tariffs() -> dict[int, int]:
    """Загружает активные тарифы из БД."""
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT days, price FROM tariffs WHERE is_active=1 ORDER BY sort_order, days"
            ).fetchall()
            return {r["days"]: r["price"] for r in rows} if rows else DEFAULT_TARIFFS
    except Exception:
        return DEFAULT_TARIFFS

def get_pay_settings() -> dict:
    """Загружает реквизиты оплаты из БД."""
    try:
        with get_db() as conn:
            rows = conn.execute("SELECT key, value FROM pay_settings").fetchall()
            d = {r["key"]: r["value"] for r in rows}
            return {
                "phone": d.get("phone", PAYMENT_PHONE),
                "bank":  d.get("bank",  PAYMENT_BANK),
                "name":  d.get("name",  PAYMENT_NAME),
            }
    except Exception:
        return {"phone": PAYMENT_PHONE, "bank": PAYMENT_BANK, "name": PAYMENT_NAME}


def is_banned(tg_id: int) -> bool:
    try:
        with get_db() as conn:
            r = conn.execute("SELECT is_banned FROM users WHERE tg_id=?", (tg_id,)).fetchone()
            return bool(r and r["is_banned"])
    except Exception:
        return False


def is_admin(tg_id: int) -> bool:
    return tg_id == ADMIN_ID or tg_id in EXTRA_ADMINS


def get_setting(key: str, default: str = "") -> str:
    """Читает динамическую настройку бота из БД."""
    try:
        with get_db() as conn:
            r = conn.execute("SELECT value FROM bot_settings WHERE key=?", (key,)).fetchone()
            return r["value"] if r else default
    except Exception:
        return default


def set_setting(key: str, value: str):
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO bot_settings (key, value) VALUES (?,?)", (key, value))
        conn.commit()


def get_trial_hours() -> int:
    v = get_setting("trial_hours", str(TRIAL_HOURS))
    try:
        return int(v)
    except (ValueError, TypeError):
        logger.warning(f"get_trial_hours: некорректное значение '{v}', используем дефолт {TRIAL_HOURS}")
        return TRIAL_HOURS


def get_ref_bonus_pct() -> float:
    v = get_setting("ref_bonus_pct", str(REF_BONUS_PERCENT))
    try:
        return float(v)
    except (ValueError, TypeError):
        logger.warning(f"get_ref_bonus_pct: некорректное значение '{v}', используем дефолт {REF_BONUS_PERCENT}")
        return REF_BONUS_PERCENT

# ══════════════════════════════════════════════════════════════════════════════
#  NAIVEPROXY PANEL CLIENT
# ══════════════════════════════════════════════════════════════════════════════

panel = NaivePanelClient()


# Трекер недоступности панели (для health-check алертов)
_panel_down_since: Optional[float] = None

# ══════════════════════════════════════════════════════════════════════════════
#  FSM STORAGE (persistent)
# ══════════════════════════════════════════════════════════════════════════════
class SimpleDiskStorage(MemoryStorage):
    _DB = os.path.join(os.path.dirname(DB_PATH), "fsm_state.db")

    def __init__(self):
        super().__init__()
        self._alock: Optional[asyncio.Lock] = None
        self._conn = sqlite3.connect(self._DB, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS fsm_states (key TEXT PRIMARY KEY, value TEXT)"
        )
        self._conn.commit()
        for k, v in self._conn.execute("SELECT key, value FROM fsm_states").fetchall():
            try: self.storage[k] = json.loads(v)
            except Exception: pass

    @property
    def _lock_(self) -> asyncio.Lock:
        if self._alock is None:
            self._alock = asyncio.Lock()
        return self._alock

    def _persist_sync(self, key):
        """Синхронная запись состояния в SQLite (вызывается через run_in_executor)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO fsm_states (key, value) VALUES (?, ?)",
            (str(key), json.dumps(self.storage.get(str(key), {}), default=str)),
        )
        self._conn.commit()

    async def _persist(self, key):
        async with self._lock_:
            await asyncio.get_running_loop().run_in_executor(None, self._persist_sync, key)

    async def set_state(self, key, state=None):
        res = await super().set_state(key, state)
        # Записываем timestamp для TTL-очистки
        str_key = str(key)
        if str_key in self.storage:
            self.storage[str_key]["__fsm_ts__"] = time.time()
        await self._persist(key)
        return res

    async def set_data(self, key, data):
        res = await super().set_data(key, data)
        await self._persist(key)
        return res

    async def update_data(self, key, data):
        res = await super().update_data(key, data)
        await self._persist(key)
        return res

# ══════════════════════════════════════════════════════════════════════════════
#  BOT / DISPATCHER / FSM STATES
# ══════════════════════════════════════════════════════════════════════════════
bot       = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
dp        = Dispatcher(storage=SimpleDiskStorage())
scheduler = AsyncIOScheduler(timezone=TIMEZONE)


class PaymentFSM(StatesGroup):
    choosing_tariff = State()


class AdminFSM(StatesGroup):
    broadcast        = State()
    broadcast_filter = State()   # выбор аудитории рассылки
    extend_user      = State()
    extend_days      = State()
    adduser_tg_id    = State()
    create_poll      = State()
    poll_options     = State()
    # Тарифы
    tariff_add_days   = State()
    tariff_add_price  = State()
    tariff_add_label  = State()
    tariff_edit_id    = State()
    tariff_edit_field = State()
    tariff_edit_value = State()
    # Промокоды
    promo_add_code    = State()
    promo_add_discount = State()
    promo_add_uses    = State()
    promo_add_days    = State()
    # Поддержка — ответ
    reply_ticket_uid  = State()
    reply_ticket_text = State()
    # Поиск
    search_query      = State()
    # Настройки оплаты
    pay_settings_field = State()
    pay_settings_value = State()
    # Бан
    ban_uid           = State()
    # Импорт с панели
    link_tg_id        = State()


class SupportFSM(StatesGroup):
    waiting = State()


class PromoFSM(StatesGroup):
    applying = State()

# ══════════════════════════════════════════════════════════════════════════════
#  КЛАВИАТУРЫ
# ══════════════════════════════════════════════════════════════════════════════
def kb_main(is_admin=False) -> ReplyKeyboardMarkup:
    rows = [
        ["💎 Моя подписка",  "⚡️ Мой ключ"],
        ["🛍 Магазин",       "🎁 Бесплатный тест"],
        ["👥 Рефералы",      "📖 Инструкция"],
        ["🗳 Опросы",        "🧾 История"],
        ["💬 Поддержка"],
    ]
    if is_admin: rows.append(["🛠 Панель управления"])
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=b) for b in r] for r in rows],
        resize_keyboard=True,
    )


def kb_admin() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(keyboard=[
        [KeyboardButton(text="📋 Пользователи"),      KeyboardButton(text="🔍 Поиск пользователя")],
        [KeyboardButton(text="➕ Добавить клиента"),   KeyboardButton(text="🗑 Удалить клиента")],
        [KeyboardButton(text="➕ Продлить вручную"),   KeyboardButton(text="⚡️ Массовое продление")],
        [KeyboardButton(text="💰 Проверить оплаты"),   KeyboardButton(text="📣 Рассылка")],
        [KeyboardButton(text="📊 Статистика"),          KeyboardButton(text="📈 График")],
        [KeyboardButton(text="📊 Пробники"),            KeyboardButton(text="🏆 Топ рефералов")],
        [KeyboardButton(text="💲 Тарифы"),              KeyboardButton(text="🎟 Промокоды")],
        [KeyboardButton(text="📩 Тикеты"),              KeyboardButton(text="🚫 Бан / Разбан")],
        [KeyboardButton(text="⚙️ Реквизиты"),           KeyboardButton(text="⚙️ Настройки бота")],
        [KeyboardButton(text="👮 Администраторы"),      KeyboardButton(text="🗳 Создать опрос")],
        [KeyboardButton(text="📥 Экспорт CSV"),         KeyboardButton(text="📥 Экспорт платежей")],
        [KeyboardButton(text="🔧 Диагностика"),         KeyboardButton(text="🔄 Импорт с панели")],
        [KeyboardButton(text="🏠 Главное меню")],
    ], resize_keyboard=True)


def kb_tariffs() -> InlineKeyboardMarkup:
    tariffs = get_tariffs()
    rows = []
    for d, p in sorted(tariffs.items()):
        months = d // 30
        label = f"{months} мес." if months >= 1 else f"{d} дн."
        rows.append([InlineKeyboardButton(text=f"📦 {label} — {p} ₽", callback_data=f"tariff:{d}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def kb_tariffs_admin(tg_id: int) -> InlineKeyboardMarkup:
    tariffs = get_tariffs()
    btns = [
        [InlineKeyboardButton(text=f"📦 {d} дн. — {p} ₽", callback_data=f"admin_add:{tg_id}:{d}")]
        for d, p in sorted(tariffs.items())
    ]
    btns.append([InlineKeyboardButton(text="❌ Отмена", callback_data="admin_add:cancel:0")])
    return InlineKeyboardMarkup(inline_keyboard=btns)


def kb_cancel() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="🏠 Главное меню")]],
        resize_keyboard=True,
    )


def ensure_ref_code(tg_id: int) -> str:
    with get_db() as conn:
        row = conn.execute("SELECT referral_code FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        if row and row["referral_code"]: return row["referral_code"]
        code = gen_ref_code(tg_id)
        conn.execute("UPDATE users SET referral_code=? WHERE tg_id=?", (code, tg_id))
        conn.commit()
        return code

# ══════════════════════════════════════════════════════════════════════════════
#  USER HANDLERS
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(Command("start"))
@handle_errors()
async def cmd_start(msg: Message, state: FSMContext):
    await state.clear()
    tg_id = msg.from_user.id
    if is_banned(tg_id):
        return await msg.answer("🚫 Ваш аккаунт заблокирован. Обратитесь в поддержку.")
    if get_setting("maintenance") == "1" and not is_admin(tg_id):
        return await msg.answer("🔧 <b>Бот на техническом обслуживании.</b>\nПопробуйте позже.")

    is_new = False
    with get_db() as conn:
        existing = conn.execute("SELECT tg_id FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        if not existing:
            is_new = True
        ref_by = None
        args = msg.text.split()
        if len(args) > 1 and args[1].startswith("ref_"):
            r = conn.execute("SELECT tg_id FROM users WHERE referral_code=?", (args[1][4:],)).fetchone()
            if r and r["tg_id"] != tg_id: ref_by = r["tg_id"]
        conn.execute(
            "INSERT OR IGNORE INTO users "
            "(tg_id, username, first_name, last_name, referral_code, referred_by) "
            "VALUES (?,?,?,?,?,?)",
            (tg_id, msg.from_user.username, msg.from_user.first_name,
             msg.from_user.last_name, gen_ref_code(tg_id), ref_by),
        )
        conn.execute(
            "UPDATE users SET username=?, first_name=?, last_name=?, "
            "updated_at=CURRENT_TIMESTAMP WHERE tg_id=?",
            (msg.from_user.username, msg.from_user.first_name,
             msg.from_user.last_name, tg_id),
        )
        conn.commit()

    # Уведомление админа о новом пользователе
    if is_new and get_setting("notify_new_user", "1") == "1":
        name = f"{msg.from_user.first_name or ''} (@{msg.from_user.username or '—'})"
        notif_text = f"👤 <b>Новый пользователь!</b>\n{name}\n🆔 <code>{tg_id}</code>"
        for admin_id in ({ADMIN_ID} | EXTRA_ADMINS):
            fire_and_forget(safe_send(admin_id, notif_text))

    custom = get_setting("welcome_text", "")
    text   = custom if custom else (
        "👋 <b>Добро пожаловать в MaestroSecure!</b>\n"
        "Неуязвимый VPN с маскировкой под обычный браузер Chrome.\n\n"
        "Выберите действие в меню 👇"
    )
    await msg.answer(text, reply_markup=kb_main(is_admin(tg_id)))


@dp.message(F.text == "🏠 Главное меню")
@handle_errors()
async def cmd_home(msg: Message, state: FSMContext):
    await state.clear()
    await cmd_start(msg, state)


@dp.message(F.text.in_({"💎 Моя подписка", "⚡️ Мой ключ"}))
@handle_errors()
async def cmd_my_sub(msg: Message):
    tg_id = msg.from_user.id
    if is_banned(tg_id): return
    with get_db() as conn:
        user  = conn.execute("SELECT * FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        trial = conn.execute(
            "SELECT * FROM trials WHERE tg_id=? AND converted=0 AND expired_processed=0", (tg_id,)
        ).fetchone()

    if user and user["proxy_user"] and user["is_active"]:
        d = days_left(user["subscription_end"])

        # Если подписка истекла (0 дней) — запускаем проверку панели фоново,
        # а пользователю сразу показываем актуальный статус из БД.
        # Тяжёлый panel.list_users() не вызывается inline — только через /check_user или планировщик.
        if d == 0 or not user["subscription_end"]:
            async def _bg_panel_check(tg_id=tg_id, u=user):
                panel_users = await panel.list_users()
                panel_names = {(pu.get("username") or pu.get("name", "")) for pu in panel_users}
                if u["proxy_user"] not in panel_names:
                    with get_db() as conn:
                        deactivate_user(conn, tg_id, source="panel_check")
                        conn.commit()
                    await safe_send(
                        tg_id,
                        "❌ <b>Подписка истекла.</b> Ваш аккаунт деактивирован.\n"
                        "Оформите новую подписку: 🛍 Магазин",
                        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                            InlineKeyboardButton(text="💳 Купить", callback_data="go_buy"),
                        ]]),
                    )
            fire_and_forget(_bg_panel_check())

        dt      = parse_date(user["subscription_end"]).strftime("%d.%m.%Y") if parse_date(user["subscription_end"]) else "—"
        key     = make_naive_key(user["proxy_user"], user["proxy_pass"])
        icon    = "🔴" if d == 0 else ("🟡" if d <= 3 else "🟢")
        traffic = (user["traffic_up"] or 0) + (user["traffic_down"] or 0)
        await send_key_with_qr(
            msg, key,
            f"💎 <b>Ваша подписка</b>\n"
            f"{icon} Активна до: <b>{dt}</b> (осталось {d} дн.)\n"
            f"📊 Трафик: <b>{fmt_traffic(traffic)}</b>\n\n"
            f"🔑 <b>Ключ NaiveProxy:</b>\n<code>{key}</code>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="💳 Продлить", callback_data="go_buy")
            ]]),
        )
    elif trial:
        exp = parse_datetime(trial["expires_at"])
        hl  = int((exp - datetime.now()).total_seconds() / 3600) if exp else 0
        key = make_naive_key(trial["proxy_user"], trial["proxy_pass"])
        await send_key_with_qr(
            msg, key,
            f"⏰ <b>Пробный период</b>\n🟢 Активен, осталось: <b>{max(0, hl)} ч.</b>\n\n"
            f"🔑 <b>Ключ:</b>\n<code>{key}</code>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="💳 Оформить подписку", callback_data="go_buy")
            ]]),
        )
    else:
        await msg.answer(
            "❌ <b>Нет активной подписки.</b>\nОформите тестовый или платный период.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="🚀 Пробный период", callback_data="trial_start"),
                InlineKeyboardButton(text="💳 Купить",         callback_data="go_buy"),
            ]]),
        )


@dp.message(F.text == "📖 Инструкция")
@handle_errors()
async def cmd_instr(msg: Message):
    if is_banned(msg.from_user.id): return
    texts = [
        "📲 <b>Как подключиться к VPN</b>\n"
        "Приложение <b>Karing</b> — работает на всех устройствах.\n"
        "Выберите вашу платформу 👇",

        "📱 <b>iPhone / iPad (iOS)</b>\n\n"
        "1. Установите Karing:\n"
        '   → <a href="https://apps.apple.com/us/app/karing/id6472431552">App Store</a>  |  '
        '<a href="https://testflight.apple.com/join/RLU59OsJ">TestFlight (бета)</a>\n\n'
        "2. Откройте приложение → нажмите <b>＋</b> (правый верхний угол)\n\n"
        "3. Выберите <b>«Импорт из буфера обмена»</b>\n\n"
        "4. Вставьте ваш ключ из раздела <b>⚡️ Мой ключ</b>\n\n"
        "5. Нажмите кнопку подключения на главном экране ✅",

        "🤖 <b>Android</b>\n\n"
        "1. Скачайте APK:\n"
        '   → <a href="https://github.com/KaringX/karing/releases/latest">GitHub Releases</a>  |  '
        '<a href="https://karing.app/download">karing.app</a>\n'
        "   Файл: <code>karing_x.x.x_android.apk</code>\n\n"
        "2. Установите APK\n"
        "   ⚠️ Разрешите установку из неизвестных источников\n\n"
        "3. Откройте Karing → нажмите <b>＋</b>\n\n"
        "4. Выберите <b>«Импорт из буфера обмена»</b>\n\n"
        "5. Вставьте ваш ключ → нажмите подключиться ✅",

        "🍎 <b>Mac (macOS)</b>\n\n"
        "1. Скачайте Karing для Mac:\n"
        '   → <a href="https://github.com/KaringX/karing/releases/latest">GitHub Releases</a>  |  '
        '<a href="https://karing.app/download">karing.app</a>\n'
        "   Файл: <code>karing_x.x.x_macos_universal.dmg</code>\n\n"
        "2. Откройте .dmg → перетащите Karing в <b>Программы</b>\n\n"
        "3. Запустите Karing → нажмите <b>＋</b>\n\n"
        "4. Выберите <b>«Импорт из буфера обмена»</b>\n\n"
        "5. Вставьте ваш ключ → нажмите подключиться ✅",

        "💻 <b>Windows</b>\n\n"
        "1. Скачайте Karing для Windows:\n"
        '   → <a href="https://github.com/KaringX/karing/releases/latest">GitHub Releases</a>  |  '
        '<a href="https://karing.app/download">karing.app</a>\n'
        "   Файл: <code>karing_x.x.x_windows_x64.zip</code>\n\n"
        "2. Распакуйте архив → запустите <code>karing.exe</code>\n"
        "   ⚠️ Запускайте <b>от имени администратора</b>\n\n"
        "3. Нажмите <b>＋</b> → <b>«Импорт из буфера обмена»</b>\n\n"
        "4. Вставьте ваш ключ → нажмите подключиться ✅",

        "🔑 <b>Где взять ключ?</b>\n\n"
        "Нажмите кнопку <b>⚡️ Мой ключ</b> в главном меню бота.\n\n"
        "Ключ выглядит так:\n"
        "<code>naive+https://логин:пароль@адрес:443</code>\n\n"
        "Скопируйте его целиком и вставьте в Karing.\n\n"
        "<i>🛡 Трафик полностью замаскирован под обычный браузер Chrome</i>",
    ]
    for text in texts:
        await msg.answer(text, disable_web_page_preview=True)


# ── TRIAL ────────────────────────────────────────────────────────────────────
@dp.callback_query(F.data == "trial_start")
@dp.message(F.text == "🎁 Бесплатный тест")
@handle_errors()
async def cmd_trial(event):
    tg_id = event.from_user.id
    msg   = event.message if isinstance(event, CallbackQuery) else event
    if isinstance(event, CallbackQuery): await event.answer()
    if is_banned(tg_id): return await msg.answer("🚫 Ваш аккаунт заблокирован.")
    if not rate_limiter.allow(tg_id, 3.0):
        return await msg.answer("⏳ Подождите перед повторным запросом.")
    with get_db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE tg_id=? AND proxy_user IS NOT NULL", (tg_id,)).fetchone():
            return await msg.answer("❌ Пробник недоступен — у вас уже есть аккаунт.")
        if conn.execute("SELECT 1 FROM trials WHERE tg_id=?", (tg_id,)).fetchone():
            return await msg.answer("❌ Вы уже использовали пробный период.")
    proxy_user = f"trial_{tg_id}"
    proxy_pass = gen_password()
    _trial_hours = get_trial_hours()
    exp = datetime.now() + timedelta(hours=_trial_hours)
    with get_db() as conn:
        inserted = conn.execute(
            "INSERT OR IGNORE INTO trials (tg_id, proxy_user, proxy_pass, expires_at) VALUES (?,?,?,?)",
            (tg_id, proxy_user, proxy_pass, exp.strftime("%Y-%m-%d %H:%M:%S")),
        ).rowcount
        conn.commit()
    if not inserted:
        return await msg.answer("❌ Вы уже использовали пробный период.")
    if await panel.add_user(proxy_user, proxy_pass):
        with get_db() as conn:
            conn.execute("UPDATE trials SET panel_added=1 WHERE tg_id=?", (tg_id,))
            conn.commit()
        _key = make_naive_key(proxy_user, proxy_pass)
        await send_key_with_qr(
            msg, _key,
            f"✅ <b>Пробный доступ активирован!</b>\n⏳ На <b>{_trial_hours} часов</b>\n\n"
            f"🔑 Ключ:\n<code>{_key}</code>"
        )
    else:
        with get_db() as conn:
            conn.execute("DELETE FROM trials WHERE tg_id=?", (tg_id,))
            conn.commit()
        await msg.answer(
            f"❌ <b>Ошибка сервера панели.</b>\n"
            f"<i>{safe_html(panel.last_error)}</i>\n\n"
            f"Попробуйте позже или обратитесь в поддержку."
        )


# ── SHOP ─────────────────────────────────────────────────────────────────────
@dp.callback_query(F.data == "go_buy")
@dp.message(F.text == "🛍 Магазин")
@handle_errors()
async def cmd_buy(event, state: FSMContext):
    msg = event.message if isinstance(event, CallbackQuery) else event
    if isinstance(event, CallbackQuery): await event.answer()
    if is_banned(event.from_user.id): return await msg.answer("🚫 Ваш аккаунт заблокирован.")
    await state.set_state(PaymentFSM.choosing_tariff)
    await msg.answer("💳 <b>Выберите тариф:</b>", reply_markup=kb_tariffs())


@dp.callback_query(F.data.startswith("tariff:"))
@handle_errors()
async def cb_tariff(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    days = safe_cb_int(cb.data, 1)
    if days is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    tariffs = get_tariffs()
    price = tariffs.get(days)
    if not price:
        return await cb.answer("Тариф не найден", show_alert=True)
    code = gen_payment_code()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO payments (tg_id, amount, duration, payment_code) VALUES (?,?,?,?)",
            (cb.from_user.id, price, days, code),
        )
        conn.commit()
    pay = get_pay_settings()
    await cb.message.edit_text(
        f"💳 <b>К оплате: {price} ₽</b> ({days} дн.)\n\n"
        f"📱 Номер: <code>{pay['phone']}</code>\n"
        f"🏦 Банк: {pay['bank']}\n"
        f"👤 Получатель: {pay['name']}\n\n"
        f"⚠️ В комментарии укажите: <code>VPN {cb.from_user.id}</code>\n\n"
        f"После перевода нажмите кнопку:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Я оплатил",  callback_data=f"paid:{code}")],
            [InlineKeyboardButton(text="❌ Отменить",   callback_data="pay_cancel")],
        ]),
    )


@dp.callback_query(F.data.startswith("paid:"))
@handle_errors()
async def cb_paid(cb: CallbackQuery):
    if not rate_limiter.allow(cb.from_user.id, 10.0):
        return await cb.answer("⏳ Подождите немного.", show_alert=True)
    code = cb.data.split(":")[1]
    with get_db() as conn:
        upd = conn.execute(
            "UPDATE payments SET status='awaiting_confirm', updated_at=CURRENT_TIMESTAMP "
            "WHERE payment_code=? AND status='pending'", (code,),
        ).rowcount
        conn.commit()
    if not upd: return await cb.answer("Уже обрабатывается", show_alert=True)
    with get_db() as conn:
        p = conn.execute("SELECT * FROM payments WHERE payment_code=?", (code,)).fetchone()
        u = conn.execute("SELECT username, first_name FROM users WHERE tg_id=?", (p["tg_id"],)).fetchone()
    name = f"{u['first_name'] or ''} (@{u['username'] or '—'})" if u else str(p["tg_id"])
    pay_msg = (
        f"💰 <b>НОВЫЙ ПЛАТЁЖ</b>\n"
        f"👤 {name}\n🆔 <code>{p['tg_id']}</code>\n"
        f"💵 {p['amount']} ₽ за {p['duration']} дн.\nКод: <code>{code}</code>"
    )
    pay_kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Подтвердить", callback_data=f"approve:{p['id']}"),
        InlineKeyboardButton(text="❌ Отклонить",   callback_data=f"reject:{p['id']}"),
    ]])
    all_admins = {ADMIN_ID} | EXTRA_ADMINS
    for admin_id in all_admins:
        try:
            await bot.send_message(admin_id, pay_msg, reply_markup=pay_kb)
        except Exception:
            pass
    await cb.message.edit_text("✅ Заявка отправлена администратору. Ожидайте подтверждения.")


@dp.callback_query(F.data == "pay_cancel")
@handle_errors()
async def cb_pay_cancel(cb: CallbackQuery):
    with get_db() as conn:
        conn.execute(
            "UPDATE payments SET status='cancelled', updated_at=CURRENT_TIMESTAMP "
            "WHERE tg_id=? AND status='pending'", (cb.from_user.id,),
        )
        conn.commit()
    await cb.message.edit_text("❌ Отменено.")


# ── APPROVE / REJECT ─────────────────────────────────────────────────────────
@dp.callback_query(F.data.startswith("approve:"))
@handle_errors()
async def cb_approve(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    p_id = safe_cb_int(cb.data, 1)
    if p_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    # Атомарно переводим в processing — защита от двойного подтверждения
    with get_db() as conn:
        upd = conn.execute(
            "UPDATE payments SET status='processing', panel_updated=0, updated_at=CURRENT_TIMESTAMP "
            "WHERE id=? AND status IN ('pending', 'awaiting_confirm')", (p_id,),
        ).rowcount
        conn.commit()
    if not upd: return await cb.answer("Уже в работе", show_alert=True)
    await cb.answer("⏳ Подтверждаю...")
    with get_db() as conn:
        p = conn.execute("SELECT * FROM payments WHERE id=?", (p_id,)).fetchone()
        u = conn.execute("SELECT * FROM users WHERE tg_id=?", (p["tg_id"],)).fetchone()
    tg_id, days = p["tg_id"], p["duration"]
    proxy_user = proxy_pass = new_end = None
    try:
        if u and u["proxy_user"]:
            proxy_user, proxy_pass = u["proxy_user"], u["proxy_pass"]
            old_end = u["subscription_end"] or ""
            cur_end = parse_date(old_end) if old_end else datetime.now(TZ).date()
            new_end = (max(cur_end, datetime.now(TZ).date()) + timedelta(days=days)).strftime("%Y-%m-%d")
            ok = await panel.add_user(proxy_user, proxy_pass)
            if not ok:
                with get_db() as conn:
                    conn.execute("UPDATE payments SET status='pending' WHERE id=?", (p_id,))
                    conn.commit()
                return await cb.message.answer(
                    f"❌ <b>Ошибка панели при продлении.</b>\n"
                    f"<i>{safe_html(panel.last_error)}</i>\n"
                    f"Платёж возвращён в pending. Проверьте панель!"
                )
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET subscription_end=?, is_active=1, last_tariff_days=?, "
                    "notified_1d=0, notified_3d=0, notified_7d=0, notified_remind=0 WHERE tg_id=?",
                    (new_end, days, tg_id),
                )
                conn.execute(
                    "INSERT INTO subscription_history "
                    "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                    (tg_id, "extend", days, old_end, new_end, f"payment:{p_id}"),
                )
                conn.execute(
                    "UPDATE payments SET status='approved', panel_updated=1, "
                    "updated_at=CURRENT_TIMESTAMP WHERE id=?", (p_id,),
                )
                conn.commit()
            # Реф. бонус — логика антинакрутки внутри _apply_ref_bonus
            if u and u["referred_by"]:
                await _apply_ref_bonus(u["referred_by"], tg_id, days, p_id)
            key = make_naive_key(proxy_user, proxy_pass)
            fire_and_forget(send_key_with_qr(
                tg_id, key,
                f"🎉 <b>Подписка продлена!</b>\n📅 До: <b>{new_end}</b>\n\n"
                f"🔑 Ключ:\n<code>{key}</code>",
            ))
        else:
            with get_db() as conn:
                base       = gen_proxy_username(tg_id, u["username"] if u else None, u["first_name"] if u else None)
                proxy_user = _ensure_unique_proxy_user(conn, base)
                proxy_pass = gen_password()
                new_end    = (datetime.now(TZ).date() + timedelta(days=days)).strftime("%Y-%m-%d")
            ok = await panel.add_user(proxy_user, proxy_pass)
            if not ok:
                with get_db() as conn:
                    conn.execute("UPDATE payments SET status='pending' WHERE id=?", (p_id,))
                    conn.commit()
                return await cb.message.answer(
                    f"❌ <b>Ошибка панели при создании пользователя.</b>\n"
                    f"<i>{safe_html(panel.last_error)}</i>\n"
                    f"Платёж возвращён в pending. Проверьте панель!"
                )
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET proxy_user=?, proxy_pass=?, subscription_end=?, "
                    "is_active=1, last_tariff_days=?, notified_1d=0, notified_3d=0, notified_7d=0, notified_remind=0 WHERE tg_id=?",
                    (proxy_user, proxy_pass, new_end, days, tg_id),
                )
                conn.execute(
                    "INSERT INTO subscription_history "
                    "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                    (tg_id, "activate", days, "", new_end, f"payment:{p_id}"),
                )
                conn.execute(
                    "UPDATE payments SET status='approved', panel_updated=1, "
                    "updated_at=CURRENT_TIMESTAMP WHERE id=?", (p_id,),
                )
                conn.execute("UPDATE trials SET converted=1 WHERE tg_id=?", (tg_id,))
                conn.commit()
            if u and u["referred_by"]:
                await _apply_ref_bonus(u["referred_by"], tg_id, days, p_id)
            key = make_naive_key(proxy_user, proxy_pass)
            fire_and_forget(send_key_with_qr(
                tg_id, key,
                f"🎉 <b>VPN активирован!</b>\n📅 До: <b>{new_end}</b>\n"
                f"👤 Логин: <code>{proxy_user}</code>\n\n"
                f"🔑 Ключ:\n<code>{key}</code>",
            ))
            # Онбординг — пошаговая инструкция под платформу
            fire_and_forget(_send_onboarding(tg_id))
        await cb.message.edit_text(cb.message.text + "\n\n✅ <b>ОДОБРЕНО</b>")
    except Exception as e:
        logger.error(f"approve error: {e}")
        with get_db() as conn:
            conn.execute("UPDATE payments SET status='pending' WHERE id=?", (p_id,))
            conn.commit()
        await cb.message.answer(f"❌ Ошибка: {e}\nПлатёж возвращён в pending.")


@dp.callback_query(F.data.startswith("reject:"))
@handle_errors()
async def cb_reject(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    p_id = safe_cb_int(cb.data, 1)
    if p_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        conn.execute(
            "UPDATE payments SET status='rejected', updated_at=CURRENT_TIMESTAMP WHERE id=?", (p_id,)
        )
        p = conn.execute("SELECT tg_id FROM payments WHERE id=?", (p_id,)).fetchone()
        conn.commit()
    if p: await safe_send(p["tg_id"], "❌ Ваш платёж отклонён. Обратитесь в поддержку.")
    await cb.message.edit_text(cb.message.text + "\n\n❌ <b>ОТКЛОНЕНО</b>")


# ══════════════════════════════════════════════════════════════════════════════
#  РЕФЕРАЛЬНАЯ СИСТЕМА
# ══════════════════════════════════════════════════════════════════════════════
async def _apply_ref_bonus(ref_id: int, referred_tg_id: int, tariff_days: int, payment_id: int):
    """
    Начисляет реферальный бонус с защитой от накрутки.

    Проверки (все настраиваются через ⚙️ Настройки бота):
    1. ref_first_only=1    → бонус только за первую оплату реферала
    2. ref_min_tariff_days → тариф должен быть не короче N дней
    3. ref_account_age_days→ аккаунт реферала должен быть старше N дней
    4. ref_max_bonus_month → реферер не может получить > N бонусных дней в месяц
    """
    # ── читаем настройки ──────────────────────────────────────────────────────
    first_only       = get_setting("ref_first_only",       "1") == "1"
    min_tariff       = int(get_setting("ref_min_tariff_days",  "30") or 0)
    min_age_days     = int(get_setting("ref_account_age_days", "2")  or 0)
    max_bonus_month  = int(get_setting("ref_max_bonus_month",  "30") or 0)

    with get_db() as conn:
        ref      = conn.execute("SELECT * FROM users WHERE tg_id=?", (ref_id,)).fetchone()
        referred = conn.execute("SELECT * FROM users WHERE tg_id=?", (referred_tg_id,)).fetchone()
        if not ref or not referred:
            return

        # ── Защита 1: только первая оплата ───────────────────────────────────
        if first_only:
            already = conn.execute(
                "SELECT 1 FROM referrals WHERE referrer_id=? AND referred_id=? AND payment_count > 0",
                (ref_id, referred_tg_id)
            ).fetchone()
            if already:
                logger.debug(f"ref_bonus skip: not first payment ref={ref_id} referred={referred_tg_id}")
                return

        # ── Защита 2: минимальный тариф ──────────────────────────────────────
        if min_tariff and tariff_days < min_tariff:
            logger.debug(f"ref_bonus skip: tariff {tariff_days}d < min {min_tariff}d")
            return

        # ── Защита 3: возраст аккаунта реферала ──────────────────────────────
        if min_age_days:
            created_at = parse_datetime(referred["created_at"])
            if created_at:
                age = (datetime.now() - created_at).days
                if age < min_age_days:
                    logger.info(
                        f"ref_bonus skip: referred {referred_tg_id} account age {age}d < {min_age_days}d"
                    )
                    return

        # ── Защита 4: месячный лимит для реферера ────────────────────────────
        bonus_days = calc_ref_bonus_days(tariff_days)
        if max_bonus_month:
            month_start = datetime.now(TZ).date().replace(day=1).isoformat()
            month_given = conn.execute(
                "SELECT COALESCE(SUM(days), 0) FROM subscription_history "
                "WHERE tg_id=? AND source LIKE 'ref_bonus:%' AND created_at >= ?",
                (ref_id, month_start)
            ).fetchone()[0]
            if month_given >= max_bonus_month:
                logger.info(
                    f"ref_bonus skip: ref={ref_id} already got {month_given}d this month "
                    f"(max={max_bonus_month}d)"
                )
                return
            # Обрезаем бонус чтобы не превысить лимит
            bonus_days = min(bonus_days, max_bonus_month - month_given)
            if bonus_days <= 0:
                return

        # ── Начисляем ─────────────────────────────────────────────────────────
        has_proxy = bool(ref["proxy_user"])
        cur     = parse_date(ref["subscription_end"]) if ref["subscription_end"] else datetime.now(TZ).date()
        new_ref = (max(cur, datetime.now(TZ).date()) + timedelta(days=bonus_days)).strftime("%Y-%m-%d")

        if has_proxy:
            conn.execute(
                "UPDATE users SET subscription_end=?, is_active=1 WHERE tg_id=?", (new_ref, ref_id)
            )
        else:
            conn.execute(
                "UPDATE users SET subscription_end=? WHERE tg_id=?", (new_ref, ref_id)
            )
        conn.execute(
            "INSERT INTO subscription_history (tg_id, action, days, old_end, new_end, source) "
            "VALUES (?,?,?,?,?,?)",
            (ref_id, "extend", bonus_days, ref["subscription_end"] or "", new_ref,
             f"ref_bonus:{referred_tg_id}"),
        )
        conn.execute(
            """INSERT INTO referrals (referrer_id, referred_id, bonus_days, payment_count, total_bonus_given)
               VALUES (?,?,?,1,?)
               ON CONFLICT(referrer_id, referred_id) DO UPDATE SET
                   payment_count     = payment_count + 1,
                   bonus_days        = bonus_days + ?,
                   total_bonus_given = total_bonus_given + ?
            """,
            (ref_id, referred_tg_id, bonus_days, bonus_days, bonus_days, bonus_days)
        )
        conn.execute(
            "UPDATE users SET ref_balance = ref_balance + ? WHERE tg_id=?",
            (bonus_days, ref_id),
        )
        conn.commit()

    fire_and_forget(safe_send(
        ref_id,
        f"🎁 <b>Реферальный бонус!</b>\n\n"
        f"Ваш реферал оплатил тариф <b>{tariff_days} дн.</b>\n"
        f"Вам начислено: <b>+{bonus_days} дней</b> ({get_ref_bonus_pct():.0f}% от тарифа)\n"
        f"📅 Ваша подписка продлена до: <b>{new_ref}</b>",
    ))


@dp.message(F.text == "👥 Рефералы")
@handle_errors()
async def show_refs(msg: Message):
    if is_banned(msg.from_user.id): return
    tg_id    = msg.from_user.id
    code     = ensure_ref_code(tg_id)
    bot_info = await bot.get_me()
    link     = f"https://t.me/{bot_info.username}?start=ref_{code}"

    with get_db() as conn:
        cnt = conn.execute(
            "SELECT COUNT(*) FROM users WHERE referred_by=?", (tg_id,)
        ).fetchone()[0]
        total_bonus = conn.execute(
            "SELECT COALESCE(ref_balance, 0) FROM users WHERE tg_id=?", (tg_id,)
        ).fetchone()[0]
        refs_detail = conn.execute(
            "SELECT r.referred_id, r.payment_count, r.total_bonus_given, u.first_name, u.username "
            "FROM referrals r LEFT JOIN users u ON r.referred_id=u.tg_id "
            "WHERE r.referrer_id=? ORDER BY r.created_at DESC LIMIT 5",
            (tg_id,),
        ).fetchall()

    cur_ref_pct     = get_ref_bonus_pct()
    first_only      = get_setting("ref_first_only",       "1") == "1"
    min_tariff      = int(get_setting("ref_min_tariff_days",  "30") or 0)
    max_bonus_month = int(get_setting("ref_max_bonus_month",  "30") or 0)

    bonus_per_tariff = "\n".join([
        f"  • {d} дн. → +{calc_ref_bonus_days(d)} дн. вам"
        for d in sorted(get_tariffs().keys())
        if not min_tariff or d >= min_tariff
    ])

    # Сколько бонусов уже получено в этом месяце
    month_start = datetime.now(TZ).date().replace(day=1).isoformat()
    with get_db() as conn:
        month_given = conn.execute(
            "SELECT COALESCE(SUM(days), 0) FROM subscription_history "
            "WHERE tg_id=? AND source LIKE 'ref_bonus:%' AND created_at >= ?",
            (tg_id, month_start)
        ).fetchone()[0]

    detail_lines = []
    for r in refs_detail:
        name  = r["first_name"] or f"id{r['referred_id']}"
        uname = f"@{r['username']}" if r["username"] else ""
        detail_lines.append(
            f"  👤 {name} {uname} — {r['payment_count']} опл. / +{r['total_bonus_given']} дн."
        )

    conditions = []
    if first_only:
        conditions.append("• Бонус только за первую оплату реферала")
    if min_tariff:
        conditions.append(f"• Минимальный тариф для бонуса: {min_tariff} дн.")
    if max_bonus_month:
        conditions.append(f"• Максимум в месяц: {max_bonus_month} дн. (получено: {month_given})")

    text = (
        f"👥 <b>Реферальная программа</b>\n\n"
        f"🔗 Ваша ссылка:\n<code>{link}</code>\n\n"
        f"📊 <b>Ваша статистика:</b>\n"
        f"  Приглашено: <b>{cnt}</b> чел.\n"
        f"  Всего бонусов: <b>{total_bonus} дн.</b>\n\n"
        f"💡 <b>Бонус {cur_ref_pct:.0f}% от тарифа реферала:</b>\n"
        f"{bonus_per_tariff if bonus_per_tariff else '  —'}\n\n"
    )
    if conditions:
        text += "📋 <b>Условия начисления:</b>\n" + "\n".join(conditions)
    if detail_lines:
        text += f"\n\n<b>Последние рефералы:</b>\n" + "\n".join(detail_lines)

    await msg.answer(text)


# ── HISTORY ──────────────────────────────────────────────────────────────────
@dp.message(F.text == "🧾 История")
@handle_errors()
async def show_history(msg: Message):
    if is_banned(msg.from_user.id): return
    with get_db() as conn:
        rows = conn.execute(
            "SELECT amount, duration, status, created_at FROM payments "
            "WHERE tg_id=? ORDER BY id DESC LIMIT 10",
            (msg.from_user.id,),
        ).fetchall()
    if not rows: return await msg.answer("📭 История платежей пуста.")
    icons = {"approved": "✅", "pending": "⏳", "awaiting_confirm": "🕐",
             "rejected": "❌", "cancelled": "🚫", "processing": "⚙️"}
    lines = ["🧾 <b>Последние платежи:</b>\n"]
    for r in rows:
        icon = icons.get(r["status"], "•")
        lines.append(f"{icon} {r['created_at'][:10]} | {r['amount']} ₽ ({r['duration']} дн.) — {r['status']}")
    await msg.answer("\n".join(lines))


# ── POLLS ─────────────────────────────────────────────────────────────────────
@dp.callback_query(F.data == "support")
@handle_errors()
async def cb_support_shortcut(cb: CallbackQuery, state: FSMContext):
    """Быстрый переход в поддержку из inline-кнопки."""
    await cb.answer()
    if is_banned(cb.from_user.id):
        return await cb.message.answer("🚫 Ваш аккаунт заблокирован.")
    await state.set_state(SupportFSM.waiting)
    await cb.message.answer("💬 Опишите вашу проблему:", reply_markup=kb_cancel())


@dp.message(F.text == "🗳 Опросы")
@handle_errors()
async def show_polls(msg: Message):
    if is_banned(msg.from_user.id): return
    with get_db() as conn:
        poll = conn.execute(
            "SELECT * FROM polls WHERE is_active=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if not poll: return await msg.answer("📭 Пока нет активных опросов.")
    opts = poll["options"].split("|||")
    kb   = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=o, callback_data=f"vote:{poll['id']}:{i}")]
        for i, o in enumerate(opts)
    ])
    await msg.answer(f"📊 <b>Опрос:</b>\n\n{poll['question']}", reply_markup=kb)


@dp.callback_query(F.data.startswith("vote:"))
@handle_errors()
async def cb_vote(cb: CallbackQuery):
    if is_banned(cb.from_user.id):
        return await cb.answer("🚫 Вы заблокированы.", show_alert=True)
    _, p_id, idx = cb.data.split(":")
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO poll_votes (poll_id, tg_id, option_idx) VALUES (?,?,?)",
                (p_id, cb.from_user.id, idx),
            )
            conn.commit()
        await cb.message.edit_text(cb.message.text + "\n\n✅ Ваш голос учтён!")
    except sqlite3.IntegrityError:
        await cb.answer("Вы уже голосовали!", show_alert=True)


# ── SUPPORT ───────────────────────────────────────────────────────────────────
@dp.message(F.text == "💬 Поддержка")
@handle_errors()
async def support_start(msg: Message, state: FSMContext):
    if is_banned(msg.from_user.id): return await msg.answer("🚫 Ваш аккаунт заблокирован.")
    if not rate_limiter.allow(msg.from_user.id, 30.0):  # не чаще раза в 30 сек
        return await msg.answer("⏳ Пожалуйста, подождите немного перед новым обращением.")
    await state.set_state(SupportFSM.waiting)
    await msg.answer("💬 Опишите вашу проблему:", reply_markup=kb_cancel())


@dp.message(SupportFSM.waiting)
@handle_errors()
async def support_msg(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    await state.clear()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO support_tickets (tg_id, message) VALUES (?,?)",
            (msg.from_user.id, msg.text or "[медиа]"),
        )
        conn.commit()
    name = f"{msg.from_user.first_name or ''} (@{msg.from_user.username or '—'})"
    ticket_text = (
        f"📩 <b>Обращение в поддержку</b>\n"
        f"👤 {name} | <code>{msg.from_user.id}</code>\n\n"
        f"{safe_html(msg.text) if msg.text else '[медиа — см. ниже]'}"
    )
    ticket_kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(
            text="💬 Ответить",
            callback_data=f"reply_ticket:{msg.from_user.id}",
        )
    ]])
    all_admins = {ADMIN_ID} | EXTRA_ADMINS
    for admin_id in all_admins:
        await safe_send(admin_id, ticket_text, reply_markup=ticket_kb)
        if not msg.text:
            try:
                await msg.forward(admin_id)
            except Exception:
                pass
    await msg.answer(
        "✅ Сообщение отправлено. Ожидайте ответа.",
        reply_markup=kb_main(is_admin(msg.from_user.id)),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN HANDLERS
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(F.text == "🛠 Панель управления")
@handle_errors()
async def admin_panel(msg: Message):
    if not is_admin(msg.from_user.id): return
    await msg.answer("⚙️ <b>Админ-панель</b>", reply_markup=kb_admin())



@dp.message(F.text == "📊 Статистика")
@handle_errors()
async def admin_stats(msg: Message):
    if not is_admin(msg.from_user.id): return
    with get_db() as conn:
        tot    = conn.execute("SELECT COUNT(*) FROM users WHERE tg_id > 0").fetchone()[0]
        act    = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1 AND tg_id > 0").fetchone()[0]
        earn   = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='approved'").fetchone()[0]
        pend   = conn.execute("SELECT COUNT(*) FROM payments WHERE status IN ('pending', 'awaiting_confirm')").fetchone()[0]
        trials = conn.execute("SELECT COUNT(*) FROM trials WHERE expired_processed=0 AND converted=0").fetchone()[0]
        ref_cnt = conn.execute("SELECT COUNT(*) FROM referrals").fetchone()[0]
        total_ref_days = conn.execute("SELECT COALESCE(SUM(total_bonus_given),0) FROM referrals").fetchone()[0]
    await msg.answer(
        f"📊 <b>Статистика</b>\n\n"
        f"👥 Всего пользователей: <b>{tot}</b>\n"
        f"🟢 Активных VPN: <b>{act}</b>\n"
        f"⏳ Пробников активных: <b>{trials}</b>\n"
        f"⌛ Ожидают оплаты: <b>{pend}</b>\n"
        f"💰 Заработано: <b>{earn} ₽</b>\n\n"
        f"🎁 Реферальных пар: <b>{ref_cnt}</b>\n"
        f"📅 Всего реф. дней выдано: <b>{total_ref_days}</b>"
    )


@dp.message(F.text == "📊 Пробники")
@handle_errors()
async def admin_trials(msg: Message):
    if not is_admin(msg.from_user.id): return
    with get_db() as conn:
        rows = conn.execute(
            "SELECT t.tg_id, t.proxy_user, t.expires_at, t.converted, u.username "
            "FROM trials t LEFT JOIN users u ON t.tg_id=u.tg_id "
            "WHERE t.expired_processed=0 ORDER BY t.expires_at"
        ).fetchall()
    if not rows: return await msg.answer("Нет активных пробников.")
    lines = [f"📊 <b>Пробников: {len(rows)}</b>\n"]
    for r in rows:
        exp  = parse_datetime(r["expires_at"])
        hl   = int((exp - datetime.now()).total_seconds() / 3600) if exp else 0
        conv = "✅ конвертирован" if r["converted"] else f"⏳ {max(0, hl)} ч."
        lines.append(f"<code>{r['tg_id']}</code> @{r['username'] or '—'} | {conv}")
    await send_long(msg, "\n".join(lines))


@dp.message(F.text == "💰 Проверить оплаты")
@handle_errors()
async def admin_check_pays(msg: Message):
    if not is_admin(msg.from_user.id): return
    with get_db() as conn:
        rows = conn.execute(
            "SELECT p.*, u.username, u.first_name FROM payments p "
            "LEFT JOIN users u ON p.tg_id=u.tg_id "
            "WHERE p.status IN ('pending', 'awaiting_confirm') ORDER BY p.created_at DESC LIMIT 20"
        ).fetchall()
    if not rows: return await msg.answer("✅ Нет ожидающих оплат.")
    for p in rows:
        name = f"{p['first_name'] or ''} (@{p['username'] or '—'})"
        await msg.answer(
            f"💰 <b>Платёж #{p['id']}</b>\n"
            f"👤 {name} | <code>{p['tg_id']}</code>\n"
            f"💵 {p['amount']} ₽ за {p['duration']} дн.\n"
            f"📅 {p['created_at'][:16]}\nСтатус: {p['status']}",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="✅ Подтвердить", callback_data=f"approve:{p['id']}"),
                InlineKeyboardButton(text="❌ Отклонить",   callback_data=f"reject:{p['id']}"),
            ]]),
        )


# ══════════════════════════════════════════════════════════════════════════════
#  ПРОМОКОДЫ
# ══════════════════════════════════════════════════════════════════════════════
def _promos_text() -> str:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, code, discount_pct, bonus_days, max_uses, used_count, is_active "
            "FROM promo_codes ORDER BY id DESC"
        ).fetchall()
    if not rows: return "Промокодов нет."
    lines = ["🎟 <b>Промокоды:</b>\n"]
    for r in rows:
        st = "🟢" if r["is_active"] else "🔴"
        lines.append(
            f"{st} <code>{r['code']}</code> — скидка {r['discount_pct']}% / +{r['bonus_days']} дн.\n"
            f"   Использований: {r['used_count']} / {r['max_uses']}"
        )
    return "\n".join(lines)


def _promos_kb() -> InlineKeyboardMarkup:
    with get_db() as conn:
        rows = conn.execute("SELECT id, code, is_active FROM promo_codes ORDER BY id DESC").fetchall()
    btns = []
    for r in rows:
        tog = "🔴 Откл" if r["is_active"] else "🟢 Вкл"
        btns.append([
            InlineKeyboardButton(text=f"🎟 {r['code']}", callback_data=f"promo_info:{r['id']}"),
            InlineKeyboardButton(text=tog,               callback_data=f"promo_tog:{r['id']}"),
            InlineKeyboardButton(text="🗑",              callback_data=f"promo_del:{r['id']}"),
        ])
    btns.append([InlineKeyboardButton(text="➕ Создать промокод", callback_data="promo_new")])
    return InlineKeyboardMarkup(inline_keyboard=btns)


@dp.message(F.text == "🎟 Промокоды")
@handle_errors()
async def admin_promos(msg: Message):
    if not is_admin(msg.from_user.id): return
    await msg.answer(_promos_text(), reply_markup=_promos_kb())


@dp.callback_query(F.data == "promo_new")
@handle_errors()
async def cb_promo_new(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    await cb.answer()
    await state.set_state(AdminFSM.promo_add_code)
    await cb.message.answer("Введите <b>код</b> (латиница/цифры, 3–20 символов):", reply_markup=kb_cancel())


@dp.message(AdminFSM.promo_add_code)
@handle_errors()
async def promo_add_code(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    code = msg.text.strip().upper()
    if not re.match(r'^[A-Z0-9_-]{3,20}$', code):
        return await msg.answer("❌ Только латиница/цифры, 3–20 символов.")
    await state.update_data(promo_code=code)
    await state.set_state(AdminFSM.promo_add_discount)
    await msg.answer("Скидка в % (0 если не нужна, например <code>10</code>):")


@dp.message(AdminFSM.promo_add_discount)
@handle_errors()
async def promo_add_discount(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit() or not (0 <= int(msg.text.strip()) <= 100):
        return await msg.answer("Введите число 0–100.")
    await state.update_data(promo_discount=int(msg.text.strip()))
    await state.set_state(AdminFSM.promo_add_days)
    await msg.answer("Бонусных дней к подписке (0 если не нужно):")


@dp.message(AdminFSM.promo_add_days)
@handle_errors()
async def promo_add_days(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit(): return await msg.answer("Введите число.")
    await state.update_data(promo_bonus_days=int(msg.text.strip()))
    await state.set_state(AdminFSM.promo_add_uses)
    await msg.answer("Максимум использований (<code>0</code> = безлимит):")


@dp.message(AdminFSM.promo_add_uses)
@handle_errors()
async def promo_add_uses(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit(): return await msg.answer("Введите число.")
    data     = await state.get_data()
    await state.clear()
    max_uses = int(msg.text.strip()) or 999999
    created = False
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO promo_codes (code, discount_pct, bonus_days, max_uses) VALUES (?,?,?,?)",
                (data["promo_code"], data["promo_discount"], data["promo_bonus_days"], max_uses),
            )
            conn.commit()
            created = True
        except sqlite3.IntegrityError:
            pass
    if created:
        await msg.answer(
            f"✅ Промокод <code>{data['promo_code']}</code> создан!\n"
            f"Скидка: {data['promo_discount']}% | Бонус: +{data['promo_bonus_days']} дн. | Лимит: {max_uses}",
            reply_markup=kb_admin(),
        )
    else:
        await msg.answer(f"❌ Промокод уже существует.", reply_markup=kb_admin())


@dp.callback_query(F.data.startswith("promo_tog:"))
@handle_errors()
async def cb_promo_toggle(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    p_id = safe_cb_int(cb.data, 1)
    if p_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        conn.execute("UPDATE promo_codes SET is_active = NOT is_active WHERE id=?", (p_id,))
        conn.commit()
    await cb.answer("Статус изменён")
    await cb.message.edit_text(_promos_text(), reply_markup=_promos_kb())


@dp.callback_query(F.data.startswith("promo_del:"))
@handle_errors()
async def cb_promo_del(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    p_id = safe_cb_int(cb.data, 1)
    if p_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        conn.execute("DELETE FROM promo_codes WHERE id=?", (p_id,))
        conn.execute("DELETE FROM promo_uses WHERE promo_id=?", (p_id,))
        conn.commit()
    await cb.answer("Удалён")
    await cb.message.edit_text(_promos_text(), reply_markup=_promos_kb())


@dp.message(Command("promo"))
@handle_errors()
async def cmd_promo_user(msg: Message, state: FSMContext):
    if is_banned(msg.from_user.id): return
    parts = msg.text.split(maxsplit=1)
    if len(parts) < 2:
        await state.set_state(PromoFSM.applying)
        return await msg.answer("🎟 Введите промокод:", reply_markup=kb_cancel())
    await _apply_promo(msg, msg.from_user.id, parts[1].strip().upper())


@dp.message(PromoFSM.applying)
@handle_errors()
async def promo_apply(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    await state.clear()
    await _apply_promo(msg, msg.from_user.id, msg.text.strip().upper())


async def _apply_promo(msg: Message, tg_id: int, code: str):
    with get_db() as conn:
        p = conn.execute("SELECT * FROM promo_codes WHERE code=? AND is_active=1", (code,)).fetchone()
        if not p: return await msg.answer("❌ Промокод не найден или недействителен.")
        if p["used_count"] >= p["max_uses"]: return await msg.answer("❌ Промокод исчерпан.")
        if p["expires_at"] and parse_datetime(p["expires_at"]) < datetime.now():
            return await msg.answer("❌ Срок промокода истёк.")
        if conn.execute("SELECT 1 FROM promo_uses WHERE promo_id=? AND tg_id=?", (p["id"], tg_id)).fetchone():
            return await msg.answer("❌ Вы уже использовали этот промокод.")
        conn.execute("INSERT INTO promo_uses (promo_id, tg_id) VALUES (?,?)", (p["id"], tg_id))
        conn.execute("UPDATE promo_codes SET used_count = used_count + 1 WHERE id=?", (p["id"],))
        parts = []
        if p["bonus_days"] > 0:
            u = conn.execute("SELECT subscription_end, proxy_user FROM users WHERE tg_id=?", (tg_id,)).fetchone()
            old_end = (u["subscription_end"] if u else None) or ""
            cur     = parse_date(old_end) or datetime.now(TZ).date()
            new_end = (max(cur, datetime.now(TZ).date()) + timedelta(days=p["bonus_days"])).strftime("%Y-%m-%d")
            # Продлеваем дату; is_active=1 только если proxy_user уже есть
            has_proxy = bool(u and u["proxy_user"])
            if has_proxy:
                conn.execute(
                    "UPDATE users SET subscription_end=?, is_active=1 WHERE tg_id=?", (new_end, tg_id)
                )
            else:
                conn.execute(
                    "UPDATE users SET subscription_end=? WHERE tg_id=?", (new_end, tg_id)
                )
            conn.execute(
                "INSERT INTO subscription_history "
                "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                (tg_id, "promo", p["bonus_days"], old_end, new_end, f"promo:{p['code']}"),
            )
            parts.append(f"+{p['bonus_days']} дней к подписке (до {new_end})")
        if p["discount_pct"] > 0:
            parts.append(f"скидка {p['discount_pct']}% (покажите при следующей оплате)")
        conn.commit()
    await msg.answer(
        f"✅ <b>Промокод применён!</b>\n\n" + "\n".join(f"🎁 {pt}" for pt in parts),
        reply_markup=kb_main(is_admin(tg_id)),
    )


@dp.callback_query(F.data.startswith("promo_info:"))
@handle_errors()
async def cb_promo_info(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    p_id = safe_cb_int(cb.data, 1)
    if p_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        p = conn.execute("SELECT * FROM promo_codes WHERE id=?", (p_id,)).fetchone()
        uses = conn.execute(
            "SELECT u.tg_id, u.username, u.first_name, pu.used_at "
            "FROM promo_uses pu LEFT JOIN users u ON pu.tg_id=u.tg_id "
            "WHERE pu.promo_id=? ORDER BY pu.used_at DESC LIMIT 20", (p_id,)
        ).fetchall()
    if not p: return await cb.answer("Не найден", show_alert=True)
    await cb.answer()
    status  = "🟢 Активен" if p["is_active"] else "🔴 Отключён"
    expires = p["expires_at"][:10] if p["expires_at"] else "∞"
    lines   = [
        f"🎟 <b>Промокод: <code>{p['code']}</code></b>",
        f"Статус: {status}",
        f"Скидка: {p['discount_pct']}% | Бонус: +{p['bonus_days']} дн.",
        f"Использований: {p['used_count']} / {p['max_uses']}",
        f"Действует до: {expires}",
    ]
    if uses:
        lines.append(f"\n<b>Последние использования:</b>")
        for u in uses:
            name = (u["first_name"] or "") + (f" @{u['username']}" if u["username"] else f" id{u['tg_id']}")
            lines.append(f"  • {safe_html(name)} — {str(u['used_at'])[:10]}")
    await cb.message.answer("\n".join(lines), reply_markup=_promos_kb())


@dp.callback_query(F.data == "promo_input")
@handle_errors()
async def cb_promo_input(cb: CallbackQuery, state: FSMContext):
    await cb.answer()
    await state.set_state(PromoFSM.applying)
    await cb.message.answer("🎟 Введите промокод:")


# ══════════════════════════════════════════════════════════════════════════════
#  ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(Command("profile"))
@handle_errors()
async def cmd_profile(msg: Message):
    tg_id = msg.from_user.id
    if is_banned(tg_id): return
    with get_db() as conn:
        u       = conn.execute("SELECT * FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        pay_cnt = conn.execute("SELECT COUNT(*) FROM payments WHERE tg_id=? AND status='approved'", (tg_id,)).fetchone()[0]
        ref_cnt = conn.execute("SELECT COUNT(*) FROM users WHERE referred_by=?", (tg_id,)).fetchone()[0]
        trial   = conn.execute("SELECT 1 FROM trials WHERE tg_id=? AND converted=0 AND expired_processed=0", (tg_id,)).fetchone()
    if not u: return await msg.answer("Используйте /start для регистрации.")
    d       = days_left(u["subscription_end"]) if u["is_active"] else 0
    status  = f"🟢 Активна ({d} дн.)" if u["is_active"] else ("⏰ Пробный период" if trial else "🔴 Неактивна")
    traffic = (u["traffic_up"] or 0) + (u["traffic_down"] or 0)
    await msg.answer(
        f"👤 <b>Ваш профиль</b>\n\n"
        f"🆔 ID: <code>{tg_id}</code>\n"
        f"📛 {safe_html(msg.from_user.first_name or '—')}\n"
        f"📅 В системе с: {(u['created_at'] or '')[:10]}\n\n"
        f"📡 Подписка: {status}\n"
        f"📆 Истекает: {u['subscription_end'] or '—'}\n"
        f"📊 Трафик: {fmt_traffic(traffic)}\n\n"
        f"💰 Успешных оплат: {pay_cnt}\n"
        f"👥 Рефералов: {ref_cnt}\n"
        f"🎁 Реф. бонусов: {u.get('ref_balance', 0)} дн.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="💳 Купить/продлить", callback_data="go_buy"),
            InlineKeyboardButton(text="🎟 Промокод",        callback_data="promo_input"),
        ]]),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  БАН / РАЗБАН
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(F.text == "🚫 Бан / Разбан")
@handle_errors()
async def admin_ban_menu(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    # Показываем текущий список забаненных
    with get_db() as conn:
        rows = conn.execute(
            "SELECT tg_id, username, first_name FROM users WHERE is_banned=1 ORDER BY tg_id"
        ).fetchall()
    if rows:
        lines = [f"🚫 <b>Забанено: {len(rows)}</b>\n"]
        for r in rows:
            name = (r["first_name"] or "") + (f" @{r['username']}" if r["username"] else "")
            lines.append(f"• <code>{r['tg_id']}</code> {safe_html(name)}")
        await send_long(msg, "\n".join(lines))
    else:
        await msg.answer("✅ Забаненных пользователей нет.")
    await state.set_state(AdminFSM.ban_uid)
    await msg.answer("Введите <b>Telegram ID</b> для бана/разбана:", reply_markup=kb_cancel())


@dp.message(AdminFSM.ban_uid)
@handle_errors()
async def admin_ban_do(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit(): return await msg.answer("Введите числовой ID.")
    tg_id = int(msg.text.strip())
    await state.clear()
    with get_db() as conn:
        u = conn.execute("SELECT username, first_name, is_banned, proxy_user, subscription_end FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        if not u: return await msg.answer(f"❌ Пользователь <code>{tg_id}</code> не найден.")
        new_ban = 0 if u["is_banned"] else 1
        if new_ban:
            # Бан: блокируем бот + деактивируем VPN + удаляем с панели
            conn.execute(
                "UPDATE users SET is_banned=1, is_active=0, proxy_user=NULL, proxy_pass=NULL, "
                "subscription_end=NULL, notified_1d=0, notified_3d=0, "
                "notified_7d=0, notified_remind=0 WHERE tg_id=?", (tg_id,)
            )
            if u["proxy_user"]:
                conn.execute(
                    "INSERT INTO subscription_history "
                    "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                    (tg_id, "expire", 0, u["subscription_end"] or "", "", "admin_ban"),
                )
        else:
            # Разбан: только снимаем флаг, подписку не восстанавливаем
            conn.execute("UPDATE users SET is_banned=0 WHERE tg_id=?", (tg_id,))
        conn.commit()

    # Удаляем с панели вне коннекта
    if new_ban and u["proxy_user"]:
        await panel.delete_user(u["proxy_user"])

    name   = (u["first_name"] or str(tg_id)) + (f" (@{u['username']})" if u["username"] else "")
    action = "🚫 ЗАБЛОКИРОВАН + VPN деактивирован" if new_ban else "✅ РАЗБЛОКИРОВАН"
    await msg.answer(f"{action}\n👤 {name} | <code>{tg_id}</code>", reply_markup=kb_admin())
    if new_ban:
        await safe_send(tg_id, "🚫 Ваш аккаунт заблокирован администратором. VPN доступ отозван.")
    else:
        await safe_send(tg_id, "✅ Ваш аккаунт разблокирован. Добро пожаловать!")


@dp.callback_query(F.data.startswith("ban_toggle:"))
@handle_errors()
async def cb_ban_toggle(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    tg_id = safe_cb_int(cb.data, 1)
    if tg_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        u = conn.execute("SELECT is_banned, proxy_user, subscription_end FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        if not u: return await cb.answer("Не найден", show_alert=True)
        new_ban = 0 if u["is_banned"] else 1
        if new_ban:
            conn.execute(
                "UPDATE users SET is_banned=1, is_active=0, proxy_user=NULL, proxy_pass=NULL, "
                "subscription_end=NULL, notified_1d=0, notified_3d=0, "
                "notified_7d=0, notified_remind=0 WHERE tg_id=?", (tg_id,)
            )
            if u["proxy_user"]:
                conn.execute(
                    "INSERT INTO subscription_history "
                    "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                    (tg_id, "expire", 0, u["subscription_end"] or "", "", "admin_ban"),
                )
        else:
            conn.execute("UPDATE users SET is_banned=0 WHERE tg_id=?", (tg_id,))
        conn.commit()

    if new_ban and u["proxy_user"]:
        await panel.delete_user(u["proxy_user"])

    await cb.answer("🚫 Заблокирован + VPN отозван" if new_ban else "✅ Разблокирован")
    if new_ban: await safe_send(tg_id, "🚫 Ваш аккаунт заблокирован. VPN доступ отозван.")
    else:       await safe_send(tg_id, "✅ Ваш аккаунт разблокирован!")


@dp.callback_query(F.data.startswith("deactivate:"))
@handle_errors()
async def cb_deactivate(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    tg_id = safe_cb_int(cb.data, 1)
    if tg_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        u = conn.execute("SELECT proxy_user, subscription_end FROM users WHERE tg_id=?", (tg_id,)).fetchone()

    panel_ok = False
    if u and u["proxy_user"]:
        panel_ok = await panel.delete_user(u["proxy_user"])

    with get_db() as conn:
        deactivate_user(conn, tg_id, source="admin_deactivate")
        conn.commit()
    await safe_send(tg_id, "⚠️ Ваша подписка деактивирована администратором.")
    await cb.message.edit_text(cb.message.text + "\n\n🔴 <b>ДЕАКТИВИРОВАН — данные очищены</b>")


# ══════════════════════════════════════════════════════════════════════════════
#  ПОИСК ПОЛЬЗОВАТЕЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(F.text == "🔍 Поиск пользователя")
@handle_errors()
async def admin_search_start(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    await state.set_state(AdminFSM.search_query)
    await msg.answer("🔍 Введите <b>ID</b>, <b>@username</b> или <b>proxy_user</b>:", reply_markup=kb_cancel())


@dp.message(AdminFSM.search_query)
@handle_errors()
async def admin_search_do(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    await state.clear()
    q = msg.text.strip().lstrip("@")
    with get_db() as conn:
        u = (
            conn.execute("SELECT * FROM users WHERE tg_id=?", (int(q),)).fetchone()
            if q.isdigit()
            else conn.execute("SELECT * FROM users WHERE username=? OR proxy_user=?", (q, q)).fetchone()
        )
    if not u: return await msg.answer(f"❌ Не найдено: <b>{safe_html(q)}</b>", reply_markup=kb_admin())
    d       = days_left(u["subscription_end"])
    status  = "🟢 Активна" if u["is_active"] else "🔴 Неактивна"
    ban_st  = " 🚫БАН" if u.get("is_banned") else ""
    traffic = (u["traffic_up"] or 0) + (u["traffic_down"] or 0)
    key     = make_naive_key(u["proxy_user"], u["proxy_pass"]) if u["proxy_user"] else "—"
    with get_db() as conn:
        pay_cnt = conn.execute("SELECT COUNT(*) FROM payments WHERE tg_id=? AND status='approved'", (u["tg_id"],)).fetchone()[0]
        ref_cnt = conn.execute("SELECT COUNT(*) FROM users WHERE referred_by=?", (u["tg_id"],)).fetchone()[0]
    await msg.answer(
        f"👤 <b>Профиль пользователя</b>{ban_st}\n"
        f"🆔 <code>{u['tg_id']}</code>\n"
        f"📛 {safe_html(u['first_name'] or '—')} (@{safe_html(u['username'] or '—')})\n"
        f"📅 Регистрация: {(u['created_at'] or '')[:10]}\n\n"
        f"📡 {status}\n"
        f"📆 До: <b>{u['subscription_end'] or '—'}</b> ({d} дн.)\n"
        f"👤 Proxy: <code>{u['proxy_user'] or '—'}</code>\n"
        f"📊 Трафик: {fmt_traffic(traffic)}\n\n"
        f"💰 Оплат: {pay_cnt} | 👥 Рефералов: {ref_cnt}\n"
        f"🎁 Реф. баланс: {u.get('ref_balance', 0)} дн.\n\n"
        f"🔑 Ключ:\n<code>{key}</code>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="➕ Выдать тариф",      callback_data=f"admin_add:{u['tg_id']}:sel"),
                InlineKeyboardButton(
                    text="🚫 Бан" if not u.get("is_banned") else "✅ Разбан",
                    callback_data=f"ban_toggle:{u['tg_id']}",
                ),
            ],
            [InlineKeyboardButton(text="🔴 Деактивировать", callback_data=f"deactivate:{u['tg_id']}")],
        ]),
    )


# Обработка "sel" - показать выбор тарифа
@dp.callback_query(F.data.startswith("admin_add:") & F.data.endswith(":sel"))
@handle_errors()
async def cb_admin_add_select(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    tg_id = safe_cb_int(cb.data, 1)
    if tg_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    await cb.answer()
    await cb.message.answer(f"Выберите тариф для <code>{tg_id}</code>:", reply_markup=kb_tariffs_admin(tg_id))


# ══════════════════════════════════════════════════════════════════════════════
#  ТОП РЕФЕРАЛОВ
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(F.text == "🏆 Топ рефералов")
@handle_errors()
async def admin_ref_top(msg: Message):
    if not is_admin(msg.from_user.id): return
    with get_db() as conn:
        rows = conn.execute("""
            SELECT u.tg_id, u.username, u.first_name,
                   COUNT(r.referred_id) AS cnt,
                   COALESCE(SUM(r.total_bonus_given), 0) AS total_days
            FROM users u
            LEFT JOIN referrals r ON r.referrer_id = u.tg_id
            GROUP BY u.tg_id HAVING cnt > 0
            ORDER BY cnt DESC LIMIT 20
        """).fetchall()
    if not rows: return await msg.answer("Рефералов пока нет.")
    medals = ["🥇","🥈","🥉","4️⃣","5️⃣","6️⃣","7️⃣","8️⃣","9️⃣","🔟"]
    lines  = ["🏆 <b>Топ рефералов:</b>\n"]
    for i, r in enumerate(rows):
        m     = medals[i] if i < len(medals) else f"{i+1}."
        name  = safe_html(r["first_name"] or f"id{r['tg_id']}")
        uname = f" @{safe_html(r['username'])}" if r["username"] else ""
        lines.append(f"{m} {name}{uname} — {r['cnt']} реф. / +{r['total_days']} дн.")
    await send_long(msg, "\n".join(lines))


# ══════════════════════════════════════════════════════════════════════════════
#  ТИКЕТЫ ПОДДЕРЖКИ (ответ администратора)
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(F.text == "📩 Тикеты")
@handle_errors()
async def admin_tickets(msg: Message):
    if not is_admin(msg.from_user.id): return
    with get_db() as conn:
        rows = conn.execute(
            "SELECT st.id, st.tg_id, st.message, st.created_at, u.username, u.first_name "
            "FROM support_tickets st LEFT JOIN users u ON st.tg_id=u.tg_id "
            "WHERE st.status='open' ORDER BY st.id DESC LIMIT 20"
        ).fetchall()
    if not rows: return await msg.answer("✅ Нет открытых тикетов.")
    for t in rows:
        name = (t["first_name"] or "") + (f" (@{t['username']})" if t["username"] else "")
        await msg.answer(
            f"📩 <b>Тикет #{t['id']}</b>\n"
            f"👤 {name} | <code>{t['tg_id']}</code>\n"
            f"📅 {t['created_at'][:16]}\n\n{safe_html(t['message'])}",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="💬 Ответить",  callback_data=f"reply_ticket:{t['tg_id']}:{t['id']}"),
                InlineKeyboardButton(text="✅ Закрыть",   callback_data=f"close_ticket:{t['id']}"),
            ]]),
        )


@dp.callback_query(F.data.startswith("reply_ticket:"))
@handle_errors()
async def cb_reply_ticket(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    parts = cb.data.split(":")
    tg_id = int(parts[1])
    t_id  = int(parts[2]) if len(parts) > 2 else 0
    await cb.answer()
    await state.update_data(reply_uid=tg_id, reply_tid=t_id)
    await state.set_state(AdminFSM.reply_ticket_text)
    await cb.message.answer(f"💬 Введите ответ пользователю <code>{tg_id}</code>:", reply_markup=kb_cancel())


@dp.message(AdminFSM.reply_ticket_text)
@handle_errors()
async def admin_reply_ticket_do(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    data = await state.get_data()
    await state.clear()
    uid  = data["reply_uid"]
    t_id = data.get("reply_tid", 0)
    sent = await safe_send(uid, f"💬 <b>Ответ поддержки:</b>\n\n{msg.text}")
    if sent:
        with get_db() as conn:
            if t_id: conn.execute("UPDATE support_tickets SET status='answered' WHERE id=?", (t_id,))
            conn.execute("INSERT INTO support_replies (ticket_id, admin_id, reply) VALUES (?,?,?)", (t_id, msg.from_user.id, msg.text))
            conn.commit()
        await msg.answer("✅ Ответ отправлен.", reply_markup=kb_admin())
    else:
        await msg.answer("❌ Не удалось отправить сообщение.", reply_markup=kb_admin())


@dp.callback_query(F.data.startswith("close_ticket:"))
@handle_errors()
async def cb_close_ticket(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    t_id = safe_cb_int(cb.data, 1)
    if t_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        conn.execute("UPDATE support_tickets SET status='closed' WHERE id=?", (t_id,))
        conn.commit()
    await cb.answer("Закрыт")
    await cb.message.edit_text(cb.message.text + "\n\n✅ <b>ЗАКРЫТ</b>")


# ══════════════════════════════════════════════════════════════════════════════
#  НАСТРОЙКИ РЕКВИЗИТОВ ОПЛАТЫ
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(F.text == "⚙️ Реквизиты")
@handle_errors()
async def admin_pay_settings(msg: Message):
    if not is_admin(msg.from_user.id): return
    pay = get_pay_settings()
    await msg.answer(
        f"⚙️ <b>Реквизиты оплаты:</b>\n\n"
        f"📱 Телефон: <code>{pay['phone']}</code>\n"
        f"🏦 Банк: {pay['bank']}\n"
        f"👤 Получатель: {pay['name']}",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📱 Изменить телефон",    callback_data="pay_edit:phone")],
            [InlineKeyboardButton(text="🏦 Изменить банк",       callback_data="pay_edit:bank")],
            [InlineKeyboardButton(text="👤 Изменить получателя", callback_data="pay_edit:name")],
        ]),
    )


@dp.callback_query(F.data.startswith("pay_edit:"))
@handle_errors()
async def cb_pay_edit(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    field = cb.data.split(":")[1]
    await cb.answer()
    await state.update_data(pay_field=field)
    await state.set_state(AdminFSM.pay_settings_value)
    labels = {"phone": "номер телефона", "bank": "название банка", "name": "имя получателя"}
    await cb.message.answer(f"Введите новое значение для <b>{labels.get(field, field)}</b>:")


@dp.message(AdminFSM.pay_settings_value)
@handle_errors()
async def admin_pay_settings_value(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    data  = await state.get_data()
    field = data["pay_field"]
    await state.clear()
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO pay_settings (key, value) VALUES (?,?)", (field, msg.text.strip()))
        conn.commit()
    await msg.answer("✅ Реквизиты обновлены!", reply_markup=kb_admin())


# ══════════════════════════════════════════════════════════════════════════════
#  РАССЫЛКА С ФИЛЬТРОМ АУДИТОРИИ
# ══════════════════════════════════════════════════════════════════════════════
# ── BROADCAST ────────────────────────────────────────────────────────────────
@dp.message(F.text == "📣 Рассылка")
@handle_errors()
async def admin_broad(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    await state.set_state(AdminFSM.broadcast_filter)
    await msg.answer(
        "📣 Кому отправить рассылку?",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="👥 Всем",           callback_data="bcast:all")],
            [InlineKeyboardButton(text="🟢 Только активным", callback_data="bcast:active")],
            [InlineKeyboardButton(text="🔴 Только неактивным",callback_data="bcast:inactive")],
            [InlineKeyboardButton(text="⏳ Только пробникам",callback_data="bcast:trial")],
            [InlineKeyboardButton(text="❌ Отмена",          callback_data="bcast:cancel")],
        ]),
    )


@dp.callback_query(F.data.startswith("bcast:"))
@handle_errors()
async def cb_bcast_filter(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    flt = cb.data.split(":")[1]
    if flt == "cancel":
        await state.clear()
        return await cb.message.edit_text("❌ Отменено.")
    await cb.answer()
    await state.update_data(bcast_filter=flt)
    await state.set_state(AdminFSM.broadcast)
    labels = {"all": "всем", "active": "активным", "inactive": "неактивным", "trial": "пробникам"}
    await cb.message.answer(
        f"📝 Текст рассылки <b>{labels.get(flt,'')}</b> (HTML, фото, видео):",
        reply_markup=kb_cancel(),
    )


@dp.message(AdminFSM.broadcast)
@handle_errors()
async def admin_broad_do(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    data = await state.get_data()
    flt  = data.get("bcast_filter", "all")
    await state.clear()
    with get_db() as conn:
        if flt == "active":
            users = conn.execute("SELECT tg_id FROM users WHERE is_active=1 AND is_banned=0").fetchall()
        elif flt == "inactive":
            users = conn.execute("SELECT tg_id FROM users WHERE is_active=0 AND is_banned=0").fetchall()
        elif flt == "trial":
            users = conn.execute("SELECT tg_id FROM trials WHERE expired_processed=0 AND converted=0").fetchall()
        else:
            users = conn.execute("SELECT tg_id FROM users WHERE is_banned=0").fetchall()
    sent = fail = 0
    total = len(users)
    await msg.answer(f"🚀 Рассылка {total} получателям...")

    async def _do_broadcast():
        nonlocal sent, fail
        for u in users:
            try:
                if msg.photo:
                    await bot.send_photo(u["tg_id"], msg.photo[-1].file_id, caption=msg.caption or "", parse_mode="HTML")
                elif msg.video:
                    await bot.send_video(u["tg_id"], msg.video.file_id, caption=msg.caption or "", parse_mode="HTML")
                elif msg.document:
                    await bot.send_document(u["tg_id"], msg.document.file_id, caption=msg.caption or "", parse_mode="HTML")
                elif msg.audio:
                    await bot.send_audio(u["tg_id"], msg.audio.file_id, caption=msg.caption or "", parse_mode="HTML")
                elif msg.sticker:
                    await bot.send_sticker(u["tg_id"], msg.sticker.file_id)
                elif msg.voice:
                    await bot.send_voice(u["tg_id"], msg.voice.file_id, caption=msg.caption or "")
                elif msg.text:
                    await bot.send_message(u["tg_id"], msg.text, parse_mode="HTML")
                sent += 1
            except Exception:
                fail += 1
            await asyncio.sleep(0.05)

        # Пишем лог рассылки
        preview = (msg.text or msg.caption or "[медиа]")[:100]
        with get_db() as conn:
            conn.execute(
                "INSERT INTO broadcast_log (admin_id, audience, message_preview, sent, failed) "
                "VALUES (?,?,?,?,?)",
                (msg.from_user.id, flt, preview, sent, fail),
            )
            conn.commit()

        await msg.answer(
            f"✅ <b>Рассылка завершена</b>\n📬 Доставлено: <b>{sent}</b>\n❌ Ошибок: <b>{fail}</b>",
            reply_markup=kb_admin(),
        )

    fire_and_forget(_do_broadcast())


# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ТАРИФАМИ (CRUD)
# ══════════════════════════════════════════════════════════════════════════════
def _tariffs_text() -> str:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, days, price, label, is_active FROM tariffs ORDER BY sort_order, days"
        ).fetchall()
    if not rows: return "Тарифов нет."
    lines = ["💲 <b>Тарифы:</b>\n"]
    for r in rows:
        status = "🟢" if r["is_active"] else "🔴"
        label  = f" <i>({r['label']})</i>" if r["label"] else ""
        lines.append(f"{status} <b>#{r['id']}</b> {r['days']} дн. — {r['price']} ₽{label}")
    return "\n".join(lines)


def _tariffs_manage_kb() -> InlineKeyboardMarkup:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, days, price, is_active FROM tariffs ORDER BY sort_order, days"
        ).fetchall()
    btns = []
    for r in rows:
        tog = "🔴 Откл" if r["is_active"] else "🟢 Вкл"
        btns.append([
            InlineKeyboardButton(text=f"{r['days']} дн. / {r['price']} ₽ — ✏️", callback_data=f"te:{r['id']}"),
            InlineKeyboardButton(text=tog, callback_data=f"tt:{r['id']}"),
            InlineKeyboardButton(text="🗑", callback_data=f"td:{r['id']}"),
        ])
    btns.append([InlineKeyboardButton(text="➕ Добавить тариф", callback_data="tariff_add")])
    return InlineKeyboardMarkup(inline_keyboard=btns)


@dp.message(F.text == "💲 Тарифы")
@handle_errors()
async def admin_tariffs(msg: Message):
    if not is_admin(msg.from_user.id): return
    await msg.answer(_tariffs_text(), reply_markup=_tariffs_manage_kb())


# Добавить тариф
@dp.callback_query(F.data == "tariff_add")
@handle_errors()
async def cb_tariff_add(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    await cb.answer()
    await state.set_state(AdminFSM.tariff_add_days)
    await cb.message.answer("Введите количество <b>дней</b> нового тарифа:", reply_markup=kb_cancel())


@dp.message(AdminFSM.tariff_add_days)
@handle_errors()
async def tariff_add_days(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit() or int(msg.text.strip()) <= 0:
        return await msg.answer("Введите положительное число дней.")
    await state.update_data(new_days=int(msg.text.strip()))
    await state.set_state(AdminFSM.tariff_add_price)
    await msg.answer("Введите <b>цену</b> (в рублях):")


@dp.message(AdminFSM.tariff_add_price)
@handle_errors()
async def tariff_add_price(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit() or int(msg.text.strip()) <= 0:
        return await msg.answer("Введите положительное число.")
    await state.update_data(new_price=int(msg.text.strip()))
    await state.set_state(AdminFSM.tariff_add_label)
    await msg.answer("Введите <b>метку</b> тарифа (или «-» чтобы пропустить):")


@dp.message(AdminFSM.tariff_add_label)
@handle_errors()
async def tariff_add_label(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    data  = await state.get_data()
    await state.clear()
    label = None if msg.text.strip() == "-" else msg.text.strip()
    tariff_created = False
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO tariffs (days, price, label, sort_order) VALUES (?,?,?,?)",
                (data["new_days"], data["new_price"], label, data["new_days"]),
            )
            conn.commit()
            tariff_created = True
        except sqlite3.IntegrityError:
            pass
    if tariff_created:
        await msg.answer(
            f"✅ Тариф добавлен: <b>{data['new_days']} дн. — {data['new_price']} ₽</b>",
            reply_markup=kb_admin(),
        )
    else:
        await msg.answer(
            f"❌ Тариф на <b>{data['new_days']} дней</b> уже существует.",
            reply_markup=kb_admin(),
        )


# Редактировать тариф
@dp.callback_query(F.data.startswith("te:"))
@handle_errors()
async def cb_tariff_edit(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    t_id = safe_cb_int(cb.data, 1)
    if t_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        t = conn.execute("SELECT * FROM tariffs WHERE id=?", (t_id,)).fetchone()
    if not t: return await cb.answer("Не найден", show_alert=True)
    await cb.answer()
    await state.update_data(edit_tariff_id=t_id)
    await state.set_state(AdminFSM.tariff_edit_field)
    await cb.message.answer(
        f"✏️ Редактирование тарифа <b>#{t_id}</b>: {t['days']} дн. / {t['price']} ₽\n\n"
        f"Что изменить?",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📅 Дни",  callback_data=f"tef:{t_id}:days")],
            [InlineKeyboardButton(text="💰 Цена", callback_data=f"tef:{t_id}:price")],
            [InlineKeyboardButton(text="🏷 Метка", callback_data=f"tef:{t_id}:label")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="tef_cancel")],
        ]),
    )


@dp.callback_query(F.data.startswith("tef:"))
@handle_errors()
async def cb_tariff_edit_field(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    parts = cb.data.split(":")
    t_id, field = int(parts[1]), parts[2]
    await cb.answer()
    await state.update_data(edit_tariff_id=t_id, edit_field=field)
    await state.set_state(AdminFSM.tariff_edit_value)
    labels = {"days": "дней", "price": "цену (₽)", "label": "метку"}
    await cb.message.answer(f"Введите новое значение для <b>{labels.get(field, field)}</b>:")


@dp.callback_query(F.data == "tef_cancel")
@handle_errors()
async def cb_tef_cancel(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.answer()
    await cb.message.answer("Отменено.", reply_markup=kb_admin())


@dp.message(AdminFSM.tariff_edit_value)
@handle_errors()
async def tariff_edit_value(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    data  = await state.get_data()
    t_id  = data["edit_tariff_id"]
    field = data["edit_field"]
    await state.clear()
    # Whitelist полей во избежание SQL-инъекции
    ALLOWED_FIELDS = {"days", "price", "label"}
    if field not in ALLOWED_FIELDS:
        return await msg.answer("❌ Недопустимое поле.", reply_markup=kb_admin())
    val = msg.text.strip()
    if field in ("days", "price"):
        if not val.isdigit() or int(val) <= 0:
            return await msg.answer("Введите положительное число.", reply_markup=kb_admin())
        val = int(val)
    tariff_err = None
    with get_db() as conn:
        try:
            conn.execute(f"UPDATE tariffs SET {field}=? WHERE id=?", (val, t_id))
            conn.commit()
        except Exception as e:
            tariff_err = str(e)
    if tariff_err:
        await msg.answer(f"❌ Ошибка: {tariff_err}", reply_markup=kb_admin())
    else:
        await msg.answer(f"✅ Тариф <b>#{t_id}</b> обновлён.", reply_markup=kb_admin())


# Переключить активность тарифа
@dp.callback_query(F.data.startswith("tt:"))
@handle_errors()
async def cb_tariff_toggle(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    t_id = safe_cb_int(cb.data, 1)
    if t_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        conn.execute("UPDATE tariffs SET is_active = NOT is_active WHERE id=?", (t_id,))
        conn.commit()
    await cb.answer("Статус изменён")
    await cb.message.edit_text(_tariffs_text(), reply_markup=_tariffs_manage_kb())


# Удалить тариф
@dp.callback_query(F.data.startswith("td:"))
@handle_errors()
async def cb_tariff_delete(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    t_id = safe_cb_int(cb.data, 1)
    if t_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        conn.execute("DELETE FROM tariffs WHERE id=?", (t_id,))
        conn.commit()
    await cb.answer("Тариф удалён")
    await cb.message.edit_text(_tariffs_text(), reply_markup=_tariffs_manage_kb())


# ══════════════════════════════════════════════════════════════════════════════
#  ADD / DELETE / EXTEND
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(F.text == "➕ Добавить клиента")
@handle_errors()
async def admin_adduser_start(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    await state.set_state(AdminFSM.adduser_tg_id)
    await msg.answer("👤 Введите <b>Telegram ID</b> клиента:", reply_markup=kb_cancel())


@dp.message(AdminFSM.adduser_tg_id)
@handle_errors()
async def admin_adduser_got_id(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit(): return await msg.answer("❌ Введите числовой Telegram ID.")
    tg_id = int(msg.text.strip())
    await state.clear()
    with get_db() as conn:
        u = conn.execute("SELECT * FROM users WHERE tg_id=?", (tg_id,)).fetchone()
    name = (
        (u["first_name"] or "") + (f" (@{u['username']})" if u and u["username"] else "")
        if u else "<i>не зарегистрирован</i>"
    )
    warn = ""
    if u and u["proxy_user"] and u["is_active"]:
        warn = f"\n⚠️ Подписка до {u['subscription_end']} — срок <b>продлится</b>."
    await msg.answer(
        f"👤 {name}\n🆔 <code>{tg_id}</code>{warn}\n\nВыберите тариф:",
        reply_markup=kb_tariffs_admin(tg_id),
    )


@dp.callback_query(F.data.startswith("admin_add:"))
@handle_errors()
async def cb_admin_add_tariff(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    parts = cb.data.split(":")
    if parts[1] == "cancel": return await cb.message.edit_text("❌ Отменено.")
    tg_id, days = int(parts[1]), int(parts[2])
    await cb.answer("⏳ Создаю...")
    with get_db() as conn:
        conn.execute("INSERT OR IGNORE INTO users (tg_id, referral_code) VALUES (?,?)", (tg_id, gen_ref_code(tg_id)))
        conn.commit()
        u       = conn.execute("SELECT * FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        cur_end = parse_date(u["subscription_end"]) if u and u["subscription_end"] else datetime.now(TZ).date()
        new_end = (max(cur_end, datetime.now(TZ).date()) + timedelta(days=days)).strftime("%Y-%m-%d")
        if u and u["proxy_user"]:
            proxy_user, proxy_pass = u["proxy_user"], u["proxy_pass"]
        else:
            base       = gen_proxy_username(tg_id, u["username"] if u else None, u["first_name"] if u else None)
            proxy_user = _ensure_unique_proxy_user(conn, base)
            proxy_pass = gen_password()
    if not await panel.add_user(proxy_user, proxy_pass):
        return await cb.message.edit_text(
            f"❌ <b>Ошибка панели NaiveProxy!</b>\n<i>{safe_html(panel.last_error)}</i>\n\n"
            f"Используйте /ping_panel для диагностики."
        )
    with get_db() as conn:
        old_end = u["subscription_end"] if u else ""
        conn.execute(
            "UPDATE users SET proxy_user=?, proxy_pass=?, subscription_end=?, "
            "is_active=1, notified_1d=0, notified_3d=0 WHERE tg_id=?",
            (proxy_user, proxy_pass, new_end, tg_id),
        )
        conn.execute(
            "INSERT INTO subscription_history "
            "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
            (tg_id, "extend", days, old_end or "", new_end, "admin_manual"),
        )
        conn.commit()
    key      = make_naive_key(proxy_user, proxy_pass)
    notified = "✅ Клиент уведомлён."
    try:
        await send_key_with_qr(
            tg_id, key,
            f"🎁 <b>Администратор активировал подписку!</b>\n"
            f"📦 {days} дн. | 📅 До: <b>{new_end}</b>\n\n🔑 Ключ:\n<code>{key}</code>",
        )
    except Exception:
        notified = "⚠️ Не удалось уведомить клиента."
    await cb.message.edit_text(
        f"✅ <b>Готово!</b>\n🆔 <code>{tg_id}</code>\n"
        f"👤 Proxy: <code>{proxy_user}</code>\n📅 До: <b>{new_end}</b>\n\n"
        f"🔑 Ключ:\n<code>{key}</code>\n\n{notified}"
    )


@dp.message(F.text == "🗑 Удалить клиента")
@handle_errors()
async def admin_deluser_prompt(msg: Message):
    if not is_admin(msg.from_user.id): return
    await msg.answer("Используйте команду: /deluser <code>TELEGRAM_ID</code>")


@dp.message(Command("deluser"))
@handle_errors()
async def cmd_deluser(msg: Message):
    if not is_admin(msg.from_user.id): return
    parts = msg.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip().isdigit():
        return await msg.answer("Используйте: /deluser <code>TELEGRAM_ID</code>")
    tg_id = int(parts[1].strip())
    with get_db() as conn:
        u = conn.execute(
            "SELECT username, first_name, proxy_user, subscription_end, is_active FROM users WHERE tg_id=?", (tg_id,)
        ).fetchone()
    if not u:
        return await msg.answer(f"❌ Пользователь <code>{tg_id}</code> не найден.")

    # Удаляем с панели если есть
    panel_ok = False
    if u["proxy_user"]:
        panel_ok = await panel.delete_user(u["proxy_user"])

    # Полностью сбрасываем данные подписки в БД
    with get_db() as conn:
        deactivate_user(conn, tg_id, source="admin_delete")
        conn.commit()

    fire_and_forget(safe_send(tg_id, "⚠️ <b>Ваша подписка деактивирована администратором.</b>"))
    name = (u["first_name"] or str(tg_id)) + (f" (@{u['username']})" if u["username"] else "")
    panel_note = "✅ удалён с панели" if panel_ok else "⚠️ не найден на панели — сброшен в БД"
    await msg.answer(
        f"🗑 <b>{name}</b> (<code>{tg_id}</code>)\n"
        f"Proxy: <code>{u['proxy_user'] or '—'}</code> — {panel_note}\n"
        f"✅ Данные подписки полностью очищены."
    )


@dp.message(F.text == "➕ Продлить вручную")
@handle_errors()
async def admin_extend_start(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    await state.set_state(AdminFSM.extend_user)
    await msg.answer("Введите <b>Telegram ID</b> для продления:", reply_markup=kb_cancel())


@dp.message(AdminFSM.extend_user)
@handle_errors()
async def admin_extend_got_user(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit(): return await msg.answer("Введите числовой ID.")
    tg_id = int(msg.text.strip())
    with get_db() as conn:
        u = conn.execute("SELECT * FROM users WHERE tg_id=?", (tg_id,)).fetchone()
    if not u: return await msg.answer("❌ Пользователь не найден.")

    cur_end = u["subscription_end"] or "—"
    d_left  = days_left(u["subscription_end"]) if u["is_active"] else 0
    status  = f"🟢 {d_left} дн." if u["is_active"] else "🔴 Неактивен"
    name    = (u["first_name"] or "") + (f" (@{u['username']})" if u["username"] else "")

    await state.update_data(extend_tg_id=tg_id)
    await state.set_state(AdminFSM.extend_days)

    # Быстрые кнопки тарифов + произвольное число
    tariffs = get_tariffs()
    quick   = [[
        InlineKeyboardButton(text=f"+{d} дн.", callback_data=f"ext_quick:{tg_id}:{d}")
        for d in sorted(tariffs.keys())
    ]]
    # Дополнительные быстрые значения
    extra = [1, 3, 7, 14]
    quick.append([
        InlineKeyboardButton(text=f"+{d} дн.", callback_data=f"ext_quick:{tg_id}:{d}")
        for d in extra if d not in tariffs
    ])
    quick.append([InlineKeyboardButton(text="❌ Отмена", callback_data=f"ext_cancel")])

    await msg.answer(
        f"👤 {safe_html(name)} | <code>{tg_id}</code>\n"
        f"📅 Подписка до: <b>{cur_end}</b> ({status})\n\n"
        f"Выберите быстрое значение <b>или введите любое число дней</b>:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=quick),
    )


@dp.callback_query(F.data.startswith("ext_quick:"))
@handle_errors()
async def cb_ext_quick(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    _, tg_id_s, days_s = cb.data.split(":")
    tg_id, days = int(tg_id_s), int(days_s)
    await state.clear()
    await cb.answer("⏳ Продлеваю...")
    await _do_extend(cb.message, tg_id, days, edit=True)


@dp.callback_query(F.data == "ext_cancel")
@handle_errors()
async def cb_ext_cancel(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.answer()
    await cb.message.edit_text("❌ Отменено.")


@dp.message(AdminFSM.extend_days)
@handle_errors()
async def admin_extend_got_days(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    try:
        days = int(msg.text.strip())
        if days <= 0: raise ValueError
    except ValueError:
        return await msg.answer("Введите положительное число дней (например <code>45</code>).")
    data  = await state.get_data()
    tg_id = data["extend_tg_id"]
    await state.clear()
    await _do_extend(msg, tg_id, days)


async def _do_extend(source, tg_id: int, days: int, edit: bool = False, source_label: str = "admin"):
    """Общая логика продления — работает и для обычных, и для триальных пользователей."""
    with get_db() as conn:
        u     = conn.execute("SELECT * FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        trial = conn.execute(
            "SELECT * FROM trials WHERE tg_id=? AND converted=0 AND expired_processed=0", (tg_id,)
        ).fetchone()

    if not u:
        text = f"❌ Пользователь <code>{tg_id}</code> не найден."
        if edit: await source.edit_text(text)
        else:    await source.answer(text, reply_markup=kb_admin())
        return

    # Если в users нет proxy_user — берём из trials (триальный пользователь)
    proxy_user = u["proxy_user"]
    proxy_pass = u["proxy_pass"]
    if not proxy_user and trial:
        proxy_user = trial["proxy_user"]
        proxy_pass = trial["proxy_pass"]
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET proxy_user=?, proxy_pass=? WHERE tg_id=?",
                (proxy_user, proxy_pass, tg_id),
            )
            conn.execute("UPDATE trials SET converted=1 WHERE tg_id=?", (tg_id,))
            conn.commit()
        logger.info(f"Trial→user конвертация при ручном продлении: tg_id={tg_id}")

    old_end = u["subscription_end"] or ""
    cur     = parse_date(old_end) if old_end else datetime.now(TZ).date()
    new_end = (max(cur, datetime.now(TZ).date()) + timedelta(days=days)).strftime("%Y-%m-%d")

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET subscription_end=?, is_active=1, "
            "notified_1d=0, notified_3d=0, notified_7d=0, notified_remind=0 WHERE tg_id=?",
            (new_end, tg_id),
        )
        conn.execute(
            "INSERT INTO subscription_history (tg_id, action, days, old_end, new_end, source) "
            "VALUES (?,?,?,?,?,?)",
            (tg_id, "extend", days, old_end, new_end, source_label),
        )
        conn.commit()

    panel_ok   = await panel.add_user(proxy_user, proxy_pass) if proxy_user else False
    panel_note = "" if panel_ok else "\n⚠️ <i>Ошибка синхронизации с панелью</i>"

    fire_and_forget(
        safe_send(tg_id, f"🎁 <b>Администратор продлил подписку на {days} дн.!</b>\n📅 До: <b>{new_end}</b>")
    )
    result = (
        f"✅ <b>Продлено на {days} дн.</b>\n"
        f"🆔 <code>{tg_id}</code>\n"
        f"📅 {old_end or '—'} → <b>{new_end}</b>{panel_note}"
    )
    if edit: await source.edit_text(result)
    else:    await source.answer(result, reply_markup=kb_admin())


# ── POLL CREATE ───────────────────────────────────────────────────────────────
@dp.message(F.text == "🗳 Создать опрос")
@handle_errors()
async def admin_poll_start(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    await state.set_state(AdminFSM.create_poll)
    await msg.answer("📝 Введите <b>вопрос</b> опроса:", reply_markup=kb_cancel())


@dp.message(AdminFSM.create_poll)
@handle_errors()
async def admin_poll_question(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    await state.update_data(poll_question=msg.text)
    await state.set_state(AdminFSM.poll_options)
    await msg.answer(
        "📋 Введите варианты через <b>|||</b>\n"
        "Пример: <code>Хорошо|||Нормально|||Плохо</code>"
    )


@dp.message(AdminFSM.poll_options)
@handle_errors()
async def admin_poll_options(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    data = await state.get_data()
    await state.clear()
    with get_db() as conn:
        conn.execute("UPDATE polls SET is_active=0 WHERE is_active=1")
        conn.execute(
            "INSERT INTO polls (question, options, is_active) VALUES (?,?,1)",
            (data["poll_question"], msg.text.strip()),
        )
        conn.commit()
    await msg.answer("✅ Опрос создан и активирован!", reply_markup=kb_admin())


# ── EXPORT CSV ────────────────────────────────────────────────────────────────
@dp.message(F.text == "📥 Экспорт CSV")
@handle_errors()
async def admin_csv(msg: Message):
    if not is_admin(msg.from_user.id): return
    out = io.StringIO()
    w   = csv.writer(out)
    w.writerow(["TG ID", "Username", "Name", "Proxy User", "Pass",
                "End Date", "Active", "Traffic Up", "Traffic Down",
                "Ref Balance", "Referred By", "Created"])
    with get_db() as conn:
        for r in conn.execute("SELECT * FROM users").fetchall():
            w.writerow([
                r["tg_id"], r["username"], r["first_name"], r["proxy_user"],
                "***" if r["proxy_pass"] else "",  # не выгружаем пароли в открытом виде
                r["subscription_end"], r["is_active"],
                r["traffic_up"], r["traffic_down"], r["ref_balance"],
                r["referred_by"], r["created_at"],
            ])
    await msg.answer_document(
        types.BufferedInputFile(out.getvalue().encode("utf-8-sig"), filename="users_export.csv")
    )


# ── DIAGNOSTICS ───────────────────────────────────────────────────────────────
@dp.message(F.text == "🔧 Диагностика")
@dp.message(Command("test_panel"))
@handle_errors()
async def cmd_test_panel(msg: Message):
    """
    Расширенная диагностика: пробует все варианты API и показывает сырой ответ.
    Используй если approve возвращает 'Ошибка панели при создании пользователя'.
    """
    if not is_admin(msg.from_user.id): return
    await msg.answer("🔬 Тестирую API панели NaiveProxy...")

    test_user = f"_test_{int(time.time())}"
    test_pass = "testpass123"

    results = []
    endpoints = [
        ("POST", "/api/proxy-users/add",       {"username": test_user, "password": test_pass}),
        ("POST", "/api/users",                  {"username": test_user, "password": test_pass}),
        ("POST", "/api/proxy-users",            {"username": test_user, "password": test_pass}),
        ("GET",  "/api/proxy-users/list",       None),
        ("GET",  "/api/users",                  None),
    ]

    for method, path, body in endpoints:
        try:
            sess = panel._sess()
            if not panel.logged_in:
                await panel.login()
            kwargs = {"json": body, "timeout": 5.0} if body else {"timeout": 5.0}
            r = await getattr(sess, method.lower())(f"{PANEL_URL}{path}", **kwargs)
            try:
                resp_body = r.text[:200]
            except Exception:
                resp_body = "(не удалось прочитать тело)"
            results.append(f"<code>{method} {path}</code>\n→ HTTP {r.status_code}: <code>{safe_html(resp_body)}</code>")
        except Exception as e:
            results.append(f"<code>{method} {path}</code>\n→ ❌ {safe_html(str(e)[:100])}")

    # Попытка удалить тестового пользователя если создался
    await panel.delete_user(test_user)

    await msg.answer(
        "🔬 <b>Результаты теста API:</b>\n\n" +
        "\n\n".join(results) +
        "\n\n<b>Что искать:</b> найдите строку с HTTP 200 или 201 — это рабочий эндпоинт. "
        "Сообщите разработчику какой именно path работает.",
        reply_markup=kb_admin()
    )


@dp.message(Command("ping_panel"))
@handle_errors()
async def admin_diag(msg: Message):
    if not is_admin(msg.from_user.id): return
    await msg.answer("🔍 Проверяю подключение к панели NaiveProxy...")
    ok, detail = await panel.ping()
    login_ok   = await panel.login()
    panel_status = "✅ Достижима" if ok else f"❌ Недоступна\n<i>{safe_html(detail)}</i>"
    login_status = "✅ Авторизация успешна" if login_ok else f"❌ Ошибка авторизации\n<i>{safe_html(panel.last_error)}</i>"
    await msg.answer(
        f"🔧 <b>Диагностика панели</b>\n\n"
        f"📡 Панель ({PANEL_URL}): {panel_status}\n"
        f"🔑 Логин ({PANEL_USER}): {login_status}\n\n"
        f"<b>Если панель недоступна:</b>\n"
        f"• Проверьте что NaiveProxy запущен\n"
        f"• Проверьте PANEL_URL в .env\n"
        f"• Проверьте firewall/порты"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 1: НАПОМИНАЛКА О НЕЗАКРЫТЫХ ПЛАТЕЖАХ (через 2 часа)
# ══════════════════════════════════════════════════════════════════════════════
async def cleanup_stale_fsm():
    """
    Сбрасывает FSM-состояния которые висят дольше 30 минут.
    Защищает от ситуации когда пользователь начал диалог и бросил.
    """
    try:
        storage = dp.storage
        if not hasattr(storage, "storage"):
            return
        stale_keys = []
        now = time.time()
        for key, data in list(storage.storage.items()):
            ts = data.get("__fsm_ts__", 0)
            if ts and (now - ts) > 1800:  # 30 минут
                stale_keys.append(key)
        for key in stale_keys:
            storage.storage.pop(key, None)
        if stale_keys:
            logger.info(f"🧹 Очищено {len(stale_keys)} устаревших FSM-состояний")
    except Exception as e:
        logger.warning(f"cleanup_stale_fsm error: {e}")


async def remind_pending_payments():
    """
    Ищет платежи в статусе awaiting_confirm старше 2 часов — напоминает
    пользователю и помечает что напоминание отправлено (user_reminded=1).
    """
    cut2h = (datetime.now(TZ).replace(tzinfo=None) - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, tg_id, amount, duration, payment_code FROM payments "
            "WHERE status='awaiting_confirm' AND updated_at < ? AND user_reminded=0",
            (cut2h,),
        ).fetchall()

    for p in rows:
        sent = await safe_send(
            p["tg_id"],
            f"⏳ <b>Ваш платёж ещё не подтверждён</b>\n\n"
            f"💵 {p['amount']} ₽ за {p['duration']} дн.\n"
            f"Код: <code>{p['payment_code']}</code>\n\n"
            f"Если вы уже оплатили — напомните администратору через 💬 Поддержка.\n"
            f"Если передумали — просто проигнорируйте.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="💬 Написать в поддержку", callback_data="open_support"),
            ]]),
        )
        if sent:
            with get_db() as conn:
                conn.execute(
                    "UPDATE payments SET user_reminded=1 WHERE id=?", (p["id"],)
                )
                conn.commit()
            logger.info(f"💬 Напоминание о платеже #{p['id']} отправлено tg_id={p['tg_id']}")


@dp.callback_query(F.data == "open_support")
@handle_errors()
async def cb_open_support(cb: CallbackQuery, state: FSMContext):
    """Быстрый переход к поддержке из напоминалки."""
    await cb.answer()
    if is_banned(cb.from_user.id):
        return await cb.message.answer("🚫 Ваш аккаунт заблокирован.")
    await state.set_state(SupportFSM.waiting)
    await cb.message.answer("💬 Опишите вашу проблему или напомните об оплате:", reply_markup=kb_cancel())


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 2: БЫСТРОЕ ПРОДЛЕНИЕ (один тап)
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data.startswith("quick_renew:"))
@handle_errors()
async def cb_quick_renew(cb: CallbackQuery):
    """
    Создаёт платёж сразу на предыдущий тариф пользователя без выбора тарифа.
    callback_data = quick_renew:{days}
    """
    if is_banned(cb.from_user.id):
        return await cb.answer("🚫 Ваш аккаунт заблокирован.", show_alert=True)
    days = safe_cb_int(cb.data, 1)
    if days is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    tariffs = get_tariffs()
    price = tariffs.get(days)
    if not price:
        # Тариф удалён — направляем в магазин
        await cb.answer("Тариф изменился, выберите новый.", show_alert=True)
        await cb.message.answer("💳 <b>Выберите тариф:</b>", reply_markup=kb_tariffs())
        return
    code = gen_payment_code()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO payments (tg_id, amount, duration, payment_code) VALUES (?,?,?,?)",
            (cb.from_user.id, price, days, code),
        )
        conn.commit()
    pay = get_pay_settings()
    months = days // 30
    label = f"{months} мес." if months >= 1 else f"{days} дн."
    await cb.message.answer(
        f"⚡️ <b>Быстрое продление — {label}</b>\n\n"
        f"💳 К оплате: <b>{price} ₽</b>\n\n"
        f"📱 Номер: <code>{pay['phone']}</code>\n"
        f"🏦 Банк: {pay['bank']}\n"
        f"👤 Получатель: {pay['name']}\n\n"
        f"⚠️ В комментарии укажите: <code>VPN {cb.from_user.id}</code>\n\n"
        f"После перевода нажмите кнопку:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Я оплатил",  callback_data=f"paid:{code}")],
            [InlineKeyboardButton(text="❌ Отменить",   callback_data="pay_cancel")],
        ]),
    )
    await cb.answer()


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 3: HEALTH-CHECK ПАНЕЛИ КАЖДЫЕ 10 МИНУТ
# ══════════════════════════════════════════════════════════════════════════════
async def panel_health_check():
    """
    Пингует панель каждые 10 минут.
    Если недоступна > 30 минут — шлёт алерт всем админам (один раз на инцидент).
    Когда панель восстанавливается — уведомляет о восстановлении.
    """
    global _panel_down_since
    ok, detail = await panel.ping()

    if not ok:
        now = time.time()
        if _panel_down_since is None:
            _panel_down_since = now
            logger.warning(f"⚠️ Панель недоступна: {detail}")
        else:
            down_minutes = (now - _panel_down_since) / 60
            # Алерт: первый раз когда > 30 минут и каждый следующий час
            elapsed = now - _panel_down_since
            # Отправляем алерт на 30-й минуте и каждые 60 минут после
            thresholds = [30 * 60] + [30 * 60 + 60 * 60 * i for i in range(1, 48)]
            prev_elapsed = elapsed - 600  # предыдущая проверка была 10 минут назад
            should_alert = any(prev_elapsed < t <= elapsed for t in thresholds)
            if should_alert:
                down_min_int = int(down_minutes)
                alert_text = (
                    f"🚨 <b>ПАНЕЛЬ НЕДОСТУПНА {down_min_int} минут!</b>\n\n"
                    f"❌ {safe_html(detail)}\n\n"
                    f"Платежи копятся в pending. Проверьте сервер немедленно!\n"
                    f"/ping_panel — диагностика"
                )
                for admin_id in ({ADMIN_ID} | EXTRA_ADMINS):
                    fire_and_forget(safe_send(admin_id, alert_text))
                logger.error(f"🚨 PANEL DOWN {down_min_int} min: {detail}")
    else:
        if _panel_down_since is not None:
            down_minutes = int((time.time() - _panel_down_since) / 60)
            _panel_down_since = None
            recovery_text = (
                f"✅ <b>Панель восстановлена!</b>\n"
                f"Простой составил <b>{down_minutes} мин.</b>"
            )
            for admin_id in ({ADMIN_ID} | EXTRA_ADMINS):
                fire_and_forget(safe_send(admin_id, recovery_text))
            logger.info(f"✅ Панель восстановлена после {down_minutes} мин.")


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 4: ОНБОРДИНГ ПОСЛЕ АКТИВАЦИИ
# ══════════════════════════════════════════════════════════════════════════════
async def _send_onboarding(tg_id: int):
    """
    Отправляет пошаговую инструкцию новому пользователю.
    Сначала спрашивает платформу — потом присылает инструкцию.
    Вызывается только при первой активации (onboarded=0).
    """
    with get_db() as conn:
        u = conn.execute("SELECT onboarded FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        if not u or u["onboarded"]: return
        conn.execute("UPDATE users SET onboarded=1 WHERE tg_id=?", (tg_id,))
        conn.commit()

    await asyncio.sleep(3)  # небольшая пауза после QR-кода
    await safe_send(
        tg_id,
        "📲 <b>Выберите вашу платформу</b>\nПришлю пошаговую инструкцию по подключению:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🤖 Android",  callback_data="onboard:android"),
                InlineKeyboardButton(text="🍎 iPhone",   callback_data="onboard:ios"),
            ],
            [
                InlineKeyboardButton(text="💻 Windows",  callback_data="onboard:windows"),
                InlineKeyboardButton(text="🖥 macOS",    callback_data="onboard:macos"),
            ],
        ]),
    )


_ONBOARD_TEXTS = {
    "android": (
        "🤖 <b>Подключение на Android</b>\n\n"
        "<b>1.</b> Установите <b>Karing</b> из Google Play:\n"
        "   → <a href='https://play.google.com/store/apps/details?id=com.karing.app'>Google Play</a>\n\n"
        "<b>2.</b> Откройте Karing → нажмите <b>＋</b>\n\n"
        "<b>3.</b> Выберите <b>«Импорт из буфера обмена»</b>\n\n"
        "<b>4.</b> Вставьте ваш ключ (кнопка <b>⚡️ Мой ключ</b> в меню бота)\n\n"
        "<b>5.</b> Нажмите <b>Подключить</b> ✅\n\n"
        "<i>🛡 Трафик замаскирован под Chrome — обходит любые блокировки</i>"
    ),
    "ios": (
        "🍎 <b>Подключение на iPhone / iPad</b>\n\n"
        "<b>1.</b> Установите <b>Karing</b> из App Store:\n"
        "   → <a href='https://apps.apple.com/app/karing/id6472431552'>App Store</a>\n\n"
        "<b>2.</b> Откройте Karing → нажмите <b>＋</b>\n\n"
        "<b>3.</b> Выберите <b>«Импорт из буфера обмена»</b>\n\n"
        "<b>4.</b> Вставьте ваш ключ (кнопка <b>⚡️ Мой ключ</b> в меню бота)\n\n"
        "<b>5.</b> Нажмите <b>Подключить</b> → разрешите добавить VPN-конфигурацию ✅\n\n"
        "<i>🛡 Работает на iOS 15+ без джейлбрейка</i>"
    ),
    "windows": (
        "💻 <b>Подключение на Windows</b>\n\n"
        "<b>1.</b> Скачайте Karing:\n"
        "   → <a href='https://github.com/KaringX/karing/releases/latest'>GitHub Releases</a>\n"
        "   Файл: <code>karing_x.x.x_windows_x64.zip</code>\n\n"
        "<b>2.</b> Распакуйте архив → запустите <code>karing.exe</code>\n"
        "   ⚠️ Запускайте <b>от имени администратора</b>\n\n"
        "<b>3.</b> Нажмите <b>＋</b> → <b>«Импорт из буфера обмена»</b>\n\n"
        "<b>4.</b> Вставьте ваш ключ (кнопка <b>⚡️ Мой ключ</b> в меню бота)\n\n"
        "<b>5.</b> Нажмите <b>Подключить</b> ✅\n\n"
        "<i>🛡 Требует Windows 10/11</i>"
    ),
    "macos": (
        "🖥 <b>Подключение на macOS</b>\n\n"
        "<b>1.</b> Скачайте Karing:\n"
        "   → <a href='https://karing.app/download'>karing.app</a>\n\n"
        "<b>2.</b> Откройте .dmg → перетащите Karing в <b>Программы</b>\n\n"
        "<b>3.</b> Запустите Karing → нажмите <b>＋</b>\n\n"
        "<b>4.</b> Выберите <b>«Импорт из буфера обмена»</b>\n\n"
        "<b>5.</b> Вставьте ваш ключ (кнопка <b>⚡️ Мой ключ</b> в меню бота)\n\n"
        "<b>6.</b> Нажмите подключиться ✅\n\n"
        "<i>🛡 Работает на macOS 12+</i>"
    ),
}


@dp.callback_query(F.data.startswith("onboard:"))
@handle_errors()
async def cb_onboard(cb: CallbackQuery):
    platform = cb.data.split(":")[1]
    text = _ONBOARD_TEXTS.get(platform)
    if not text:
        return await cb.answer("Неизвестная платформа", show_alert=True)
    await cb.answer()
    await cb.message.edit_text(
        text,
        disable_web_page_preview=True,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="⚡️ Мой ключ", callback_data="show_key"),
            InlineKeyboardButton(text="❓ Не работает?", callback_data="open_support"),
        ]]),
    )


@dp.callback_query(F.data == "show_key")
@handle_errors()
async def cb_show_key_inline(cb: CallbackQuery):
    """Быстрый показ ключа из онбординга."""
    await cb.answer()
    tg_id = cb.from_user.id
    with get_db() as conn:
        u = conn.execute("SELECT proxy_user, proxy_pass FROM users WHERE tg_id=?", (tg_id,)).fetchone()
    if not u or not u["proxy_user"]:
        return await cb.message.answer("❌ Ключ не найден. Обратитесь в поддержку.")
    key = make_naive_key(u["proxy_user"], u["proxy_pass"])
    await send_key_with_qr(cb.from_user.id, key, f"🔑 Ваш ключ NaiveProxy:\n<code>{key}</code>")


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 5: /check_panel — РАСХОЖДЕНИЯ БД vs ПАНЕЛЬ (без авто-правки)
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(Command("check_panel"))
@handle_errors()
async def cmd_check_panel_diff(msg: Message):
    """
    Показывает расхождения между БД и панелью НЕ меняя ничего автоматически.
    - Активны в БД, но отсутствуют на панели (возможно удалены вручную)
    - Есть на панели, но не привязаны к TG ID в БД
    Команда для диагностики, не для синхронизации (/sync_users).
    """
    if not is_admin(msg.from_user.id): return
    await msg.answer("🔍 Сверяю БД с панелью, подождите...")

    panel_users = await panel.list_users()
    if panel_users is None:
        return await msg.answer(
            f"❌ Не удалось получить список с панели.\n<i>{safe_html(panel.last_error)}</i>"
        )

    panel_names: set[str] = {
        (u.get("username") or u.get("name", "")).strip()
        for u in panel_users
        if (u.get("username") or u.get("name", ""))
    }

    with get_db() as conn:
        db_active = conn.execute(
            "SELECT tg_id, proxy_user, username, first_name, subscription_end "
            "FROM users WHERE is_active=1 AND proxy_user IS NOT NULL"
        ).fetchall()
        db_proxy_names: set[str] = {r["proxy_user"] for r in db_active}
        db_all_proxies: set[str] = {
            r["proxy_user"] for r in
            conn.execute("SELECT proxy_user FROM users WHERE proxy_user IS NOT NULL").fetchall()
        }

    # 1) Активны в БД, но нет на панели
    only_in_db = [u for u in db_active if u["proxy_user"] not in panel_names]

    # 2) Есть на панели, но нет в БД вообще (новые/ручные)
    only_on_panel = [
        name for name in panel_names
        if name not in db_all_proxies
        and not name.startswith("_test_")
        and not name.startswith("trial_")
    ]

    lines = [f"📊 <b>Сверка БД ↔ Панель</b>\n"]
    lines.append(f"На панели: <b>{len(panel_names)}</b> | В БД активных: <b>{len(db_active)}</b>\n")

    if only_in_db:
        lines.append(f"⚠️ <b>Активны в БД, но НЕТ на панели ({len(only_in_db)}):</b>")
        for u in only_in_db[:20]:
            name = safe_html(u["first_name"] or f"id{u['tg_id']}")
            lines.append(
                f"  • <code>{u['proxy_user']}</code> — {name} "
                f"(до {u['subscription_end'] or '?'})\n"
                f"    /check_user {u['tg_id']}"
            )
        if len(only_in_db) > 20:
            lines.append(f"  ...и ещё {len(only_in_db) - 20}")
    else:
        lines.append("✅ Все активные в БД — есть на панели")

    if only_on_panel:
        lines.append(f"\n🆕 <b>Есть на панели, нет в БД ({len(only_on_panel)}):</b>")
        for name in sorted(only_on_panel)[:20]:
            lines.append(f"  • <code>{name}</code>")
        if len(only_on_panel) > 20:
            lines.append(f"  ...и ещё {len(only_on_panel) - 20}")
        lines.append("\nИспользуйте <b>🔄 Импорт с панели</b> для привязки.")
    else:
        lines.append("✅ Нет лишних пользователей на панели")

    if only_in_db:
        lines.append(
            "\n💡 <b>Для исправления:</b> /check_user &lt;ID&gt; деактивирует конкретного, "
            "/sync_users синхронизирует всех."
        )

    await send_long(msg, "\n".join(lines), reply_markup=kb_admin())


# ══════════════════════════════════════════════════════════════════════════════
#  SCHEDULER
# ══════════════════════════════════════════════════════════════════════════════
async def check_expiring():
    logger.info("🔍 Проверка подписок...")
    today = datetime.now(TZ).date()
    d1    = (today + timedelta(days=1)).isoformat()
    d3    = (today + timedelta(days=3)).isoformat()
    d7    = (today + timedelta(days=7)).isoformat()
    today_s = today.isoformat()

    # Сначала забираем всё из БД — не держим коннект через await
    with get_db() as conn:
        notify_7d = conn.execute(
            "SELECT tg_id, last_tariff_days FROM users WHERE subscription_end<=? AND subscription_end>? "
            "AND notified_7d=0 AND is_active=1", (d7, d3)
        ).fetchall()
        notify_3d = conn.execute(
            "SELECT tg_id, last_tariff_days FROM users WHERE subscription_end<=? AND subscription_end>? "
            "AND notified_3d=0 AND is_active=1", (d3, d1)
        ).fetchall()
        notify_1d = conn.execute(
            "SELECT tg_id, last_tariff_days FROM users WHERE subscription_end<=? AND subscription_end>? "
            "AND notified_1d=0 AND is_active=1", (d1, today_s)
        ).fetchall()
        expired = conn.execute(
            "SELECT tg_id, proxy_user, subscription_end FROM users "
            "WHERE subscription_end < ? AND is_active=1", (today_s,)
        ).fetchall()

    def _renew_kb(last_days: int) -> InlineKeyboardMarkup:
        """Кнопки продления: один тап если есть предыдущий тариф, иначе в магазин."""
        tariffs = get_tariffs()
        if last_days and last_days in tariffs:
            price = tariffs[last_days]
            months = last_days // 30
            label = f"{months} мес." if months >= 1 else f"{last_days} дн."
            return InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(
                    text=f"⚡️ Продлить {label} — {price} ₽",
                    callback_data=f"quick_renew:{last_days}",
                )],
                [InlineKeyboardButton(text="💳 Другой тариф", callback_data="go_buy")],
            ])
        return InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="💳 Продлить сейчас", callback_data="go_buy")
        ]])

    # Уведомления — вне открытого коннекта
    for u in notify_7d:
        if await safe_send(u["tg_id"],
            "📅 <b>Подписка истекает через 7 дней.</b>\nПодготовьте оплату заранее.",
            reply_markup=_renew_kb(u["last_tariff_days"] or 0),
        ):
            with get_db() as conn:
                conn.execute("UPDATE users SET notified_7d=1 WHERE tg_id=?", (u["tg_id"],))
                conn.commit()

    for u in notify_3d:
        if await safe_send(u["tg_id"],
            "⚠️ <b>Подписка истекает через 3 дня!</b>\n"
            "Продлите заранее, чтобы ключ не был удалён с сервера.",
            reply_markup=_renew_kb(u["last_tariff_days"] or 0),
        ):
            with get_db() as conn:
                conn.execute("UPDATE users SET notified_3d=1 WHERE tg_id=?", (u["tg_id"],))
                conn.commit()

    for u in notify_1d:
        if await safe_send(u["tg_id"],
            "⚠️ <b>Подписка истекает завтра!</b>\nПоследний шанс продлить без прерывания.",
            reply_markup=_renew_kb(u["last_tariff_days"] or 0),
        ):
            with get_db() as conn:
                conn.execute("UPDATE users SET notified_1d=1 WHERE tg_id=?", (u["tg_id"],))
                conn.commit()

    # Истёкшие — удаляем с панели, полностью очищаем данные в БД
    for u in expired:
        if u["proxy_user"]:
            await panel.delete_user(u["proxy_user"])
        with get_db() as conn:
            deactivate_user(conn, u["tg_id"], source="auto_expire")
            conn.commit()
        await safe_send(
            u["tg_id"],
            "🔴 <b>Подписка истекла.</b> Доступ закрыт.\nДля продления: 🛍 Магазин",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="💳 Продлить сейчас", callback_data="go_buy")
            ]]),
        )


async def check_trials():
    now   = datetime.now(TZ).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    warn6 = (datetime.now(TZ).replace(tzinfo=None) + timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S")

    # Собираем списки до await-вызовов, не держим коннект через await
    with get_db() as conn:
        notify_6h_list = conn.execute(
            "SELECT tg_id FROM trials WHERE expires_at <= ? AND expires_at > ? "
            "AND notified_6h=0 AND converted=0 AND expired_processed=0",
            (warn6, now),
        ).fetchall()
        expired_trials = conn.execute(
            "SELECT tg_id, proxy_user FROM trials "
            "WHERE expires_at < ? AND converted=0 AND expired_processed=0", (now,)
        ).fetchall()

    for u in notify_6h_list:
        if await safe_send(
            u["tg_id"],
            "⏰ <b>Пробный период истекает через 6 часов!</b>\n"
            "Оформите подписку, чтобы не потерять доступ.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="💳 Оформить подписку", callback_data="go_buy")
            ]]),
        ):
            with get_db() as conn:
                conn.execute("UPDATE trials SET notified_6h=1 WHERE tg_id=?", (u["tg_id"],))
                conn.commit()

    # await вынесен за пределы with get_db — нет риска "database is locked"
    for u in expired_trials:
        if u["proxy_user"]:
            await panel.delete_user(u["proxy_user"])
        with get_db() as conn:
            conn.execute("UPDATE trials SET expired_processed=1 WHERE tg_id=?", (u["tg_id"],))
            conn.commit()
        await safe_send(u["tg_id"], "⏰ <b>Пробный период завершён.</b>\nОформите подписку: 🛍 Магазин")


async def sync_traffic():
    """Синхронизация трафика из панели NaiveProxy в БД."""
    try:
        panel_users = await panel.list_users()
        if not panel_users:
            return
        with get_db() as conn:
            for pu in panel_users:
                uname = pu.get("username") or pu.get("name", "")
                up    = pu.get("upload",   pu.get("up",   0)) or 0
                down  = pu.get("download", pu.get("down", 0)) or 0
                if uname:
                    conn.execute(
                        "UPDATE users SET traffic_up=?, traffic_down=? WHERE proxy_user=?",
                        (up, down, uname),
                    )
            conn.commit()
        logger.info(f"📊 Трафик синхронизирован: {len(panel_users)} пользователей")
    except Exception as e:
        logger.warning(f"Traffic sync error: {e}")


async def recover_stuck_payments():
    cut15 = (datetime.now(TZ).replace(tzinfo=None) - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    cut24 = (datetime.now(TZ).replace(tzinfo=None) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        stuck = conn.execute(
            "SELECT id FROM payments WHERE status='processing' AND updated_at < ? AND panel_updated=0",
            (cut15,),
        ).fetchall()
        for p in stuck:
            conn.execute(
                "UPDATE payments SET status='pending', updated_at=CURRENT_TIMESTAMP "
                "WHERE id=? AND status='processing' AND panel_updated=0", (p["id"],),
            )
            logger.warning(f"♻️ Recovery платёж #{p['id']} → pending")
        stale = [
            p["id"] for p in conn.execute(
                "SELECT id FROM payments WHERE status IN ('pending', 'awaiting_confirm') AND updated_at < ?",
                (cut24,),
            ).fetchall()
        ]
        if stale:
            conn.execute(
                f"UPDATE payments SET status='cancelled' WHERE id IN ({','.join(['?']*len(stale))})", stale
            )
        conn.commit()


async def daily_report():
    """Ежедневный отчёт администратору в 9:00."""
    # created_at / updated_at в SQLite хранятся как UTC (CURRENT_TIMESTAMP).
    # Вычисляем границы вчера/сегодня в UTC чтобы сравнение было корректным.
    now_utc  = datetime.now(timezone.utc).replace(tzinfo=None)
    yday_utc = (now_utc - timedelta(days=1)).strftime("%Y-%m-%d")
    today_utc = now_utc.strftime("%Y-%m-%d")
    # Отображаемая дата — московская
    display_date = datetime.now(TZ).date().isoformat()
    with get_db() as conn:
        new_users  = conn.execute(
            "SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?", (yday_utc,)
        ).fetchone()[0]
        new_pays   = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(amount),0) FROM payments "
            "WHERE status='approved' AND DATE(updated_at) = ?", (yday_utc,),
        ).fetchone()
        active     = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1 AND tg_id > 0").fetchone()[0]
        exp_soon   = conn.execute(
            "SELECT COUNT(*) FROM users WHERE subscription_end BETWEEN ? AND ? AND is_active=1",
            (display_date, (datetime.now(TZ).date() + timedelta(days=3)).isoformat()),
        ).fetchone()[0]
        pending    = conn.execute("SELECT COUNT(*) FROM payments WHERE status IN ('pending', 'awaiting_confirm')").fetchone()[0]
        open_tickets = conn.execute("SELECT COUNT(*) FROM support_tickets WHERE status='open'").fetchone()[0]

    report_text = (
        f"📊 <b>Ежедневный отчёт</b> ({display_date})\n\n"
        f"👤 Новых пользователей: <b>{new_users}</b>\n"
        f"💰 Оплат за день: <b>{new_pays[0]}</b> на сумму <b>{new_pays[1]} ₽</b>\n"
        f"🟢 Активных подписок: <b>{active}</b>\n"
        f"⚠️ Истекают в ближайшие 3 дня: <b>{exp_soon}</b>\n"
        f"⌛ Ожидают подтверждения: <b>{pending}</b>\n"
        f"📩 Открытых тикетов: <b>{open_tickets}</b>"
    )
    for admin_id in ({ADMIN_ID} | EXTRA_ADMINS):
        await safe_send(admin_id, report_text)


def _run_daily_backup():
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = f"{BACKUP_DIR}/bot_{ts}.db"
    src = sqlite3.connect(DB_PATH)
    bk  = sqlite3.connect(dst)
    try:
        src.backup(bk)
        with zipfile.ZipFile(f"{BACKUP_DIR}/bot_{ts}.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.write(dst, Path(dst).name)
        os.remove(dst)
        logger.info(f"💾 Бэкап: {ts}")
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        raise
    finally:
        bk.close()
        src.close()
    for old in sorted(Path(BACKUP_DIR).glob("bot_*.zip"))[:-7]:
        old.unlink()


async def daily_backup():
    # FIX BUG 8: src.backup() блокирует event loop — выносим в executor
    try:
        await asyncio.get_running_loop().run_in_executor(None, _run_daily_backup)
    except Exception as e:
        logger.error(f"daily_backup error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  ДОПОЛНИТЕЛЬНЫЕ КОМАНДЫ
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(Command("sync"))
@handle_errors()
async def cmd_sync(msg: Message):
    """Ручная синхронизация трафика с панелью."""
    if not is_admin(msg.from_user.id): return
    await msg.answer("🔄 Синхронизирую трафик с панелью...")
    await sync_traffic()
    await msg.answer("✅ Трафик синхронизирован.", reply_markup=kb_admin())


@dp.message(Command("stats"))
@handle_errors()
async def cmd_stats_quick(msg: Message):
    """Быстрая статистика по команде /stats."""
    if not is_admin(msg.from_user.id): return
    with get_db() as conn:
        act   = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1 AND tg_id > 0").fetchone()[0]
        tot   = conn.execute("SELECT COUNT(*) FROM users WHERE tg_id > 0").fetchone()[0]
        earn  = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='approved'").fetchone()[0]
        pend  = conn.execute("SELECT COUNT(*) FROM payments WHERE status IN ('pending', 'awaiting_confirm')").fetchone()[0]
    await msg.answer(
        f"📊 <b>Быстрая статистика</b>\n"
        f"👥 Всего / 🟢 Активных: {tot} / {act}\n"
        f"💰 Заработано: {earn} ₽\n"
        f"⌛ Ожидают оплаты: {pend}"
    )


@dp.message(Command("help"))
@handle_errors()
async def cmd_help(msg: Message):
    if is_admin(msg.from_user.id):
        await msg.answer(
            "🛠 <b>Команды администратора:</b>\n\n"
            "/start — главное меню\n"
            "/stats — быстрая статистика\n"
            "/sync — синхронизация трафика с панелью\n"
            "/sync_users — синхронизация пользователей с панелью\n"
            "/check_panel — сверка БД с панелью (деактивирует удалённых)\n"
            "/ping_panel — диагностика панели\n"
            "/deluser ID — деактивировать пользователя\n"
            "/promo КОД — применить промокод\n"
            "/profile — профиль пользователя\n"
            "/help — эта справка\n\n"
            "📋 Все функции доступны через <b>🛠 Панель управления</b>"
        )
    else:
        await msg.answer(
            "📋 <b>Доступные команды:</b>\n\n"
            "/start — главное меню\n"
            "/profile — ваш профиль\n"
            "/promo КОД — ввести промокод\n"
            "/help — эта справка"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  НАСТРОЙКИ БОТА (динамические)
# ══════════════════════════════════════════════════════════════════════════════
class BotSettingsFSM(StatesGroup):
    choosing = State()
    value    = State()


BOT_SETTINGS_META = {
    "trial_hours":          ("⏳ Длительность пробника (ч)",        "часов"),
    "ref_bonus_pct":        ("🎁 Реф. бонус (%)",                    "%"),
    "ref_first_only":       ("🔂 Бонус только за 1-ю оплату",        "1=да 0=нет"),
    "ref_min_tariff_days":  ("📦 Мин. тариф для реф. бонуса (дн.)", "дней, 0=выкл"),
    "ref_account_age_days": ("🕐 Мин. возраст аккаунта реферала",    "дней, 0=выкл"),
    "ref_max_bonus_month":  ("📅 Макс. бонус рефереру в месяц (дн.)","дней, 0=выкл"),
    "notify_new_user":      ("🔔 Уведомлять о новых users",           "1=да 0=нет"),
    "welcome_text":         ("👋 Текст приветствия",                  "пусто = стандартный"),
    "maintenance":          ("🔧 Режим обслуживания",                 "1=вкл 0=выкл"),
}


def _bot_settings_kb() -> InlineKeyboardMarkup:
    btns = [
        [InlineKeyboardButton(text=meta[0], callback_data=f"bset:{key}")]
        for key, meta in BOT_SETTINGS_META.items()
    ]
    return InlineKeyboardMarkup(inline_keyboard=btns)


@dp.message(F.text == "⚙️ Настройки бота")
@handle_errors()
async def admin_bot_settings(msg: Message):
    if not is_admin(msg.from_user.id): return
    lines = ["⚙️ <b>Настройки бота:</b>\n"]
    for key, meta in BOT_SETTINGS_META.items():
        val = get_setting(key, "—")
        lines.append(f"• {meta[0]}: <b>{safe_html(val)}</b>")
    await msg.answer("\n".join(lines), reply_markup=_bot_settings_kb())


@dp.callback_query(F.data.startswith("bset:"))
@handle_errors()
async def cb_bset(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    key = cb.data.split(":")[1]
    meta = BOT_SETTINGS_META.get(key)
    if not meta: return await cb.answer("Не найдено")
    await cb.answer()
    await state.update_data(bset_key=key)
    await state.set_state(BotSettingsFSM.value)
    cur = get_setting(key, "—")
    await cb.message.answer(
        f"✏️ <b>{meta[0]}</b>\nТекущее: <code>{safe_html(cur)}</code>\nФормат: {meta[1]}\n\nВведите новое значение:",
        reply_markup=kb_cancel(),
    )


@dp.message(BotSettingsFSM.value)
@handle_errors()
async def bot_settings_value(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    data = await state.get_data()
    key  = data["bset_key"]
    await state.clear()
    set_setting(key, msg.text.strip())
    await msg.answer(f"✅ <b>{BOT_SETTINGS_META[key][0]}</b> обновлено: <code>{safe_html(msg.text.strip())}</code>", reply_markup=kb_admin())


# ══════════════════════════════════════════════════════════════════════════════
#  МУЛЬТИ-ADMIN УПРАВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
class MultiAdminFSM(StatesGroup):
    add_id = State()


@dp.message(F.text == "👮 Администраторы")
@handle_errors()
async def admin_admins_list(msg: Message):
    if not is_admin(msg.from_user.id): return  # только администраторы
    with get_db() as conn:
        rows = conn.execute(
            "SELECT a.tg_id, a.username, a.added_at, u.first_name "
            "FROM admins a LEFT JOIN users u ON a.tg_id=u.tg_id ORDER BY a.added_at"
        ).fetchall()
    lines = [f"👮 <b>Администраторы ({len(rows)}):</b>\n"]
    for r in rows:
        name = r["first_name"] or ""
        lines.append(f"• <code>{r['tg_id']}</code> {safe_html(name)} (@{safe_html(r['username'] or '—')}) — с {(r['added_at'] or '')[:10]}")
    btns = [[InlineKeyboardButton(text="➕ Добавить", callback_data="admin_add_new")]]
    if rows:
        for r in rows:
            btns.append([
                InlineKeyboardButton(text=f"🗑 Удалить {r['tg_id']}", callback_data=f"admin_del:{r['tg_id']}")
            ])
    await msg.answer("\n".join(lines) if len(lines) > 1 else "Доп. администраторов нет.",
                     reply_markup=InlineKeyboardMarkup(inline_keyboard=btns))


@dp.callback_query(F.data == "admin_add_new")
@handle_errors()
async def cb_admin_add_new(cb: CallbackQuery, state: FSMContext):
    if cb.from_user.id != ADMIN_ID: return await cb.answer("⛔", show_alert=True)
    await cb.answer()
    await state.set_state(MultiAdminFSM.add_id)
    await cb.message.answer("Введите <b>Telegram ID</b> нового администратора:")


@dp.message(MultiAdminFSM.add_id)
@handle_errors()
async def multi_admin_add(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit(): return await msg.answer("Введите числовой ID.")
    tg_id = int(msg.text.strip())
    await state.clear()
    if tg_id == ADMIN_ID: return await msg.answer("Это главный администратор.", reply_markup=kb_admin())
    with get_db() as conn:
        u = conn.execute("SELECT username FROM users WHERE tg_id=?", (tg_id,)).fetchone()
        conn.execute(
            "INSERT OR IGNORE INTO admins (tg_id, username, added_by) VALUES (?,?,?)",
            (tg_id, u["username"] if u else None, msg.from_user.id),
        )
        conn.commit()
    EXTRA_ADMINS.add(tg_id)
    await msg.answer(f"✅ Администратор <code>{tg_id}</code> добавлен.", reply_markup=kb_admin())
    await safe_send(tg_id, "👮 Вам выданы права администратора бота!")


@dp.callback_query(F.data.startswith("admin_del:"))
@handle_errors()
async def cb_admin_del(cb: CallbackQuery):
    if cb.from_user.id != ADMIN_ID: return await cb.answer("⛔", show_alert=True)
    tg_id = safe_cb_int(cb.data, 1)
    if tg_id is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    with get_db() as conn:
        conn.execute("DELETE FROM admins WHERE tg_id=?", (tg_id,))
        conn.commit()
    EXTRA_ADMINS.discard(tg_id)
    await cb.answer("Удалён")
    await cb.message.edit_text(cb.message.text + f"\n\n🗑 <code>{tg_id}</code> удалён из администраторов.")


# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОРИЯ ПОДПИСКИ ПОЛЬЗОВАТЕЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(Command("subhistory"))
@handle_errors()
async def cmd_subhistory(msg: Message):
    parts = msg.text.split(maxsplit=1)
    if is_admin(msg.from_user.id) and len(parts) > 1 and parts[1].strip().isdigit():
        tg_id = int(parts[1].strip())
    else:
        tg_id = msg.from_user.id
    with get_db() as conn:
        rows = conn.execute(
            "SELECT action, days, old_end, new_end, source, created_at "
            "FROM subscription_history WHERE tg_id=? ORDER BY id DESC LIMIT 15",
            (tg_id,),
        ).fetchall()
    if not rows: return await msg.answer("История подписки пуста.")
    icons = {"extend": "➕", "activate": "🟢", "expire": "🔴", "trial": "⏰", "promo": "🎟"}
    lines = [f"📋 <b>История подписки</b> <code>{tg_id}</code>\n"]
    for r in rows:
        icon = icons.get(r["action"], "•")
        lines.append(
            f"{icon} {r['created_at'][:10]} | +{r['days']} дн. | "
            f"{r['old_end'] or '—'} → {r['new_end'] or '—'} <i>({r['source']})</i>"
        )
    await send_long(msg, "\n".join(lines))


# ══════════════════════════════════════════════════════════════════════════════
#  ПАГИНАЦИЯ СПИСКА ПОЛЬЗОВАТЕЛЕЙ
# ══════════════════════════════════════════════════════════════════════════════
def _users_page_text(page: int, only_active: bool = True) -> tuple[str, InlineKeyboardMarkup]:
    offset = page * PAGE_SIZE
    with get_db() as conn:
        where = "WHERE is_active=1" if only_active else ""
        total = conn.execute(f"SELECT COUNT(*) FROM users {where}").fetchone()[0]
        users = conn.execute(
            f"SELECT * FROM users {where} ORDER BY subscription_end DESC NULLS LAST LIMIT ? OFFSET ?",
            (PAGE_SIZE, offset),
        ).fetchall()

    lines = [f"{'📋 Активные' if only_active else '👥 Все'} ({total} чел.) — стр. {page+1}\n"]
    for u in users:
        d    = days_left(u["subscription_end"])
        icon = "🔴" if d == 0 else ("🟡" if d <= 3 else "🟢")
        # Показываем @username если есть, иначе first_name, иначе ID
        if u["username"]:
            name = f"@{u['username']}"
        elif u["first_name"]:
            name = safe_html(u["first_name"])
        else:
            name = f"id{u['tg_id']}"
        lines.append(f"{icon} <code>{u['tg_id']}</code> {name} | {u['subscription_end'] or '—'} ({d}д.)")

    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="◀️", callback_data=f"upage:{page-1}:{int(only_active)}"))
    nav.append(InlineKeyboardButton(text=f"{page+1}/{total_pages}", callback_data="noop"))
    if (page + 1) * PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="▶️", callback_data=f"upage:{page+1}:{int(only_active)}"))

    toggle_label = "👥 Все" if only_active else "🟢 Активные"
    kb = InlineKeyboardMarkup(inline_keyboard=[
        nav,
        [InlineKeyboardButton(text=toggle_label, callback_data=f"upage:0:{int(not only_active)}")],
    ])
    return "\n".join(lines), kb


@dp.message(F.text == "📋 Пользователи")
@handle_errors()
async def admin_users(msg: Message):
    if not is_admin(msg.from_user.id): return
    text, kb = _users_page_text(0, only_active=True)
    await msg.answer(text, reply_markup=kb)


@dp.callback_query(F.data.startswith("upage:"))
@handle_errors()
async def cb_upage(cb: CallbackQuery):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    _, page_s, active_s = cb.data.split(":")
    text, kb = _users_page_text(int(page_s), bool(int(active_s)))
    await cb.message.edit_text(text, reply_markup=kb)
    await cb.answer()


@dp.callback_query(F.data == "noop")
@handle_errors()
async def cb_noop(cb: CallbackQuery):
    await cb.answer()


# ══════════════════════════════════════════════════════════════════════════════
#  МАССОВОЕ ПРОДЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
class MassExtendFSM(StatesGroup):
    days = State()


@dp.message(F.text == "⚡️ Массовое продление")
@handle_errors()
async def admin_mass_extend_start(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    with get_db() as conn:
        cnt = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
    await state.set_state(MassExtendFSM.days)
    await msg.answer(
        f"⚡️ <b>Массовое продление</b>\n\n"
        f"Активных подписок: <b>{cnt}</b>\n\n"
        f"Введите количество дней для продления <b>ВСЕМ активным</b> пользователям:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=f"+{d} дн.", callback_data=f"mass_ext:{d}") for d in [1, 3, 7, 14, 30]],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="mass_ext_cancel")],
        ]),
    )


@dp.callback_query(F.data == "mass_ext_cancel")
@handle_errors()
async def cb_mass_ext_cancel(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.answer()
    await cb.message.edit_text("❌ Отменено.")


@dp.callback_query(F.data.startswith("mass_ext:"))
@handle_errors()
async def cb_mass_ext_quick(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    days = safe_cb_int(cb.data, 1)
    if days is None: return await cb.answer("❌ Некорректные данные", show_alert=True)
    await state.clear()
    await cb.answer("⏳ Продлеваю...")
    await _do_mass_extend(cb.message, days, edit=True)


@dp.message(MassExtendFSM.days)
@handle_errors()
async def admin_mass_extend_do(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    try:
        days = int(msg.text.strip())
        if days <= 0: raise ValueError
    except ValueError:
        return await msg.answer("Введите положительное число дней.")
    await state.clear()
    await _do_mass_extend(msg, days)


async def _do_mass_extend(source, days: int, edit: bool = False):
    with get_db() as conn:
        users = conn.execute("SELECT tg_id, subscription_end, proxy_user, proxy_pass FROM users WHERE is_active=1").fetchall()
    cnt = 0
    notify_list = []
    with get_db() as conn:
        for u in users:
            cur     = parse_date(u["subscription_end"]) if u["subscription_end"] else datetime.now(TZ).date()
            new_end = (max(cur, datetime.now(TZ).date()) + timedelta(days=days)).strftime("%Y-%m-%d")
            conn.execute(
                "UPDATE users SET subscription_end=?, notified_1d=0, notified_3d=0, notified_7d=0 WHERE tg_id=?",
                (new_end, u["tg_id"]),
            )
            conn.execute(
                "INSERT INTO subscription_history (tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                (u["tg_id"], "extend", days, u["subscription_end"], new_end, "mass"),
            )
            notify_list.append((u["tg_id"], new_end))
            cnt += 1
        conn.commit()
    # Уведомляем после закрытия соединения
    for tg_id, new_end in notify_list:
        fire_and_forget(safe_send(tg_id, f"🎁 <b>Подарок от сервиса!</b>\nВаша подписка продлена на <b>{days} дн.</b>\n📅 До: <b>{new_end}</b>"))
    await asyncio.sleep(0)
    result = f"✅ <b>Массовое продление завершено!</b>\nПродлено: <b>{cnt}</b> подписок на <b>{days} дн.</b>"
    if edit: await source.edit_text(result)
    else:    await source.answer(result, reply_markup=kb_admin())


# ══════════════════════════════════════════════════════════════════════════════
#  СПИСОК ЗАБАНЕННЫХ
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  ИМПОРТ / РУЧНАЯ ПРИВЯЗКА КЛИЕНТОВ С ПАНЕЛИ
# ══════════════════════════════════════════════════════════════════════════════

class LinkUserFSM(StatesGroup):
    proxy_user  = State()   # шаг 1 — вводим proxy_user
    proxy_pass  = State()   # шаг 2 — вводим пароль (или авто с панели)
    tg_id       = State()   # шаг 3 — вводим Telegram ID
    sub_end     = State()   # шаг 4 — вводим дату подписки (или пропускаем)


async def _do_link_user(
    source,
    proxy_user: str,
    proxy_pass: str,
    tg_id: int,
    sub_end: str = "",
    notify: bool = True,
):
    """Общая логика привязки — используется и FSM и командой /link."""
    error_text = None
    with get_db() as conn:
        existing = conn.execute(
            "SELECT proxy_user FROM users WHERE tg_id=?", (tg_id,)
        ).fetchone()
        if existing and existing["proxy_user"] and existing["proxy_user"] != proxy_user:
            error_text = (
                f"⚠️ TG ID <code>{tg_id}</code> уже привязан к "
                f"<code>{existing['proxy_user']}</code>.\n"
                f"Сначала снимите привязку через 🔍 Поиск пользователя."
            )
        if not error_text:
            dup = conn.execute(
                "SELECT tg_id FROM users WHERE proxy_user=?", (proxy_user,)
            ).fetchone()
            if dup and dup["tg_id"] != tg_id:
                error_text = (
                    f"⚠️ Proxy <code>{proxy_user}</code> уже привязан к "
                    f"TG ID <code>{dup['tg_id']}</code>."
                )
        if not error_text:
            conn.execute(
                "INSERT OR IGNORE INTO users (tg_id, referral_code) VALUES (?,?)",
                (tg_id, gen_ref_code(tg_id))
            )
            fields = "proxy_user=?, proxy_pass=?, is_active=1"
            params = [proxy_user, proxy_pass]
            if sub_end:
                fields += ", subscription_end=?"
                params.append(sub_end)
            params.append(tg_id)
            conn.execute(f"UPDATE users SET {fields} WHERE tg_id=?", params)
            if sub_end:
                conn.execute(
                    "INSERT INTO subscription_history "
                    "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                    (tg_id, "activate", 0, "", sub_end, "admin_link"),
                )
            conn.commit()

    # await вынесен за пределы with get_db()
    if error_text:
        await source.answer(error_text)
        return False

    key = make_naive_key(proxy_user, proxy_pass)
    sub_line = f"📅 Подписка до: <b>{sub_end}</b>\n" if sub_end else ""
    await source.answer(
        f"✅ <b>Клиент привязан!</b>\n\n"
        f"👤 Proxy: <code>{proxy_user}</code>\n"
        f"🆔 TG ID: <code>{tg_id}</code>\n"
        f"{sub_line}\n"
        f"🔑 Ключ:\n<code>{key}</code>",
        reply_markup=kb_admin()
    )
    if notify:
        fire_and_forget(send_key_with_qr(
            tg_id, key,
            f"✅ <b>Ваш аккаунт активирован!</b>\n\n"
            f"🔑 Ваш ключ NaiveProxy:\n<code>{key}</code>\n\n"
            f"Нажмите <b>⚡️ Мой ключ</b> в меню чтобы увидеть его в любой момент."
        ))
    return True


# ── Кнопка «🔄 Импорт с панели» ──────────────────────────────────────────────
@dp.message(F.text == "🔄 Импорт с панели")
@handle_errors()
async def admin_import_panel(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    await msg.answer("⏳ Загружаю список пользователей с панели...")

    panel_users = await panel.list_users()

    with get_db() as conn:
        bot_users = {
            r["proxy_user"] for r in
            conn.execute("SELECT proxy_user FROM users WHERE proxy_user IS NOT NULL").fetchall()
        }

    if panel_users:
        unlinked = [
            u for u in panel_users
            if u.get("username") and
               not u["username"].startswith("_test_") and
               not u["username"].startswith("trial_")
        ]
        # Из БД берём тех у кого нет реального TG ID (заглушки)
        with get_db() as conn:
            no_tgid_set = {
                r["proxy_user"] for r in conn.execute(
                    "SELECT proxy_user FROM users WHERE tg_id < 0 AND proxy_user IS NOT NULL"
                ).fetchall()
            }
            linked_set = {
                r["proxy_user"] for r in conn.execute(
                    "SELECT proxy_user FROM users WHERE tg_id > 0 AND proxy_user IS NOT NULL"
                ).fetchall()
            }

        need_link = [u for u in unlinked if u.get("username") in no_tgid_set]
        not_in_db = [u for u in unlinked if u.get("username") not in no_tgid_set and u.get("username") not in linked_set]

        lines = [f"📊 Всего на панели: <b>{len(panel_users)}</b> | Привязано: <b>{len(linked_set)}</b>\n"]
        if need_link:
            lines.append(f"⚠️ <b>Нужна привязка TG ID ({len(need_link)}):</b>")
            for u in need_link:
                lines.append(f"• <code>{u['username']}</code>")
        if not_in_db:
            lines.append(f"\n🆕 <b>Новые, не синхронизированы ({len(not_in_db)}):</b>")
            for u in not_in_db:
                lines.append(f"• <code>{u['username']}</code>")
        if not need_link and not not_in_db:
            lines.append("✅ Все пользователи панели привязаны к Telegram!")

        await send_long(msg, "\n".join(lines))
    else:
        await msg.answer(
            "⚠️ Не удалось получить список с панели или панель пуста.\n"
            f"<i>{safe_html(panel.last_error)}</i>"
        )

    await msg.answer(
        "➕ <b>Привязать клиента вручную</b>\n\n"
        "Нажмите кнопку ниже — бот пошагово спросит все данные.\n"
        "Ключ клиента <b>не изменится</b>.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="🔗 Привязать клиента", callback_data="link_start"),
        ]])
    )


# ── FSM: шаг 1 — старт ───────────────────────────────────────────────────────
@dp.callback_query(F.data == "link_start")
@handle_errors()
async def cb_link_start(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    await cb.answer()
    await state.set_state(LinkUserFSM.proxy_user)
    await cb.message.answer(
        "🔗 <b>Привязка клиента — шаг 1/4</b>\n\n"
        "Введите <b>логин</b> клиента (proxy_user).\n"
        "Это часть ключа между <code>//</code> и <code>:</code>\n\n"
        "Пример ключа:\n"
        "<code>naive+https://<b>wapmixx</b>:пароль@домен:443</code>",
        reply_markup=kb_cancel()
    )


# ── FSM: шаг 1 — получаем proxy_user ─────────────────────────────────────────
@dp.message(LinkUserFSM.proxy_user)
@handle_errors()
async def link_got_proxy_user(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    proxy_user = msg.text.strip()
    if not re.match(r'^[a-z0-9_\-\.]{1,32}$', proxy_user, re.IGNORECASE):
        return await msg.answer("❌ Логин может содержать только латиницу, цифры, _ и -. Попробуйте ещё раз.")

    # Пробуем автоматически найти пароль на панели
    panel_users = await panel.list_users()
    auto_pass = next(
        (u.get("password", "") for u in panel_users if u.get("username") == proxy_user), None
    )

    await state.update_data(proxy_user=proxy_user, auto_pass=auto_pass)
    await state.set_state(LinkUserFSM.proxy_pass)

    if auto_pass:
        await msg.answer(
            f"✅ Пользователь <code>{proxy_user}</code> найден на панели.\n\n"
            f"🔗 <b>Привязка клиента — шаг 2/4</b>\n\n"
            f"Пароль подтянут автоматически: <code>{auto_pass}</code>\n\n"
            f"Нажмите <b>Использовать</b> или введите пароль вручную:",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text=f"✅ Использовать: {auto_pass[:8]}...", callback_data="link_use_auto_pass"),
            ]])
        )
    else:
        await msg.answer(
            f"⚠️ <code>{proxy_user}</code> не найден на панели (или пароль недоступен).\n\n"
            f"🔗 <b>Привязка клиента — шаг 2/4</b>\n\n"
            f"Введите <b>пароль</b> клиента вручную.\n"
            f"Это часть ключа между <code>:</code> и <code>@</code>\n\n"
            f"Пример:\n<code>naive+https://логин:<b>пароль_здесь</b>@домен:443</code>",
            reply_markup=kb_cancel()
        )


@dp.callback_query(F.data == "link_use_auto_pass")
@handle_errors()
async def cb_link_use_auto_pass(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    data = await state.get_data()
    await state.update_data(proxy_pass=data["auto_pass"])
    await state.set_state(LinkUserFSM.tg_id)
    await cb.answer()
    await cb.message.answer(
        "🔗 <b>Привязка клиента — шаг 3/4</b>\n\n"
        "Введите <b>Telegram ID</b> клиента.\n\n"
        "Клиент может узнать свой ID через @userinfobot",
        reply_markup=kb_cancel()
    )


# ── FSM: шаг 2 — получаем пароль ─────────────────────────────────────────────
@dp.message(LinkUserFSM.proxy_pass)
@handle_errors()
async def link_got_proxy_pass(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    await state.update_data(proxy_pass=msg.text.strip())
    await state.set_state(LinkUserFSM.tg_id)
    await msg.answer(
        "🔗 <b>Привязка клиента — шаг 3/4</b>\n\n"
        "Введите <b>Telegram ID</b> клиента.\n\n"
        "Клиент может узнать свой ID через @userinfobot",
        reply_markup=kb_cancel()
    )


# ── FSM: шаг 3 — получаем tg_id ──────────────────────────────────────────────
@dp.message(LinkUserFSM.tg_id)
@handle_errors()
async def link_got_tg_id(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    if not msg.text.strip().isdigit():
        return await msg.answer("❌ Telegram ID — это число. Попробуйте ещё раз.")
    await state.update_data(tg_id=int(msg.text.strip()))
    await state.set_state(LinkUserFSM.sub_end)
    await msg.answer(
        "🔗 <b>Привязка клиента — шаг 4/4</b>\n\n"
        "Введите <b>дату окончания подписки</b> в формате <code>ГГГГ-ММ-ДД</code>\n"
        "Например: <code>2025-12-31</code>\n\n"
        "Или нажмите кнопку чтобы пропустить:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="⏭ Пропустить (без даты)", callback_data="link_skip_date"),
        ]])
    )


@dp.callback_query(F.data == "link_skip_date")
@handle_errors()
async def cb_link_skip_date(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id): return await cb.answer("⛔", show_alert=True)
    data = await state.get_data()
    await state.clear()
    await cb.answer()
    await _do_link_user(cb.message, data["proxy_user"], data["proxy_pass"], data["tg_id"], sub_end="")


# ── FSM: шаг 4 — получаем дату подписки ──────────────────────────────────────
@dp.message(LinkUserFSM.sub_end)
@handle_errors()
async def link_got_sub_end(msg: Message, state: FSMContext):
    if msg.text == "🏠 Главное меню": return await cmd_home(msg, state)
    raw = msg.text.strip()
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', raw):
        return await msg.answer("❌ Введите дату в формате <code>ГГГГ-ММ-ДД</code>, например <code>2025-12-31</code>")
    data = await state.get_data()
    await state.clear()
    await _do_link_user(msg, data["proxy_user"], data["proxy_pass"], data["tg_id"], sub_end=raw)


# ── Команда /link для быстрой привязки ───────────────────────────────────────
@dp.message(Command("link"))
@handle_errors()
async def cmd_link_user(msg: Message):
    """
    Быстрая привязка клиента командой.
    Варианты:
      /link proxy_user tg_id
      /link proxy_user tg_id пароль
      /link proxy_user tg_id пароль дата(ГГГГ-ММ-ДД)
    """
    if not is_admin(msg.from_user.id): return
    parts = msg.text.split(maxsplit=4)

    if len(parts) < 3 or not parts[2].strip().isdigit():
        return await msg.answer(
            "📌 <b>Использование:</b>\n\n"
            "<code>/link proxy_user tg_id</code> — пароль подтянется с панели\n"
            "<code>/link proxy_user tg_id пароль</code> — указать пароль вручную\n"
            "<code>/link proxy_user tg_id пароль 2025-12-31</code> — + дата подписки\n\n"
            "Пример:\n"
            "<code>/link wapmixx 5369333089</code>\n"
            "<code>/link wapmixx 5369333089 mypassword123</code>\n"
            "<code>/link wapmixx 5369333089 mypassword123 2025-12-31</code>"
        )

    proxy_user = parts[1].strip()
    tg_id      = int(parts[2].strip())
    proxy_pass = parts[3].strip() if len(parts) > 3 else None
    sub_end    = parts[4].strip() if len(parts) > 4 else ""

    # Если пароль не указан — тянем с панели
    if not proxy_pass:
        await msg.answer("⏳ Ищу пользователя на панели...")
        panel_users = await panel.list_users()
        proxy_pass = next(
            (u.get("password", "") for u in panel_users if u.get("username") == proxy_user), None
        )
        if not proxy_pass:
            return await msg.answer(
                f"❌ <code>{proxy_user}</code> не найден на панели.\n\n"
                f"Укажите пароль вручную:\n"
                f"<code>/link {proxy_user} {tg_id} ВАШ_ПАРОЛЬ</code>"
            )

    await _do_link_user(msg, proxy_user, proxy_pass, tg_id, sub_end=sub_end)

@dp.message(F.text == "📥 Экспорт платежей")
@handle_errors()
async def admin_csv_payments(msg: Message):
    if not is_admin(msg.from_user.id): return
    out = io.StringIO()
    w   = csv.writer(out)
    w.writerow(["ID", "TG ID", "Username", "Сумма", "Дней", "Статус", "Код", "Дата"])
    BATCH  = 500
    offset = 0
    total  = 0
    with get_db() as conn:
        while True:
            rows = conn.execute(
                "SELECT p.id, p.tg_id, u.username, p.amount, p.duration, p.status, "
                "p.payment_code, p.created_at "
                "FROM payments p LEFT JOIN users u ON p.tg_id=u.tg_id "
                "ORDER BY p.id DESC LIMIT ? OFFSET ?",
                (BATCH, offset),
            ).fetchall()
            if not rows:
                break
            for r in rows:
                w.writerow([r["id"], r["tg_id"], r["username"], r["amount"],
                            r["duration"], r["status"], r["payment_code"], r["created_at"]])
            total  += len(rows)
            offset += BATCH
            if len(rows) < BATCH:
                break
    fname = f"payments_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    await msg.answer_document(
        types.BufferedInputFile(out.getvalue().encode("utf-8-sig"), filename=fname),
        caption=f"📊 Экспорт: <b>{total}</b> платежей",
    )


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕКСТОВЫЙ ГРАФИК СТАТИСТИКИ
# ══════════════════════════════════════════════════════════════════════════════
@dp.message(F.text == "📈 График")
@handle_errors()
async def admin_chart(msg: Message):
    if not is_admin(msg.from_user.id): return
    # Используем МСК дату, а не UTC DATE('now').
    # created_at хранится в UTC → прибавляем смещение чтобы группировка была по МСК-дням.
    tz_today   = datetime.now(TZ).date()
    since_date = (tz_today - timedelta(days=7)).isoformat()
    tz_offset  = "+3 hours"  # Europe/Moscow UTC+3 (без перехода на летнее время)
    with get_db() as conn:
        rows_reg = conn.execute(f"""
            SELECT DATE(created_at, '{tz_offset}') as d, COUNT(*) as cnt
            FROM users WHERE DATE(created_at, '{tz_offset}') >= ?
            GROUP BY DATE(created_at, '{tz_offset}') ORDER BY d
        """, (since_date,)).fetchall()
        rows_pay = conn.execute(f"""
            SELECT DATE(created_at, '{tz_offset}') as d, COUNT(*) as cnt, COALESCE(SUM(amount),0) as total
            FROM payments WHERE status='approved' AND DATE(created_at, '{tz_offset}') >= ?
            GROUP BY DATE(created_at, '{tz_offset}') ORDER BY d
        """, (since_date,)).fetchall()

    def bar(val: int, max_val: int, width: int = 10) -> str:
        filled = round(val / max_val * width) if max_val else 0
        return "█" * filled + "░" * (width - filled)

    lines = ["📈 <b>График за 7 дней</b>\n"]
    lines.append("👤 <b>Регистрации:</b>")
    reg_map = {r["d"]: r["cnt"] for r in rows_reg}
    max_reg = max(reg_map.values(), default=1)
    for i in range(7):
        d   = (tz_today - timedelta(days=6-i)).isoformat()
        cnt = reg_map.get(d, 0)
        lines.append(f"  {d[5:]} {bar(cnt, max_reg)} {cnt}")

    lines.append("\n💰 <b>Оплаты:</b>")
    pay_map = {r["d"]: (r["cnt"], r["total"]) for r in rows_pay}
    max_pay = max((v[0] for v in pay_map.values()), default=1)
    total_week = 0
    for i in range(7):
        d   = (tz_today - timedelta(days=6-i)).isoformat()
        cnt, amt = pay_map.get(d, (0, 0))
        total_week += amt
        lines.append(f"  {d[5:]} {bar(cnt, max_pay)} {cnt} шт. / {amt} ₽")

    lines.append(f"\n💵 Итого за 7 дней: <b>{total_week} ₽</b>")
    await send_long(msg, "\n".join(lines))


# ══════════════════════════════════════════════════════════════════════════════
#  НЕЗАРЕГИСТРИРОВАННЫЕ СООБЩЕНИЯ (fallback)
# ══════════════════════════════════════════════════════════════════════════════
@dp.message()
@handle_errors()
async def fallback_handler(msg: Message, state: FSMContext):
    tg_id = msg.from_user.id
    if is_banned(tg_id): return
    if get_setting("maintenance") == "1" and not is_admin(tg_id):
        return await msg.answer("🔧 Бот на техническом обслуживании.")

    # Для администратора проверяем — вдруг застрял в FSM
    if is_admin(tg_id):
        current = await state.get_state()
        if current:
            await state.clear()
            return await msg.answer(
                "⚠️ Предыдущий диалог отменён. Используйте кнопки меню.",
                reply_markup=kb_admin(),
            )
        return  # не в FSM — просто игнорируем

    await msg.answer(
        "🤷 Не понял команду.\n\n"
        "Используйте кнопки меню или:\n"
        "/start — главное меню\n"
        "/profile — ваш профиль\n"
        "/promo КОД — ввести промокод\n"
        "/help — справка",
        reply_markup=kb_main(False),
    )

# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP / SHUTDOWN
# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
#  АВТОСИНХРОНИЗАЦИЯ КЛИЕНТОВ С ПАНЕЛИ
# ══════════════════════════════════════════════════════════════════════════════
async def sync_panel_users(notify_admin: bool = False):
    """
    Синхронизирует пользователей панели с базой данных бота.
    Защищён sync_lock — нельзя запустить параллельно (scheduler + ручной /sync_users).
    """
    if sync_lock.locked():
        logger.warning("sync_panel_users: уже выполняется, пропускаем")
        return

    async with sync_lock:
        logger.info("🔄 Синхронизация пользователей с панели...")
        panel_users = await panel.list_users()

        # Фикс 1.2: проверяем что получили именно список, а не None/dict
        if not isinstance(panel_users, list):
            logger.error(f"sync_panel_users: panel.list_users() вернул {type(panel_users)}, ожидался list — прерываем")
            return
        if not panel_users:
            logger.warning("sync_panel_users: панель вернула пустой список — прерываем")
            return

        activated = created = skipped = removed = 0

        panel_set = {
            (pu.get("username") or pu.get("name", ""))
            for pu in panel_users
            if (pu.get("username") or pu.get("name", ""))
            and not (pu.get("username") or pu.get("name", "")).startswith(("_test_", "trial_"))
        }

        with get_db() as conn:
            db_map = {
                r["proxy_user"]: r["tg_id"]
                for r in conn.execute(
                    "SELECT proxy_user, tg_id FROM users WHERE proxy_user IS NOT NULL"
                ).fetchall()
            }

            min_id_row   = conn.execute("SELECT COALESCE(MIN(tg_id), 0) FROM users").fetchone()
            next_fake_id = min_id_row[0] - 1

            # Шаг 1: bulk update/insert через executemany (фикс 3.1)
            to_update = []
            to_insert = []
            for pu in panel_users:
                username = pu.get("username") or pu.get("name", "")
                password = pu.get("password", "")
                if not username:
                    continue
                if username.startswith(("_test_", "trial_")):
                    skipped += 1
                    continue
                if username in db_map:
                    to_update.append((password, username))
                    activated += 1
                else:
                    to_insert.append((
                        next_fake_id, username, password,
                        gen_ref_code(abs(next_fake_id))
                    ))
                    next_fake_id -= 1
                    created += 1

            if to_update:
                conn.executemany(
                    "UPDATE users SET proxy_pass=? WHERE proxy_user=?", to_update
                )
            if to_insert:
                conn.executemany(
                    "INSERT OR IGNORE INTO users "
                    "(tg_id, proxy_user, proxy_pass, is_active, referral_code) "
                    "VALUES (?,?,?,1,?)",
                    to_insert,
                )

            # Шаг 2: деактивируем тех кого нет на панели
            # Фикс 1.1: сразу материализуем как dict чтобы не было lazy-ссылок
            active_in_db = [
                dict(r) for r in conn.execute(
                    "SELECT tg_id, proxy_user, subscription_end FROM users "
                    "WHERE is_active=1 AND proxy_user IS NOT NULL AND tg_id > 0"
                ).fetchall()
            ]

            deactivate_ids = [
                u["tg_id"] for u in active_in_db
                if u["proxy_user"] not in panel_set
            ]

            if deactivate_ids:
                conn.executemany(
                    "UPDATE users SET is_active=0, proxy_user=NULL, proxy_pass=NULL, "
                    "subscription_end=NULL, notified_1d=0, notified_3d=0, "
                    "notified_7d=0, notified_remind=0 WHERE tg_id=?",
                    [(tid,) for tid in deactivate_ids],
                )
                history_rows = [
                    (u["tg_id"], "expire", 0, u["subscription_end"] or "", "", "panel_removed")
                    for u in active_in_db if u["tg_id"] in set(deactivate_ids)
                ]
                conn.executemany(
                    "INSERT INTO subscription_history "
                    "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                    history_rows,
                )
                removed = len(deactivate_ids)

            conn.commit()

        logger.info(
            f"✅ sync_panel_users: обновлено={activated}, "
            f"создано={created}, пропущено={skipped}, деактивировано={removed}"
        )

        # Уведомления — после закрытия коннекта
        deactivated_users = [u for u in active_in_db if u["tg_id"] in set(deactivate_ids if deactivate_ids else [])]
        for u in deactivated_users:
            await safe_send(
                u["tg_id"],
                "⚠️ <b>Ваш аккаунт был удалён с сервера.</b>\n"
                "Обратитесь в поддержку или оформите новую подписку.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(text="💬 Поддержка", callback_data="support"),
                    InlineKeyboardButton(text="🛍 Магазин",   callback_data="go_buy"),
                ]])
            )

        if notify_admin and (activated or created or removed):
            lines = ["🔄 <b>Синхронизация с панелью завершена</b>\n"]
            if activated: lines.append(f"✅ Обновлено: <b>{activated}</b>")
            if created:   lines.append(f"📋 Новых заглушек: <b>{created}</b> → /link")
            if removed:   lines.append(f"🔴 Деактивировано: <b>{removed}</b>")
            for admin_id in ({ADMIN_ID} | EXTRA_ADMINS):
                await safe_send(admin_id, "\n".join(lines))


# ── Ручной запуск синхронизации ───────────────────────────────────────────────
_last_sync_time: float = 0.0
SYNC_COOLDOWN_SEC = 120  # минимум 2 минуты между ручными синхронизациями

@dp.message(Command("sync_users"))
@handle_errors()
async def cmd_sync_users(msg: Message):
    """Ручная синхронизация пользователей с панели."""
    if not is_admin(msg.from_user.id): return
    global _last_sync_time
    elapsed = time.time() - _last_sync_time
    if sync_lock.locked():
        return await msg.answer("⏳ Синхронизация уже выполняется, подождите.")
    if elapsed < SYNC_COOLDOWN_SEC:
        wait = int(SYNC_COOLDOWN_SEC - elapsed)
        return await msg.answer(f"⏳ Следующая синхронизация доступна через <b>{wait} сек.</b>")
    _last_sync_time = time.time()
    await msg.answer("🔄 Синхронизирую пользователей с панелью...")
    await sync_panel_users(notify_admin=False)

    # Показываем итог
    with get_db() as conn:
        total   = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active  = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
        no_tgid = conn.execute(
            "SELECT COUNT(*) FROM users WHERE is_active=1 AND tg_id < 0"
        ).fetchone()[0]

    text = (
        f"✅ <b>Синхронизация завершена</b>\n\n"
        f"👥 Всего в БД: <b>{total}</b>\n"
        f"🟢 Активных: <b>{active}</b>\n"
    )
    if no_tgid:
        text += (
            f"⚠️ Без Telegram ID: <b>{no_tgid}</b>\n"
            f"Привяжите их через <b>🔄 Импорт с панели</b>"
        )
    await msg.answer(text, reply_markup=kb_admin())


@dp.message(Command("sync_check"))
@handle_errors()
async def cmd_sync_check(msg: Message):
    """
    /sync_check — сверка + немедленная деактивация расхождений.
    /check_panel — только показать расхождения без изменений.
    """
    if not is_admin(msg.from_user.id): return
    if sync_lock.locked():
        return await msg.answer("⏳ Синхронизация уже выполняется, подождите.")
    await msg.answer("🔍 Сверяю базу данных с панелью и деактивирую расхождения...")
    await sync_panel_users(notify_admin=False)
    with get_db() as conn:
        active = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1 AND tg_id > 0").fetchone()[0]
    await msg.answer(
        f"✅ <b>Сверка завершена.</b>\n"
        f"🟢 Активных в БД после сверки: <b>{active}</b>\n\n"
        f"Для просмотра расхождений без изменений: /check_panel",
        reply_markup=kb_admin()
    )


@dp.message(Command("check_user"))
@handle_errors()
async def cmd_check_user(msg: Message):
    """
    Мгновенная проверка конкретного пользователя по панели.
    Использование: /check_user TELEGRAM_ID
    Если пользователь отсутствует на панели — деактивирует его в БД.
    """
    if not is_admin(msg.from_user.id): return
    parts = msg.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip().lstrip("-").isdigit():
        return await msg.answer(
            "Использование: /check_user <code>TELEGRAM_ID</code>\n"
            "Проверяет есть ли пользователь на панели и деактивирует если нет."
        )
    tg_id = int(parts[1].strip())
    with get_db() as conn:
        u = conn.execute(
            "SELECT tg_id, proxy_user, proxy_pass, is_active, subscription_end FROM users WHERE tg_id=?",
            (tg_id,)
        ).fetchone()
    if not u:
        return await msg.answer(f"❌ Пользователь <code>{tg_id}</code> не найден в БД.")
    if not u["proxy_user"]:
        return await msg.answer(
            f"ℹ️ У пользователя <code>{tg_id}</code> нет proxy_user — не активирован."
        )

    await msg.answer(f"🔍 Проверяю <code>{u['proxy_user']}</code> на панели...")
    panel_users = await panel.list_users()
    panel_names = {(pu.get("username") or pu.get("name", "")) for pu in panel_users}

    if u["proxy_user"] in panel_names:
        status = "🟢 активен" if u["is_active"] else "🔴 неактивен (в БД)"
        return await msg.answer(
            f"✅ <code>{u['proxy_user']}</code> <b>найден на панели</b>.\n"
            f"Статус в БД: {status}"
        )

    # Не найден на панели
    if u["is_active"]:
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET is_active=0, proxy_user=NULL, proxy_pass=NULL, "
                "subscription_end=NULL, notified_1d=0, notified_3d=0, "
                "notified_7d=0, notified_remind=0 WHERE tg_id=?",
                (tg_id,),
            )
            conn.execute(
                "INSERT INTO subscription_history "
                "(tg_id, action, days, old_end, new_end, source) VALUES (?,?,?,?,?,?)",
                (tg_id, "expire", 0, u["subscription_end"] or "", "", "panel_removed_manual"),
            )
            conn.commit()
        await safe_send(
            tg_id,
            "⚠️ <b>Ваш аккаунт был удалён с сервера.</b>\n"
            "Обратитесь в поддержку или оформите новую подписку."
        )
        await msg.answer(
            f"🔴 <code>{u['proxy_user']}</code> <b>не найден на панели</b>.\n"
            f"Пользователь <code>{tg_id}</code> деактивирован в БД и уведомлён.",
            reply_markup=kb_admin()
        )
    else:
        await msg.answer(
            f"ℹ️ <code>{u['proxy_user']}</code> не найден на панели,\n"
            f"но пользователь <code>{tg_id}</code> уже неактивен в БД — всё в порядке.",
            reply_markup=kb_admin()
        )


async def on_startup():
    await init_db()
    await panel.login()

    # Загружаем дополнительных администраторов из БД
    try:
        with get_db() as conn:
            rows = conn.execute("SELECT tg_id FROM admins").fetchall()
            for r in rows:
                EXTRA_ADMINS.add(r["tg_id"])
        logger.info(f"👮 Загружено доп. администраторов: {len(EXTRA_ADMINS)}")
    except Exception as e:
        logger.warning(f"Ошибка загрузки администраторов: {e}")

    # Кнопка меню с командами
    try:
        from aiogram.types import BotCommand, BotCommandScopeDefault, MenuButtonCommands
        await bot.set_my_commands([
            BotCommand(command="start",       description="🏠 Главное меню"),
            BotCommand(command="profile",     description="👤 Мой профиль"),
            BotCommand(command="promo",       description="🎟 Ввести промокод"),
            BotCommand(command="subhistory",  description="🧾 История подписки"),
            BotCommand(command="check_panel", description="🔍 Расхождения БД/панель — только просмотр (admin)"),
            BotCommand(command="sync_check",  description="🔄 Сверка + деактивация расхождений (admin)"),
            BotCommand(command="sync_users",  description="🔄 Синхронизация с панелью (admin)"),
            BotCommand(command="help",        description="❓ Помощь"),
        ], scope=BotCommandScopeDefault())
        await bot.set_chat_menu_button(menu_button=MenuButtonCommands())
        logger.info("✅ Кнопка меню установлена")
    except Exception as e:
        logger.warning(f"Не удалось установить кнопку меню: {e}")

    # Планировщик задач
    # max_instances=1  — одновременно только одна копия задачи
    # coalesce=True    — если бот лежал и пропустил N запусков, запустить ровно 1 раз
    # misfire_grace_time=300 — задача считается пропущенной если опоздала >5 минут
    JOB_DEFAULTS = dict(max_instances=1, coalesce=True, misfire_grace_time=300)
    scheduler.add_job(check_expiring,          IntervalTrigger(hours=6),           **JOB_DEFAULTS)
    scheduler.add_job(check_trials,            IntervalTrigger(minutes=30),         **JOB_DEFAULTS)
    scheduler.add_job(sync_traffic,            IntervalTrigger(hours=2),            **JOB_DEFAULTS)
    scheduler.add_job(sync_panel_users,        IntervalTrigger(hours=6),            **JOB_DEFAULTS)
    scheduler.add_job(recover_stuck_payments,  IntervalTrigger(hours=1),            **JOB_DEFAULTS)
    scheduler.add_job(remind_pending_payments, IntervalTrigger(hours=1),            **JOB_DEFAULTS)
    scheduler.add_job(panel_health_check,      IntervalTrigger(minutes=10),         **JOB_DEFAULTS)
    scheduler.add_job(cleanup_stale_fsm,       IntervalTrigger(minutes=30),         **JOB_DEFAULTS)
    scheduler.add_job(daily_backup,            CronTrigger(hour=3,  minute=0, timezone=TIMEZONE), **JOB_DEFAULTS)
    scheduler.add_job(daily_report,            CronTrigger(hour=9,  minute=0, timezone=TIMEZONE), **JOB_DEFAULTS)
    scheduler.start()
    logger.info("🚀 NaiveProxy Bot v3 запущен")
    for _aid in ({ADMIN_ID} | EXTRA_ADMINS):
        fire_and_forget(safe_send(_aid, "🚀 <b>Бот запущен и готов к работе!</b>"))
    # Синхронизация с панелью при старте
    fire_and_forget(sync_panel_users(notify_admin=True))


async def on_shutdown():
    logger.info("⏹ Остановка...")
    scheduler.shutdown(wait=True)
    if _background_tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*_background_tasks, return_exceptions=True), timeout=10
            )
        except asyncio.TimeoutError:
            pass
    await panel.aclose()
    await bot.session.close()
    logger.info("✅ Бот остановлен")


async def main():
    await on_startup()
    try:
        await dp.start_polling(bot, skip_updates=True)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.exception(f"Критическая ошибка: {e}")
    finally:
        await on_shutdown()


if __name__ == "__main__":
    asyncio.run(main())