"""
Telegram-бот для выдачи конфигов AmneziaWG (сервер Amnezia в Docker, AWG 2.0).

Пользователь: заявка -> одобрение админом -> свои устройства (ПК, телефон...)
с конфигами в трёх форматах, инструкции и статус (rich-сообщения).
Админ: панель с пользователями, заявками, конфигами из приложения и дашбордом.
"""
import asyncio
import functools
import base64
import gzip
import html
import io
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import struct
import subprocess
import time
import urllib.request
import zlib
from datetime import date, datetime

import maxminddb
import qrcode
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (BufferedInputFile, CallbackQuery, InlineKeyboardButton,
                           InlineKeyboardMarkup, InputRichMessage, Message)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = {int(x) for x in os.environ["ADMIN_IDS"].split(",") if x.strip()}
VPN_HOST = os.environ["VPN_HOST"]
SERVER_NAME = os.getenv("SERVER_NAME", "").strip() or "vpn"   # имя сервера в AmneziaVPN
CONTAINER = os.getenv("CONTAINER", "amnezia-awg2")
CONF_DIR = os.getenv("CONF_DIR", "/opt/amnezia/awg")
IFACE = os.getenv("IFACE", "awg0")
WG_BIN = os.getenv("WG_BIN", "awg")
WG_QUICK_BIN = os.getenv("WG_QUICK_BIN", "awg-quick")
DNS1 = os.getenv("DNS1", "1.1.1.1")
DNS2 = os.getenv("DNS2", "1.0.0.1")
MTU = os.getenv("MTU", "1280")
KEEPALIVE = os.getenv("KEEPALIVE", "")          # пусто = как в приложении (25-35 для AWG 2)
MAX_DEVICES = int(os.getenv("MAX_DEVICES", "5"))
DB_PATH = os.getenv("DB_PATH", "bot.db")
# локальная база стран по IP (DB-IP Lite, CC BY 4.0, https://db-ip.com) — бот скачивает сам
GEOIP_DB = os.getenv("GEOIP_DB") or os.path.join(os.path.dirname(os.path.abspath(DB_PATH)),
                                                 "dbip-country-lite.mmdb")

ANDROID_URL = "https://play.google.com/store/apps/details?id=org.amnezia.vpn"
IOS_URL = "https://apps.apple.com/app/defaultvpn/id6744725017"
DESKTOP_URL = "https://github.com/amnezia-vpn/amnezia-client/releases/latest"
DESKTOP_SITE_URL = "https://amnezia.org/ru/downloads"

SERVER_CONF = f"{CONF_DIR}/{IFACE}.conf"
# параметры [Interface] сервера, которые НЕ переносятся в конфиг клиента
SERVER_ONLY = {"address", "listenport", "privatekey", "postup", "postdown", "preup",
               "predown", "saveconfig", "table", "mtu", "dns", "fwmark"}
ONLINE_SEC = 180

log = logging.getLogger("amnezia-bot")
wg_lock = asyncio.Lock()


# ================================================================ docker ===

def dexec(cmd: str, stdin: str | None = None) -> str:
    r = subprocess.run(["docker", "exec", "-i", CONTAINER, "sh", "-c", cmd],
                       input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"docker exec failed: {cmd}\n{r.stderr.strip()}")
    return r.stdout


def read_file(path: str, default: str | None = None) -> str:
    try:
        return dexec(f"cat '{path}'")
    except RuntimeError:
        if default is not None:
            return default
        raise


def write_file(path: str, content: str) -> None:
    dexec(f"cat > '{path}'", stdin=content)


def sync_wg() -> None:
    dexec(f"{WG_QUICK_BIN} strip '{SERVER_CONF}' > /tmp/bot_strip.conf && "
          f"{WG_BIN} syncconf {IFACE} /tmp/bot_strip.conf && rm -f /tmp/bot_strip.conf")


# ============================================================= wireguard ===

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def gen_keypair() -> tuple[str, str]:
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64(priv), b64(pub)


def pub_from_priv(priv: str) -> str:
    k = X25519PrivateKey.from_private_bytes(base64.b64decode(priv))
    return b64(k.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw))


def split_sections(text: str) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = [("", [])]
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            sections.append((s.lower(), [line]))
        else:
            sections[-1][1].append(line)
    return sections


def section_kv(lines: list[str]) -> dict[str, str]:
    kv = {}
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s and not s.startswith("["):
            k, v = s.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def server_info() -> dict:
    text = read_file(SERVER_CONF)
    iface, used_ips = {}, set()
    for name, lines in split_sections(text):
        kv = section_kv(lines)
        if name == "[interface]":
            iface = kv
        elif name == "[peer]" and "AllowedIPs" in kv:
            for ip in kv["AllowedIPs"].split(","):
                used_ips.add(ip.strip().split("/")[0])

    spub = read_file(f"{CONF_DIR}/wireguard_server_public_key.key", "").strip()
    if not spub:
        spub = pub_from_priv(iface["PrivateKey"])
    psk = read_file(f"{CONF_DIR}/wireguard_psk.key", "").strip()
    params = {k: v for k, v in iface.items() if k.lower() not in SERVER_ONLY}
    awg2 = "HeaderProtectionKey" in params or "S3" in params

    return {
        "text": text,
        "address": iface["Address"].split(",")[0].strip(),
        "port": iface["ListenPort"],
        "obf": params,                 # всё, что клиент должен знать (Jc, S1.., H1.., ...)
        "awg2": awg2,
        "keepalive": KEEPALIVE or ("25-35" if awg2 else "25"),
        "server_pub": spub,
        "psk": psk,
        "used_ips": used_ips,
    }


def next_free_ip(info: dict) -> str:
    net = ipaddress.ip_interface(info["address"]).network
    taken = set(info["used_ips"]) | {info["address"].split("/")[0]}
    for i, host in enumerate(net.hosts()):
        if i == 0:
            continue
        if str(host) not in taken:
            return str(host)
    raise RuntimeError("В подсети закончились адреса")


def read_clients_table() -> list:
    try:
        return json.loads(read_file(f"{CONF_DIR}/clientsTable", "[]") or "[]")
    except json.JSONDecodeError:
        return []


def add_peer(name: str) -> dict:
    info = server_info()
    priv, pub = gen_keypair()
    psk = info["psk"] or b64(os.urandom(32))
    ip = next_free_ip(info)

    text = info["text"].rstrip("\n") + (
        f"\n\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {ip}/32\n")
    write_file(SERVER_CONF, text)
    sync_wg()

    table = read_clients_table()
    table.append({"clientId": pub, "userData": {
        "clientName": name, "creationDate": datetime.now().strftime("%a %b %d %H:%M:%S %Y")}})
    write_file(f"{CONF_DIR}/clientsTable", json.dumps(table, indent=4, ensure_ascii=False))
    return {"priv": priv, "pub": pub, "psk": psk, "ip": ip}


def remove_peer(pub: str) -> None:
    info = server_info()
    out = []
    for name, lines in split_sections(info["text"]):
        if name == "[peer]" and section_kv(lines).get("PublicKey") == pub:
            continue
        out.extend(lines)
    write_file(SERVER_CONF, "\n".join(out).rstrip("\n") + "\n")
    sync_wg()
    table = [c for c in read_clients_table() if c.get("clientId") != pub]
    write_file(f"{CONF_DIR}/clientsTable", json.dumps(table, indent=4, ensure_ascii=False))


def server_peers() -> list[dict]:
    """Все клиенты сервера с именами из clientsTable (как в приложении AmneziaVPN)."""
    info = server_info()
    names = {c.get("clientId"): (c.get("userData") or {}).get("clientName", "")
             for c in read_clients_table()}
    peers = []
    for name, lines in split_sections(info["text"]):
        if name != "[peer]":
            continue
        kv = section_kv(lines)
        if kv.get("PublicKey"):
            ip = kv.get("AllowedIPs", "").split(",")[0].split("/")[0].strip()
            peers.append({"pub": kv["PublicKey"], "ip": ip,
                          "name": names.get(kv["PublicKey"]) or "без имени"})
    return peers


def peer_stats() -> dict[str, dict]:
    """pub -> {hs: unix-время последнего handshake, rx, tx}"""
    stats = {}
    try:
        out = dexec(f"{WG_BIN} show {IFACE} dump")
    except RuntimeError:
        return stats
    for line in out.splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 7:
            stats[p[0]] = {"hs": int(p[4] or 0), "rx": int(p[5] or 0), "tx": int(p[6] or 0)}
    return stats


# =============================================================== форматы ===

def client_conf(c, info: dict, dns: str | None = None) -> str:
    params = "".join(f"{k} = {v}\n" for k, v in info["obf"].items())
    return (
        "[Interface]\n"
        f"Address = {c['ip']}/32\n"
        f"DNS = {dns or f'{DNS1}, {DNS2}'}\n"
        f"PrivateKey = {c['priv']}\n"
        f"{params}\n"
        "[Peer]\n"
        f"PublicKey = {info['server_pub']}\n"
        f"PresharedKey = {c['psk']}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {VPN_HOST}:{info['port']}\n"
        f"PersistentKeepalive = {info['keepalive']}\n"
    )


def amnezia_key(c, info: dict) -> str:
    """Ключ vpn:// в том же формате, что «Поделиться» в AmneziaVPN."""
    obf = info["obf"]
    last_config = {
        **obf,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "clientId": c["pub"],
        "client_ip": c["ip"],
        "client_priv_key": c["priv"],
        "client_pub_key": c["pub"],
        "config": client_conf(c, info, dns="$PRIMARY_DNS, $SECONDARY_DNS"),
        "hostName": VPN_HOST,
        "mtu": MTU,
        "persistent_keep_alive": info["keepalive"],
        "port": int(info["port"]),
        "psk_key": c["psk"],
        "server_pub_key": info["server_pub"],
    }
    awg = {**obf,
           "last_config": json.dumps(last_config, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False),
           "port": str(info["port"]),
           "subnet_address": str(ipaddress.ip_interface(info["address"]).network.network_address),
           "transport_proto": "udp"}
    if info["awg2"]:
        for k in ("I1", "I2", "I3", "I4", "I5"):
            awg.setdefault(k, "")
        awg["protocol_version"] = os.getenv("AWG_PROTOCOL_VERSION", "3.1")
    data = {
        "containers": [{"awg": awg, "container": CONTAINER}],
        "defaultContainer": CONTAINER,
        "description": SERVER_NAME,
        "dns1": DNS1,
        "dns2": DNS2,
        "format_version": 1,
        "hostName": VPN_HOST,
    }
    raw = json.dumps(data, indent=4, sort_keys=True, ensure_ascii=False).encode()
    packed = struct.pack(">I", len(raw)) + zlib.compress(raw, 8)
    return "vpn://" + base64.urlsafe_b64encode(packed).decode().rstrip("=")


def qr_png(data: str) -> bytes:
    img = qrcode.make(data, error_correction=qrcode.constants.ERROR_CORRECT_L, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ==================================================================== БД ===

db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row


def init_db():
    cols = [r[1] for r in db.execute("PRAGMA table_info(users)")]
    db.execute("""CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, name TEXT,
        ip TEXT, priv TEXT, pub TEXT, psk TEXT, created TEXT)""")
    if "pub" in cols:   # миграция со старой версии (один конфиг на человека)
        db.execute("""INSERT INTO devices (chat_id, name, ip, priv, pub, psk, created)
                      SELECT chat_id, 'Устройство 1', ip, priv, pub, psk, created
                      FROM users WHERE pub IS NOT NULL""")
        db.execute("ALTER TABLE users RENAME TO users_old")
        db.execute("""CREATE TABLE users (chat_id INTEGER PRIMARY KEY, username TEXT,
                      name TEXT, status TEXT, created TEXT)""")
        db.execute("INSERT INTO users SELECT chat_id, username, name, status, created FROM users_old")
        db.execute("DROP TABLE users_old")
    db.execute("""CREATE TABLE IF NOT EXISTS users (chat_id INTEGER PRIMARY KEY,
                  username TEXT, name TEXT, status TEXT, created TEXT)""")
    # личный лимит устройств (NULL = общий MAX_DEVICES)
    if "max_devices" not in [r[1] for r in db.execute("PRAGMA table_info(users)")]:
        db.execute("ALTER TABLE users ADD COLUMN max_devices INTEGER")
    db.commit()


init_db()


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def get_user(chat_id: int):
    return db.execute("SELECT * FROM users WHERE chat_id=?", (chat_id,)).fetchone()


def set_user(chat_id: int, **fields):
    if get_user(chat_id) is None:
        db.execute("INSERT INTO users (chat_id, created) VALUES (?, ?)", (chat_id, now()))
    for k, v in fields.items():
        db.execute(f"UPDATE users SET {k}=? WHERE chat_id=?", (v, chat_id))
    db.commit()


def user_devices(chat_id: int):
    return db.execute("SELECT * FROM devices WHERE chat_id=? ORDER BY id", (chat_id,)).fetchall()


def get_device(dev_id: int):
    return db.execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()


def bot_pubs() -> set[str]:
    return {r["pub"] for r in db.execute("SELECT pub FROM devices")}


# =============================================================== утилиты ===

TRANSLIT = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
    ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p", "r",
     "s", "t", "u", "f", "h", "c", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya"]))


def file_name(device: str) -> str:
    """Имя туннеля: латиница, до 15 символов (иначе WireGuard на Windows не импортирует)."""
    s = "".join(TRANSLIT.get(ch, ch) for ch in device.lower())
    s = "".join(ch if ch.isascii() and (ch.isalnum() or ch in "_-.") else "_" for ch in s)
    return (s.strip("_") or "vpn")[:15]


def esc(t) -> str:
    return html.escape(str(t or ""), quote=False)


def owner_label(u) -> str:
    return f"@{u['username']}" if u["username"] else str(u["chat_id"])


def fmt_bytes(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit in ("Б", "КБ") else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def fmt_seen(hs: int) -> str:
    if not hs:
        return "не подключался"
    ago = int(time.time()) - hs
    if ago < ONLINE_SEC:
        return "в сети"
    if ago < 3600:
        return f"{ago // 60} мин назад"
    if ago < 86400:
        return f"{ago // 3600} ч назад"
    return f"{ago // 86400} дн назад"


def is_online(st: dict | None) -> bool:
    return bool(st and st["hs"] and time.time() - st["hs"] < ONLINE_SEC)


def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS


def has_access(uid: int) -> bool:
    if is_admin(uid):
        return True
    u = get_user(uid)
    return bool(u and u["status"] == "approved")


def device_limit(uid: int) -> int | None:
    """Лимит устройств: личный, если задан, иначе MAX_DEVICES; у админов — без лимита (None)."""
    if is_admin(uid):
        return None
    u = get_user(uid)
    return u["max_devices"] if u and u["max_devices"] is not None else MAX_DEVICES


def own_device(uid: int, dev_id: int):
    d = get_device(dev_id)
    return d if d and (d["chat_id"] == uid or is_admin(uid)) else None


# ============================================================ оформление ===
# Кастомные эмодзи (пак Telegram iOS Icons, t.me/addemoji/tgiosicons).
# Работают, если у владельца бота Telegram Premium. Без Premium Telegram
# отклоняет их — тогда бот сам переключается на обычные эмодзи.

CUSTOM_EMOJI = os.getenv("CUSTOM_EMOJI", "1").strip().lower() not in ("0", "false", "no", "off")

EMOJI = {   # имя: (обычный эмодзи, id кастомного)
    "vpn": ("🛡", "6030445631921721471"),       "home": ("🏠", "6042137469204303531"),
    "devices": ("🗂", "5766994197705921104"),   "device": ("🔳", "5771652845652677093"),
    "add": ("➕", "5882207227997066107"),       "help": ("ℹ️", "6028435952299413210"),
    "status": ("📊", "5936143551854285132"),    "admin": ("👑", "5805553606635559688"),
    "users": ("👥", "6032609071373226027"),     "user": ("👤", "6035084557378654059"),
    "pending": ("⏳", "5891211339170326418"),   "app": ("📦", "5778672437122045013"),
    "denied": ("🚫", "5938215362473496448"),    "back": ("⬅️", "5960671702059848143"),
    "key": ("🔑", "5776078972659962594"),       "qr": ("📷", "5766975922620076409"),
    "file": ("📄", "6050643982646513651"),      "trash": ("🗑", "6039522349517115015"),
    "android": ("🤖", "6030400221232501136"),   "apple": ("🍏", "5775870512127283512"),
    "download": ("⬇️", "6039802767931871481"),  "ok": ("✅", "5774022692642492953"),
    "no": ("❌", "5774077015388852135"),        "edit": ("✏️", "6039779802741739617"),
    "refresh": ("🔁", "6030657343744644592"),   "send": ("⬆️", "6039391666547201160"),
    "hello": ("👋", "6041921818896372382"),     "party": ("🎉", "6041731551845159060"),
    "warn": ("❗️", "6030563507299160824"),      "globe": ("🌐", "5776233299424843260"),
    "lock": ("🔒", "6037249452824072506"),      "calendar": ("📅", "5890937706803894250"),
    "traffic": ("📈", "5938539885907415367"),   "pin": ("📍", "6042011682497106307"),
    "reset": ("↩️", "5778432163766604235"),     "restore": ("👤", "5891207662678317861"),
    "revoke": ("👤", "5893192487324880883"),    "again": ("🔁", "6030657343744644592"),
    "clock": ("⏰", "5983150113483134607"),      "question": ("❓", "6030848053177486888"),
    "sad": ("☹️", "6042029429301973188"),       "idea": ("💡", "5891120964468480450"),
    "bell": ("🔔", "6039486778597970865"),      "link": ("🔗", "6028171274939797252"),
    "windows": ("🪟", "5366318141771096216"),   "linux": ("🐧", "5208428250547633632"),
    "online": ("🟢", "5330533835765462529"),    "offline": ("⚪️", "5330203192003146212"),
    "error": ("🔴", "5974083768233760323"),
}
EMOJI_BY_ID = {cid: plain for plain, cid in EMOJI.values() if cid}


def em(name: str) -> str:
    """Эмодзи для текста сообщения: кастомный (tg-emoji) или обычный."""
    plain, cid = EMOJI[name]
    return f'<tg-emoji emoji-id="{cid}">{plain}</tg-emoji>' if CUSTOM_EMOJI and cid else plain


def btn(text: str, data: str | None = None, url: str | None = None, style: str | None = None,
        icon: str | None = None):
    """Кнопка; icon — имя из EMOJI (кастомная иконка или обычный эмодзи перед текстом)."""
    kw = {"text": text}
    if icon:
        plain, cid = EMOJI[icon]
        if CUSTOM_EMOJI and cid:
            kw["icon_custom_emoji_id"] = cid
        else:
            kw["text"] = f"{plain} {text}"
    if url:
        kw["url"] = url
    else:
        kw["callback_data"] = data
    if style:
        kw["style"] = style
    try:
        return InlineKeyboardButton(**kw)
    except Exception:          # старые клиенты/версии без style
        kw.pop("style", None)
        return InlineKeyboardButton(**kw)


def kb(*rows) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[list(r) for r in rows if r])


def strip_custom(text: str, markup: InlineKeyboardMarkup | None):
    """Убрать кастомные эмодзи из текста и кнопок (оставить обычные)."""
    text = re.sub(r'<tg-emoji emoji-id="\d+">(.*?)</tg-emoji>', r"\1", text or "", flags=re.S)
    if markup:
        rows = []
        for row in markup.inline_keyboard:
            new = []
            for b in row:
                if b.icon_custom_emoji_id:
                    plain = EMOJI_BY_ID.get(b.icon_custom_emoji_id, "")
                    b = b.model_copy(update={"icon_custom_emoji_id": None,
                                             "text": f"{plain} {b.text}".strip()})
                new.append(b)
            rows.append(new)
        markup = InlineKeyboardMarkup(inline_keyboard=rows)
    return text, markup


def emoji_error(e: Exception) -> bool:
    s = str(e).upper()
    return "EMOJI" in s or "ICON" in s or "PREMIUM" in s


async def with_emoji_fallback(call, text: str, markup):
    """call(text, markup); если Telegram не принял кастомные эмодзи — повтор без них."""
    global CUSTOM_EMOJI
    if not CUSTOM_EMOJI:
        text, markup = strip_custom(text, markup)
    try:
        return await call(text, markup)
    except TelegramBadRequest as e:
        if not (CUSTOM_EMOJI and emoji_error(e)):
            raise
        log.warning("кастомные эмодзи недоступны (нужен Premium у владельца бота): %s", e)
        CUSTOM_EMOJI = False
        return await call(*strip_custom(text, markup))


def rich(html_text: str) -> InputRichMessage:
    return InputRichMessage(html=html_text.strip())


async def send_view(bot: Bot, chat_id: int, text: str, markup: InlineKeyboardMarkup | None = None):
    """Прислать rich-сообщение; если rich недоступен — обычный HTML."""
    try:
        return await with_emoji_fallback(
            lambda t, mk: bot.send_rich_message(chat_id=chat_id, rich_message=rich(t),
                                                reply_markup=mk), text, markup)
    except Exception as e:
        log.warning("rich message failed, fallback: %s", e)
    return await with_emoji_fallback(
        lambda t, mk: bot.send_message(chat_id, rich_to_plain(t), reply_markup=mk,
                                       disable_web_page_preview=True), text, markup)


async def edit_view(m: Message, text: str, markup: InlineKeyboardMarkup | None) -> bool:
    """Отредактировать сообщение в rich (или обычный HTML). False — если это нельзя."""
    for make in (lambda t: {"rich_message": rich(t)},
                 lambda t: {"text": rich_to_plain(t), "disable_web_page_preview": True}):
        try:
            await with_emoji_fallback(
                lambda t, mk: m.bot.edit_message_text(chat_id=m.chat.id, message_id=m.message_id,
                                                      reply_markup=mk, **make(t)), text, markup)
            return True
        except TelegramBadRequest as e:
            if "not modified" in str(e):
                return True
            log.debug("edit failed: %s", e)
        except Exception as e:
            log.debug("edit failed: %s", e)
    return False


async def show(target, text: str, markup: InlineKeyboardMarkup | None = None):
    """Отредактировать сообщение с кнопкой, а если нельзя — прислать новое."""
    if isinstance(target, CallbackQuery):
        if await edit_view(target.message, text, markup):
            return
        target = target.message
    await send_view(target.bot, target.chat.id, text, markup)


async def notify(bot: Bot, chat_id: int, text: str, markup=None) -> bool:
    """Уведомление пользователю/админу; False — если бот заблокирован или чат недоступен."""
    try:
        await send_view(bot, chat_id, text, markup)
        return True
    except Exception as e:
        log.warning("notify %s failed: %s", chat_id, e)
        return False


def rich_to_plain(s: str) -> str:
    """Rich HTML -> обычный Telegram HTML (для клиентов/API без rich-сообщений)."""
    s = re.sub(r"<h[1-6]>(.*?)</h[1-6]>", r"\n<b>\1</b>\n", s, flags=re.S)
    s = re.sub(r"<summary>(.*?)</summary>", r"\n<b>\1</b>\n", s, flags=re.S)
    s = re.sub(r"<caption>(.*?)</caption>", r"<b>\1</b>\n", s, flags=re.S)
    s = re.sub(r"</t[dh]>\s*<t[dh][^>]*>", " · ", s)
    s = re.sub(r"</?t[dh][^>]*>|<tr[^>]*>", "", s)
    s = re.sub(r"<li>", "• ", s)
    s = re.sub(r"</li>|</p>|</tr>|<br\s*/?>|<hr\s*/?>", "\n", s)
    s = re.sub(r"<footer>(.*?)</footer>", r"\n<i>\1</i>", s, flags=re.S)
    s = re.sub(r"<blockquote[^>]*>", "<blockquote>", s)
    s = re.sub(r"</?(p|ol|ul|details|section|div|table|aside|mark|cite)[^>]*>", "", s)
    s = re.sub(r"\n\s*\n(?=• )", "\n", s)
    return re.sub(r"\n{3,}", "\n\n", s).strip()


def user_line(u) -> str:
    """Имя (ссылка на профиль) · @username (ссылка) · ID."""
    uid = u["chat_id"]
    name = esc(u["name"] or "без имени")
    uname = (f'<a href="https://t.me/{esc(u["username"])}">@{esc(u["username"])}</a>'
             if u["username"] else "<i>без username</i>")
    return f'<a href="tg://user?id={uid}">{name}</a> · {uname} · ID <code>{uid}</code>'


# ======================================================== тексты и меню ===

dp = Dispatcher()


class AddDevice(StatesGroup):
    name = State()


class SetLimit(StatesGroup):
    value = State()


def table(rows, head=None, caption: str = "") -> str:
    """Компактная rich-таблица; rows — списки ячеек (уже с HTML)."""
    out = ["<table bordered striped compact>"]
    if caption:
        out.append(f"<caption>{caption}</caption>")
    if head:
        out.append("<tr>" + "".join(f"<th>{h}</th>" for h in head) + "</tr>")
    for r in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
    out.append("</table>")
    return "".join(out)


def kv(rows) -> str:
    """Таблица «название — значение»."""
    return "<table bordered compact>" + "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in rows) + "</table>"


def user_table(u) -> str:
    """Карточка человека: имя со ссылкой на профиль, username, ID."""
    uid = u["chat_id"]
    uname = (f'<a href="https://t.me/{esc(u["username"])}">@{esc(u["username"])}</a>'
             if u["username"] else "<i>нет</i>")
    return kv([(f"{em('user')} Имя", f'<a href="tg://user?id={uid}">{esc(u["name"] or "без имени")}</a>'),
               (f"{em('link')} Username", uname),
               ("🆔 ID", f"<code>{uid}</code>")])


def dot(st) -> str:
    return em("online" if is_online(st) else "offline")


def main_menu(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    u = get_user(uid)
    n = len(user_devices(uid))
    lim = device_limit(uid)
    limit = "" if lim is None else f" из {lim}"
    name = esc(u["name"].split()[0]) if u and u["name"] else "друг"
    text = (f"<h2>{em('vpn')} Привет, {name}!</h2>"
            f"<p>Это твой личный VPN. Здесь можно выпустить конфиг для каждого устройства "
            f"и посмотреть, как подключиться.</p>"
            + kv([(f"{em('devices')} Устройств", f"<b>{n}{limit}</b>"),
                  (f"{em('globe')} Сервер", server_location_html())]))
    rows = [
        [btn("Мои устройства", "devs", icon="devices")],
        [btn("Добавить устройство", "add", style="primary", icon="add")],
        [btn("Как подключиться", "help", icon="help"), btn("Статус", "status", icon="status")],
    ]
    if is_admin(uid):
        rows.append([btn("Админка", "adm", icon="admin")])
    return text, kb(*rows)


def devices_menu(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    devs = user_devices(uid)
    stats = peer_stats() if devs else {}
    rows = []
    for d in devs:
        rows.append([btn(d["name"], f"dev:{d['id']}",
                         icon="online" if is_online(stats.get(d["pub"])) else "offline")])
    rows.append([btn("Добавить устройство", "add", style="primary", icon="add")])
    rows.append([btn("Меню", "menu", icon="back")])
    text = f"<h2>{em('devices')} Мои устройства</h2>"
    if devs:
        text += table([[dot(stats.get(d["pub"])), f"<b>{esc(d['name'])}</b>",
                        fmt_seen(stats[d["pub"]]["hs"] if d["pub"] in stats else 0)] for d in devs],
                      head=["", "Устройство", "Подключение"])
        text += "<p>Выбери устройство, чтобы получить его конфиг. " + em("online") + " — сейчас подключено.</p>"
    else:
        text += ("<p>Пока пусто. Добавь первое устройство — например, «Телефон» или «Ноутбук».</p>")
    return text, kb(*rows)


def server_ip() -> str:
    """Текущий публичный IP сервера: VPN_HOST, а если это домен — его A-запись."""
    try:
        ipaddress.ip_address(VPN_HOST)
        return VPN_HOST
    except ValueError:
        pass
    try:
        return socket.gethostbyname(VPN_HOST)
    except OSError:
        return VPN_HOST


# ================================================================== гео ===
# Страна сервера по IP из локальной базы DB-IP Lite (.mmdb). База скачивается
# при старте, если её нет или она старше месяца; обновляется раз в сутки в фоне.

GEOIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{}.mmdb.gz"
GEO_REFRESH = 600              # как часто перепроверять IP сервера, сек
_geo_reader = None
_location = {"ip": VPN_HOST, "code": "", "country": "", "ts": 0.0}


def geoip_update(force: bool = False) -> None:
    """Скачать свежую базу DB-IP, если файла нет или он старше 30 дней."""
    global _geo_reader
    try:
        if not force and time.time() - os.path.getmtime(GEOIP_DB) < 30 * 86400:
            return
    except OSError:
        pass
    today = date.today()
    prev = date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1)
    for d in (today, prev):           # в начале месяца свежей базы может ещё не быть
        url = GEOIP_URL.format(d.strftime("%Y-%m"))
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "amnezia-control-bot/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = gzip.decompress(resp.read())
            tmp = GEOIP_DB + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, GEOIP_DB)
            _geo_reader = None        # переоткрыть с новым файлом
            log.info("GeoIP: база обновлена (%s)", url)
            return
        except Exception as e:
            log.warning("GeoIP: не удалось скачать %s: %s", url, e)


def geo_reader():
    global _geo_reader
    if _geo_reader is None and os.path.exists(GEOIP_DB):
        try:
            _geo_reader = maxminddb.open_database(GEOIP_DB)
        except Exception as e:
            log.warning("GeoIP: не удалось открыть базу: %s", e)
    return _geo_reader


def ip_country(ip: str) -> tuple[str, str]:
    """(ISO-код, название по-русски) или ("", "")."""
    try:
        rec = (geo_reader() or {}).get(ip) or {}
    except Exception:
        return "", ""
    c = rec.get("country") or {}
    names = c.get("names") or {}
    return c.get("iso_code", ""), names.get("ru") or names.get("en", "")


def flag(code: str) -> str:
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in code.upper()) if len(code) == 2 else ""


def refresh_location() -> dict:
    ip = server_ip()
    code, country = ip_country(ip)
    _location.update(ip=ip, code=code, country=country, ts=time.time())
    return _location


def server_location_html() -> str:
    """«🇩🇪 Германия · 1.2.3.4» — из кэша (обновляется в фоне), без блокировок."""
    loc = _location
    ip = f"<code>{esc(loc['ip'])}</code>"
    if not loc["country"]:
        return ip
    return f"{flag(loc['code'])} {esc(loc['country'])} · {ip}"


async def geo_loop() -> None:
    """Фон: IP сервера — каждые 10 минут, база стран — раз в сутки проверить возраст."""
    last_db = 0.0
    while True:
        try:
            if time.time() - last_db > 86400:
                await asyncio.to_thread(geoip_update)
                last_db = time.time()
            await asyncio.to_thread(refresh_location)
        except Exception as e:
            log.warning("geo refresh failed: %s", e)
        await asyncio.sleep(GEO_REFRESH)


def device_card(d, viewer: int) -> tuple[str, InlineKeyboardMarkup]:
    st = peer_stats().get(d["pub"])
    created = (d["created"] or "")[:10]
    try:
        created = datetime.fromisoformat(d["created"]).strftime("%d.%m.%Y")
    except Exception:
        pass
    status = f"{dot(st)} в сети" if is_online(st) else f"{dot(st)} {fmt_seen(st['hs'] if st else 0)}"
    info = [("Статус", status)]
    if st and (st["rx"] or st["tx"]):
        info.append((f"{em('traffic')} Трафик", f"↓ {fmt_bytes(st['rx'])} · ↑ {fmt_bytes(st['tx'])}"))
    info.append((f"{em('globe')} Сервер", server_location_html()))
    if is_admin(viewer):
        info.append((f"{em('pin')} IP в VPN", f"<code>{d['ip']}</code>"))
    info.append((f"{em('calendar')} Создано", created))
    text = (f"<h2>{em('device')} {esc(d['name'])}</h2>" + kv(info) +
            f"<p>Выбери формат конфига 👇</p>"
            f"<blockquote>{em('key')} <b>Ключ</b> — самый простой способ для AmneziaVPN "
            f"и DefaultVPN.</blockquote>")
    i = d["id"]
    return text, kb(
        [btn("Ключ для приложения", f"fmt:{i}:key", style="success", icon="key")],
        [btn("QR-код", f"fmt:{i}:qr", icon="qr"), btn("Файл .conf", f"fmt:{i}:file", icon="file")],
        [btn("Как подключиться", "help", icon="help")],
        [btn("Удалить", f"del:{i}", style="danger", icon="trash"), btn("Назад", "devs", icon="back")],
    )


def help_menu() -> tuple[str, InlineKeyboardMarkup]:
    text = (f"<h2>{em('help')} Как подключиться</h2>"
            f"<p>Выбери, что у тебя за устройство — покажу пошаговую инструкцию.</p>"
            + table([[f"{em('android')} Android", "AmneziaVPN"],
                     [f"{em('apple')} iPhone (iOS 17+)", "DefaultVPN"],
                     [f"{em('windows')} Windows · {em('apple')} macOS · {em('linux')} Linux",
                      "AmneziaVPN"],
                     ["iOS 15–16, старые Android", "AmneziaWG + файл .conf"]],
                    head=["Устройство", "Приложение"]))
    return text, kb([btn("Android", "guide:android", icon="android"),
                     btn("iPhone", "guide:ios", icon="apple")],
                    [btn("Windows", "guide:windows", icon="windows"),
                     btn("macOS", "guide:mac", icon="apple"),
                     btn("Linux", "guide:linux", icon="linux")],
                    [btn("Меню", "menu", icon="back")])


def guide_android() -> str:
    return f"""
<h2>{em('android')} Android — AmneziaVPN</h2>
<p>Официальное приложение Amnezia из Google Play. Подключение займёт минуту.</p>

<h3>1. Установи приложение</h3>
<p>Нажми кнопку <b>«Google Play»</b> под сообщением и установи <b>AmneziaVPN</b>.</p>

<h3>2. Скопируй ключ</h3>
<p>В боте: <b>Мои устройства → твоё устройство → Ключ для приложения</b>. Нажми на ключ — он скопируется целиком.</p>

<h3>3. Добавь подключение</h3>
<ol>
<li>Открой AmneziaVPN и нажми <b>«Приступим»</b> (или ➕, если подключения уже есть).</li>
<li>Нажми <b>«Вставить»</b> рядом с полем для ключа.</li>
<li>Нажми <b>«Продолжить»</b>, затем <b>«Подключиться»</b>.</li>
<li>Разреши Android создать VPN-подключение.</li>
</ol>

<details>
<summary>{em('question')} Не получается?</summary>
<ul>
<li>Приложения нет в Google Play — скачай APK с официального GitHub Amnezia (раздел Releases).</li>
<li>Вместо ключа можно отсканировать <b>QR-код</b> с экрана другого устройства или импортировать <b>файл .conf</b>.</li>
<li>Не подключается — напиши администратору, он проверит сервер.</li>
</ul>
</details>

<footer>{em('lock')} Ключ — как пароль: не пересылай его другим людям.</footer>
"""


def guide_ios() -> str:
    return f"""
<h2>{em('apple')} iPhone — DefaultVPN</h2>
<p>AmneziaVPN убрали из российского App Store, поэтому используем <b>DefaultVPN</b> — альтернативное приложение от разработчиков Amnezia. Нужна iOS 17 или новее.</p>

<h3>1. Установи приложение</h3>
<p>Нажми кнопку <b>«App Store»</b> под сообщением и установи <b>DefaultVPN</b>.</p>

<h3>2. Скопируй ключ</h3>
<p>В боте: <b>Мои устройства → твоё устройство → Ключ для приложения</b>. Нажми на ключ — он скопируется целиком.</p>

<h3>3. Добавь подключение</h3>
<ol>
<li>Открой DefaultVPN и нажми <b>➕</b> на главном экране.</li>
<li>Нажми <b>«Вставить»</b> возле поля для ключа.</li>
<li>Нажми <b>«Продолжить»</b>, затем <b>«Подключиться»</b>.</li>
<li>Разреши iPhone добавить конфигурацию VPN.</li>
</ol>

<details>
<summary>{em('question')} Не получается?</summary>
<ul>
<li>Если App Store у тебя не российский — можно поставить и сам <b>AmneziaVPN</b>, шаги те же.</li>
<li>iOS 15–16: используй приложение <b>AmneziaWG</b> и <b>файл .conf</b> из бота.</li>
<li>Не подключается — напиши администратору, он проверит сервер.</li>
</ul>
</details>

<footer>{em('lock')} Ключ — как пароль: не пересылай его другим людям.</footer>
"""


DESKTOP = {   # os: (заголовок, иконка, шаги установки, запасной вариант)
    "windows": (
        "Windows", "windows",
        "<ol>\n<li>Нажми <b>«Скачать»</b> под сообщением и скачай установщик для Windows "
        "(файл <code>.exe</code>).</li>\n"
        "<li>Запусти его и пройди установку. Если появится окно SmartScreen — "
        "<b>«Подробнее» → «Выполнить в любом случае»</b>.</li>\n"
        "<li>Разреши установку драйвера VPN, если Windows спросит.</li>\n</ol>",
        "<li>Можно поставить <b>AmneziaWG для Windows</b> (GitHub amnezia-vpn, репозиторий "
        "<code>amneziawg-windows-client</code>) и импортировать <b>файл .conf</b> из бота: "
        "<b>«Импорт туннелей из файла»</b> → <b>«Подключить»</b>.</li>",
    ),
    "mac": (
        "macOS", "apple",
        "<ol>\n<li>Нажми <b>«Скачать»</b> под сообщением и скачай установщик для macOS.</li>\n"
        "<li>Открой его и установи AmneziaVPN (перетащи в «Программы» или пройди "
        "мастер установки).</li>\n"
        "<li>Если macOS не даёт открыть приложение — <b>Системные настройки → "
        "Конфиденциальность и безопасность → «Всё равно открыть»</b>.</li>\n</ol>",
        "<li>Можно поставить <b>AmneziaWG</b> из Mac App Store и импортировать "
        "<b>файл .conf</b> из бота.</li>",
    ),
    "linux": (
        "Linux", "linux",
        "<ol>\n<li>Нажми <b>«Скачать»</b> под сообщением и скачай архив для Linux.</li>\n"
        "<li>Распакуй его и запусти установщик из архива в терминале (команды ниже).</li>\n"
        "<li>После установки AmneziaVPN появится в меню приложений.</li>\n</ol>\n"
        "<pre>chmod +x AmneziaVPN_*\nsudo ./AmneziaVPN_*</pre>",
        "<li>Без графического приложения: установи <code>amneziawg-tools</code> "
        "(и модуль <code>amneziawg</code>), положи <b>файл .conf</b> из бота в "
        "<code>/etc/amnezia/amneziawg/</code> и выполни "
        "<code>sudo awg-quick up &lt;имя&gt;</code>.</li>",
    ),
}


def guide_desktop(os_name: str) -> str:
    title, icon, install, fallback = DESKTOP[os_name]
    return f"""
<h2>{em(icon)} {title} — AmneziaVPN</h2>
<p>Официальное приложение Amnezia для компьютера. Подключение займёт пару минут.</p>

<h3>1. Установи приложение</h3>
{install}

<h3>2. Скопируй ключ</h3>
<p>В боте: <b>Мои устройства → твоё устройство → Ключ для приложения</b>. Нажми на ключ — он скопируется целиком. Удобнее всего открыть бота прямо на компьютере (Telegram Desktop или web.telegram.org).</p>

<h3>3. Добавь подключение</h3>
<ol>
<li>Открой AmneziaVPN и нажми <b>«Приступим»</b> (или ➕, если подключения уже есть).</li>
<li>Нажми <b>«Вставить»</b> рядом с полем для ключа.</li>
<li>Нажми <b>«Продолжить»</b>, затем <b>«Подключиться»</b>.</li>
</ol>

<details>
<summary>{em('question')} Не получается?</summary>
<ul>
<li>GitHub не открывается — скачай приложение с сайта Amnezia (кнопка <b>«Сайт Amnezia»</b>).</li>
<li>Вместо ключа можно импортировать <b>файл .conf</b> из бота: в AmneziaVPN ➕ → <b>«Файл с настройками»</b>.</li>
{fallback}
<li>Не подключается — напиши администратору, он проверит сервер.</li>
</ul>
</details>

<footer>{em('lock')} Ключ — как пароль: не пересылай его другим людям.</footer>
"""


# ================================================================ статус ===
# Статус устройств (у пользователя) и дашборд сервера (у админа) —
# rich-сообщение с таблицей; «Обновить» перерисовывает его на месте.

STATUS_ROWS_MAX = 100


def status_view(kind: str, uid: int) -> tuple[str, InlineKeyboardMarkup]:
    stats = peer_stats()
    rows = []
    if kind == "a":                       # админ: все клиенты сервера
        users = {d["pub"]: d for d in db.execute(
            "SELECT d.pub, d.name, u.username, u.chat_id FROM devices d "
            "LEFT JOIN users u ON u.chat_id=d.chat_id")}
        for p in server_peers():
            d = users.get(p["pub"])
            if d:
                who = f"@{d['username']}" if d["username"] else str(d["chat_id"])
                name = f"{esc(who)} · {esc(d['name'])}"
            else:
                name = f"{em('app')} {esc(p['name'])}"
            rows.append((name, p["pub"]))
        title = f"{em('status')} Сервер"
    else:
        rows = [(esc(d["name"]), d["pub"]) for d in user_devices(uid)]
        title = f"{em('status')} Мои устройства"

    items = []
    for name, pub in rows:
        st = stats.get(pub, {"hs": 0, "rx": 0, "tx": 0})
        items.append((is_online(st), st["hs"], name, st))
    items.sort(key=lambda x: (-x[0], -x[1]))
    online = sum(1 for x in items if x[0])
    total = sum(x[3]["rx"] + x[3]["tx"] for x in items)
    summary = [[f"{em('online')} в сети", f"<b>{online}</b>"], [f"{em('devices')} устройств", f"<b>{len(items)}</b>"]]
    if kind == "a":
        people = db.execute("SELECT COUNT(*) FROM users WHERE status='approved'").fetchone()[0]
        summary.append([f"{em('users')} людей", f"<b>{people}</b>"])
    summary.append([f"{em('traffic')} трафик", f"<b>{fmt_bytes(total)}</b>"])

    text = f"<h2>{title}</h2>" + kv(summary)
    if items:
        text += table([[em("online" if on else "offline"), name, fmt_seen(hs),
                        f"↓ {fmt_bytes(st['rx'])}<br>↑ {fmt_bytes(st['tx'])}"]
                       for on, hs, name, st in items[:STATUS_ROWS_MAX]],
                      head=["", "Устройство", "Подключение", "Трафик"])
        if len(items) > STATUS_ROWS_MAX:
            text += f"<p><i>…и ещё {len(items) - STATUS_ROWS_MAX}</i></p>"
    else:
        text += "<p>Устройств пока нет.</p>"
    text += f"<footer>{em('clock')} обновлено {datetime.now().strftime('%H:%M:%S')}</footer>"
    back = btn("Админка", "adm", icon="back") if kind == "a" else btn("Меню", "menu", icon="back")
    return text, kb([btn("Обновить", "adm:dash" if kind == "a" else "status", icon="refresh")], [back])


# ======================================================= пользователь ===

@dp.message(CommandStart())
@dp.message(Command("menu", "config"))
async def start(m: Message, bot: Bot, state: FSMContext):
    await state.clear()
    uid = m.from_user.id
    if is_admin(uid) and not get_user(uid):
        set_user(uid, username=m.from_user.username, name=m.from_user.full_name, status="approved")
    u = get_user(uid)

    if u and u["status"] == "approved":
        set_user(uid, username=m.from_user.username, name=m.from_user.full_name)
        return await show(m, *main_menu(uid))
    if u and u["status"] == "pending":
        return await show(m, f"<p>{em('pending')} <b>Заявка уже у администратора.</b></p>"
                             f"<p>Как только её одобрят — я напишу.</p>")
    if u and u["status"] in ("denied", "revoked"):
        return await show(m, f"<p>{em('denied')} <b>Доступ не выдан.</b></p>"
                             f"<p>Если это ошибка — напиши администратору.</p>")

    await show(m, f"<h2>{em('hello')} Привет!</h2>"
                  f"<p>Это бот для подключения к приватному VPN.</p>"
                  f"<blockquote>{em('lock')} Доступ выдаёт администратор — отправить ему заявку?</blockquote>",
               kb([btn("Отправить заявку", "request", style="primary", icon="send")]))


@dp.callback_query(F.data == "request")
async def send_request(cb: CallbackQuery, bot: Bot):
    uid = cb.from_user.id
    u = get_user(uid)
    if u and u["status"] in ("pending", "approved", "denied", "revoked"):
        return await cb.answer("Заявка уже отправлена")
    set_user(uid, username=cb.from_user.username, name=cb.from_user.full_name, status="pending")
    await show(cb, f"<h3>{em('send')} Заявка отправлена!</h3>"
                   f"<p>Как только администратор её одобрит — я напишу.</p>")
    u = get_user(uid)
    for admin in ADMIN_IDS:
        await notify(bot, admin, f"<h3>{em('bell')} Новая заявка на VPN</h3>" + user_table(u),
                     kb([btn("Одобрить", f"ok:{uid}", style="success", icon="ok"),
                         btn("Отклонить", f"no:{uid}", style="danger", icon="no")],
                        [btn("Карточка", f"u:{uid}", icon="user")]))
    await cb.answer()


@dp.callback_query(F.data == "menu")
async def cb_menu(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    await show(cb, *main_menu(cb.from_user.id))
    await cb.answer()


@dp.callback_query(F.data == "devs")
async def cb_devs(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    text, markup = await asyncio.to_thread(devices_menu, cb.from_user.id)
    await show(cb, text, markup)
    await cb.answer()


@dp.callback_query(F.data == "add")
async def ask_name(cb: CallbackQuery, state: FSMContext):
    uid = cb.from_user.id
    if not has_access(uid):
        return await cb.answer("Доступ не выдан", show_alert=True)
    lim = device_limit(uid)
    if lim is not None and len(user_devices(uid)) >= lim:
        return await cb.answer(f"Максимум {lim} устройств. Удали ненужное.", show_alert=True)
    await state.set_state(AddDevice.name)
    await show(cb, f"<h3>{em('edit')} Новое устройство</h3>"
                   f"<p>Как его назвать? Просто напиши в ответ.</p>"
                   f"<blockquote><i>Например: Телефон, Ноутбук, ПК, iPad мамы</i></blockquote>",
               kb([btn("Отмена", "devs", icon="no")]))
    await cb.answer()


@dp.message(AddDevice.name, F.text)
async def create_device(m: Message, bot: Bot, state: FSMContext):
    uid = m.from_user.id
    name = " ".join(m.text.split())
    if not has_access(uid):
        return await state.clear()
    if name.startswith("/"):
        await state.clear()
        return await show(m, *main_menu(uid))
    if not 1 <= len(name) <= 32:
        return await show(m, f"<p>{em('warn')} Название должно быть от 1 до 32 символов. "
                             f"Попробуй ещё раз.</p>")
    if any(d["name"].lower() == name.lower() for d in user_devices(uid)):
        return await show(m, f"<p>{em('warn')} Такое устройство уже есть — придумай другое название.</p>")
    lim = device_limit(uid)
    if lim is not None and len(user_devices(uid)) >= lim:
        await state.clear()
        return await show(m, f"<p>{em('warn')} Максимум {lim} устройств.</p>")

    await state.clear()
    u = get_user(uid)
    wait = await send_view(bot, m.chat.id, f"<p>{em('pending')} Создаю конфиг…</p>")
    try:
        async with wg_lock:
            c = await asyncio.to_thread(add_peer, f"{owner_label(u)} — {name}")
    except Exception as e:
        log.exception("add_peer failed")
        fail = f"<p>{em('sad')} Не получилось создать конфиг. Администратор уже в курсе.</p>"
        if not await edit_view(wait, fail, None):
            await send_view(bot, m.chat.id, fail)
        for admin in ADMIN_IDS:
            await notify(bot, admin, f"<h3>{em('warn')} Ошибка создания устройства</h3>"
                                     + user_table(u) + f"<pre>{esc(e)}</pre>")
        return

    cur = db.execute("""INSERT INTO devices (chat_id, name, ip, priv, pub, psk, created)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                     (uid, name, c["ip"], c["priv"], c["pub"], c["psk"], now()))
    db.commit()
    try:
        await bot.delete_message(m.chat.id, wait.message_id)
    except Exception:
        pass
    text, markup = await asyncio.to_thread(device_card, get_device(cur.lastrowid), uid)
    await send_view(bot, m.chat.id, f"<p>{em('party')} <b>Готово!</b> Устройство создано.</p>" + text,
                    markup)
    if not is_admin(uid):
        for admin in ADMIN_IDS:
            await notify(bot, admin, f"<h3>{em('bell')} Новое устройство</h3>" + user_table(u)
                         + kv([(f"{em('device')} Устройство", f"«{esc(name)}»"),
                               (f"{em('pin')} IP", f"<code>{c['ip']}</code>")]),
                         kb([btn("Карточка", f"u:{uid}", icon="user")]))


@dp.callback_query(F.data.startswith("dev:"))
async def cb_device(cb: CallbackQuery):
    d = own_device(cb.from_user.id, int(cb.data.split(":")[1]))
    if not d or not has_access(cb.from_user.id):
        return await cb.answer("Устройство не найдено", show_alert=True)
    text, markup = await asyncio.to_thread(device_card, d, cb.from_user.id)
    await show(cb, text, markup)
    await cb.answer()


@dp.callback_query(F.data.startswith("fmt:"))
async def send_config(cb: CallbackQuery, bot: Bot):
    _, dev_id, fmt = cb.data.split(":")
    d = own_device(cb.from_user.id, int(dev_id))
    if not d or not has_access(cb.from_user.id):
        return await cb.answer("Устройство не найдено", show_alert=True)
    await cb.answer()

    info = await asyncio.to_thread(server_info)
    back = kb([btn("Как подключиться", "help", icon="help"),
               btn("К устройству", f"dev:{d['id']}", icon="back")])
    name = esc(d["name"])
    chat_id = cb.message.chat.id

    if fmt == "key":
        key = amnezia_key(d, info)
        await send_view(bot, chat_id,
                        f"<h3>{em('key')} Ключ для «{name}»</h3>"
                        f"<p>Нажми на ключ — он скопируется. Затем вставь его в <b>AmneziaVPN</b> "
                        f"(Android, Windows, macOS, Linux) или <b>DefaultVPN</b> (iPhone).</p>"
                        f"<pre>{key}</pre>"
                        f"<footer>{em('lock')} Ключ — как пароль: не пересылай его другим людям.</footer>",
                        back)
    elif fmt == "qr":
        conf = client_conf(d, info)
        try:
            png = qr_png(conf)
        except Exception:
            return await send_view(bot, chat_id, f"<p>{em('warn')} Конфиг слишком длинный для QR — "
                                                 f"возьми ключ или файл.</p>", back)
        await with_emoji_fallback(
            lambda t, mk: bot.send_photo(chat_id, BufferedInputFile(png, filename="qr.png"),
                                         caption=t, reply_markup=mk),
            f"{em('qr')} <b>QR-код для «{name}»</b>\n\nОтсканируй его в AmneziaVPN или "
            f"AmneziaWG с другого устройства.", back)
    elif fmt == "file":
        conf = client_conf(d, info)
        await with_emoji_fallback(
            lambda t, mk: bot.send_document(
                chat_id, BufferedInputFile(conf.encode(), filename=f"{file_name(d['name'])}.conf"),
                caption=t, reply_markup=mk),
            f"{em('file')} <b>Файл для «{name}»</b>\n\nОткрой его в AmneziaVPN, DefaultVPN "
            f"или AmneziaWG.", back)


@dp.callback_query(F.data.startswith("del:"))
async def ask_delete(cb: CallbackQuery):
    d = own_device(cb.from_user.id, int(cb.data.split(":")[1]))
    if not d:
        return await cb.answer("Устройство не найдено", show_alert=True)
    await show(cb, f"<h3>{em('trash')} Удалить «{esc(d['name'])}»?</h3>"
                   f"<blockquote>{em('warn')} Конфиг на этом устройстве сразу перестанет работать."
                   f"</blockquote>",
               kb([btn("Да, удалить", f"delok:{d['id']}", style="danger", icon="trash"),
                   btn("Отмена", f"dev:{d['id']}", icon="no")]))
    await cb.answer()


async def delete_device(d) -> None:
    async with wg_lock:
        await asyncio.to_thread(remove_peer, d["pub"])
    db.execute("DELETE FROM devices WHERE id=?", (d["id"],))
    db.commit()


@dp.callback_query(F.data.startswith("delok:"))
async def do_delete(cb: CallbackQuery, bot: Bot):
    uid = cb.from_user.id
    d = own_device(uid, int(cb.data.split(":")[1]))
    if not d:
        return await cb.answer("Устройство не найдено", show_alert=True)
    await delete_device(d)
    await cb.answer(f"«{d['name']}» удалено")
    if d["chat_id"] != uid:           # админ удалил чужое
        await notify(bot, d["chat_id"], f"<p>{em('trash')} Администратор удалил устройство "
                                        f"«{esc(d['name'])}».</p>")
        text, markup = await asyncio.to_thread(user_card, d["chat_id"])
    else:
        text, markup = await asyncio.to_thread(devices_menu, uid)
    await show(cb, text, markup)


@dp.callback_query(F.data == "help")
async def cb_help(cb: CallbackQuery):
    await show(cb, *help_menu())
    await cb.answer()


@dp.message(Command("help"))
async def cmd_help(m: Message):
    await show(m, *help_menu())


@dp.callback_query(F.data.startswith("guide:"))
async def cb_guide(cb: CallbackQuery):
    await cb.answer()
    os_name = cb.data.split(":", 1)[1]
    if os_name == "android":
        guide, store = guide_android(), [btn("Google Play", url=ANDROID_URL, icon="download")]
    elif os_name in DESKTOP:
        guide = guide_desktop(os_name)
        store = [btn("Скачать", url=DESKTOP_URL, icon="download"),
                 btn("Сайт Amnezia", url=DESKTOP_SITE_URL, icon="globe")]
    else:
        guide, store = guide_ios(), [btn("App Store", url=IOS_URL, icon="download")]
    await show(cb, guide, kb(store, [btn("Мои устройства", "devs", icon="devices"),
                                       btn("Назад", "help", icon="back")]))


@dp.callback_query(F.data == "status")
async def cb_status(cb: CallbackQuery):
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    await show(cb, *(await asyncio.to_thread(status_view, "u", cb.from_user.id)))
    await cb.answer()


# ================================================================ админ ===

STATUS_ICON = {"approved": "✅", "pending": "⏳", "denied": "❌", "revoked": "🚫"}
STATUS_EMOJI = {"approved": "ok", "pending": "pending", "denied": "no", "revoked": "denied"}
STATUS_NAME = {"approved": "доступ есть", "pending": "заявка", "denied": "отклонён",
               "revoked": "доступ отозван"}
USERS_LIST_MAX = 90


def admin_menu() -> tuple[str, InlineKeyboardMarkup]:
    q = lambda sql: db.execute(sql).fetchone()[0]
    approved = q("SELECT COUNT(*) FROM users WHERE status='approved'")
    pending = q("SELECT COUNT(*) FROM users WHERE status='pending'")
    denied = q("SELECT COUNT(*) FROM users WHERE status IN ('denied', 'revoked')")
    devices = q("SELECT COUNT(*) FROM devices")
    try:
        peers = server_peers()
        stats = peer_stats()
        mine = bot_pubs()
        app_n = sum(1 for p in peers if p["pub"] not in mine)
        online = sum(1 for p in peers if is_online(stats.get(p["pub"])))
        srv = f"{em('online')} работает, порт {server_info()['port']}"
    except Exception as e:
        app_n, online, srv = "?", "?", f"{em('error')} ошибка: {esc(str(e)[:100])}"
    text = (f"<h2>{em('admin')} Админка</h2>"
            + kv([(f"{em('vpn')} Сервер", srv),
                  (f"{em('globe')} Адрес", f"<code>{esc(VPN_HOST)}</code>")])
            + table([[f"{em('users')} Пользователей", f"<b>{approved}</b>"],
                     [f"{em('pending')} Заявок", f"<b>{pending}</b>"],
                     [f"{em('denied')} Отклонённых", f"<b>{denied}</b>"],
                     [f"{em('devices')} Устройств через бота", f"<b>{devices}</b>"],
                     [f"{em('app')} Из приложения", f"<b>{app_n}</b>"],
                     [f"{em('online')} Сейчас в сети", f"<b>{online}</b>"]]))
    rows = [[btn("Пользователи", "adm:users", icon="users"),
             btn(f"Заявки ({pending})", "adm:pending", icon="pending")],
            [btn("Из приложения", "adm:app", icon="app"), btn("Дашборд", "adm:dash", icon="status")],
            [btn(f"Отклонённые ({denied})", "adm:denied", icon="denied")],
            [btn("Меню", "menu", icon="back")]]
    return text, kb(*rows)


USERS_FILTER = {"pending": " WHERE status='pending'",
                "denied": " WHERE status IN ('denied', 'revoked')"}


def users_list(flt: str = "") -> tuple[str, InlineKeyboardMarkup]:
    """flt: "" — все, "pending" — заявки, "denied" — отклонённые и отозванные."""
    sql = "SELECT * FROM users" + USERS_FILTER.get(flt, "") + \
          " ORDER BY status='approved' DESC, created"
    users = db.execute(sql).fetchall()
    rows, lines = [], []
    for u in users[:USERS_LIST_MAX]:
        n = len(user_devices(u["chat_id"]))
        who = f"@{u['username']}" if u["username"] else str(u["chat_id"])
        rows.append([btn(f"{u['name'] or 'без имени'} · {who} · 📱{n}", f"u:{u['chat_id']}",
                         icon=STATUS_EMOJI.get(u["status"]))])
        lines.append([STATUS_ICON.get(u["status"], "?"), user_line(u), str(n)])
    rows.append([btn("Админка", "adm", icon="back")])
    title = {"pending": f"{em('pending')} Заявки",
             "denied": f"{em('denied')} Отклонённые и отозванные"}.get(flt, f"{em('users')} Пользователи")
    text = f"<h2>{title}</h2>"
    if not users:
        text += "<p>Пусто.</p>"
    else:
        text += table(lines, head=["", "Человек", "📱"])
        if len(users) > USERS_LIST_MAX:
            text += f"<p><i>Показаны первые {USERS_LIST_MAX} из {len(users)}.</i></p>"
        text += "<p>Нажми на человека, чтобы открыть карточку.</p>"
    return text, kb(*rows)


def user_card(chat_id: int) -> tuple[str, InlineKeyboardMarkup]:
    u = get_user(chat_id)
    if not u:
        return (f"<p>{em('warn')} Пользователь не найден.</p>",
                kb([btn("Пользователи", "adm:users", icon="back")]))
    devs = user_devices(chat_id)
    stats = peer_stats() if devs else {}
    if is_admin(chat_id):
        limit = "без ограничений (админ)"
    elif u["max_devices"] is None:
        limit = f"{MAX_DEVICES} (по умолчанию)"
    else:
        limit = f"<b>{u['max_devices']}</b> (по умолчанию {MAX_DEVICES})"
    s = u["status"]
    text = (f"<h2>{em(STATUS_EMOJI.get(s, 'user'))} {esc(u['name'] or 'без имени')}</h2>"
            + user_table(u)
            + kv([("Статус", f"{STATUS_ICON.get(s, '?')} {STATUS_NAME.get(s, esc(s))}"),
                  (f"{em('calendar')} С нами с", (u["created"] or "")[:10]),
                  (f"{em('devices')} Лимит устройств", limit)]))
    rows = []
    if devs:
        text += table([[dot(stats.get(d["pub"])), esc(d["name"]), f"<code>{d['ip']}</code>",
                        fmt_seen(stats[d["pub"]]["hs"] if d["pub"] in stats else 0)] for d in devs],
                      head=["", "Устройство", "IP", "Подключение"],
                      caption=f"Устройства ({len(devs)})")
        for d in devs:
            rows.append([btn(d["name"], f"del:{d['id']}", icon="trash")])
    else:
        text += "<p>Устройств нет.</p>"
    if s == "pending":
        rows.append([btn("Одобрить", f"ok:{chat_id}", style="success", icon="ok"),
                     btn("Отклонить", f"no:{chat_id}", style="danger", icon="no")])
    elif s == "approved" and not is_admin(chat_id):
        rows.append([btn("Отозвать доступ", f"rv:{chat_id}", style="danger", icon="revoke")])
    elif s in ("denied", "revoked"):
        rows.append([btn("Вернуть доступ", f"rs:{chat_id}", style="success", icon="restore")])
        rows.append([btn("Разрешить заявку снова", f"al:{chat_id}", icon="again")])
    if not is_admin(chat_id):
        rows.append([btn("Лимит устройств", f"lim:{chat_id}", icon="edit")])
    rows.append([btn("Пользователи", "adm:users", icon="back")])
    return text, kb(*rows)


def app_list() -> tuple[str, InlineKeyboardMarkup]:
    mine = bot_pubs()
    stats = peer_stats()
    peers = [p for p in server_peers() if p["pub"] not in mine]
    text = f"<h2>{em('app')} Конфиги из приложения AmneziaVPN</h2>"
    rows = []
    if peers:
        text += table([[dot(stats.get(p["pub"])), esc(p["name"]), f"<code>{p['ip']}</code>",
                        fmt_seen(stats[p["pub"]]["hs"] if p["pub"] in stats else 0)] for p in peers],
                      head=["", "Имя", "IP", "Подключение"])
        for p in peers:
            rows.append([btn(p["name"], f"ap:{p['ip']}", icon="trash")])
    else:
        text += "<p>Таких нет — все конфиги выпущены через бота.</p>"
    rows.append([btn("Админка", "adm", icon="back")])
    return text, kb(*rows)


def admin_only(handler):
    @functools.wraps(handler)
    async def wrapper(cb: CallbackQuery, *a, **kw):
        if not is_admin(cb.from_user.id):
            return await cb.answer("Нет доступа", show_alert=True)
        return await handler(cb, *a, **kw)
    return wrapper


@dp.callback_query(F.data == "adm")
@admin_only
async def cb_adm(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(admin_menu)))
    await cb.answer()


@dp.message(Command("admin", "list"))
async def cmd_admin(m: Message):
    if is_admin(m.from_user.id):
        await show(m, *(await asyncio.to_thread(admin_menu)))


@dp.callback_query(F.data.in_({"adm:users", "adm:pending", "adm:denied"}))
@admin_only
async def cb_users(cb: CallbackQuery):
    await show(cb, *users_list(cb.data[4:] if cb.data != "adm:users" else ""))
    await cb.answer()


@dp.callback_query(F.data.startswith("u:"))
@admin_only
async def cb_user(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await show(cb, *(await asyncio.to_thread(user_card, int(cb.data[2:]))))
    await cb.answer()


@dp.callback_query(F.data == "adm:app")
@admin_only
async def cb_app(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(app_list)))
    await cb.answer()


@dp.callback_query(F.data == "adm:dash")
@admin_only
async def cb_dash(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(status_view, "a", cb.from_user.id)))
    await cb.answer()


@dp.callback_query(F.data.startswith("ok:"))
@admin_only
async def approve(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[3:])
    u = get_user(chat_id)
    if not u:
        return await cb.answer("Пользователь не найден", show_alert=True)
    set_user(chat_id, status="approved")
    await show(cb, f"<h3>{em('ok')} Заявка одобрена</h3>" + user_table(u),
               kb([btn("Открыть карточку", f"u:{chat_id}", icon="user")]))
    sent = await notify_approved(bot, chat_id)
    await cb.answer("Одобрено" if sent else "Одобрено, но написать ему не вышло",
                    show_alert=not sent)


async def notify_approved(bot: Bot, chat_id: int) -> bool:
    """Сообщить об одобрении; False — если бот заблокирован или чат недоступен."""
    return await notify(bot, chat_id,
                        f"<h2>{em('party')} Доступ одобрен!</h2>"
                        f"<p>Добавь своё первое устройство, а потом загляни в «Как подключиться».</p>",
                        kb([btn("Добавить устройство", "add", style="primary", icon="add")],
                           [btn("Как подключиться", "help", icon="help")]))


@dp.callback_query(F.data.startswith("rs:"))
@admin_only
async def restore(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[3:])
    u = get_user(chat_id)
    if not u:
        return await cb.answer("Пользователь не найден", show_alert=True)
    if u["status"] not in ("denied", "revoked"):
        return await cb.answer("Доступ уже не закрыт", show_alert=True)
    set_user(chat_id, status="approved")
    sent = await notify_approved(bot, chat_id)
    await cb.answer("Доступ возвращён" if sent else
                    "Доступ возвращён, но написать ему не вышло (бот заблокирован?)",
                    show_alert=not sent)
    await show(cb, *(await asyncio.to_thread(user_card, chat_id)))


@dp.callback_query(F.data.startswith("no:"))
@admin_only
async def deny(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[3:])
    set_user(chat_id, status="denied")
    u = get_user(chat_id)
    await show(cb, f"<h3>{em('no')} Заявка отклонена</h3>" + user_table(u),
               kb([btn("Открыть карточку", f"u:{chat_id}", icon="user")]))
    await notify(bot, chat_id, f"<p>{em('sad')} К сожалению, заявка отклонена.</p>")
    await cb.answer("Отклонено")


@dp.callback_query(F.data.startswith("rv:"))
@admin_only
async def ask_revoke(cb: CallbackQuery):
    chat_id = int(cb.data[3:])
    u = get_user(chat_id)
    await show(cb, f"<h3>{em('revoke')} Отозвать доступ?</h3>" + user_table(u)
                   + f"<blockquote>{em('warn')} Все его устройства ({len(user_devices(chat_id))}) "
                     f"перестанут работать.</blockquote>",
               kb([btn("Да, отозвать", f"rvok:{chat_id}", style="danger", icon="revoke"),
                   btn("Отмена", f"u:{chat_id}", icon="no")]))
    await cb.answer()


@dp.callback_query(F.data.startswith("rvok:"))
@admin_only
async def do_revoke(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[5:])
    for d in user_devices(chat_id):
        await delete_device(d)
    set_user(chat_id, status="revoked")
    await notify(bot, chat_id, f"<p>{em('denied')} Твой доступ к VPN отозван.</p>")
    await cb.answer("Доступ отозван")
    await show(cb, *(await asyncio.to_thread(user_card, chat_id)))


@dp.callback_query(F.data.startswith("al:"))
@admin_only
async def allow_again(cb: CallbackQuery):
    chat_id = int(cb.data[3:])
    db.execute("DELETE FROM users WHERE chat_id=?", (chat_id,))
    db.commit()
    await cb.answer("Теперь он может снова отправить заявку через /start", show_alert=True)
    await show(cb, *users_list())


LIMIT_MAX = 100


@dp.callback_query(F.data.startswith("lim:"))
@admin_only
async def ask_limit(cb: CallbackQuery, state: FSMContext):
    chat_id = int(cb.data[4:])
    u = get_user(chat_id)
    if not u:
        return await cb.answer("Пользователь не найден", show_alert=True)
    await state.set_state(SetLimit.value)
    await state.update_data(chat_id=chat_id)
    cur = "по умолчанию" if u["max_devices"] is None else str(u["max_devices"])
    await show(cb, f"<h3>{em('edit')} Лимит устройств</h3>" + user_table(u)
                   + kv([("Сейчас", cur), ("Общий лимит", str(MAX_DEVICES))])
                   + f"<p>Пришли число от 0 до {LIMIT_MAX}. Чтобы вернуть общий лимит — "
                     f"нажми «Сбросить» или пришли «-».</p>",
               kb([btn("Сбросить", f"limrs:{chat_id}", icon="reset"),
                   btn("Отмена", f"u:{chat_id}", icon="no")]))
    await cb.answer()


def limit_saved(chat_id: int, value: int | None) -> str:
    set_user(chat_id, max_devices=value)
    n = len(user_devices(chat_id))
    text = (f"<p>{em('ok')} Лимит устройств: <b>{value}</b></p>" if value is not None else
            f"<p>{em('ok')} Лимит сброшен — общий, <b>{MAX_DEVICES}</b></p>")
    lim = MAX_DEVICES if value is None else value
    if n > lim:
        text += (f"<blockquote>{em('warn')} Сейчас у него {n} устройств — они останутся, "
                 f"но добавить новые не получится, пока их не станет меньше {lim}.</blockquote>")
    return text


@dp.callback_query(F.data.startswith("limrs:"))
@admin_only
async def reset_limit(cb: CallbackQuery, state: FSMContext):
    chat_id = int(cb.data[6:])
    await state.clear()
    if not get_user(chat_id):
        return await cb.answer("Пользователь не найден", show_alert=True)
    text = limit_saved(chat_id, None)
    await cb.answer()
    card, markup = await asyncio.to_thread(user_card, chat_id)
    await show(cb, text + card, markup)


@dp.message(SetLimit.value, F.text)
async def set_limit(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return await state.clear()
    chat_id = (await state.get_data()).get("chat_id")
    raw = m.text.strip()
    if raw.startswith("/") or not chat_id or not get_user(chat_id):
        await state.clear()
        return await show(m, "<p>Отменено.</p>")
    if raw == "-":
        value = None
    elif raw.isdigit() and 0 <= int(raw) <= LIMIT_MAX:
        value = int(raw)
    else:
        return await show(m, f"<p>{em('warn')} Нужно целое число от 0 до {LIMIT_MAX} или «-» "
                             f"для сброса. Попробуй ещё раз.</p>",
                          kb([btn("Отмена", f"u:{chat_id}", icon="no")]))
    await state.clear()
    text = limit_saved(chat_id, value)
    card, markup = await asyncio.to_thread(user_card, chat_id)
    await show(m, text + card, markup)


@dp.callback_query(F.data.startswith("ap:"))
@admin_only
async def ask_del_app(cb: CallbackQuery):
    ip = cb.data[3:]
    p = next((p for p in await asyncio.to_thread(server_peers) if p["ip"] == ip), None)
    if not p:
        return await cb.answer("Не найден", show_alert=True)
    await show(cb, f"<h3>{em('trash')} Удалить «{esc(p['name'])}» ({ip})?</h3>"
                   f"<blockquote>{em('warn')} Конфиг, выпущенный в приложении, перестанет работать."
                   f"</blockquote>",
               kb([btn("Да, удалить", f"apok:{ip}", style="danger", icon="trash"),
                   btn("Отмена", "adm:app", icon="no")]))
    await cb.answer()


@dp.callback_query(F.data.startswith("apok:"))
@admin_only
async def do_del_app(cb: CallbackQuery):
    ip = cb.data[5:]
    mine = bot_pubs()
    p = next((p for p in await asyncio.to_thread(server_peers)
              if p["ip"] == ip and p["pub"] not in mine), None)
    if p:
        async with wg_lock:
            await asyncio.to_thread(remove_peer, p["pub"])
        await cb.answer("Удалено")
    else:
        await cb.answer("Не найден", show_alert=True)
    await show(cb, *(await asyncio.to_thread(app_list)))


async def main():
    logging.basicConfig(level=logging.INFO)
    info = await asyncio.to_thread(server_info)   # падаем сразу, если контейнер не найден
    log.info("Сервер: %s, порт %s, AWG2=%s, параметры: %s",
             info["address"], info["port"], info["awg2"], ", ".join(info["obf"]))
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    from aiogram.types import BotCommand
    await bot.set_my_commands([BotCommand(command="start", description="Главное меню"),
                               BotCommand(command="help", description="Как подключиться")])
    await asyncio.to_thread(geoip_update)
    await asyncio.to_thread(refresh_location)
    log.info("Сервер %s: %s", _location["ip"], _location["country"] or "страна неизвестна")
    geo_task = asyncio.create_task(geo_loop())   # noqa: F841 (держим ссылку)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
