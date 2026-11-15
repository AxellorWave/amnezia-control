"""
Telegram-бот для выдачи конфигов AmneziaWG (сервер Amnezia в Docker, AWG 2.0).

Пользователь: заявка -> одобрение админом -> свои устройства (ПК, телефон...)
с конфигами в трёх форматах, инструкции (rich-сообщения), виджет статуса.
Админ: панель с пользователями, заявками, конфигами из приложения и дашбордом.
"""
import asyncio
import functools
import base64
import html
import io
import ipaddress
import json
import logging
import os
import re
import sqlite3
import struct
import subprocess
import time
import zlib
from datetime import datetime

import qrcode
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (BufferedInputFile, CallbackQuery, InlineKeyboardButton,
                           InlineKeyboardMarkup, InputRichMessage, Message, WidgetQuery)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = {int(x) for x in os.environ["ADMIN_IDS"].split(",") if x.strip()}
VPN_HOST = os.environ["VPN_HOST"]
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

ANDROID_URL = "https://play.google.com/store/apps/details?id=org.amnezia.vpn"
IOS_URL = "https://apps.apple.com/app/defaultvpn/id6744725017"

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


def amnezia_key(c, info: dict, name: str) -> str:
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
        "description": name,
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


def own_device(uid: int, dev_id: int):
    d = get_device(dev_id)
    return d if d and (d["chat_id"] == uid or is_admin(uid)) else None


def btn(text: str, data: str | None = None, url: str | None = None, style: str | None = None):
    kw = {"text": text}
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


async def show(target, text: str, markup: InlineKeyboardMarkup | None = None):
    """Отредактировать сообщение с кнопкой, а если нельзя — прислать новое."""
    if isinstance(target, CallbackQuery):
        try:
            await target.message.edit_text(text, reply_markup=markup)
            return
        except TelegramBadRequest as e:
            if "not modified" in str(e):
                return
        await target.message.answer(text, reply_markup=markup)
    else:
        await target.answer(text, reply_markup=markup)


async def send_rich(bot: Bot, chat_id: int, rich_html: str, markup=None):
    """Rich-сообщение (Bot API 10.1+), при ошибке — обычный HTML."""
    try:
        await bot.send_rich_message(chat_id=chat_id, rich_message=InputRichMessage(html=rich_html),
                                    reply_markup=markup)
    except Exception as e:
        log.warning("rich message failed, fallback: %s", e)
        await bot.send_message(chat_id, rich_to_plain(rich_html), reply_markup=markup,
                               disable_web_page_preview=True)


def rich_to_plain(s: str) -> str:
    s = re.sub(r"<h[1-6]>(.*?)</h[1-6]>", r"\n<b>\1</b>\n", s, flags=re.S)
    s = re.sub(r"<summary>(.*?)</summary>", r"\n<b>\1</b>\n", s, flags=re.S)
    s = re.sub(r"<li>", "• ", s)
    s = re.sub(r"</li>|</p>|<br\s*/?>|<hr\s*/?>", "\n", s)
    s = re.sub(r"<footer>(.*?)</footer>", r"\n<i>\1</i>", s, flags=re.S)
    s = re.sub(r"</?(p|ol|ul|details|section|div)[^>]*>", "", s)
    s = re.sub(r"\n\s*\n(?=• )", "\n", s)
    return re.sub(r"\n{3,}", "\n\n", s).strip()


# ======================================================== тексты и меню ===

dp = Dispatcher()


class AddDevice(StatesGroup):
    name = State()


def main_menu(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    u = get_user(uid)
    n = len(user_devices(uid))
    limit = "" if is_admin(uid) else f" из {MAX_DEVICES}"
    name = esc(u["name"].split()[0]) if u and u["name"] else "друг"
    text = (f"🛡 <b>Привет, {name}!</b>\n\n"
            f"Это твой личный VPN. Здесь можно выпустить конфиг для каждого устройства "
            f"и посмотреть, как подключиться.\n\n"
            f"📱 Устройств: <b>{n}{limit}</b>\n"
            f"🌐 Сервер: <code>{esc(VPN_HOST)}</code>")
    rows = [
        [btn("📱 Мои устройства", "devs")],
        [btn("➕ Добавить устройство", "add", style="primary")],
        [btn("📖 Как подключиться", "help"), btn("📊 Статус", "status")],
    ]
    if is_admin(uid):
        rows.append([btn("👑 Админка", "adm")])
    return text, kb(*rows)


def devices_menu(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    devs = user_devices(uid)
    stats = peer_stats() if devs else {}
    rows = []
    for d in devs:
        dot = "🟢" if is_online(stats.get(d["pub"])) else "⚪️"
        rows.append([btn(f"{dot} {d['name']}", f"dev:{d['id']}")])
    rows.append([btn("➕ Добавить устройство", "add", style="primary")])
    rows.append([btn("← Меню", "menu")])
    if devs:
        text = ("📱 <b>Мои устройства</b>\n\n"
                "Выбери устройство, чтобы получить его конфиг.\n🟢 — сейчас подключено")
    else:
        text = ("📱 <b>Мои устройства</b>\n\nПока пусто. Добавь первое устройство — "
                "например, «Телефон» или «Ноутбук».")
    return text, kb(*rows)


def device_card(d) -> tuple[str, InlineKeyboardMarkup]:
    st = peer_stats().get(d["pub"])
    created = (d["created"] or "")[:10]
    try:
        created = datetime.fromisoformat(d["created"]).strftime("%d.%m.%Y")
    except Exception:
        pass
    traffic = (f"\n📶 Трафик: ↓ {fmt_bytes(st['rx'])}  ↑ {fmt_bytes(st['tx'])}"
               if st and (st["rx"] or st["tx"]) else "")
    status = "🟢 в сети" if is_online(st) else f"⚪️ {fmt_seen(st['hs'] if st else 0)}"
    text = (f"📱 <b>{esc(d['name'])}</b>\n\n"
            f"Статус: {status}{traffic}\n"
            f"IP в VPN: <code>{d['ip']}</code>\n"
            f"Создано: {created}\n\n"
            f"Выбери формат конфига 👇\n"
            f"<i>🔑 Ключ — самый простой способ для AmneziaVPN и DefaultVPN.</i>")
    i = d["id"]
    return text, kb(
        [btn("🔑 Ключ для приложения", f"fmt:{i}:key", style="success")],
        [btn("📷 QR-код", f"fmt:{i}:qr"), btn("📄 Файл .conf", f"fmt:{i}:file")],
        [btn("📖 Как подключиться", "help")],
        [btn("🗑 Удалить", f"del:{i}", style="danger"), btn("← Назад", "devs")],
    )


HELP_MENU = ("📖 <b>Как подключиться</b>\n\n"
             "Выбери, что у тебя за устройство — пришлю пошаговую инструкцию.")

GUIDE_ANDROID = """
<h2>🤖 Android — AmneziaVPN</h2>
<p>Официальное приложение Amnezia из Google Play. Подключение займёт минуту.</p>

<h3>1. Установи приложение</h3>
<p>Нажми кнопку <b>«Google Play»</b> под сообщением и установи <b>AmneziaVPN</b>.</p>

<h3>2. Скопируй ключ</h3>
<p>В боте: <b>Мои устройства → твоё устройство → 🔑 Ключ для приложения</b>. Нажми на ключ — он скопируется целиком.</p>

<h3>3. Добавь подключение</h3>
<ol>
<li>Открой AmneziaVPN и нажми <b>«Приступим»</b> (или ➕, если подключения уже есть).</li>
<li>Нажми <b>«Вставить»</b> рядом с полем для ключа.</li>
<li>Нажми <b>«Продолжить»</b>, затем <b>«Подключиться»</b>.</li>
<li>Разреши Android создать VPN-подключение.</li>
</ol>

<details>
<summary>Не получается?</summary>
<ul>
<li>Приложения нет в Google Play — скачай APK с официального GitHub Amnezia (раздел Releases).</li>
<li>Вместо ключа можно отсканировать <b>QR-код</b> с экрана другого устройства или импортировать <b>файл .conf</b>.</li>
<li>Не подключается — напиши администратору, он проверит сервер.</li>
</ul>
</details>

<footer>🔒 Ключ — как пароль: не пересылай его другим людям.</footer>
"""

GUIDE_IOS = """
<h2>🍏 iPhone — DefaultVPN</h2>
<p>AmneziaVPN убрали из российского App Store, поэтому используем <b>DefaultVPN</b> — альтернативное приложение от разработчиков Amnezia. Нужна iOS 17 или новее.</p>

<h3>1. Установи приложение</h3>
<p>Нажми кнопку <b>«App Store»</b> под сообщением и установи <b>DefaultVPN</b>.</p>

<h3>2. Скопируй ключ</h3>
<p>В боте: <b>Мои устройства → твоё устройство → 🔑 Ключ для приложения</b>. Нажми на ключ — он скопируется целиком.</p>

<h3>3. Добавь подключение</h3>
<ol>
<li>Открой DefaultVPN и нажми <b>➕</b> на главном экране.</li>
<li>Нажми <b>«Вставить»</b> возле поля для ключа.</li>
<li>Нажми <b>«Продолжить»</b>, затем <b>«Подключиться»</b>.</li>
<li>Разреши iPhone добавить конфигурацию VPN.</li>
</ol>

<details>
<summary>Не получается?</summary>
<ul>
<li>Если App Store у тебя не российский — можно поставить и сам <b>AmneziaVPN</b>, шаги те же.</li>
<li>iOS 15–16: используй приложение <b>AmneziaWG</b> и <b>файл .conf</b> из бота.</li>
<li>Не подключается — напиши администратору, он проверит сервер.</li>
</ul>
</details>

<footer>🔒 Ключ — как пароль: не пересылай его другим людям.</footer>
"""


# ================================================================ виджет ===
# HTML-виджет (Bot API 10.4): данные лежат в chat_data, кнопка «Обновить»
# отправляет запрос боту, бот обновляет chat_data через editMessageWidgetData.

WIDGET_HTML = """<style>
body{margin:0;font:14px/1.35 -apple-system,system-ui,sans-serif;color:var(--tg-theme-text-color)}
.w{padding:12px 14px}.h{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:10px}
.t{font-weight:700;font-size:16px}.u{color:var(--tg-theme-hint-color);font-size:12px}
.s{display:flex;gap:8px;margin-bottom:8px}.c{flex:1;background:var(--tg-theme-secondary-bg-color);border-radius:12px;padding:8px 4px;text-align:center}
.c b{display:block;font-size:18px}.c span{font-size:11px;color:var(--tg-theme-hint-color)}
.r{display:flex;align-items:center;gap:10px;padding:7px 0;border-top:1px solid var(--tg-theme-section-separator-color)}
.d{display:block;width:9px;height:9px;border-radius:50%;background:var(--tg-theme-hint-color);opacity:.45;flex:none}
.on .d{background:#34c759;opacity:1;box-shadow:0 0 6px #34c759}
.n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}
.m{font-size:11px;color:var(--tg-theme-hint-color);text-align:right;white-space:nowrap}
.e{color:var(--tg-theme-hint-color);text-align:center;padding:8px 0}
button{margin-top:10px;width:100%;border:0;border-radius:10px;padding:9px;font:600 14px system-ui;background:var(--tg-theme-button-color);color:var(--tg-theme-button-text-color)}
</style><div class="w"><div class="h"><div class="t" id="t"></div><div class="u" id="u"></div></div>
<div class="s" id="s"></div><div id="l"></div><button id="b">↻ Обновить</button></div>
<script>
const W=window.TelegramWidget,$=i=>document.getElementById(i);let D={};
const e=x=>String(x).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function r(){try{D=JSON.parse(W.chatData)||{}}catch(_){D={}}
$('t').textContent=D.h||'VPN';$('u').textContent=D.u?'обновлено '+D.u:'';
$('s').innerHTML=(D.s||[]).map(x=>'<div class="c"><b>'+e(x[1])+'</b><span>'+e(x[0])+'</span></div>').join('');
const l=D.d||[];$('l').innerHTML=l.length?l.map(x=>'<div class="r'+(x[1]?' on':'')+'"><i class="d"></i><div class="n">'+e(x[0])+'</div><div class="m">'+e(x[4])+'<br>↓ '+e(x[2])+' · ↑ '+e(x[3])+'</div></div>').join('')+(D.m?'<div class="e">и ещё '+D.m+'</div>':''):'<div class="e">Устройств пока нет</div>'}
if(W){W.onEvent('chatDataChanged',r);r();W.ready();
$('b').addEventListener('click',()=>{const b=$('b');b.textContent='Обновляю…';
try{W.HapticFeedback.impactOccurred('light')}catch(_){}
W.request(D.k||'u').then(()=>{b.textContent='↻ Обновить'},()=>{b.textContent='Не вышло, ещё раз'})})}
</script>"""


def widget_data(kind: str, uid: int) -> str:
    stats = peer_stats()
    rows = []
    if kind == "a":                       # админ: все клиенты сервера
        users = {d["pub"]: d for d in db.execute(
            "SELECT d.pub, d.name, u.username, u.chat_id FROM devices d "
            "LEFT JOIN users u ON u.chat_id=d.chat_id")}
        for p in server_peers():
            d = users.get(p["pub"])
            name = (f"{d['username'] or d['chat_id']} · {d['name']}" if d else f"📲 {p['name']}")
            rows.append((name, p["pub"]))
        title = "Сервер"
    else:
        rows = [(d["name"], d["pub"]) for d in user_devices(uid)]
        title = "Мои устройства"

    items = []
    for name, pub in rows:
        st = stats.get(pub, {"hs": 0, "rx": 0, "tx": 0})
        items.append([name[:28], 1 if is_online(st) else 0, fmt_bytes(st["rx"]),
                      fmt_bytes(st["tx"]), fmt_seen(st["hs"]), st["hs"]])
    items.sort(key=lambda x: (-x[1], -x[5]))
    online = sum(x[1] for x in items)
    total = sum(stats.get(p, {}).get("rx", 0) + stats.get(p, {}).get("tx", 0) for _, p in rows)
    summary = [["в сети", online], ["устройств", len(items)], ["трафик", fmt_bytes(total)]]
    if kind == "a":
        summary[2] = ["людей", db.execute(
            "SELECT COUNT(*) FROM users WHERE status='approved'").fetchone()[0]]

    data = {"k": kind, "h": title, "u": datetime.now().strftime("%H:%M"), "s": summary,
            "d": [x[:5] for x in items]}
    # chat_data максимум 1024 байта — лишние строки сворачиваем в «и ещё N»
    while len(json.dumps(data, ensure_ascii=False).encode()) > 1000 and data["d"]:
        data["d"].pop()
        data["m"] = len(items) - len(data["d"])
    return json.dumps(data, ensure_ascii=False)


async def send_status_widget(bot: Bot, chat_id: int, kind: str, uid: int):
    data = await asyncio.to_thread(widget_data, kind, uid)
    try:
        await bot.send_widget(chat_id=chat_id, html=WIDGET_HTML, chat_data=data,
                              allow_queries=True,
                              reply_markup=kb([btn("← Меню", "menu")]))
    except Exception as e:                # клиент/сервер без виджетов — текстом
        log.warning("widget failed, fallback: %s", e)
        d = json.loads(data)
        lines = [f"📊 <b>{esc(d['h'])}</b>  <i>{d['u']}</i>\n",
                 " · ".join(f"{s[0]}: <b>{s[1]}</b>" for s in d["s"]), ""]
        for x in d["d"]:
            lines.append(f"{'🟢' if x[1] else '⚪️'} {esc(x[0])} — {x[4]}, ↓{x[2]} ↑{x[3]}")
        if d.get("m"):
            lines.append(f"…и ещё {d['m']}")
        await bot.send_message(chat_id, "\n".join(lines), reply_markup=kb([btn("← Меню", "menu")]))


@dp.widget_query()
async def on_widget_query(q: WidgetQuery, bot: Bot):
    kind = "a" if q.data == "a" and is_admin(q.from_user.id) else "u"
    if not has_access(q.from_user.id):
        return await bot.answer_widget_query(widget_query_id=q.id, data="denied")
    data = await asyncio.to_thread(widget_data, kind, q.from_user.id)
    try:
        await bot.edit_message_widget_data(chat_id=q.chat.id, message_id=q.message_id,
                                           chat_data=data)
    finally:
        await bot.answer_widget_query(widget_query_id=q.id, data="ok")


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
        return await m.answer("⏳ Заявка уже у администратора. Как только её одобрят — я напишу.")
    if u and u["status"] in ("denied", "revoked"):
        return await m.answer("🚫 Доступ не выдан. Если это ошибка — напиши администратору.")

    await m.answer(
        "👋 <b>Привет!</b>\n\nЭто бот для подключения к приватному VPN.\n"
        "Доступ выдаёт администратор — отправить ему заявку?",
        reply_markup=kb([btn("📨 Отправить заявку", "request", style="primary")]))


@dp.callback_query(F.data == "request")
async def send_request(cb: CallbackQuery, bot: Bot):
    uid = cb.from_user.id
    u = get_user(uid)
    if u and u["status"] in ("pending", "approved", "denied", "revoked"):
        return await cb.answer("Заявка уже отправлена")
    set_user(uid, username=cb.from_user.username, name=cb.from_user.full_name, status="pending")
    await show(cb, "📨 <b>Заявка отправлена!</b>\n\nКак только администратор её одобрит — я напишу.")
    uname = f"@{cb.from_user.username}" if cb.from_user.username else "без username"
    for admin in ADMIN_IDS:
        await bot.send_message(
            admin, f"📨 <b>Новая заявка на VPN</b>\n\n👤 {esc(cb.from_user.full_name)} ({esc(uname)})\n"
                   f"🆔 <code>{uid}</code>",
            reply_markup=kb([btn("✅ Одобрить", f"ok:{uid}", style="success"),
                             btn("❌ Отклонить", f"no:{uid}", style="danger")]))
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
    if not is_admin(uid) and len(user_devices(uid)) >= MAX_DEVICES:
        return await cb.answer(f"Максимум {MAX_DEVICES} устройств. Удали ненужное.", show_alert=True)
    await state.set_state(AddDevice.name)
    await show(cb, "✏️ <b>Новое устройство</b>\n\nКак его назвать? Просто напиши в ответ.\n\n"
                   "<i>Например: Телефон, Ноутбук, ПК, iPad мамы</i>",
               kb([btn("Отмена", "devs")]))
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
        return await m.answer("Название должно быть от 1 до 32 символов. Попробуй ещё раз.")
    if any(d["name"].lower() == name.lower() for d in user_devices(uid)):
        return await m.answer("Такое устройство уже есть — придумай другое название.")
    if not is_admin(uid) and len(user_devices(uid)) >= MAX_DEVICES:
        await state.clear()
        return await m.answer(f"Максимум {MAX_DEVICES} устройств.")

    await state.clear()
    u = get_user(uid)
    wait = await m.answer("⏳ Создаю конфиг…")
    try:
        async with wg_lock:
            c = await asyncio.to_thread(add_peer, f"{owner_label(u)} — {name}")
    except Exception as e:
        log.exception("add_peer failed")
        await bot.edit_message_text("😕 Не получилось создать конфиг. Администратор уже в курсе.",
                                    chat_id=m.chat.id, message_id=wait.message_id)
        for admin in ADMIN_IDS:
            await bot.send_message(admin, f"⚠️ Ошибка создания устройства для "
                                          f"{esc(owner_label(u))}:\n<code>{esc(e)}</code>")
        return

    cur = db.execute("""INSERT INTO devices (chat_id, name, ip, priv, pub, psk, created)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                     (uid, name, c["ip"], c["priv"], c["pub"], c["psk"], now()))
    db.commit()
    try:
        await bot.delete_message(m.chat.id, wait.message_id)
    except Exception:
        pass
    text, markup = await asyncio.to_thread(device_card, get_device(cur.lastrowid))
    await m.answer("✅ Готово! " + text, reply_markup=markup)
    if not is_admin(uid):
        for admin in ADMIN_IDS:
            await bot.send_message(admin, f"ℹ️ {esc(owner_label(u))} добавил устройство "
                                          f"«{esc(name)}» ({c['ip']})")


@dp.callback_query(F.data.startswith("dev:"))
async def cb_device(cb: CallbackQuery):
    d = own_device(cb.from_user.id, int(cb.data.split(":")[1]))
    if not d or not has_access(cb.from_user.id):
        return await cb.answer("Устройство не найдено", show_alert=True)
    text, markup = await asyncio.to_thread(device_card, d)
    await show(cb, text, markup)
    await cb.answer()


@dp.callback_query(F.data.startswith("fmt:"))
async def send_config(cb: CallbackQuery):
    _, dev_id, fmt = cb.data.split(":")
    d = own_device(cb.from_user.id, int(dev_id))
    if not d or not has_access(cb.from_user.id):
        return await cb.answer("Устройство не найдено", show_alert=True)
    await cb.answer()

    info = await asyncio.to_thread(server_info)
    back = kb([btn("📖 Как подключиться", "help"), btn("← К устройству", f"dev:{d['id']}")])
    name = esc(d["name"])

    if fmt == "key":
        key = amnezia_key(d, info, d["name"])
        await cb.message.answer(
            f"🔑 <b>Ключ для «{name}»</b>\n\nНажми на ключ — он скопируется. Затем вставь его "
            f"в <b>AmneziaVPN</b> (Android) или <b>DefaultVPN</b> (iPhone).\n\n<pre>{key}</pre>",
            reply_markup=back)
    elif fmt == "qr":
        conf = client_conf(d, info)
        try:
            png = qr_png(conf)
        except Exception:
            return await cb.message.answer("Конфиг слишком длинный для QR — возьми ключ или файл.",
                                           reply_markup=back)
        await cb.message.answer_photo(
            BufferedInputFile(png, filename="qr.png"),
            caption=f"📷 <b>QR-код для «{name}»</b>\n\nОтсканируй его в AmneziaVPN или "
                    f"AmneziaWG с другого устройства.", reply_markup=back)
    elif fmt == "file":
        conf = client_conf(d, info)
        await cb.message.answer_document(
            BufferedInputFile(conf.encode(), filename=f"{file_name(d['name'])}.conf"),
            caption=f"📄 <b>Файл для «{name}»</b>\n\nОткрой его в AmneziaVPN, DefaultVPN "
                    f"или AmneziaWG.", reply_markup=back)


@dp.callback_query(F.data.startswith("del:"))
async def ask_delete(cb: CallbackQuery):
    d = own_device(cb.from_user.id, int(cb.data.split(":")[1]))
    if not d:
        return await cb.answer("Устройство не найдено", show_alert=True)
    await show(cb, f"🗑 <b>Удалить «{esc(d['name'])}»?</b>\n\n"
                   f"Конфиг на этом устройстве сразу перестанет работать.",
               kb([btn("Да, удалить", f"delok:{d['id']}", style="danger"),
                   btn("Отмена", f"dev:{d['id']}")]))
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
        try:
            await bot.send_message(d["chat_id"], f"🗑 Администратор удалил устройство "
                                                 f"«{esc(d['name'])}».")
        except Exception:
            pass
        text, markup = user_card(d["chat_id"])
    else:
        text, markup = await asyncio.to_thread(devices_menu, uid)
    await show(cb, text, markup)


@dp.callback_query(F.data == "help")
async def cb_help(cb: CallbackQuery):
    await show(cb, HELP_MENU, kb([btn("🤖 Android", "guide:android"), btn("🍏 iPhone", "guide:ios")],
                                 [btn("← Меню", "menu")]))
    await cb.answer()


@dp.message(Command("help"))
async def cmd_help(m: Message):
    await show(m, HELP_MENU, kb([btn("🤖 Android", "guide:android"), btn("🍏 iPhone", "guide:ios")],
                                [btn("← Меню", "menu")]))


@dp.callback_query(F.data.startswith("guide:"))
async def cb_guide(cb: CallbackQuery, bot: Bot):
    await cb.answer()
    if cb.data.endswith("android"):
        guide, store = GUIDE_ANDROID, btn("⬇️ Google Play", url=ANDROID_URL)
    else:
        guide, store = GUIDE_IOS, btn("⬇️ App Store", url=IOS_URL)
    await send_rich(bot, cb.message.chat.id, guide.strip(),
                    kb([store], [btn("📱 Мои устройства", "devs"), btn("← Меню", "menu")]))


@dp.callback_query(F.data == "status")
async def cb_status(cb: CallbackQuery, bot: Bot):
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    await cb.answer()
    await send_status_widget(bot, cb.message.chat.id, "u", cb.from_user.id)


# ================================================================ админ ===

STATUS_ICON = {"approved": "✅", "pending": "⏳", "denied": "❌", "revoked": "🚫"}


def admin_menu() -> tuple[str, InlineKeyboardMarkup]:
    q = lambda sql: db.execute(sql).fetchone()[0]
    approved = q("SELECT COUNT(*) FROM users WHERE status='approved'")
    pending = q("SELECT COUNT(*) FROM users WHERE status='pending'")
    devices = q("SELECT COUNT(*) FROM devices")
    try:
        peers = server_peers()
        stats = peer_stats()
        mine = bot_pubs()
        app_n = sum(1 for p in peers if p["pub"] not in mine)
        online = sum(1 for p in peers if is_online(stats.get(p["pub"])))
        srv = f"🟢 работает, порт {server_info()['port']}"
    except Exception as e:
        app_n, online, srv = "?", "?", f"🔴 ошибка: {esc(str(e)[:100])}"
    text = (f"👑 <b>Админка</b>\n\n"
            f"Сервер: {srv}\n"
            f"🌐 <code>{esc(VPN_HOST)}</code>\n\n"
            f"👥 Пользователей: <b>{approved}</b>\n"
            f"⏳ Заявок: <b>{pending}</b>\n"
            f"📱 Устройств через бота: <b>{devices}</b>\n"
            f"📲 Из приложения: <b>{app_n}</b>\n"
            f"🟢 Сейчас в сети: <b>{online}</b>")
    rows = [[btn("👥 Пользователи", "adm:users"), btn(f"⏳ Заявки ({pending})", "adm:pending")],
            [btn("📲 Из приложения", "adm:app"), btn("📊 Дашборд", "adm:dash")],
            [btn("← Меню", "menu")]]
    return text, kb(*rows)


def users_list(pending_only: bool = False) -> tuple[str, InlineKeyboardMarkup]:
    sql = "SELECT * FROM users" + (" WHERE status='pending'" if pending_only else "") + \
          " ORDER BY status='approved' DESC, created"
    rows = []
    for u in db.execute(sql):
        n = len(user_devices(u["chat_id"]))
        rows.append([btn(f"{STATUS_ICON.get(u['status'], '?')} {u['name']} · 📱{n}",
                         f"u:{u['chat_id']}")])
    rows.append([btn("← Админка", "adm")])
    title = "⏳ <b>Заявки</b>" if pending_only else "👥 <b>Пользователи</b>"
    empty = "\n\nПусто." if len(rows) == 1 else "\n\nВыбери человека:"
    return title + empty, kb(*rows)


def user_card(chat_id: int) -> tuple[str, InlineKeyboardMarkup]:
    u = get_user(chat_id)
    if not u:
        return "Пользователь не найден.", kb([btn("← Пользователи", "adm:users")])
    devs = user_devices(chat_id)
    stats = peer_stats() if devs else {}
    lines = [f"{STATUS_ICON.get(u['status'], '?')} <b>{esc(u['name'])}</b>",
             f"{esc(owner_label(u))} · 🆔 <code>{u['chat_id']}</code>",
             f"С нами с {(u['created'] or '')[:10]}", ""]
    rows = []
    for d in devs:
        st = stats.get(d["pub"])
        dot = "🟢" if is_online(st) else "⚪️"
        lines.append(f"{dot} {esc(d['name'])} — <code>{d['ip']}</code>, {fmt_seen(st['hs'] if st else 0)}")
        rows.append([btn(f"🗑 {d['name']}", f"del:{d['id']}")])
    if not devs:
        lines.append("Устройств нет.")
    s = u["status"]
    if s == "pending":
        rows.append([btn("✅ Одобрить", f"ok:{chat_id}", style="success"),
                     btn("❌ Отклонить", f"no:{chat_id}", style="danger")])
    elif s == "approved" and not is_admin(chat_id):
        rows.append([btn("🚫 Отозвать доступ", f"rv:{chat_id}", style="danger")])
    elif s in ("denied", "revoked"):
        rows.append([btn("♻️ Разрешить заявку снова", f"al:{chat_id}")])
    rows.append([btn("← Пользователи", "adm:users")])
    return "\n".join(lines), kb(*rows)


def app_list() -> tuple[str, InlineKeyboardMarkup]:
    mine = bot_pubs()
    stats = peer_stats()
    peers = [p for p in server_peers() if p["pub"] not in mine]
    lines = ["📲 <b>Конфиги из приложения AmneziaVPN</b>", ""]
    rows = []
    for p in peers:
        st = stats.get(p["pub"])
        dot = "🟢" if is_online(st) else "⚪️"
        lines.append(f"{dot} {esc(p['name'])} — <code>{p['ip']}</code>, {fmt_seen(st['hs'] if st else 0)}")
        rows.append([btn(f"🗑 {p['name']}", f"ap:{p['ip']}")])
    if not peers:
        lines.append("Таких нет — все конфиги выпущены через бота.")
    rows.append([btn("← Админка", "adm")])
    return "\n".join(lines), kb(*rows)


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


@dp.callback_query(F.data.in_({"adm:users", "adm:pending"}))
@admin_only
async def cb_users(cb: CallbackQuery):
    await show(cb, *users_list(cb.data == "adm:pending"))
    await cb.answer()


@dp.callback_query(F.data.startswith("u:"))
@admin_only
async def cb_user(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(user_card, int(cb.data[2:]))))
    await cb.answer()


@dp.callback_query(F.data == "adm:app")
@admin_only
async def cb_app(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(app_list)))
    await cb.answer()


@dp.callback_query(F.data == "adm:dash")
@admin_only
async def cb_dash(cb: CallbackQuery, bot: Bot):
    await cb.answer()
    await send_status_widget(bot, cb.message.chat.id, "a", cb.from_user.id)


@dp.callback_query(F.data.startswith("ok:"))
@admin_only
async def approve(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[3:])
    u = get_user(chat_id)
    if not u:
        return await cb.answer("Пользователь не найден", show_alert=True)
    set_user(chat_id, status="approved")
    await show(cb, f"✅ <b>{esc(u['name'])}</b> ({esc(owner_label(u))}) — одобрено",
               kb([btn("👤 Открыть", f"u:{chat_id}")]))
    await bot.send_message(chat_id, "🎉 <b>Доступ одобрен!</b>\n\nДобавь своё первое устройство, "
                                    "а потом загляни в «Как подключиться».",
                           reply_markup=kb([btn("➕ Добавить устройство", "add", style="primary")],
                                           [btn("📖 Как подключиться", "help")]))
    await cb.answer("Одобрено")


@dp.callback_query(F.data.startswith("no:"))
@admin_only
async def deny(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[3:])
    u = get_user(chat_id)
    set_user(chat_id, status="denied")
    await show(cb, f"❌ <b>{esc(u['name'] if u else chat_id)}</b> — отклонено",
               kb([btn("👤 Открыть", f"u:{chat_id}")]))
    await bot.send_message(chat_id, "😕 К сожалению, заявка отклонена.")
    await cb.answer("Отклонено")


@dp.callback_query(F.data.startswith("rv:"))
@admin_only
async def ask_revoke(cb: CallbackQuery):
    chat_id = int(cb.data[3:])
    u = get_user(chat_id)
    await show(cb, f"🚫 <b>Отозвать доступ у {esc(u['name'])}?</b>\n\n"
                   f"Все его устройства ({len(user_devices(chat_id))}) перестанут работать.",
               kb([btn("Да, отозвать", f"rvok:{chat_id}", style="danger"),
                   btn("Отмена", f"u:{chat_id}")]))
    await cb.answer()


@dp.callback_query(F.data.startswith("rvok:"))
@admin_only
async def do_revoke(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[5:])
    for d in user_devices(chat_id):
        await delete_device(d)
    set_user(chat_id, status="revoked")
    try:
        await bot.send_message(chat_id, "🚫 Твой доступ к VPN отозван.")
    except Exception:
        pass
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


@dp.callback_query(F.data.startswith("ap:"))
@admin_only
async def ask_del_app(cb: CallbackQuery):
    ip = cb.data[3:]
    p = next((p for p in await asyncio.to_thread(server_peers) if p["ip"] == ip), None)
    if not p:
        return await cb.answer("Не найден", show_alert=True)
    await show(cb, f"🗑 <b>Удалить «{esc(p['name'])}»</b> ({ip})?\n\n"
                   f"Конфиг, выпущенный в приложении, перестанет работать.",
               kb([btn("Да, удалить", f"apok:{ip}", style="danger"), btn("Отмена", "adm:app")]))
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
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
