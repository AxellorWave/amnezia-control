"""Оформление: эмодзи, кнопки, rich-сообщения, таблицы и форматирование."""
import html
import logging
import re
import time

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import (CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup,
                           InputRichMessage, Message)

from . import config
from .config import ONLINE_SEC

log = logging.getLogger("amnezia-bot")

# Кастомные эмодзи (пак Telegram iOS Icons, t.me/addemoji/tgiosicons).
# Работают, если у владельца бота Telegram Premium. Без Premium Telegram
# отклоняет их — тогда бот сам переключается на обычные эмодзи.

CUSTOM_EMOJI = config.CUSTOM_EMOJI

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
    "download": ("⬇️", "6039802767931871481"),  "ok": ("✅", "5188216731453103384"),
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
    "id": ("🆔", "5332465669105529951"),        "phone": ("📱", "5870748341150683538"),
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


# =========================================================== форматирование ===

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


def fmt_traffic(rx: int, tx: int) -> str:
    return f"<b>{fmt_bytes(rx + tx)}</b> (↓ {fmt_bytes(rx)} · ↑ {fmt_bytes(tx)})"


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


def dot(st) -> str:
    return em("online" if is_online(st) else "offline")


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


def user_line(u) -> str:
    """Имя (ссылка на профиль) · @username (ссылка) · ID."""
    uid = u["chat_id"]
    name = esc(u["name"] or "без имени")
    uname = (f'<a href="https://t.me/{esc(u["username"])}">@{esc(u["username"])}</a>'
             if u["username"] else "<i>без username</i>")
    return f'<a href="tg://user?id={uid}">{name}</a> · {uname} · ID <code>{uid}</code>'


def user_table(u) -> str:
    """Карточка человека: имя со ссылкой на профиль, username, ID."""
    uid = u["chat_id"]
    uname = (f'<a href="https://t.me/{esc(u["username"])}">@{esc(u["username"])}</a>'
             if u["username"] else "<i>нет</i>")
    return kv([(f"{em('user')} Имя", f'<a href="tg://user?id={uid}">{esc(u["name"] or "без имени")}</a>'),
               (f"{em('link')} Username", uname),
               (f"{em('id')} ID", f"<code>{uid}</code>")])
