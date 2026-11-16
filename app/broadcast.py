"""Рассылки и личные сообщения: черновики, получатели, очередь отправки.

Черновик хранится в базе ссылками на исходные сообщения админа (chat_id, message_id,
media_group_id) плюс то, что нужно для запасной отправки (file_id, текст и entities) —
сами файлы не копируются. Отправка — copyMessage / copyMessages, поэтому сохраняются
форматирование, премиум-эмодзи, подписи и стикеры, без пометки «переслано».
Очередь получателей лежит в базе: рассылка переживает перезапуск бота.
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone

from aiogram import Bot
from aiogram.exceptions import (TelegramBadRequest, TelegramForbiddenError,
                                TelegramNetworkError, TelegramRetryAfter, TelegramServerError)
from aiogram.types import (InputMediaAudio, InputMediaDocument, InputMediaPhoto, InputMediaVideo,
                           Message, MessageEntity)

from .config import ADMIN_IDS
from .db import db, now
from .ui import btn, em, emoji_error, kb, rich

log = logging.getLogger("amnezia-bot")

MSK = timezone(timedelta(hours=3))
RATE = 25                      # сообщений в секунду (лимит Bot API ~30/с на бота)
DELETE_WINDOW = 48 * 3600      # Bot API: удалить сообщение можно в течение 48 часов
SECTIONS = {"menu": "Меню", "sub": "Моя подписка", "devs": "Мои устройства", "help": "Как подключиться"}


def init_tables() -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS broadcasts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, admin_id INTEGER, status TEXT,
        created TEXT, options TEXT, target INTEGER, scheduled_at REAL, started_at REAL,
        finished_at REAL, progress_chat INTEGER, progress_msg INTEGER,
        total INTEGER NOT NULL DEFAULT 0, emoji_fallback INTEGER NOT NULL DEFAULT 0)""")
    db.execute("""CREATE TABLE IF NOT EXISTS bc_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT, bc_id INTEGER, chat_id INTEGER, message_id INTEGER,
        media_group_id TEXT, kind TEXT, meta TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS bc_queue (
        bc_id INTEGER, chat_id INTEGER, status TEXT NOT NULL DEFAULT 'pending',
        message_ids TEXT, error TEXT, sent_at REAL, PRIMARY KEY(bc_id, chat_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, direction TEXT, admin_id INTEGER,
        ts TEXT, summary TEXT, src_chat INTEGER, src_msg INTEGER)""")
    db.commit()


init_tables()


# ============================================================ черновик ===

KIND_NAMES = {   # вид: (один, несколько)
    "text": ("текст", "текста"), "rich": ("статья", "статьи"), "photo": ("фото", "фото"),
    "video": ("видео", "видео"), "animation": ("GIF", "GIF"),
    "document": ("документ", "документа"), "audio": ("аудио", "аудио"),
    "voice": ("голосовое", "голосовых"), "video_note": ("кружок", "кружка"),
    "sticker": ("стикер", "стикера"), "poll": ("опрос", "опроса"),
    "location": ("геоточка", "геоточки"), "contact": ("контакт", "контакта"),
    "other": ("сообщение", "сообщения"),
}


def message_kind(m: Message) -> str:
    if getattr(m, "rich_message", None):
        return "rich"
    for k in ("photo", "video", "animation", "document", "audio", "voice", "video_note",
              "sticker", "poll", "location", "contact"):
        if getattr(m, k, None):
            return k
    return "text" if m.text else "other"


def message_meta(m: Message, html: str = "") -> dict:
    """То, что нужно для запасной отправки без кастомных эмодзи."""
    kind = message_kind(m)
    file_id = None
    if kind == "photo":
        file_id = m.photo[-1].file_id
    elif kind in ("video", "animation", "document", "audio", "voice", "video_note", "sticker"):
        file_id = getattr(m, kind).file_id
    text = m.text if m.text is not None else m.caption
    ents = m.entities if m.text is not None else m.caption_entities
    return {"kind": kind, "file_id": file_id, "text": text or "",
            "entities": [e.model_dump(exclude_none=True) for e in (ents or [])],
            "html": html, "custom": any(e.type == "custom_emoji" for e in (ents or []))}


def summary_line(m: Message) -> str:
    meta = message_meta(m)
    if meta["text"]:
        t = meta["text"].replace("\n", " ")
        return f"{KIND_NAMES[meta['kind']][0]}: {t[:60]}{'…' if len(t) > 60 else ''}"
    return KIND_NAMES[meta["kind"]][0]


def create(kind: str, admin_id: int, target: int | None = None, options: dict | None = None) -> int:
    cur = db.execute("INSERT INTO broadcasts (kind, admin_id, status, created, options, target) "
                     "VALUES (?, ?, 'draft', ?, ?, ?)",
                     (kind, admin_id, now(), json.dumps(options or {}), target))
    db.commit()
    return cur.lastrowid


def get(bc_id: int):
    return db.execute("SELECT * FROM broadcasts WHERE id=?", (bc_id,)).fetchone()


def options(bc_id: int) -> dict:
    row = get(bc_id)
    try:
        return json.loads(row["options"] or "{}") if row else {}
    except ValueError:
        return {}


def set_options(bc_id: int, **kw) -> dict:
    o = options(bc_id)
    o.update(kw)
    db.execute("UPDATE broadcasts SET options=? WHERE id=?", (json.dumps(o), bc_id))
    db.commit()
    return o


def set_status(bc_id: int, status: str, **fields) -> None:
    sets = ", ".join(["status=?"] + [f"{k}=?" for k in fields])
    db.execute(f"UPDATE broadcasts SET {sets} WHERE id=?", (status, *fields.values(), bc_id))
    db.commit()


def add_item(bc_id: int, m: Message, html: str = "") -> None:
    meta = message_meta(m, html)
    db.execute("INSERT INTO bc_items (bc_id, chat_id, message_id, media_group_id, kind, meta) "
               "VALUES (?, ?, ?, ?, ?, ?)",
               (bc_id, m.chat.id, m.message_id, m.media_group_id, meta["kind"], json.dumps(meta)))
    db.commit()


def items(bc_id: int):
    return db.execute("SELECT * FROM bc_items WHERE bc_id=? ORDER BY id", (bc_id,)).fetchall()


def units(rows) -> list[list]:
    """Склеить подряд идущие сообщения одного альбома (media_group_id) в одну единицу."""
    res: list[list] = []
    for r in rows:
        if res and r["media_group_id"] and res[-1][0]["media_group_id"] == r["media_group_id"]:
            res[-1].append(r)
        else:
            res.append([r])
    return res


def remove_last_unit(bc_id: int) -> bool:
    us = units(items(bc_id))
    if not us:
        return False
    db.executemany("DELETE FROM bc_items WHERE id=?", [(r["id"],) for r in us[-1]])
    db.commit()
    return True


def _kind_name(kind: str, n: int) -> str:
    one, many = KIND_NAMES.get(kind, KIND_NAMES["other"])
    return one if n == 1 else many


def draft_summary(rows) -> str:
    """«1 текст, 3 фото (альбом), 1 стикер» — одиночные одного вида складываются."""
    order: list = []
    singles: dict[str, int] = {}
    for u in units(rows):
        if len(u) > 1:
            kinds = {r["kind"] for r in u}
            name = _kind_name(kinds.pop(), len(u)) if len(kinds) == 1 else "файла"
            order.append(f"{len(u)} {name} (альбом)")
        else:
            k = u[0]["kind"]
            if k not in singles:
                order.append(("single", k))
            singles[k] = singles.get(k, 0) + 1
    out = [f"{singles[x[1]]} {_kind_name(x[1], singles[x[1]])}" if isinstance(x, tuple) else x
           for x in order]
    return ", ".join(out) or "пусто"


# ============================================================ получатели ===

GROUPS = {
    "online": "Сейчас в сети",
    "a24": "Активные за 24 часа",
    "a7": "Активные за 7 дней",
    "inactive": "Неактивные 30+ дней",
    "awg": "С устройствами AWG",
    "sub": "С подпиской",
    "all": "Все одобренные",
    "pending": "Ожидают одобрения",
    "manual": "Выбранные вручную",
    "admins": "Только админы (тест)",
}


def _iso_ago(seconds: float) -> str:
    return (datetime.now() - timedelta(seconds=seconds)).isoformat(timespec="seconds")


def recipients(group: str, manual: list[int] | None = None, online: set[int] | None = None) -> list[int]:
    ok = "status='approved' AND blocked_bot=0"
    q = lambda sql, *a: [r[0] for r in db.execute(sql, a)]
    if group == "online":
        if online is None:
            from .traffic import online_users
            online = online_users()
        approved = set(q(f"SELECT chat_id FROM users WHERE {ok}"))
        return sorted(set(online) & approved)
    if group in ("a24", "a7"):
        cut = _iso_ago(86400 if group == "a24" else 7 * 86400)
        return q(f"SELECT chat_id FROM users WHERE {ok} AND (COALESCE(last_seen_bot, '') >= ? "
                 f"OR COALESCE(last_online, '') >= ?)", cut, cut)
    if group == "inactive":
        return q(f"SELECT chat_id FROM users WHERE {ok} AND COALESCE(last_online, '') < ?",
                 _iso_ago(30 * 86400))
    if group == "awg":
        return q(f"SELECT chat_id FROM users u WHERE {ok} AND EXISTS "
                 f"(SELECT 1 FROM devices d WHERE d.chat_id=u.chat_id)")
    if group == "sub":
        return q(f"SELECT chat_id FROM users u WHERE {ok} AND sub_token IS NOT NULL AND "
                 f"(uuid IS NOT NULL OR EXISTS (SELECT 1 FROM sub_devices s "
                 f"WHERE s.chat_id=u.chat_id))")
    if group == "all":
        return q(f"SELECT chat_id FROM users WHERE {ok}")
    if group == "pending":
        return q("SELECT chat_id FROM users WHERE status='pending' AND blocked_bot=0")
    if group == "manual":
        return sorted(set(manual or []))
    if group == "admins":
        return sorted(ADMIN_IDS)
    return []


def group_counts() -> dict[str, int]:
    try:
        from .traffic import online_users
        online = online_users()
    except Exception as e:
        log.debug("online users: %s", e)
        online = set()
    return {g: len(recipients(g, online=online)) for g in GROUPS if g != "manual"}


def enqueue(bc_id: int, chat_ids: list[int]) -> int:
    db.executemany("INSERT OR IGNORE INTO bc_queue (bc_id, chat_id) VALUES (?, ?)",
                   [(bc_id, c) for c in chat_ids])
    db.execute("UPDATE broadcasts SET total=(SELECT COUNT(*) FROM bc_queue WHERE bc_id=?) "
               "WHERE id=?", (bc_id, bc_id))
    db.commit()
    return len(chat_ids)


def counts(bc_id: int) -> dict[str, int]:
    res = {"pending": 0, "sent": 0, "failed": 0, "blocked": 0}
    for r in db.execute("SELECT status, COUNT(*) FROM bc_queue WHERE bc_id=? GROUP BY status",
                        (bc_id,)):
        res[r[0]] = r[1]
    return res


def parse_msk(s: str) -> float | None:
    """«ДД.ММ ЧЧ:ММ», «ДД.ММ.ГГГГ ЧЧ:ММ» или «ЧЧ:ММ» по Москве -> unix-время (только будущее)."""
    s = " ".join(s.split())
    nowm = datetime.now(MSK)
    candidates = []
    try:
        candidates.append(datetime.strptime(s, "%d.%m.%Y %H:%M"))
    except ValueError:
        pass
    try:   # без года: этот год, а если уже прошло — следующий
        for y in (nowm.year, nowm.year + 1):
            candidates.append(datetime.strptime(f"{s} {y}", "%d.%m %H:%M %Y"))
    except ValueError:
        pass
    try:   # только время: сегодня, а если уже прошло — завтра
        t = datetime.strptime(s, "%H:%M")
        for d in (0, 1):
            day = nowm + timedelta(days=d)
            candidates.append(datetime(day.year, day.month, day.day, t.hour, t.minute))
    except ValueError:
        pass
    for dt in candidates:
        ts = dt.replace(tzinfo=MSK).timestamp()
        if ts > time.time():
            return ts
    return None


def fmt_msk(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, MSK).strftime("%d.%m %H:%M МСК") if ts else "—"


# ============================================================ отправка ===

def link_markup(o: dict):
    link = o.get("link")
    if not link:
        return None
    if link.get("url"):
        return kb([btn(link["text"], url=link["url"])])
    sec = link.get("section")
    return kb([btn(link.get("text") or SECTIONS.get(sec, "Открыть"), sec)])


def strip_custom_entities(meta: dict) -> list[MessageEntity]:
    return [MessageEntity(**e) for e in meta.get("entities", []) if e.get("type") != "custom_emoji"]


async def _fallback_single(bot: Bot, chat_id: int, r, markup, silent: bool) -> int:
    """Отправка без кастомных эмодзи (у владельца бота нет Premium)."""
    meta = json.loads(r["meta"] or "{}")
    ents = strip_custom_entities(meta)
    if meta["kind"] == "rich" and meta.get("html"):
        from .ui import strip_custom
        html, mk = strip_custom(meta["html"], markup)
        m = await bot.send_rich_message(chat_id=chat_id, rich_message=rich(html), reply_markup=mk,
                                        disable_notification=silent)
        return m.message_id
    if meta["kind"] == "text":
        m = await bot.send_message(chat_id, meta["text"], entities=ents, parse_mode=None,
                                   reply_markup=markup, disable_notification=silent)
        return m.message_id
    res = await bot.copy_message(chat_id, r["chat_id"], r["message_id"], caption=meta["text"] or None,
                                 caption_entities=ents if meta["text"] else None, parse_mode=None,
                                 reply_markup=markup, disable_notification=silent)
    return res.message_id


async def _fallback_album(bot: Bot, chat_id: int, unit, silent: bool) -> list[int]:
    media = []
    for r in unit:
        meta = json.loads(r["meta"] or "{}")
        cls = {"photo": InputMediaPhoto, "video": InputMediaVideo, "document": InputMediaDocument,
               "audio": InputMediaAudio}.get(meta["kind"])
        if not cls or not meta.get("file_id"):
            raise RuntimeError("альбом нельзя пересобрать")
        kw = {"media": meta["file_id"]}
        if meta["text"]:
            kw.update(caption=meta["text"], caption_entities=strip_custom_entities(meta),
                      parse_mode=None)
        media.append(cls(**kw))
    msgs = await bot.send_media_group(chat_id, media, disable_notification=silent)
    return [m.message_id for m in msgs]


async def send_units(bot: Bot, chat_id: int, us: list[list], o: dict, state: dict,
                     extra_markup=None) -> list[int]:
    """Скопировать черновик одному получателю. state["emoji_fallback"] — переключатель на
    отправку без кастомных эмодзи (запоминается на всю рассылку)."""
    silent = bool(o.get("silent"))
    markup = extra_markup or link_markup(o)
    ids: list[int] = []
    for i, unit in enumerate(us):
        last = i == len(us) - 1
        mk = markup if last and len(unit) == 1 else None
        if len(unit) > 1:
            try:
                if state.get("emoji_fallback") and any(json.loads(r["meta"]).get("custom") for r in unit):
                    raise _NeedFallback()
                res = await bot.copy_messages(chat_id, unit[0]["chat_id"],
                                              [r["message_id"] for r in unit],
                                              disable_notification=silent)
                ids += [x.message_id for x in res]
            except (_NeedFallback, TelegramBadRequest) as e:
                if isinstance(e, TelegramBadRequest) and not emoji_error(e):
                    raise
                state["emoji_fallback"] = True
                ids += await _fallback_album(bot, chat_id, unit, silent)
            await asyncio.sleep(len(unit) / RATE)
        else:
            r = unit[0]
            meta = json.loads(r["meta"] or "{}")
            try:
                if state.get("emoji_fallback") and meta.get("custom"):
                    raise _NeedFallback()
                res = await bot.copy_message(chat_id, r["chat_id"], r["message_id"],
                                             reply_markup=mk, disable_notification=silent)
                ids.append(res.message_id)
            except (_NeedFallback, TelegramBadRequest) as e:
                if isinstance(e, TelegramBadRequest) and not (emoji_error(e) or meta["kind"] == "rich"):
                    raise
                if isinstance(e, TelegramBadRequest) and emoji_error(e):
                    state["emoji_fallback"] = True
                ids.append(await _fallback_single(bot, chat_id, r, mk, silent))
            await asyncio.sleep(1 / RATE)
        if last and markup is not None and len(unit) > 1:
            m = await bot.send_message(chat_id, "👇", reply_markup=markup, disable_notification=silent)
            ids.append(m.message_id)
    return ids


class _NeedFallback(Exception):
    pass


# =========================================================== очередь ===

_running: dict[int, asyncio.Task] = {}
_progress_cb = None            # async (bot, bc_id, final: bool) -> None — из handlers


def set_progress_callback(cb) -> None:
    global _progress_cb
    _progress_cb = cb


def mark_blocked(chat_id: int) -> None:
    db.execute("UPDATE users SET blocked_bot=1 WHERE chat_id=?", (chat_id,))
    db.commit()


def record_conversation(chat_id: int, direction: str, admin_id: int | None, summary: str,
                        src_chat: int | None = None, src_msg: int | None = None) -> None:
    db.execute("INSERT INTO conversations (chat_id, direction, admin_id, ts, summary, src_chat, "
               "src_msg) VALUES (?, ?, ?, ?, ?, ?, ?)",
               (chat_id, direction, admin_id, now(), summary[:300], src_chat, src_msg))
    db.commit()


async def _deliver(bot: Bot, bc, us, o: dict, chat_id: int, state: dict) -> None:
    extra = None
    if bc["kind"] == "personal":
        extra = kb([btn("Ответить", "urep", icon="reply")])
    for attempt in range(4):
        try:
            ids = await send_units(bot, chat_id, us, o, state, extra_markup=extra)
            if o.get("pin") and ids:
                try:
                    await bot.pin_chat_message(chat_id, ids[0], disable_notification=True)
                except Exception as e:
                    log.debug("pin failed: %s", e)
            db.execute("UPDATE bc_queue SET status='sent', message_ids=?, sent_at=?, error=NULL "
                       "WHERE bc_id=? AND chat_id=?", (json.dumps(ids), time.time(), bc["id"], chat_id))
            db.commit()
            return
        except TelegramRetryAfter as e:
            await asyncio.sleep(e.retry_after + 1)
        except TelegramForbiddenError as e:
            mark_blocked(chat_id)
            db.execute("UPDATE bc_queue SET status='blocked', error=? WHERE bc_id=? AND chat_id=?",
                       (str(e)[:200], bc["id"], chat_id))
            db.commit()
            return
        except (TelegramNetworkError, TelegramServerError) as e:
            log.warning("broadcast %s -> %s: network error %s", bc["id"], chat_id, e)
            await asyncio.sleep(2 * (attempt + 1))
        except Exception as e:
            err = str(e)
            status = "blocked" if "chat not found" in err.lower() or "deactivated" in err.lower() else "failed"
            if status == "blocked":
                mark_blocked(chat_id)
            db.execute("UPDATE bc_queue SET status=?, error=? WHERE bc_id=? AND chat_id=?",
                       (status, err[:200], bc["id"], chat_id))
            db.commit()
            return
    db.execute("UPDATE bc_queue SET status='failed', error='сеть' WHERE bc_id=? AND chat_id=?",
               (bc["id"], chat_id))
    db.commit()


async def _worker(bot: Bot, bc_id: int) -> None:
    bc = get(bc_id)
    if not bc:
        return
    o = options(bc_id)
    us = units(items(bc_id))
    state = {"emoji_fallback": bool(bc["emoji_fallback"])}
    if not bc["started_at"]:
        db.execute("UPDATE broadcasts SET started_at=? WHERE id=?", (time.time(), bc_id))
        db.commit()
    last_progress = 0.0
    try:
        while True:
            bc = get(bc_id)
            if not bc or bc["status"] != "sending":
                break
            row = db.execute("SELECT chat_id FROM bc_queue WHERE bc_id=? AND status='pending' "
                             "ORDER BY rowid LIMIT 1", (bc_id,)).fetchone()
            if not row:
                set_status(bc_id, "done", finished_at=time.time(),
                           emoji_fallback=int(state["emoji_fallback"]))
                if bc["kind"] == "personal":
                    record_conversation(bc["target"], "out", bc["admin_id"],
                                        draft_summary(items(bc_id)), *_first_src(bc_id))
                break
            await _deliver(bot, bc, us, o, row["chat_id"], state)
            if state["emoji_fallback"] and not bc["emoji_fallback"]:
                db.execute("UPDATE broadcasts SET emoji_fallback=1 WHERE id=?", (bc_id,))
                db.commit()
            if _progress_cb and time.time() - last_progress > 2:
                last_progress = time.time()
                await _progress_cb(bot, bc_id, False)
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("broadcast %s worker failed", bc_id)
        set_status(bc_id, "paused")
    finally:
        _running.pop(bc_id, None)
        if _progress_cb:
            try:
                await _progress_cb(bot, bc_id, True)
            except Exception as e:
                log.debug("progress final failed: %s", e)


def _first_src(bc_id: int) -> tuple[int | None, int | None]:
    r = db.execute("SELECT chat_id, message_id FROM bc_items WHERE bc_id=? ORDER BY id LIMIT 1",
                   (bc_id,)).fetchone()
    return (r[0], r[1]) if r else (None, None)


def start(bot: Bot, bc_id: int) -> None:
    set_status(bc_id, "sending")
    if bc_id not in _running:
        _running[bc_id] = asyncio.create_task(_worker(bot, bc_id))


def stop(bc_id: int) -> None:
    bc = get(bc_id)
    if bc and bc["status"] == "sending":
        set_status(bc_id, "paused")


async def resume(bot: Bot) -> None:
    """После перезапуска бота — продолжить рассылки с места остановки."""
    for r in db.execute("SELECT id FROM broadcasts WHERE status='sending'").fetchall():
        log.info("broadcast %s: продолжаю после перезапуска", r["id"])
        start(bot, r["id"])


async def broadcast_loop(bot: Bot) -> None:
    """Отложенные рассылки."""
    while True:
        try:
            for r in db.execute("SELECT id FROM broadcasts WHERE status='scheduled' AND "
                                "scheduled_at <= ?", (time.time(),)).fetchall():
                start(bot, r["id"])
        except Exception as e:
            log.warning("broadcast loop: %s", e)
        await asyncio.sleep(20)


async def delete_everywhere(bot: Bot, bc_id: int) -> tuple[int, int]:
    """Удалить разосланное у всех (deleteMessages по сохранённым id). (удалено, ошибок)."""
    ok = fail = 0
    for r in db.execute("SELECT chat_id, message_ids FROM bc_queue WHERE bc_id=? AND "
                        "status='sent'", (bc_id,)).fetchall():
        ids = json.loads(r["message_ids"] or "[]")
        for i in range(0, len(ids), 100):
            try:
                await bot.delete_messages(r["chat_id"], ids[i:i + 100])
                ok += 1
            except TelegramRetryAfter as e:
                await asyncio.sleep(e.retry_after + 1)
                fail += 1
            except Exception as e:
                log.debug("delete %s: %s", r["chat_id"], e)
                fail += 1
            await asyncio.sleep(1 / RATE)
    db.execute("UPDATE bc_queue SET status='deleted' WHERE bc_id=? AND status='sent'", (bc_id,))
    db.commit()
    return ok, fail


def history(limit: int = 10):
    return db.execute("SELECT * FROM broadcasts WHERE status NOT IN ('draft', 'cancelled') "
                      "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def conversation_rows(chat_id: int, limit: int = 15):
    return db.execute("SELECT * FROM conversations WHERE chat_id=? ORDER BY id DESC LIMIT ?",
                      (chat_id, limit)).fetchall()


def conversation_view(chat_id: int) -> str:
    """Переписка с человеком — HTML для карточки пользователя в админке."""
    rows = conversation_rows(chat_id)
    if not rows:
        return ""
    from .ui import esc, table
    return table([[(em("send") if r["direction"] == "out" else em("reply")),
                   esc((r["ts"] or "")[5:16].replace("T", " ")), esc(r["summary"])]
                  for r in reversed(rows)],
                 head=["", "Когда", "Сообщение"], caption=f"{em('message')} Переписка")
