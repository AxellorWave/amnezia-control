"""Админка → «Рассылка», личные сообщения пользователю и ответы пользователей админам."""
import asyncio
import logging
import time

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message

from .. import broadcast as B
from ..access import has_access, is_admin
from ..config import ADMIN_IDS
from ..db import db, get_user
from ..ui import (btn, em, esc, kb, kv, notify, send_view, show, table, user_table,
                  with_emoji_fallback)
from .admin import admin_only

log = logging.getLogger("amnezia-bot")
router = Router()

SUMMARY_DELAY = 1.2             # пауза, чтобы на альбом пришла одна сводка
MANUAL_PAGE = 15


class BC(StatesGroup):
    collect = State()           # админ присылает сообщения в черновик
    link = State()              # текст и URL кнопки
    sched = State()             # время отложенной отправки
    search = State()            # поиск при ручном выборе получателей


class UMsg(StatesGroup):
    collect = State()           # пользователь пишет администратору


_summary_tasks: dict[int, asyncio.Task] = {}
_reply_tasks: dict[int, asyncio.Task] = {}


# ============================================================ раздел ===

def section_view() -> tuple[str, object]:
    active = db.execute("SELECT * FROM broadcasts WHERE status IN ('sending', 'paused', "
                        "'scheduled') ORDER BY id DESC").fetchall()
    text = (f"<h2>{em('broadcast')} Рассылка</h2>"
            f"<p>Собери черновик из любых сообщений (текст с премиум-эмодзи, фото, альбомы, "
            f"видео, стикеры, опросы…), посмотри предпросмотр, выбери получателей и отправь.</p>")
    rows = [[btn("Новая рассылка", "bc:new", style="primary", icon="draft")],
            [btn("Обновите подписку", "bc:tpl:sub", icon="subscription")]]
    if active:
        text += table([[f"#{b['id']}", status_name(b), progress_line(b["id"])] for b in active],
                      head=["", "Состояние", "Прогресс"], caption="Сейчас")
        for b in active:
            rows.append([btn(f"#{b['id']} — {status_name(b, plain=True)}", f"bch:{b['id']}",
                             icon="history")])
    rows.append([btn("История", "bch", icon="history")])
    rows.append([btn("Админка", "adm", icon="back")])
    return text, kb(*rows)


STATUS_NAMES = {"sending": "отправляется", "paused": "на паузе", "scheduled": "запланирована",
                "done": "отправлена", "draft": "черновик", "cancelled": "отменена"}


def status_name(b, plain: bool = False) -> str:
    s = STATUS_NAMES.get(b["status"], b["status"])
    if b["status"] == "scheduled":
        s += f" на {B.fmt_msk(b['scheduled_at'])}"
    return s if plain else esc(s)


def progress_line(bc_id: int) -> str:
    c = B.counts(bc_id)
    return (f"{em('ok')} {c['sent']} · {em('no')} {c['failed']} · {em('denied')} {c['blocked']} · "
            f"{em('pending')} {c['pending']}")


@router.callback_query(F.data == "bc")
@admin_only
async def cb_section(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await show(cb, *section_view())
    await cb.answer()


# ======================================================= сбор черновика ===

def collect_prompt(personal_to=None) -> str:
    who = (f"<p>Кому: {esc(personal_to['name'] or personal_to['chat_id'])}</p>"
           if personal_to else "")
    return (f"<h3>{em('draft')} {'Сообщение пользователю' if personal_to else 'Новая рассылка'}</h3>"
            + who +
            f"<p>Присылай сообщения подряд — любые: текст с форматированием и премиум-эмодзи, "
            f"фото, видео, альбомы, документы, голосовые, кружки, стикеры, GIF, опросы. "
            f"Можно переслать готовое rich-сообщение.</p>"
            f"<blockquote>{em('idea')} Rich-статья в разметке бота: начни текст с "
            f"<code>rich:</code>, дальше HTML (<code>&lt;h3&gt;</code>, <code>&lt;table&gt;</code>, "
            f"<code>&lt;blockquote&gt;</code>…).</blockquote>"
            f"<p>Когда закончишь — «Готово».</p>")


def collect_kb():
    return kb([btn("Готово", "bcd:done", style="success", icon="ok")],
              [btn("Убрать последнее", "bcd:undo", icon="reset"),
               btn("Отменить", "bcd:cancel", icon="trash")])


@router.callback_query(F.data == "bc:new")
@admin_only
async def cb_new(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    bc_id = B.create("mass", cb.from_user.id, options={"group": "all"})
    await state.set_state(BC.collect)
    await state.update_data(bc_id=bc_id)
    await show(cb, collect_prompt(), kb([btn("Отменить", "bcd:cancel", icon="no")]))
    await cb.answer()


@router.callback_query(F.data.startswith("msg:"))
@admin_only
async def cb_personal(cb: CallbackQuery, state: FSMContext):
    chat_id = int(cb.data[4:])
    u = get_user(chat_id)
    if not u:
        return await cb.answer("Пользователь не найден", show_alert=True)
    await state.clear()
    bc_id = B.create("personal", cb.from_user.id, target=chat_id,
                     options={"group": "manual", "manual": [chat_id]})
    await state.set_state(BC.collect)
    await state.update_data(bc_id=bc_id)
    await show(cb, collect_prompt(u), kb([btn("Отменить", "bcd:cancel", icon="no")]))
    await cb.answer()


async def current_draft(state: FSMContext):
    bc_id = (await state.get_data()).get("bc_id")
    bc = B.get(bc_id) if bc_id else None
    return bc if bc and bc["status"] == "draft" else None


async def _send_summary(bot: Bot, chat_id: int, state: FSMContext) -> None:
    await asyncio.sleep(SUMMARY_DELAY)
    bc = await current_draft(state)
    if not bc:
        return
    data = await state.get_data()
    old = data.get("summary_msg")
    if old:
        try:
            await bot.delete_message(chat_id, old)
        except Exception:
            pass
    m = await send_view(bot, chat_id, f"<p>{em('draft')} <b>В черновике:</b> "
                                      f"{esc(B.draft_summary(B.items(bc['id'])))}</p>", collect_kb())
    await state.update_data(summary_msg=m.message_id if m else None)


def schedule_summary(bot: Bot, chat_id: int, state: FSMContext) -> None:
    t = _summary_tasks.get(chat_id)
    if t and not t.done():
        t.cancel()
    _summary_tasks[chat_id] = asyncio.create_task(_send_summary(bot, chat_id, state))


@router.message(BC.collect)
async def collect(m: Message, state: FSMContext, bot: Bot):
    if not is_admin(m.from_user.id):
        return await state.clear()
    bc = await current_draft(state)
    if not bc:
        await state.clear()
        return await show(m, "<p>Черновик устарел — начни заново в разделе «Рассылка».</p>")
    if m.text and m.text.lstrip().lower().startswith("rich:"):
        html = m.text.lstrip()[5:].strip()
        try:
            sent = await send_view(bot, m.chat.id, html)
        except Exception as e:
            return await show(m, f"<p>{em('warn')} Не получилось собрать rich-сообщение: "
                                 f"<code>{esc(str(e)[:200])}</code></p>")
        B.add_item(bc["id"], sent, html=html)
    else:
        B.add_item(bc["id"], m)
    schedule_summary(bot, m.chat.id, state)


@router.callback_query(F.data == "bcd:undo")
@admin_only
async def cb_undo(cb: CallbackQuery, state: FSMContext):
    bc = await current_draft(state)
    if not bc:
        return await cb.answer("Черновик устарел", show_alert=True)
    B.remove_last_unit(bc["id"])
    await show(cb, f"<p>{em('draft')} <b>В черновике:</b> "
                   f"{esc(B.draft_summary(B.items(bc['id'])))}</p>", collect_kb())
    await cb.answer("Убрано")


@router.callback_query(F.data == "bcd:cancel")
@admin_only
async def cb_cancel(cb: CallbackQuery, state: FSMContext):
    bc = await current_draft(state)
    if bc:
        B.set_status(bc["id"], "cancelled")
    await state.clear()
    await show(cb, f"<p>{em('trash')} Черновик удалён.</p>",
               kb([btn("Рассылка", "bc", icon="broadcast")]))
    await cb.answer()


@router.callback_query(F.data == "bcd:done")
@admin_only
async def cb_done(cb: CallbackQuery, state: FSMContext, bot: Bot):
    bc = await current_draft(state)
    if not bc:
        return await cb.answer("Черновик устарел", show_alert=True)
    if not B.items(bc["id"]):
        return await cb.answer("Черновик пуст — пришли хотя бы одно сообщение", show_alert=True)
    await state.set_state(None)
    await cb.answer()
    await preview(bot, cb.message.chat.id, bc["id"])
    if bc["kind"] == "personal":
        await send_view(bot, cb.message.chat.id, *confirm_view(bc["id"]))
    else:
        await send_view(bot, cb.message.chat.id, *recipients_view(bc["id"]))


async def preview(bot: Bot, chat_id: int, bc_id: int) -> None:
    await send_view(bot, chat_id, f"<p>{em('draft')} <b>Предпросмотр</b> — так увидят "
                                  f"получатели:</p>")
    o = B.options(bc_id)
    extra = kb([btn("Ответить", "urep", icon="reply")]) if B.get(bc_id)["kind"] == "personal" else None
    try:
        await B.send_units(bot, chat_id, B.units(B.items(bc_id)), o, {}, extra_markup=extra)
    except Exception as e:
        await send_view(bot, chat_id, f"<p>{em('warn')} Предпросмотр не удался: "
                                      f"<code>{esc(str(e)[:300])}</code></p>")


# ============================================================ получатели ===

def recipients_view(bc_id: int) -> tuple[str, object]:
    o = B.options(bc_id)
    cnt = B.group_counts()
    cnt["manual"] = len(o.get("manual") or [])
    cur = o.get("group", "all")
    text = (f"<h3>{em('group')} Кому отправить?</h3>"
            + table([[em("ok") if g == cur else "", esc(name), f"<b>{cnt.get(g, 0)}</b>"]
                     for g, name in B.GROUPS.items()], head=["", "Группа", "Людей"]))
    rows = []
    for g, name in B.GROUPS.items():
        if g == "manual":
            rows.append([btn(f"{name} ({cnt['manual']})", "bcm:p:0", icon="users")])
        else:
            rows.append([btn(f"{name} ({cnt.get(g, 0)})", f"bcr:{g}",
                             icon="ok" if g == cur else None)])
    rows.append([btn("Дальше", "bco", style="primary", icon="send")])
    rows.append([btn("Отменить", "bcd:cancel", icon="no")])
    return text, kb(*rows)


async def draft_or_alert(cb: CallbackQuery, state: FSMContext):
    bc = await current_draft(state)
    if not bc:
        await cb.answer("Черновик устарел — начни заново", show_alert=True)
    return bc


@router.callback_query(F.data.startswith("bcr:"))
@admin_only
async def cb_group(cb: CallbackQuery, state: FSMContext):
    bc = await draft_or_alert(cb, state)
    if not bc:
        return
    g = cb.data[4:]
    if g in B.GROUPS:
        B.set_options(bc["id"], group=g)
    await show(cb, *(await asyncio.to_thread(recipients_view, bc["id"])))
    await cb.answer()


def manual_view(bc_id: int, page: int, q: str = "") -> tuple[str, object]:
    o = B.options(bc_id)
    chosen = set(o.get("manual") or [])
    sql = "SELECT * FROM users WHERE status IN ('approved', 'pending')"
    args: list = []
    if q:
        sql += " AND (name LIKE ? OR username LIKE ? OR CAST(chat_id AS TEXT) LIKE ?)"
        args = [f"%{q}%"] * 3
    users = db.execute(sql + " ORDER BY name", args).fetchall()
    pages = max(1, (len(users) + MANUAL_PAGE - 1) // MANUAL_PAGE)
    page = min(max(page, 0), pages - 1)
    rows = []
    for u in users[page * MANUAL_PAGE:(page + 1) * MANUAL_PAGE]:
        who = f"@{u['username']}" if u["username"] else str(u["chat_id"])
        rows.append([btn(f"{u['name'] or 'без имени'} · {who}", f"bcm:t:{u['chat_id']}:{page}",
                         icon="ok" if u["chat_id"] in chosen else "offline")])
    nav = []
    if page > 0:
        nav.append(btn("‹", f"bcm:p:{page - 1}"))
    if page < pages - 1:
        nav.append(btn("›", f"bcm:p:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append([btn("Поиск", "bcm:s", icon="question"),
                 btn("Сбросить выбор", "bcm:clr", icon="reset")])
    rows.append([btn(f"Готово ({len(chosen)})", "bcm:done", style="success", icon="ok")])
    text = (f"<h3>{em('users')} Выбор получателей</h3>"
            f"<p>Выбрано: <b>{len(chosen)}</b>. Страница {page + 1} из {pages}"
            + (f" · поиск: <code>{esc(q)}</code>" if q else "") + "</p>")
    return text, kb(*rows)


@router.callback_query(F.data.startswith("bcm:"))
@admin_only
async def cb_manual(cb: CallbackQuery, state: FSMContext):
    bc = await draft_or_alert(cb, state)
    if not bc:
        return
    parts = cb.data.split(":")
    q = (await state.get_data()).get("q", "")
    page = 0
    if parts[1] == "t":
        cid, page = int(parts[2]), int(parts[3])
        chosen = set(B.options(bc["id"]).get("manual") or [])
        chosen ^= {cid}
        B.set_options(bc["id"], manual=sorted(chosen), group="manual")
    elif parts[1] == "p":
        page = int(parts[2])
    elif parts[1] == "clr":
        B.set_options(bc["id"], manual=[])
    elif parts[1] == "s":
        await state.set_state(BC.search)
        await show(cb, f"<p>{em('question')} Пришли часть имени, @username или ID. "
                       f"Пустой поиск — «-».</p>", kb([btn("Назад", "bcm:p:0", icon="back")]))
        return await cb.answer()
    elif parts[1] == "done":
        B.set_options(bc["id"], group="manual")
        await show(cb, *(await asyncio.to_thread(recipients_view, bc["id"])))
        return await cb.answer()
    await show(cb, *manual_view(bc["id"], page, q))
    await cb.answer()


@router.message(BC.search, F.text)
async def search_input(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return await state.clear()
    bc = await current_draft(state)
    if not bc:
        await state.clear()
        return
    q = "" if m.text.strip() == "-" else m.text.strip().lstrip("@")[:50]
    await state.set_state(None)
    await state.update_data(q=q)
    await show(m, *manual_view(bc["id"], 0, q))


# ============================================================== опции ===

def options_view(bc_id: int) -> tuple[str, object]:
    o = B.options(bc_id)
    n = len(B.recipients(o.get("group", "all"), o.get("manual")))
    link = o.get("link")
    link_s = ("нет" if not link else
              f"«{esc(link['text'])}» → {esc(link.get('url') or B.SECTIONS.get(link.get('section'), ''))}")
    text = (f"<h3>{em('broadcast')} Параметры</h3>"
            + kv([(f"{em('group')} Получатели",
                   f"{esc(B.GROUPS.get(o.get('group', 'all')))} — <b>{n}</b>"),
                  ("Без звука", "да" if o.get("silent") else "нет"),
                  ("Закрепить первое", "да" if o.get("pin") else "нет"),
                  (f"{em('link')} Кнопка", link_s),
                  (f"{em('schedule')} Когда", B.fmt_msk(o.get("at")) if o.get("at") else "сразу")]))
    return text, kb(
        [btn("Без звука: вкл/выкл", "bco:silent", icon="bell"),
         btn("Закрепить: вкл/выкл", "bco:pin", icon="pin")],
        [btn("Кнопка под сообщением", "bco:link", icon="link")],
        [btn("Отложить", "bco:sched", icon="schedule"), btn("Сразу", "bco:snow", icon="send")],
        [btn("Получатели", "bco:rcp", icon="group")],
        [btn("Дальше", "bcs", style="primary", icon="send")],
        [btn("Отменить", "bcd:cancel", icon="no")])


@router.callback_query(F.data.startswith("bco"))
@admin_only
async def cb_options(cb: CallbackQuery, state: FSMContext):
    bc = await draft_or_alert(cb, state)
    if not bc:
        return
    o = B.options(bc["id"])
    act = cb.data[4:]
    if act == "silent":
        B.set_options(bc["id"], silent=not o.get("silent"))
    elif act == "pin":
        B.set_options(bc["id"], pin=not o.get("pin"))
    elif act == "snow":
        B.set_options(bc["id"], at=None)
    elif act == "rcp":
        await show(cb, *(await asyncio.to_thread(recipients_view, bc["id"])))
        return await cb.answer()
    elif act == "link":
        rows = [[btn(name, f"bco:ls:{sec}")] for sec, name in B.SECTIONS.items()]
        rows.append([btn("Своя ссылка (URL)", "bco:lurl", icon="link")])
        rows.append([btn("Без кнопки", "bco:lnone", icon="no"), btn("Назад", "bco", icon="back")])
        await show(cb, f"<h3>{em('link')} Кнопка под последним сообщением</h3>"
                       f"<p>Переход в раздел бота или своя ссылка.</p>", kb(*rows))
        return await cb.answer()
    elif act.startswith("ls:"):
        sec = act[3:]
        if sec in B.SECTIONS:
            B.set_options(bc["id"], link={"text": B.SECTIONS[sec], "section": sec})
    elif act == "lnone":
        B.set_options(bc["id"], link=None)
    elif act == "lurl":
        await state.set_state(BC.link)
        await show(cb, f"<p>{em('link')} Пришли текст кнопки и ссылку через «|»:</p>"
                       f"<blockquote><code>Наш канал | https://t.me/example</code></blockquote>",
                   kb([btn("Назад", "bco", icon="back")]))
        return await cb.answer()
    elif act == "sched":
        await state.set_state(BC.sched)
        await show(cb, f"<p>{em('schedule')} Когда отправить? Время московское: "
                       f"<code>ДД.ММ ЧЧ:ММ</code> или <code>ЧЧ:ММ</code>.</p>",
                   kb([btn("Назад", "bco", icon="back")]))
        return await cb.answer()
    await state.set_state(None)
    await show(cb, *(await asyncio.to_thread(options_view, bc["id"])))
    await cb.answer()


@router.message(BC.link, F.text)
async def link_input(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return await state.clear()
    bc = await current_draft(state)
    if not bc:
        return await state.clear()
    text, _, url = m.text.partition("|")
    text, url = text.strip()[:60], url.strip()
    if not text or not url.startswith(("https://", "http://", "tg://")):
        return await show(m, f"<p>{em('warn')} Нужно «Текст | https://…».</p>",
                          kb([btn("Назад", "bco", icon="back")]))
    B.set_options(bc["id"], link={"text": text, "url": url})
    await state.set_state(None)
    await show(m, *(await asyncio.to_thread(options_view, bc["id"])))


@router.message(BC.sched, F.text)
async def sched_input(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return await state.clear()
    bc = await current_draft(state)
    if not bc:
        return await state.clear()
    ts = B.parse_msk(m.text)
    if not ts:
        return await show(m, f"<p>{em('warn')} Не понял время (или оно уже прошло). Пример: "
                             f"<code>25.12 10:00</code>.</p>", kb([btn("Назад", "bco", icon="back")]))
    B.set_options(bc["id"], at=ts)
    await state.set_state(None)
    await show(m, *(await asyncio.to_thread(options_view, bc["id"])))


# ======================================================= подтверждение ===

def confirm_view(bc_id: int) -> tuple[str, object]:
    bc = B.get(bc_id)
    o = B.options(bc_id)
    if bc["kind"] == "personal":
        u = get_user(bc["target"])
        return (f"<h3>{em('message')} Отправить сообщение?</h3>" + (user_table(u) if u else ""),
                kb([btn("Отправить", "bcgo", style="success", icon="send"),
                    btn("Отменить", "bcd:cancel", icon="no")]))
    n = len(B.recipients(o.get("group", "all"), o.get("manual")))
    when = f" {B.fmt_msk(o['at'])}" if o.get("at") else ""
    verb = "Запланировать на" + when + " для" if when else "Отправить"
    return (f"<h3>{em('broadcast')} {verb} {n} пользователям?</h3>"
            f"<p>{esc(B.draft_summary(B.items(bc_id)))}</p>",
            kb([btn("Да, отправить" if not when else "Запланировать", "bcgo", style="success",
                    icon="send")],
               [btn("Назад", "bco", icon="back"), btn("Отменить", "bcd:cancel", icon="no")]))


@router.callback_query(F.data == "bcs")
@admin_only
async def cb_confirm(cb: CallbackQuery, state: FSMContext):
    bc = await draft_or_alert(cb, state)
    if not bc:
        return
    o = B.options(bc["id"])
    if not B.recipients(o.get("group", "all"), o.get("manual")):
        return await cb.answer("В выбранной группе никого нет", show_alert=True)
    await show(cb, *(await asyncio.to_thread(confirm_view, bc["id"])))
    await cb.answer()


@router.callback_query(F.data == "bcgo")
@admin_only
async def cb_go(cb: CallbackQuery, state: FSMContext, bot: Bot):
    bc = await draft_or_alert(cb, state)
    if not bc:
        return
    await state.clear()                       # старые кнопки черновика больше не сработают
    o = B.options(bc["id"])
    ids = await asyncio.to_thread(B.recipients, o.get("group", "all"), o.get("manual"))
    if bc["kind"] == "personal":
        ids = [bc["target"]]
    if not ids:
        B.set_status(bc["id"], "cancelled")
        return await cb.answer("Некому отправлять", show_alert=True)
    B.enqueue(bc["id"], ids)
    db.execute("UPDATE broadcasts SET progress_chat=?, progress_msg=? WHERE id=?",
               (cb.message.chat.id, cb.message.message_id, bc["id"]))
    db.commit()
    await cb.answer()
    if o.get("at") and bc["kind"] != "personal":
        B.set_status(bc["id"], "scheduled", scheduled_at=o["at"])
        return await show(cb, f"<p>{em('schedule')} Рассылка #{bc['id']} запланирована на "
                              f"{B.fmt_msk(o['at'])} — {len(ids)} получателей.</p>",
                          kb([btn("Отменить рассылку", f"bcp:{bc['id']}", icon="stop")],
                             [btn("Рассылка", "bc", icon="broadcast")]))
    B.start(bot, bc["id"])
    await render_progress(bot, bc["id"], False)


# ============================================================= прогресс ===

async def render_progress(bot: Bot, bc_id: int, final: bool) -> None:
    bc = B.get(bc_id)
    if not bc or not bc["progress_chat"]:
        return
    c = B.counts(bc_id)
    total = bc["total"] or sum(c.values())
    if bc["kind"] == "personal" and bc["status"] == "done":
        u = get_user(bc["target"])
        ok = c["sent"] > 0
        text = (f"<p>{em('ok' if ok else 'warn')} "
                f"{'Сообщение доставлено' if ok else 'Не доставлено (бот заблокирован?)'}: "
                f"{esc((u['name'] if u else '') or bc['target'])}.</p>")
        markup = kb([btn("Карточка", f"u:{bc['target']}", icon="user")])
    else:
        head = {"sending": f"{em('broadcast')} Рассылка #{bc_id} идёт",
                "paused": f"{em('pause')} Рассылка #{bc_id} на паузе",
                "done": f"{em('ok')} Рассылка #{bc_id} завершена",
                "scheduled": f"{em('schedule')} Рассылка #{bc_id} запланирована"}.get(
                    bc["status"], f"Рассылка #{bc_id}")
        rows = [(f"{em('ok')} Отправлено", f"<b>{c['sent']}</b> из {total}"),
                (f"{em('no')} Ошибок", str(c["failed"])),
                (f"{em('denied')} Заблокировали бота", str(c["blocked"])),
                (f"{em('pending')} Осталось", str(c["pending"]))]
        text = f"<h3>{head}</h3>" + kv(rows)
        if bc["emoji_fallback"]:
            text += (f"<blockquote>{em('warn')} Премиум-эмодзи не отправились (нет Premium у "
                     f"владельца бота) — заменены на обычные.</blockquote>")
        if bc["status"] == "sending":
            markup = kb([btn("Остановить", f"bcp:{bc_id}", icon="pause")])
        elif bc["status"] == "paused":
            markup = kb([btn("Продолжить", f"bcpl:{bc_id}", icon="play")],
                        [btn("Рассылка", "bc", icon="broadcast")])
        else:
            markup = kb([btn("История", f"bch:{bc_id}", icon="history"),
                         btn("Рассылка", "bc", icon="broadcast")])
    try:
        await with_emoji_fallback(
            lambda t, mk: bot.edit_message_text(chat_id=bc["progress_chat"],
                                                message_id=bc["progress_msg"],
                                                rich_message=B.rich(t), reply_markup=mk),
            text, markup)
    except Exception as e:
        if "not modified" not in str(e):
            log.debug("progress edit: %s", e)
            if final:
                await notify(bot, bc["progress_chat"], text, markup)


B.set_progress_callback(render_progress)


@router.callback_query(F.data.startswith("bcp:"))
@admin_only
async def cb_stop(cb: CallbackQuery, bot: Bot):
    bc_id = int(cb.data[4:])
    bc = B.get(bc_id)
    if not bc:
        return await cb.answer("Не найдена", show_alert=True)
    if bc["status"] == "scheduled":
        B.set_status(bc_id, "cancelled")
        await show(cb, f"<p>{em('stop')} Отложенная рассылка #{bc_id} отменена.</p>",
                   kb([btn("Рассылка", "bc", icon="broadcast")]))
        return await cb.answer()
    B.stop(bc_id)
    await cb.answer("Останавливаю…")
    await render_progress(bot, bc_id, False)


@router.callback_query(F.data.startswith("bcpl:"))
@admin_only
async def cb_resume(cb: CallbackQuery, bot: Bot):
    bc_id = int(cb.data[5:])
    bc = B.get(bc_id)
    if not bc or bc["status"] != "paused":
        return await cb.answer("Нечего продолжать", show_alert=True)
    db.execute("UPDATE broadcasts SET progress_chat=?, progress_msg=? WHERE id=?",
               (cb.message.chat.id, cb.message.message_id, bc_id))
    db.commit()
    B.start(bot, bc_id)
    await cb.answer("Продолжаю")
    await render_progress(bot, bc_id, False)


# ============================================================== история ===

@router.callback_query(F.data == "bch")
@admin_only
async def cb_history(cb: CallbackQuery):
    hs = B.history(10)
    text = f"<h2>{em('history')} История рассылок</h2>"
    rows = []
    if hs:
        text += table([[f"#{b['id']}", esc((b["created"] or "")[:16].replace("T", " ")),
                        "личное" if b["kind"] == "personal" else "рассылка",
                        status_name(b), str(B.counts(b["id"])["sent"])] for b in hs],
                      head=["", "Создана", "Вид", "Состояние", "Доставлено"])
        rows = [[btn(f"#{b['id']} · {status_name(b, plain=True)}", f"bch:{b['id']}",
                     icon="history")] for b in hs]
    else:
        text += "<p>Пока пусто.</p>"
    rows.append([btn("Рассылка", "bc", icon="back")])
    await show(cb, text, kb(*rows))
    await cb.answer()


@router.callback_query(F.data.startswith("bch:"))
@admin_only
async def cb_history_item(cb: CallbackQuery):
    bc_id = int(cb.data[4:])
    bc = B.get(bc_id)
    if not bc:
        return await cb.answer("Не найдена", show_alert=True)
    c = B.counts(bc_id)
    text = (f"<h3>{em('history')} Рассылка #{bc_id}</h3>"
            + kv([("Состояние", status_name(bc)),
                  ("Содержимое", esc(B.draft_summary(B.items(bc_id)))),
                  ("Получатели", esc(B.GROUPS.get(B.options(bc_id).get("group", ""), "—"))),
                  (f"{em('ok')} Доставлено", str(c["sent"])),
                  (f"{em('no')} Ошибок", str(c["failed"])),
                  (f"{em('denied')} Заблокировали бота", str(c["blocked"])),
                  (f"{em('pending')} Осталось", str(c["pending"])),
                  ("Удалено у всех", str(c.get("deleted", 0)))]))
    rows = []
    if bc["status"] == "sending":
        rows.append([btn("Остановить", f"bcp:{bc_id}", icon="pause")])
    if bc["status"] == "paused":
        rows.append([btn("Продолжить", f"bcpl:{bc_id}", icon="play")])
    if c["sent"]:
        rows.append([btn("Удалить у всех", f"bcx:{bc_id}", style="danger", icon="trash")])
    rows.append([btn("История", "bch", icon="back")])
    await show(cb, text, kb(*rows))
    await cb.answer()


@router.callback_query(F.data.startswith("bcx:"))
@admin_only
async def cb_delete_ask(cb: CallbackQuery):
    bc_id = int(cb.data[4:])
    bc = B.get(bc_id)
    if not bc:
        return await cb.answer("Не найдена", show_alert=True)
    first = db.execute("SELECT MIN(sent_at) FROM bc_queue WHERE bc_id=? AND status='sent'",
                       (bc_id,)).fetchone()[0]
    note = ""
    if first and time.time() - first > B.DELETE_WINDOW:
        note = (f"<blockquote>{em('warn')} Прошло больше 48 часов — Telegram не даёт ботам "
                f"удалять такие сообщения, часть не удалится.</blockquote>")
    await show(cb, f"<h3>{em('trash')} Удалить рассылку #{bc_id} у всех получателей?</h3>{note}",
               kb([btn("Да, удалить", f"bcxok:{bc_id}", style="danger", icon="trash"),
                   btn("Отмена", f"bch:{bc_id}", icon="no")]))
    await cb.answer()


@router.callback_query(F.data.startswith("bcxok:"))
@admin_only
async def cb_delete(cb: CallbackQuery, bot: Bot):
    bc_id = int(cb.data[6:])
    await cb.answer("Удаляю…")
    await show(cb, f"<p>{em('pending')} Удаляю сообщения рассылки #{bc_id}…</p>")
    ok, fail = await B.delete_everywhere(bot, bc_id)
    await show(cb, f"<p>{em('ok')} Удалено у {ok} получателей"
                   + (f", не удалось: {fail}" if fail else "") + ".</p>",
               kb([btn("История", "bch", icon="history")]))


# ============================================== шаблон «Обновите подписку» ===

UPDATE_SUB_TEXT = (
    "{icon} <b>Обнови подписку</b>\n\n"
    "Настройки сервера изменились. Открой приложение (Happ, v2RayTun или Hiddify) и обнови "
    "подписку: потяни список серверов вниз или нажми «Обновить».\n\n"
    "Если VPN не подключается — открой бота и нажми «Не работает VPN».")


async def start_update_sub(target, bot: Bot, state: FSMContext | None = None) -> int:
    """Готовый черновик «Обновите подписку» → экран выбора получателей (группа «С подпиской»)."""
    admin_id = target.from_user.id
    chat_id = target.message.chat.id if isinstance(target, CallbackQuery) else target.chat.id
    m = await with_emoji_fallback(lambda t, mk: bot.send_message(chat_id, t, reply_markup=mk),
                                  UPDATE_SUB_TEXT.format(icon=em("broadcast")), None)
    bc_id = B.create("mass", admin_id, options={"group": "sub",
                                                 "link": {"text": B.SECTIONS["sub"],
                                                          "section": "sub"}})
    B.add_item(bc_id, m)
    if state is not None:
        await state.clear()
        await state.update_data(bc_id=bc_id)
    await send_view(bot, chat_id, f"<p>{em('draft')} Черновик готов — выше то, что получат "
                                  f"пользователи (с кнопкой «Моя подписка»).</p>")
    await send_view(bot, chat_id, *(await asyncio.to_thread(recipients_view, bc_id)))
    return bc_id


@router.callback_query(F.data == "bc:tpl:sub")
@admin_only
async def cb_tpl_sub(cb: CallbackQuery, state: FSMContext, bot: Bot):
    await cb.answer()
    await start_update_sub(cb, bot, state)


# ============================================== переписка с пользователем ===

def conversation_view(chat_id: int) -> str:
    return B.conversation_view(chat_id)


@router.callback_query(F.data.startswith("msgh:"))
@admin_only
async def cb_conversation(cb: CallbackQuery):
    chat_id = int(cb.data[5:])
    u = get_user(chat_id)
    text = (f"<h3>{em('message')} Переписка</h3>" + (user_table(u) if u else "")
            + (B.conversation_view(chat_id) or "<p>Сообщений пока нет.</p>"))
    await show(cb, text, kb([btn("Написать", f"msg:{chat_id}", style="primary", icon="message")],
                            [btn("Карточка", f"u:{chat_id}", icon="user")]))
    await cb.answer()


@router.callback_query(F.data.in_({"urep", "umsg", "umsg:sos"}))
async def cb_user_write(cb: CallbackQuery, state: FSMContext):
    if not has_access(cb.from_user.id):
        u = get_user(cb.from_user.id)
        if not (u and u["status"] == "pending"):
            return await cb.answer("Доступ не выдан", show_alert=True)
    await state.set_state(UMsg.collect)
    await state.update_data(sos=cb.data == "umsg:sos")
    await send_view(cb.bot, cb.message.chat.id,
                    f"<h3>{em('message')} Сообщение администратору</h3>"
                    f"<p>Напиши, что случилось, — можно приложить скриншот или голосовое. "
                    f"Я передам администратору.</p>",
                    kb([btn("Отмена", "umsgx", icon="no")]))
    await cb.answer()


@router.callback_query(F.data == "umsgx")
async def cb_user_write_cancel(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await show(cb, "<p>Отменено.</p>", kb([btn("Меню", "menu", icon="back")]))
    await cb.answer()


def health_text() -> str:
    try:
        from ..health import last_result_text
    except ImportError:
        return ""
    try:
        return last_result_text() or ""
    except Exception as e:
        log.debug("health text: %s", e)
        return ""


async def _finish_user_message(bot: Bot, chat_id: int, state: FSMContext) -> None:
    await asyncio.sleep(SUMMARY_DELAY)
    await state.clear()
    await send_view(bot, chat_id, f"<p>{em('ok')} Передал администратору. Ответ придёт сюда.</p>",
                    kb([btn("Написать ещё", "umsg", icon="message"),
                        btn("Меню", "menu", icon="back")]))


@router.message(UMsg.collect)
async def user_message(m: Message, state: FSMContext, bot: Bot):
    uid = m.from_user.id
    data = await state.get_data()
    first = not data.get("sent_card")
    u = get_user(uid)
    for admin in ADMIN_IDS:
        if admin == uid:
            continue
        try:
            if first:
                head = (f"<h3>{em('message')} {'SOS: ' if data.get('sos') else ''}"
                        f"Сообщение от пользователя</h3>"
                        + (user_table(u) if u else f"<p>ID <code>{uid}</code></p>"))
                if data.get("sos"):
                    head += health_text()
                await send_view(bot, admin, head,
                                kb([btn("Ответить", f"msg:{uid}", style="primary", icon="reply"),
                                    btn("Переписка", f"msgh:{uid}", icon="history")]))
            await bot.copy_message(admin, m.chat.id, m.message_id)
        except Exception as e:
            log.warning("user message to admin %s failed: %s", admin, e)
    if first:
        await state.update_data(sent_card=True)
    B.record_conversation(uid, "in", None, B.summary_line(m), m.chat.id, m.message_id)
    t = _reply_tasks.get(uid)
    if t and not t.done():
        t.cancel()
    _reply_tasks[uid] = asyncio.create_task(_finish_user_message(bot, m.chat.id, state))

