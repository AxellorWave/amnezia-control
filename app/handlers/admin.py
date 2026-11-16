"""Админка: пользователи, заявки, лимиты, клиенты из приложения, дашборд."""
import asyncio
import functools
import logging

from aiogram import Bot, F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from .. import detect
from ..access import is_admin
from ..config import MAX_DEVICES, VPN_HOST
from ..db import bot_pubs, db, devices_count, get_user, set_user, user_devices
from ..protocols.awg import peer_stats, remove_peer, server_info, server_peers, wg_lock
from ..traffic import account_traffic, user_traffic
from ..ui import (btn, dot, em, esc, fmt_bytes, fmt_seen, fmt_traffic, is_online, kb, kv,
                  notify, show, table, user_line, user_table)
from ..subsync import access_changed, sync_all
from .subscription import user_sub_summary
from .user import delete_device, status_view

log = logging.getLogger("amnezia-bot")
router = Router()


class SetLimit(StatesGroup):
    value = State()


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
    awg_e = detect.get("awg")
    if not awg_e:
        app_n, online = "—", "—"
        srv = f"{em('offline')} AmneziaWG не установлен"
    elif awg_e["state"] != "running":
        app_n, online = "—", "—"
        srv = f"{em('error')} AmneziaWG остановлен"
    else:
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
    rows = [[btn("Протоколы", "proto", icon="protocols"),
             btn("Мониторинг", "inc:status", icon="health_ok")],
            [btn("Рассылка", "bc", icon="broadcast")]
            + ([btn("Обновите подписку", "bc:tpl:sub", icon="subscription")]
               if detect.sub_protocols() else []),
            [btn("Пользователи", "adm:users", icon="users"),
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
        n = devices_count(u["chat_id"])
        who = f"@{u['username']}" if u["username"] else str(u["chat_id"])
        rows.append([btn(f"{u['name'] or 'без имени'} · {who} · {n} устр.", f"u:{u['chat_id']}",
                         icon=STATUS_EMOJI.get(u["status"]))])
        rx, tx = user_traffic(u["chat_id"])
        lines.append([em(STATUS_EMOJI.get(u["status"], "question")), user_line(u), str(n),
                      fmt_bytes(rx + tx)])
    rows.append([btn("Админка", "adm", icon="back")])
    title = {"pending": f"{em('pending')} Заявки",
             "denied": f"{em('denied')} Отклонённые и отозванные"}.get(flt, f"{em('users')} Пользователи")
    text = f"<h2>{title}</h2>"
    if not users:
        text += "<p>Пусто.</p>"
    else:
        text += table(lines, head=["", "Человек", em("phone"), em("traffic")])
        if len(users) > USERS_LIST_MAX:
            text += f"<p><i>Показаны первые {USERS_LIST_MAX} из {len(users)}.</i></p>"
        text += "<p>Нажми на человека, чтобы открыть карточку.</p>"
    return text, kb(*rows)


def user_card(chat_id: int) -> tuple[str, InlineKeyboardMarkup]:
    u = get_user(chat_id)
    if not u:
        return (f"<p>{em('warn')} Пользователь не найден.</p>",
                kb([btn("Пользователи", "adm:users", icon="back")]))
    stats = peer_stats()
    account_traffic(stats)
    devs = user_devices(chat_id)
    if is_admin(chat_id):
        limit = "без ограничений (админ)"
    elif u["max_devices"] is None:
        limit = f"{MAX_DEVICES} (по умолчанию)"
    else:
        limit = f"<b>{u['max_devices']}</b> (по умолчанию {MAX_DEVICES})"
    s = u["status"]
    text = (f"<h2>{em(STATUS_EMOJI.get(s, 'user'))} {esc(u['name'] or 'без имени')}</h2>"
            + user_table(u)
            + kv([("Статус", f"{em(STATUS_EMOJI.get(s, 'question'))} {STATUS_NAME.get(s, esc(s))}"),
                  (f"{em('calendar')} С нами с", (u["created"] or "")[:10]),
                  (f"{em('devices')} Лимит устройств", limit),
                  (f"{em('traffic')} Трафик всего", fmt_traffic(*user_traffic(chat_id)))]
                 + user_sub_summary(chat_id)))
    rows = []
    if devs:
        text += table([[dot(stats.get(d["pub"])), esc(d["name"]), f"<code>{d['ip']}</code>",
                        fmt_seen(stats[d["pub"]]["hs"] if d["pub"] in stats else 0),
                        fmt_bytes(d["rx_total"] + d["tx_total"])] for d in devs],
                      head=["", "Устройство", "IP", "Подключение", "Трафик"],
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
    rows.append([btn("Написать", f"msg:{chat_id}", icon="message"),
                 btn("Переписка", f"msgh:{chat_id}", icon="history")])
    rows.append([btn("Пользователи", "adm:users", icon="back")])
    return text, kb(*rows)


def app_list() -> tuple[str, InlineKeyboardMarkup]:
    if not detect.running("awg"):
        return (f"<h2>{em('app')} Конфиги из приложения AmneziaVPN</h2>"
                f"<p>AmneziaWG не запущен.</p>", kb([btn("Админка", "adm", icon="back")]))
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


@router.callback_query(F.data == "adm")
@admin_only
async def cb_adm(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(admin_menu)))
    await cb.answer()


@router.message(Command("admin", "list"))
async def cmd_admin(m: Message):
    if is_admin(m.from_user.id):
        await show(m, *(await asyncio.to_thread(admin_menu)))


@router.callback_query(F.data.in_({"adm:users", "adm:pending", "adm:denied"}))
@admin_only
async def cb_users(cb: CallbackQuery):
    await show(cb, *users_list(cb.data[4:] if cb.data != "adm:users" else ""))
    await cb.answer()


@router.callback_query(F.data.startswith("u:"))
@admin_only
async def cb_user(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await show(cb, *(await asyncio.to_thread(user_card, int(cb.data[2:]))))
    await cb.answer()


@router.callback_query(F.data == "adm:app")
@admin_only
async def cb_app(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(app_list)))
    await cb.answer()


@router.callback_query(F.data == "adm:dash")
@admin_only
async def cb_dash(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(status_view, "a", cb.from_user.id)))
    await cb.answer()


@router.callback_query(F.data.startswith("ok:"))
@admin_only
async def approve(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[3:])
    u = get_user(chat_id)
    if not u:
        return await cb.answer("Пользователь не найден", show_alert=True)
    set_user(chat_id, status="approved")
    await access_changed(chat_id, True)
    await show(cb, f"<h3>{em('ok')} Заявка одобрена</h3>" + user_table(u),
               kb([btn("Открыть карточку", f"u:{chat_id}", icon="user")]))
    sent = await notify_approved(bot, chat_id)
    await cb.answer("Одобрено" if sent else "Одобрено, но написать ему не вышло",
                    show_alert=not sent)


async def notify_approved(bot: Bot, chat_id: int) -> bool:
    """Сообщить об одобрении; False — если бот заблокирован или чат недоступен."""
    rows = []
    if detect.sub_protocols():
        rows.append([btn("Моя подписка", "sub", style="primary", icon="subscription")])
    if detect.running("awg"):
        rows.append([btn("Добавить устройство", "add", style=None if rows else "primary",
                         icon="add")])
    rows.append([btn("Как подключиться", "help", icon="help")])
    first = ("Возьми ссылку-подписку или добавь первое устройство"
             if len(rows) > 2 else "Добавь своё первое устройство" if detect.running("awg")
             else "Возьми ссылку-подписку" if detect.sub_protocols() else "Загляни в меню")
    return await notify(bot, chat_id,
                        f"<h2>{em('party')} Доступ одобрен!</h2>"
                        f"<p>{first}, а потом загляни в «Как подключиться».</p>", kb(*rows))


@router.callback_query(F.data.startswith("rs:"))
@admin_only
async def restore(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[3:])
    u = get_user(chat_id)
    if not u:
        return await cb.answer("Пользователь не найден", show_alert=True)
    if u["status"] not in ("denied", "revoked"):
        return await cb.answer("Доступ уже не закрыт", show_alert=True)
    set_user(chat_id, status="approved")
    await access_changed(chat_id, True)
    sent = await notify_approved(bot, chat_id)
    await cb.answer("Доступ возвращён" if sent else
                    "Доступ возвращён, но написать ему не вышло (бот заблокирован?)",
                    show_alert=not sent)
    await show(cb, *(await asyncio.to_thread(user_card, chat_id)))


@router.callback_query(F.data.startswith("no:"))
@admin_only
async def deny(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[3:])
    set_user(chat_id, status="denied")
    u = get_user(chat_id)
    await show(cb, f"<h3>{em('no')} Заявка отклонена</h3>" + user_table(u),
               kb([btn("Открыть карточку", f"u:{chat_id}", icon="user")]))
    await notify(bot, chat_id, f"<p>{em('sad')} К сожалению, заявка отклонена.</p>")
    await cb.answer("Отклонено")


@router.callback_query(F.data.startswith("rv:"))
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


@router.callback_query(F.data.startswith("rvok:"))
@admin_only
async def do_revoke(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data[5:])
    for d in user_devices(chat_id):
        await delete_device(d)
    set_user(chat_id, status="revoked")
    await access_changed(chat_id, False)
    await notify(bot, chat_id, f"<p>{em('denied')} Твой доступ к VPN отозван.</p>")
    await cb.answer("Доступ отозван")
    await show(cb, *(await asyncio.to_thread(user_card, chat_id)))


@router.callback_query(F.data.startswith("al:"))
@admin_only
async def allow_again(cb: CallbackQuery):
    chat_id = int(cb.data[3:])
    db.execute("DELETE FROM users WHERE chat_id=?", (chat_id,))
    db.execute("DELETE FROM sub_devices WHERE chat_id=?", (chat_id,))
    db.commit()
    await sync_all()
    await cb.answer("Теперь он может снова отправить заявку через /start", show_alert=True)
    await show(cb, *users_list())


LIMIT_MAX = 100


@router.callback_query(F.data.startswith("lim:"))
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
    n = devices_count(chat_id)
    text = (f"<p>{em('ok')} Лимит устройств: <b>{value}</b></p>" if value is not None else
            f"<p>{em('ok')} Лимит сброшен — общий, <b>{MAX_DEVICES}</b></p>")
    lim = MAX_DEVICES if value is None else value
    if n > lim:
        text += (f"<blockquote>{em('warn')} Сейчас у него {n} устройств — они останутся, "
                 f"но добавить новые не получится, пока их не станет меньше {lim}.</blockquote>")
    return text


@router.callback_query(F.data.startswith("limrs:"))
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


@router.message(SetLimit.value, F.text)
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


@router.callback_query(F.data.startswith("ap:"))
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


@router.callback_query(F.data.startswith("apok:"))
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
