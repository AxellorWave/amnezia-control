"""Админка «Сервисы обхода»: свои сервисы с доменами и IP, правка и удаление сервисов
для раздельного туннелирования."""
import asyncio
import logging

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from .. import routes
from ..access import is_admin
from ..ui import btn, em, esc, kb, kv, show
from .admin import admin_only

log = logging.getLogger("amnezia-bot")
router = Router()

SHOW_MAX = 40          # сколько своих адресов показывать в карточке
INPUT_HINT = ("<p>Пришли домены и/или IP-адреса и подсети — по одному в строке, через "
              "пробел или запятую. Например:</p>"
              "<pre>example.com\ncdn.example.net\n203.0.113.10\n198.51.100.0/24</pre>"
              "<p>Поддомены домена учитываются автоматически.</p>")


class RoutesEdit(StatesGroup):
    title = State()
    entries = State()


def cancel_row(back: str):
    return [btn("Отмена", back, icon="no")]


def topic_title(topic: str) -> str:
    return next((title for t, title, _ in routes.TOPICS if t == topic), topic)


def home_view() -> tuple[str, InlineKeyboardMarkup]:
    custom = sum(1 for k in routes.SERVICES if routes.is_custom(k))
    hidden = routes.hidden_services()
    text = (f"<h2>{em('globe')} Сервисы обхода</h2>"
            f"<p>Каталог для раздельного туннелирования. Можно добавить свой сервис с "
            f"доменами и IP, дописать или убрать адреса у любого сервиса, скрыть ненужный.</p>"
            + kv([("Сервисов", str(len(routes.SERVICES))),
                  ("Своих", str(custom)),
                  ("Скрытых", str(len(hidden)))]))
    rows, pair = [], []
    for t, title, keys in routes.TOPICS:
        pair.append(btn(f"{title} ({len(keys)})", f"ra:g:{t}", icon="group"))
        if len(pair) == 2:
            rows.append(pair)
            pair = []
    if pair:
        rows.append(pair)
    if hidden:
        rows.append([btn(f"Скрытые ({len(hidden)})", "ra:h", icon="reset")])
    rows.append([btn("Админка", "adm", icon="back")])
    return text, kb(*rows)


def topic_view(topic: str) -> tuple[str, InlineKeyboardMarkup]:
    t = next((x for x in routes.TOPICS if x[0] == topic), None)
    if not t:
        return home_view()
    rows = [[btn(routes.SERVICES[k]["title"], f"ra:s:{k}",
                 icon="edit" if routes.is_custom(k) else "globe")]
            for k in t[2]]
    rows.append([btn("Новый сервис", f"ra:n:{topic}", style="primary", icon="add")])
    rows.append([btn("Сервисы обхода", "ra", icon="back")])
    return (f"<h2>{em('group')} {esc(t[1])}</h2>"
            f"<p>Выбери сервис, чтобы посмотреть и поправить адреса, или добавь новый.</p>",
            kb(*rows))


def _codes(items: list[str]) -> str:
    shown = ", ".join(f"<code>{esc(x)}</code>" for x in items[:SHOW_MAX])
    more = len(items) - SHOW_MAX
    return shown + (f" и ещё {more}" if more > 0 else "")


def service_view(key: str) -> tuple[str, InlineKeyboardMarkup]:
    if key not in routes.SERVICES:
        return home_view()
    svc = routes.SERVICES[key]
    e = routes.get_service(key)
    custom = routes.is_custom(key)
    rows_kv = [("Тема", esc(topic_title(routes.TOPIC_OF.get(key, "")))),
               ("Тип", "свой" if custom else "встроенный, обновляется из открытых списков"),
               ("Доменов всего", str(len(e["domains"]))),
               ("Подсетей всего", str(len(e["cidrs"]))),
               ("IP доменов (для WireGuard)", str(len(e.get("resolved", []))))]
    for field, label in (("extra_domains", "Добавленные домены"),
                         ("extra_cidrs", "Добавленные IP"),
                         ("excluded_domains", "Убранные домены"),
                         ("excluded_cidrs", "Убранные IP")):
        if svc.get(field):
            rows_kv.append((label, _codes(svc[field])))
    text = f"<h2>{em('globe')} {esc(svc['title'])}</h2>" + kv(rows_kv)
    if not custom and e.get("domains"):
        text += (f"<blockquote>Из источников: {_codes(e['domains'][:10])}"
                 + (" …" if len(e["domains"]) > 10 else "") + "</blockquote>")
    topic = routes.TOPIC_OF.get(key, "")
    rows = [[btn("Добавить адреса", f"ra:a:{key}", style="primary", icon="add"),
             btn("Убрать адреса", f"ra:r:{key}", icon="no")]]
    if not custom:
        rows.append([btn("Обновить из источников", f"ra:u:{key}", icon="refresh")])
        if any(svc.get(f) for f in routes.LIST_FIELDS):
            rows.append([btn("Сбросить правки", f"ra:z:{key}", icon="reset")])
    rows.append([btn("Удалить сервис" if custom else "Скрыть сервис", f"ra:d:{key}",
                     style="danger", icon="trash")])
    rows.append([btn(topic_title(topic), f"ra:g:{topic}", icon="back")])
    return text, kb(*rows)


def hidden_view() -> tuple[str, InlineKeyboardMarkup]:
    keys = routes.hidden_services()
    rows = [[btn(routes.BUILTIN_SERVICES[k]["title"], f"ra:v:{k}", icon="reset")] for k in keys]
    rows.append([btn("Сервисы обхода", "ra", icon="back")])
    return (f"<h2>{em('reset')} Скрытые сервисы</h2>"
            f"<p>Нажми на сервис, чтобы вернуть его в каталог.</p>"
            if keys else f"<h2>{em('reset')} Скрытых сервисов нет</h2>"), kb(*rows)


def delete_confirm_view(key: str) -> tuple[str, InlineKeyboardMarkup]:
    svc = routes.SERVICES[key]
    custom = routes.is_custom(key)
    what = ("Сервис и все его адреса будут удалены." if custom else
            "Сервис пропадёт из каталога, его можно вернуть в «Скрытых».")
    return (f"<h3>{em('warn')} {'Удалить' if custom else 'Скрыть'} «{esc(svc['title'])}»?</h3>"
            f"<p>{what} У пользователей, которые его выбрали, он исчезнет из выбора — "
            f"новые файлы туннелирования соберутся уже без него.</p>",
            kb([btn("Да, удалить" if custom else "Да, скрыть", f"ra:dd:{key}",
                    style="danger", icon="trash")],
               [btn("Отмена", f"ra:s:{key}", icon="no")]))


@router.callback_query(F.data == "ra")
@admin_only
async def cb_ra_home(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await show(cb, *home_view())
    await cb.answer()


@router.callback_query(F.data.startswith("ra:"))
@admin_only
async def cb_ra(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    parts = cb.data.split(":", 2)
    act, arg = parts[1], (parts[2] if len(parts) > 2 else "")
    if act == "g":
        await show(cb, *topic_view(arg))
    elif act == "h":
        await show(cb, *hidden_view())
    elif act == "v":
        routes.restore_service(arg)
        await cb.answer("Сервис возвращён")
        return await show(cb, *hidden_view())
    elif act == "n":
        await state.set_state(RoutesEdit.title)
        await state.update_data(topic=arg)
        await show(cb, f"<h3>{em('add')} Новый сервис в «{esc(topic_title(arg))}»</h3>"
                       f"<p>Как назвать сервис? До {routes.MAX_TITLE} символов.</p>",
                   kb(cancel_row(f"ra:g:{arg}")))
    elif arg not in routes.SERVICES:
        await cb.answer("Сервис не найден", show_alert=True)
        return await show(cb, *home_view())
    elif act == "s":
        await show(cb, *service_view(arg))
    elif act in ("a", "r"):
        await state.set_state(RoutesEdit.entries)
        await state.update_data(key=arg, op=act)
        title = routes.SERVICES[arg]["title"]
        head = (f"<h3>{em('add')} Добавить адреса в «{esc(title)}»</h3>" if act == "a" else
                f"<h3>{em('no')} Убрать адреса из «{esc(title)}»</h3>")
        extra = ("" if act == "a" else
                 "<p>Адреса из открытых списков тоже можно убрать: бот запомнит их и "
                 "не будет добавлять при обновлении.</p>")
        await show(cb, head + INPUT_HINT + extra, kb(cancel_row(f"ra:s:{arg}")))
    elif act == "u":
        await cb.answer("Обновляю…")
        try:
            await asyncio.to_thread(routes.refresh_service, arg)
        except Exception as e:
            return await cb.answer(f"Не получилось: {e}"[:190], show_alert=True)
        return await show(cb, *service_view(arg))
    elif act == "z":
        routes.reset_service(arg)
        await cb.answer("Правки сброшены")
        return await show(cb, *service_view(arg))
    elif act == "d":
        await show(cb, *delete_confirm_view(arg))
    elif act == "dd":
        topic = routes.TOPIC_OF.get(arg, "")
        custom = routes.is_custom(arg)
        routes.delete_service(arg)
        await cb.answer("Удалено" if custom else "Скрыто")
        return await show(cb, *topic_view(topic))
    await cb.answer()


@router.message(RoutesEdit.title)
async def ra_title(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return await state.clear()
    title = " ".join((m.text or "").split())
    data = await state.get_data()
    if not title or len(title) > routes.MAX_TITLE:
        return await show(m, f"<p>{em('warn')} Название — от 1 до {routes.MAX_TITLE} "
                             f"символов. Попробуй ещё раз.</p>",
                          kb(cancel_row(f"ra:g:{data.get('topic', '')}")))
    await state.update_data(title=title)
    await state.set_state(RoutesEdit.entries)
    await show(m, f"<h3>{em('add')} {esc(title)}</h3>" + INPUT_HINT,
               kb(cancel_row(f"ra:g:{data.get('topic', '')}")))


@router.message(RoutesEdit.entries)
async def ra_entries(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return await state.clear()
    data = await state.get_data()
    text = m.text or ""
    try:
        if data.get("key"):
            key = data["key"]
            if data.get("op") == "r":
                nd, nc = routes.remove_entries(key, text)
                msg = f"Убрано: доменов {nd}, подсетей {nc}."
            else:
                nd, nc = routes.add_entries(key, text)
                msg = f"Добавлено новых: доменов {nd}, подсетей {nc}."
        else:
            key = routes.add_custom(data.get("title", ""), data.get("topic", "other"), text)
            msg = "Сервис добавлен. Пользователи увидят его в «Списках сервисов»."
    except (ValueError, KeyError) as e:
        back = f"ra:s:{data['key']}" if data.get("key") else f"ra:g:{data.get('topic', '')}"
        return await show(m, f"<p>{em('warn')} {esc(str(e))}. Пришли список ещё раз.</p>",
                          kb(cancel_row(back)))
    await state.clear()
    text_v, markup = service_view(key)
    await show(m, f"<p>{em('ok')} {msg}</p>" + text_v, markup)
