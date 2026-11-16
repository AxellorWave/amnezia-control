"""«Списки сервисов»: выбор сервисов по темам, режим (через VPN только выбранные /
всё, кроме выбранных) и готовые файлы раздельного туннелирования для клиентов."""
import asyncio
import json
import logging
from datetime import datetime

from aiogram import Bot, F, Router
from aiogram.types import BufferedInputFile, CallbackQuery, InlineKeyboardMarkup

from .. import detect, routes
from ..access import has_access
from ..db import get_user, user_devices
from ..ui import btn, em, esc, file_name, kb, kv, show, table, with_emoji_fallback

log = logging.getLogger("amnezia-bot")
router = Router()

CLIENTS = {
    "amnezia": "AmneziaVPN / DefaultVPN",
    "awg": "AmneziaWG (.conf устройства)",
    "happ": "Happ",
    "incy": "Incy",
    "hiddify": "Hiddify",
    "v2raytun": "v2RayTun",
    "txt": "Списки .txt",
}


def mode_text(mode: str) -> str:
    return routes.MODES.get(mode, routes.MODES["include"])


def main_view(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    p = routes.get_prefs(uid)
    sel = p["services"]
    ts = routes.last_update()
    upd = datetime.fromtimestamp(ts).strftime("%d.%m.%Y") if ts else "встроенный список"
    rows_t = []
    for topic, title, keys in routes.TOPICS:
        n = sum(1 for k in keys if k in sel)
        rows_t.append([esc(title), f"{n} из {len(keys)}" if n else "—"])
    text = (f"<h2>{em('globe')} Списки сервисов</h2>"
            f"<p>Раздельное туннелирование: выбери сервисы, и я пришлю готовые файлы для "
            f"твоего приложения — через VPN пойдёт только нужное (или наоборот, всё, "
            f"кроме выбранного).</p>"
            + kv([(f"{em('edit')} Режим", f"<b>{mode_text(p['mode'])}</b>"),
                  (f"{em('ok')} Выбрано", esc(routes.selection_title(sel)) if sel
                   else "<i>пока ничего</i>"),
                  (f"{em('refresh')} Списки обновлены", upd)])
            + table(rows_t, head=["Тема", "Выбрано"]))
    if p["mode"] == "include":
        text += (f"<blockquote>{em('idea')} Обычно в этом режиме выбирают заблокированные "
                 f"сервисы: YouTube, Instagram, Telegram, ChatGPT…</blockquote>")
    else:
        text += (f"<blockquote>{em('idea')} В этом режиме обычно выбирают «Российские сервисы»: "
                 f"банки, Госуслуги и маркетплейсы будут работать напрямую.</blockquote>")
    rows = []
    pair = []
    for topic, title, _ in routes.TOPICS:
        pair.append(btn(title, f"rt:g:{topic}", icon="group"))
        if len(pair) == 2:
            rows.append(pair)
            pair = []
    if pair:
        rows.append(pair)
    other = "exclude" if p["mode"] == "include" else "include"
    rows.append([btn(f"Режим: {mode_text(other).lower()}", f"rt:m:{other}", icon="refresh")])
    if sel:
        rows.append([btn("Получить файлы", "rt:f", style="primary", icon="download")])
        rows.append([btn("Сбросить выбор", "rt:x", icon="reset")])
    rows.append([btn("Меню", "menu", icon="back")])
    return text, kb(*rows)


def topic_view(uid: int, topic: str) -> tuple[str, InlineKeyboardMarkup]:
    p = routes.get_prefs(uid)
    t = next((x for x in routes.TOPICS if x[0] == topic), None)
    if not t:
        return main_view(uid)
    _, title, keys = t
    text = (f"<h2>{em('group')} {esc(title)}</h2>"
            f"<p>Нажми на сервис, чтобы отметить его. Режим: <b>{mode_text(p['mode'])}</b>.</p>")
    if topic == "ru":
        text += (f"<blockquote>{em('warn')} «Все сайты .ru / .рф / .su» — большой список подсетей: "
                 f"для AmneziaWG он сжимается, а Happ/Incy работают по доменам.</blockquote>")
    rows = []
    for k in keys:
        on = k in p["services"]
        rows.append([btn(routes.SERVICES[k]["title"], f"rt:t:{k}", icon="online" if on else "offline")])
    all_on = all(k in p["services"] for k in keys)
    rows.append([btn("Снять все" if all_on else "Выбрать все", f"rt:a:{topic}",
                     icon="no" if all_on else "ok")])
    rows.append([btn("Назад", "routes", icon="back")])
    return text, kb(*rows)


def clients_view(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    p = routes.get_prefs(uid)
    text = (f"<h2>{em('download')} Файлы для приложения</h2>"
            + kv([(f"{em('edit')} Режим", mode_text(p["mode"])),
                  (f"{em('ok')} Сервисы", esc(routes.selection_title(p["services"])))])
            + "<p>Выбери приложение — пришлю файл и короткую инструкцию по импорту.</p>")
    rows = [[btn(CLIENTS["happ"], "rt:c:happ", icon="play"),
             btn(CLIENTS["incy"], "rt:c:incy", icon="play")],
            [btn(CLIENTS["hiddify"], "rt:c:hiddify", icon="play"),
             btn(CLIENTS["v2raytun"], "rt:c:v2raytun", icon="play")],
            [btn(CLIENTS["amnezia"], "rt:c:amnezia", icon="awg")]]
    if detect.running("awg") and user_devices(uid):
        rows.append([btn(CLIENTS["awg"], "rt:c:awg", icon="file")])
    rows.append([btn(CLIENTS["txt"], "rt:c:txt", icon="file")])
    rows.append([btn("Назад", "routes", icon="back")])
    return text, kb(*rows)


def awg_devices_view(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    devs = user_devices(uid)
    rows = [[btn(d["name"], f"rt:d:{d['id']}", icon="device")] for d in devs]
    rows.append([btn("Назад", "rt:f", icon="back")])
    return (f"<h2>{em('awg')} Конфиг AmneziaWG с раздельным туннелированием</h2>"
            f"<p>Для какого устройства собрать конфиг? Ключи останутся прежними, поменяется "
            f"только список маршрутов (AllowedIPs).</p>"), kb(*rows)


# ================================================================ файлы ===

def instructions(client: str, mode: str) -> str:
    inc = mode == "include"
    if client == "amnezia":
        am_mode = ("«Только адреса из списка должны открываться через VPN»" if inc
                   else "«Адреса из списка не должны открываться через VPN»")
        return (f"<b>AmneziaVPN / DefaultVPN</b>\n"
                f"1. Настройки → «Раздельное туннелирование сайтов» → включи.\n"
                f"2. Режим: {am_mode}.\n"
                f"3. Меню (⋮) → «Импорт» → «Заменить список сайтов» → выбери этот файл.\n"
                f"4. Переподключись.\n"
                f"Для приложений (Android/Windows) есть ещё «Раздельное туннелирование приложений».")
    if client == "awg":
        return ("<b>AmneziaWG / AmneziaVPN</b>\n"
                "1. Удали (или выключи) старый туннель этого устройства.\n"
                "2. Импортируй этот файл .conf.\n"
                "3. Подключись. Ключ тот же — устройство в боте не меняется.\n"
                "Чтобы вернуть «всё через VPN» — снова возьми обычный файл в карточке устройства.")
    if client in ("happ", "incy"):
        name = "Happ" if client == "happ" else "Incy"
        return (f"<b>{name}</b>\n"
                f"1. Нажми «Добавить в {name}» (или скопируй ссылку из файла — {name} сам "
                f"предложит импорт из буфера).\n"
                f"2. Профиль «VPN» добавится и включится: Настройки → Маршрутизация.\n"
                f"3. Переподключись — правила применяются после переподключения.\n"
                f"Отключить: Настройки → Маршрутизация → выключи переключатель.")
    if client == "hiddify":
        return ("<b>Hiddify</b>\n"
                "Файл .json — rule-set sing-box (version 2). В Hiddify: Настройки → "
                "«Параметры маршрутизации» / Config options → добавь правила из списков .txt "
                "или подключи rule-set в своём конфиге sing-box. Режим «обход RU»: в Hiddify "
                "есть готовая опция региона «Россия» — включи её, и российские сайты пойдут напрямую.")
    if client == "v2raytun":
        return ("<b>v2RayTun</b>\n"
                "Файл — правила маршрутизации Xray (domain / ip). В v2RayTun: Настройки → "
                "Маршрутизация → добавь правила: домены из списка — в "
                f"«{'Proxy' if inc else 'Direct'}», остальное — в «{'Direct' if inc else 'Proxy'}».")
    return ("<b>Списки</b>\n"
            "domains.txt — домены (по одному в строке), ips.txt — подсети. Подходят для любого "
            "клиента с ручными правилами маршрутизации и для роутеров.")


def build_files(uid: int, client: str) -> tuple[list[tuple[str, bytes]], str, str]:
    """-> ([(имя файла, содержимое)], примечание, ссылка happ/incy)."""
    p = routes.get_prefs(uid)
    data = routes.collect(p["services"])
    mode = p["mode"]
    note, link = "", ""
    if client == "amnezia":
        files = [("amnezia-split-tunnel.json", routes.amnezia_json(data).encode())]
        if data["zones"]:
            note = "Зоны .ru/.рф/.su в AmneziaVPN по доменам не задаются — использованы подсети."
    elif client in ("happ", "incy"):
        prof = routes.happ_profile(data, mode)
        link = routes.happ_link(prof, client)
        files = [(f"{client}-routing.txt", (link + "\n").encode()),
                 (f"{client}-routing.json", json.dumps(prof, ensure_ascii=False,
                                                               indent=1).encode())]
    elif client == "hiddify":
        doms, ips = routes.plain_lists(data)
        files = [("singbox-ruleset.json", routes.singbox_ruleset(data).encode()),
                 ("domains.txt", doms.encode()), ("ips.txt", ips.encode())]
    elif client == "v2raytun":
        files = [("xray-routing.json", routes.xray_rules(data, mode).encode())]
    else:
        doms, ips = routes.plain_lists(data)
        files = [("domains.txt", doms.encode()), ("ips.txt", ips.encode())]
    return files, note, link


def build_awg(uid: int, dev_id: int) -> tuple[str, bytes, str]:
    from ..protocols.awg import client_conf, server_info
    d = next((x for x in user_devices(uid) if x["id"] == dev_id), None)
    if not d:
        raise LookupError("Устройство не найдено")
    p = routes.get_prefs(uid)
    data = routes.collect(p["services"])
    allowed, n, squeezed = routes.wg_allowed_ips(data, p["mode"])
    conf = routes.awg_conf(client_conf(d, server_info()), allowed)
    note = f"Маршрутов: {n}."
    if squeezed:
        note += (" Список был слишком большим и сжат до более широких подсетей — часть "
                 "соседних адресов тоже пойдёт этим же путём.")
    if p["mode"] == "include" and not (data["cidrs"] or data["resolved"]):
        note += " Подсетей для выбранных сервисов пока нет — обнови списки позже."
    return f"{file_name(d['name'])}-split.conf", conf.encode(), note


async def send_files(bot: Bot, chat_id: int, files, caption: str, markup=None) -> None:
    for i, (name, content) in enumerate(files):
        last = i == len(files) - 1
        await with_emoji_fallback(
            lambda t, mk, n=name, c=content: bot.send_document(
                chat_id, BufferedInputFile(c, filename=n), caption=t or None, reply_markup=mk),
            caption if last else "", markup if last else None)


# ============================================================ обработчики ===

@router.callback_query(F.data == "routes")
async def cb_routes(cb: CallbackQuery):
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    await show(cb, *main_view(cb.from_user.id))
    await cb.answer()


@router.callback_query(F.data.startswith("rt:"))
async def cb_routes_action(cb: CallbackQuery, bot: Bot):
    uid = cb.from_user.id
    if not has_access(uid):
        return await cb.answer("Доступ не выдан", show_alert=True)
    parts = cb.data.split(":")
    act, arg = parts[1], (parts[2] if len(parts) > 2 else "")
    if act == "g":
        await show(cb, *topic_view(uid, arg))
    elif act == "t" and arg in routes.SERVICES:
        routes.toggle(uid, arg)
        await show(cb, *topic_view(uid, routes.TOPIC_OF[arg]))
    elif act == "a":
        routes.toggle_topic(uid, arg)
        await show(cb, *topic_view(uid, arg))
    elif act == "m" and arg in routes.MODES:
        routes.set_mode(uid, arg)
        await show(cb, *main_view(uid))
    elif act == "x":
        routes.save_prefs(uid, routes.get_prefs(uid)["mode"], [])
        await show(cb, *main_view(uid))
    elif act == "f":
        if not routes.get_prefs(uid)["services"]:
            return await cb.answer("Сначала выбери сервисы", show_alert=True)
        await show(cb, *clients_view(uid))
    elif act == "c" and arg in CLIENTS:
        if not routes.get_prefs(uid)["services"]:
            return await cb.answer("Сначала выбери сервисы", show_alert=True)
        if arg == "awg":
            if not detect.running("awg"):
                return await cb.answer("AmneziaWG сейчас недоступен", show_alert=True)
            await show(cb, *awg_devices_view(uid))
            return await cb.answer()
        await cb.answer("Готовлю файлы…")
        return await send_client(cb, bot, arg)
    elif act == "d" and arg.isdigit():
        if not detect.running("awg"):
            return await cb.answer("AmneziaWG сейчас недоступен", show_alert=True)
        await cb.answer("Собираю конфиг…")
        try:
            name, content, note = await asyncio.to_thread(build_awg, uid, int(arg))
        except Exception as e:
            log.warning("routes awg conf failed: %s", e)
            return await show(cb, f"<p>{em('error')} Не получилось собрать конфиг.</p>",
                              kb([btn("Назад", "rt:f", icon="back")]))
        caption = (f"{em('file')} " + instructions("awg", routes.get_prefs(uid)["mode"])
                   + f"\n\n{esc(note)}\n{em('lock')} В файле приватный ключ — не пересылай его.")
        await send_files(bot, cb.message.chat.id, [(name, content)], caption,
                         kb([btn("Списки сервисов", "routes", icon="back")]))
        return
    await cb.answer()


async def send_client(cb: CallbackQuery, bot: Bot, client: str) -> None:
    uid = cb.from_user.id
    p = routes.get_prefs(uid)
    files, note, link = await asyncio.to_thread(build_files, uid, client)
    caption = f"{em('file')} " + instructions(client, p["mode"])
    if note:
        caption += f"\n\n{esc(note)}"
    rows = []
    if link:
        u = get_user(uid)
        try:
            from .. import sub_server
            if u and u["sub_token"]:
                url = sub_server.sub_url(u["sub_token"]).replace("/sub/", f"/routing/{client}/", 1)
                rows.append([btn(f"Добавить в {CLIENTS[client]}", url=url, style="primary",
                                 icon="play")])
        except Exception as e:
            log.debug("routing link: %s", e)
    rows.append([btn("Списки сервисов", "routes", icon="back")])
    await send_files(bot, cb.message.chat.id, files, caption, kb(*rows))
