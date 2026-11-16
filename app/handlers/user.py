"""Экраны и обработчики пользователя: меню, устройства AWG, инструкции, статус."""
import asyncio
import logging
from datetime import datetime

from aiogram import Bot, F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BufferedInputFile, CallbackQuery, InlineKeyboardMarkup, Message

from .. import detect
from ..access import device_limit, has_access, is_admin, own_device
from ..config import (ADMIN_IDS, ANDROID_URL, DESKTOP_SITE_URL, DESKTOP_URL, IOS_URL)
from ..db import db, devices_count, get_device, get_user, now, set_user, user_devices
from ..geo import server_location_html

from ..protocols.awg import (add_peer, amnezia_key, client_conf, peer_stats, qr_png, remove_peer, server_info,
                             server_peers, wg_lock)
from ..traffic import account_traffic, drop_device, user_traffic
from ..ui import (btn, dot, edit_view, em, esc, file_name, fmt_bytes, fmt_seen, fmt_traffic,
                  is_online, kb, kv, notify, owner_label, send_view, show, table, user_table,
                  with_emoji_fallback)

log = logging.getLogger("amnezia-bot")
router = Router()


class AddDevice(StatesGroup):
    name = State()


def awg_state() -> str:
    """"running" | "stopped" | "" (AWG не установлен)."""
    e = detect.get("awg")
    return e["state"] if e else ""


def main_menu(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    u = get_user(uid)
    name = esc(u["name"].split()[0]) if u and u["name"] else "друг"
    st = awg_state()
    rows = []
    if not detect.any_installed():
        text = (f"<h2>{em('vpn')} Привет, {name}!</h2>"
                f"<p>{em('pending')} <b>VPN пока не настроен</b> — администратор уже в курсе. "
                f"Как только всё будет готово, здесь появятся кнопки для подключения.</p>")
        if is_admin(uid):
            rows.append([btn("Протоколы", "proto", style="primary", icon="protocols")])
            rows.append([btn("Админка", "adm", icon="admin")])
        return text, kb(*rows)

    n = devices_count(uid)
    lim = device_limit(uid)
    limit = "" if lim is None else f" из {lim}"
    subs = detect.sub_protocols()
    info = []
    if st or subs:
        info.append((f"{em('devices')} Устройств", f"<b>{n}{limit}</b>"))
    info += [(f"{em('traffic')} Трафик", fmt_traffic(*user_traffic(uid))),
             (f"{em('globe')} Сервер", server_location_html())]
    about = ("Здесь можно выпустить конфиг для каждого устройства" if st else "")
    if subs:
        about += (" или взять одну ссылку-подписку на все устройства" if about
                  else "Здесь — твоя ссылка-подписка на все устройства")
    text = (f"<h2>{em('vpn')} Привет, {name}!</h2>"
            f"<p>Это твой личный VPN. {about} и посмотреть, как подключиться.</p>" + kv(info))
    if st == "stopped":
        text += (f"<blockquote>{em('warn')} AmneziaWG временно недоступен — выдача новых "
                 f"конфигов отключена. Администратор уже в курсе.</blockquote>")
    if subs:
        rows.append([btn("Моя подписка", "sub", style=None if st else "primary",
                         icon="subscription")])
    if st:
        rows.append([btn("Мои устройства", "devs", icon="devices")])
        if st == "running":
            rows.append([btn("Добавить устройство", "add", style="primary", icon="add")])
    rows.append([btn("Как подключиться", "help", icon="help"), btn("Статус", "status", icon="status")])
    rows.append([btn("Не работает VPN", "sos", icon="sos"),
                 btn("Написать админу", "umsg", icon="message")])
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



def device_card(d, viewer: int) -> tuple[str, InlineKeyboardMarkup]:
    stats = peer_stats()
    account_traffic(stats)
    d = get_device(d["id"]) or d
    st = stats.get(d["pub"])
    created = (d["created"] or "")[:10]
    try:
        created = datetime.fromisoformat(d["created"]).strftime("%d.%m.%Y")
    except Exception:
        pass
    status = f"{dot(st)} в сети" if is_online(st) else f"{dot(st)} {fmt_seen(st['hs'] if st else 0)}"
    if awg_state() != "running":
        status = f"{em('warn')} временно недоступен"
    info = [("Статус", status)]
    if d["rx_total"] or d["tx_total"]:
        info.append((f"{em('traffic')} Трафик", fmt_traffic(d["rx_total"], d["tx_total"])))
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
        [btn("Как подключиться", "help", icon="help"), btn("Не работает VPN", "sos", icon="sos")],
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
    rows_sub = []
    if detect.sub_protocols():
        text += (f"<blockquote>{em('subscription')} Есть и <b>подписка</b> (VLESS, Hysteria2) — "
                 f"одна ссылка для Happ, v2RayTun или Hiddify на всех устройствах.</blockquote>")
        rows_sub = [btn("Подписка: Happ, v2RayTun, Hiddify", "sg", icon="subscription")]
    return text, kb(rows_sub, [btn("Android", "guide:android", icon="android"),
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


def sub_status(kind: str, uid: int) -> str:
    """Подписка (Xray / Hysteria2) в статусе: у человека — своё, у админа — сводка."""
    from ..protocols.registry import TITLES
    from ..traffic import ONLINE_NOW
    subs = detect.sub_protocols()
    if not subs:
        return ""
    icon = {"xray": "xray", "hy2": "hysteria"}
    rows = []
    for pid in subs:
        if kind == "a":
            r = db.execute("SELECT COALESCE(SUM(rx_total),0), COALESCE(SUM(tx_total),0) "
                           "FROM traffic WHERE proto=?", (pid,)).fetchone()
            rows.append([f"{em(icon[pid])} {TITLES[pid]}",
                         f"{em('online')} {len(ONLINE_NOW.get(pid, set()))}",
                         fmt_bytes(r[0] + r[1])])
        else:
            from ..traffic import proto_traffic
            rx, tx = proto_traffic(uid, pid)
            on = uid in ONLINE_NOW.get(pid, set())
            rows.append([f"{em(icon[pid])} {TITLES[pid]}",
                         em("online" if on else "offline") + (" в сети" if on else ""),
                         fmt_bytes(rx + tx)])
    return table(rows, head=["Подписка", "В сети", "Трафик"])


def status_view(kind: str, uid: int) -> tuple[str, InlineKeyboardMarkup]:
    stats = peer_stats()
    account_traffic(stats)
    # для устройств бота — накопленный трафик, для клиентов из приложения — счётчик awg
    totals = {d["pub"]: (d["rx_total"], d["tx_total"])
              for d in db.execute("SELECT pub, rx_total, tx_total FROM devices")}
    rows = []
    if kind == "a":                       # админ: все клиенты сервера
        users = {d["pub"]: d for d in db.execute(
            "SELECT d.pub, d.name, u.username, u.chat_id FROM devices d "
            "LEFT JOIN users u ON u.chat_id=d.chat_id")}
        for p in (server_peers() if awg_state() == "running" else []):
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
        title = f"{em('status')} Мой VPN"

    items = []
    for name, pub in rows:
        st = dict(stats.get(pub, {"hs": 0, "rx": 0, "tx": 0}))
        if pub in totals:
            st["rx"], st["tx"] = totals[pub]
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
    elif awg_state():
        text += "<p>Устройств пока нет.</p>"
    text += sub_status(kind, uid)
    text += f"<footer>{em('clock')} обновлено {datetime.now().strftime('%H:%M:%S')}</footer>"
    back = btn("Админка", "adm", icon="back") if kind == "a" else btn("Меню", "menu", icon="back")
    return text, kb([btn("Обновить", "adm:dash" if kind == "a" else "status", icon="refresh")], [back])


# ======================================================= пользователь ===

@router.message(CommandStart())
@router.message(Command("menu", "config"))
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


@router.callback_query(F.data == "request")
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


@router.callback_query(F.data == "menu")
async def cb_menu(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    await show(cb, *main_menu(cb.from_user.id))
    await cb.answer()


@router.callback_query(F.data == "devs")
async def cb_devs(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    text, markup = await asyncio.to_thread(devices_menu, cb.from_user.id)
    await show(cb, text, markup)
    await cb.answer()


@router.callback_query(F.data == "add")
async def ask_name(cb: CallbackQuery, state: FSMContext):
    uid = cb.from_user.id
    if not has_access(uid):
        return await cb.answer("Доступ не выдан", show_alert=True)
    if awg_state() != "running":
        return await cb.answer("AmneziaWG сейчас недоступен — выдача новых конфигов временно "
                               "отключена.", show_alert=True)
    lim = device_limit(uid)
    if lim is not None and devices_count(uid) >= lim:
        return await cb.answer(f"Максимум {lim} устройств. Удали ненужное.", show_alert=True)
    await state.set_state(AddDevice.name)
    await show(cb, f"<h3>{em('edit')} Новое устройство</h3>"
                   f"<p>Как его назвать? Просто напиши в ответ.</p>"
                   f"<blockquote><i>Например: Телефон, Ноутбук, ПК, iPad мамы</i></blockquote>",
               kb([btn("Отмена", "devs", icon="no")]))
    await cb.answer()


@router.message(AddDevice.name, F.text)
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
    if lim is not None and devices_count(uid) >= lim:
        await state.clear()
        return await show(m, f"<p>{em('warn')} Максимум {lim} устройств.</p>")
    if awg_state() != "running":
        await state.clear()
        return await show(m, f"<p>{em('warn')} AmneziaWG сейчас недоступен — попробуй позже.</p>")

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


@router.callback_query(F.data.startswith("dev:"))
async def cb_device(cb: CallbackQuery):
    d = own_device(cb.from_user.id, int(cb.data.split(":")[1]))
    if not d or not has_access(cb.from_user.id):
        return await cb.answer("Устройство не найдено", show_alert=True)
    text, markup = await asyncio.to_thread(device_card, d, cb.from_user.id)
    await show(cb, text, markup)
    await cb.answer()


@router.callback_query(F.data.startswith("fmt:"))
async def send_config(cb: CallbackQuery, bot: Bot):
    _, dev_id, fmt = cb.data.split(":")
    d = own_device(cb.from_user.id, int(dev_id))
    if not d or not has_access(cb.from_user.id):
        return await cb.answer("Устройство не найдено", show_alert=True)
    if awg_state() != "running":
        return await cb.answer("AmneziaWG временно недоступен — попробуй позже.", show_alert=True)
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


@router.callback_query(F.data.startswith("del:"))
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
    await asyncio.to_thread(drop_device, d["id"])   # сначала снять трафик, пока пир жив
    if not detect.running("awg"):
        log.warning("AWG не запущен — устройство %s удалено только из базы", d["id"])
        return
    async with wg_lock:
        await asyncio.to_thread(remove_peer, d["pub"])


@router.callback_query(F.data.startswith("delok:"))
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
        from .admin import user_card
        text, markup = await asyncio.to_thread(user_card, d["chat_id"])
    else:
        text, markup = await asyncio.to_thread(devices_menu, uid)
    await show(cb, text, markup)


@router.callback_query(F.data == "help")
async def cb_help(cb: CallbackQuery):
    await show(cb, *help_menu())
    await cb.answer()


@router.message(Command("help"))
async def cmd_help(m: Message):
    await show(m, *help_menu())


@router.callback_query(F.data.startswith("guide:"))
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


@router.callback_query(F.data == "status")
async def cb_status(cb: CallbackQuery):
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    await show(cb, *(await asyncio.to_thread(status_view, "u", cb.from_user.id)))
    await cb.answer()

