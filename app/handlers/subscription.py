"""«Моя подписка»: одна ссылка на все устройства (VLESS + Hysteria2), QR, открытие в
приложениях, устройства подписки (HWID), перевыпуск ссылки, инструкции."""
import asyncio
import logging
from datetime import datetime

from aiogram import Bot, F, Router
from aiogram.types import BufferedInputFile, CallbackQuery, InlineKeyboardMarkup

from .. import detect, sub_server
from ..access import device_limit, has_access
from ..db import db, devices_count, ensure_creds, get_user, sub_devices
from ..protocols.awg import qr_png
from ..protocols.registry import SUB_PROTOCOLS, TITLES
from ..subsync import reissue
from ..traffic import ONLINE_NOW, proto_traffic
from ..ui import btn, em, esc, fmt_traffic, kb, kv, show, table, with_emoji_fallback

log = logging.getLogger("amnezia-bot")
router = Router()

PROTO_ICON = {"xray": "xray", "hy2": "hysteria"}
GUIDES = {
    "happ": ("Happ", "https://www.happ.su/main",
             "iPhone и iPad, Android, Windows, macOS",
             "Открой Happ → нажми <b>➕</b> → <b>«Вставить из буфера»</b> (ссылка подписки "
             "должна быть скопирована) или просто нажми кнопку <b>«Открыть в Happ»</b> в боте."),
    "v2raytun": ("v2RayTun", "https://v2raytun.com",
                 "iPhone и iPad, Android, Windows, macOS",
                 "Открой v2RayTun → <b>➕</b> → <b>«Импорт из буфера»</b> или нажми кнопку "
                 "<b>«Открыть в v2RayTun»</b> в боте."),
    "hiddify": ("Hiddify", "https://hiddify.com",
                "Android, iPhone, Windows, macOS, Linux",
                "Открой Hiddify → <b>«Новый профиль»</b> → <b>«Добавить из буфера обмена»</b> или "
                "нажми <b>«Открыть в Hiddify»</b> в боте."),
}


def fmt_dt(s: str | None) -> str:
    if not s:
        return "—"
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return esc(s)
    ago = (datetime.now() - d).total_seconds()
    if ago < 120:
        return "только что"
    if ago < 3600:
        return f"{int(ago // 60)} мин назад"
    if ago < 86400:
        return f"{int(ago // 3600)} ч назад"
    return d.strftime("%d.%m.%Y")


def sub_view(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    u = ensure_creds(uid)
    url = sub_server.sub_url(u["sub_token"])
    rows_t = []
    for pid in detect.sub_protocols():
        st = (f"{em('online')} работает" if detect.running(pid)
              else f"{em('warn')} временно недоступен")
        on = " · сейчас в сети" if uid in ONLINE_NOW.get(pid, set()) else ""
        rx, tx = proto_traffic(uid, pid)
        rows_t.append([f"{em(PROTO_ICON[pid])} {TITLES[pid]}", st + on,
                       fmt_traffic(rx, tx) if rx or tx else "—"])
    lim = device_limit(uid)
    n = devices_count(uid)
    text = (f"<h2>{em('subscription')} Моя подписка</h2>"
            f"<p>Одна ссылка на все устройства: добавь её в приложение — серверы обновятся "
            f"сами. Нажми на ссылку, чтобы скопировать.</p>"
            f"<pre>{esc(url)}</pre>"
            + table(rows_t, head=["Протокол", "Состояние", "Трафик"])
            + kv([(f"{em('devices')} Устройств", f"<b>{n}</b>" + ("" if lim is None else f" из {lim}"))])
            + f"<footer>{em('lock')} Ссылка — как пароль: не пересылай её другим людям.</footer>")
    rows = [[btn("Открыть в Happ", url=sub_server.open_url("happ", u["sub_token"]), icon="play")],
            [btn("v2RayTun", url=sub_server.open_url("v2raytun", u["sub_token"]), icon="play"),
             btn("Hiddify", url=sub_server.open_url("hiddify", u["sub_token"]), icon="play")],
            [btn("QR-код", "sub:qr", icon="qr"), btn("Как подключиться", "sg", icon="help")],
            [btn("Устройства подписки", "subdev", icon="sub_devices")],
            [btn("Перевыпустить ссылку", "sub:reissue", icon="refresh")],
            [btn("Меню", "menu", icon="back")]]
    return text, kb(*rows)


def devices_view(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    devs = sub_devices(uid)
    lim = device_limit(uid)
    text = f"<h2>{em('sub_devices')} Устройства подписки</h2>"
    rows = []
    if devs:
        text += table([[f"{em('hwid_device')} {esc(d['model'] or d['os'] or 'устройство')}",
                        esc(d["os"] or "—"), esc(d["app"] or "—"), fmt_dt(d["last_seen"])]
                       for d in devs], head=["Устройство", "ОС", "Приложение", "Обновлял"])
        for d in devs:
            name = d["model"] or d["os"] or d["app"] or "устройство"
            rows.append([btn(f"Удалить: {name}"[:60], f"subdel:{d['id']}", icon="trash")])
    else:
        text += "<p>Пока ни одно приложение не загружало подписку.</p>"
    text += (f"<blockquote>{em('limit')} Лимит: "
             f"<b>{'без ограничений' if lim is None else lim}</b> устройств вместе с "
             f"устройствами AmneziaWG. Удалённое устройство перестанет получать обновления "
             f"подписки; чтобы старые подключения точно оборвались — перевыпусти ссылку."
             f"</blockquote>")
    rows.append([btn("Моя подписка", "sub", icon="back")])
    return text, kb(*rows)


def guides_view() -> tuple[str, InlineKeyboardMarkup]:
    text = (f"<h2>{em('help')} Как подключиться по подписке</h2>"
            f"<p>Подойдёт любое из приложений — выбери, покажу шаги.</p>"
            + table([[name, esc(where)] for name, _, where, _ in GUIDES.values()],
                    head=["Приложение", "Устройства"]))
    return text, kb([btn(GUIDES[k][0], f"sg:{k}", icon="help") for k in GUIDES],
                    [btn("Моя подписка", "sub", icon="back")])


def guide_view(key: str) -> tuple[str, InlineKeyboardMarkup]:
    name, site, where, steps = GUIDES[key]
    text = f"""
<h2>{em('help')} {name}</h2>
<p>Работает на: {esc(where)}.</p>
<h3>1. Установи приложение</h3>
<p>Кнопка <b>«Сайт {name}»</b> ниже — там ссылки на App Store, Google Play и версии для компьютера.</p>
<h3>2. Скопируй ссылку подписки</h3>
<p>В боте: <b>Моя подписка</b> → нажми на ссылку, она скопируется.</p>
<h3>3. Добавь подписку</h3>
<p>{steps}</p>
<h3>4. Подключись</h3>
<p>Выбери сервер (VLESS или Hysteria2) и нажми кнопку подключения. Если один не работает — попробуй другой.</p>
<details>
<summary>{em('question')} Не получается?</summary>
<ul>
<li>Обнови подписку в приложении (обычно — потянуть список вниз или кнопка 🔄).</li>
<li>Видишь сервер «Лимит устройств» — удали лишнее устройство в боте.</li>
<li>Не помогло — напиши администратору.</li>
</ul>
</details>
<footer>{em('lock')} Ссылка подписки — как пароль: не пересылай её другим людям.</footer>
"""
    return text, kb([btn(f"Сайт {name}", url=site, icon="download")],
                    [btn("Моя подписка", "sub", icon="subscription"), btn("Назад", "sg", icon="back")])


def allowed(uid: int) -> bool:
    return has_access(uid) and bool(detect.sub_protocols())


@router.callback_query(F.data == "sub")
async def cb_sub(cb: CallbackQuery):
    if not allowed(cb.from_user.id):
        return await cb.answer("Подписка недоступна", show_alert=True)
    await show(cb, *(await asyncio.to_thread(sub_view, cb.from_user.id)))
    await cb.answer()


@router.callback_query(F.data == "sub:qr")
async def cb_sub_qr(cb: CallbackQuery, bot: Bot):
    if not allowed(cb.from_user.id):
        return await cb.answer("Подписка недоступна", show_alert=True)
    await cb.answer()
    u = ensure_creds(cb.from_user.id)
    png = await asyncio.to_thread(qr_png, sub_server.sub_url(u["sub_token"]))
    await with_emoji_fallback(
        lambda t, mk: bot.send_photo(cb.message.chat.id, BufferedInputFile(png, filename="sub.png"),
                                     caption=t, reply_markup=mk),
        f"{em('qr')} <b>QR-код подписки</b>\n\nОтсканируй его в Happ, v2RayTun или Hiddify.",
        kb([btn("Моя подписка", "sub", icon="back")]))


@router.callback_query(F.data == "subdev")
async def cb_sub_devices(cb: CallbackQuery):
    if not has_access(cb.from_user.id):
        return await cb.answer("Доступ не выдан", show_alert=True)
    await show(cb, *devices_view(cb.from_user.id))
    await cb.answer()


@router.callback_query(F.data.startswith("subdel:"))
async def cb_sub_device_delete(cb: CallbackQuery):
    uid = cb.from_user.id
    dev_id = int(cb.data[7:])
    row = db.execute("SELECT * FROM sub_devices WHERE id=? AND chat_id=?", (dev_id, uid)).fetchone()
    if not row:
        return await cb.answer("Устройство не найдено", show_alert=True)
    db.execute("DELETE FROM sub_devices WHERE id=?", (dev_id,))
    db.commit()
    log.info("sub device %s of %s deleted", dev_id, uid)
    await cb.answer("Удалено")
    await show(cb, *devices_view(uid))


@router.callback_query(F.data == "sub:reissue")
async def cb_reissue_ask(cb: CallbackQuery):
    if not allowed(cb.from_user.id):
        return await cb.answer("Подписка недоступна", show_alert=True)
    await show(cb, f"<h3>{em('refresh')} Перевыпустить ссылку?</h3>"
                   f"<blockquote>{em('warn')} Старая ссылка и все текущие подключения перестанут "
                   f"работать, список устройств подписки очистится. Новую ссылку нужно будет "
                   f"добавить во все приложения заново.</blockquote>",
               kb([btn("Да, перевыпустить", "sub:reissueok", style="danger", icon="refresh"),
                   btn("Отмена", "sub", icon="no")]))
    await cb.answer()


@router.callback_query(F.data == "sub:reissueok")
async def cb_reissue(cb: CallbackQuery):
    uid = cb.from_user.id
    if not allowed(uid):
        return await cb.answer("Подписка недоступна", show_alert=True)
    await cb.answer("Перевыпускаю…")
    await reissue(uid)
    log.info("subscription reissued for %s", uid)
    text, markup = await asyncio.to_thread(sub_view, uid)
    await show(cb, f"<p>{em('ok')} <b>Готово!</b> Вот новая ссылка — добавь её в приложения.</p>"
                   + text, markup)


@router.callback_query(F.data == "sg")
async def cb_guides(cb: CallbackQuery):
    await show(cb, *guides_view())
    await cb.answer()


@router.callback_query(F.data.startswith("sg:"))
async def cb_guide(cb: CallbackQuery):
    key = cb.data[3:]
    if key not in GUIDES:
        return await cb.answer()
    await show(cb, *guide_view(key))
    await cb.answer()


def user_sub_summary(chat_id: int) -> list[tuple[str, str]]:
    """Строки для карточки пользователя в админке."""
    u = get_user(chat_id)
    if not u or not u["sub_token"] or not SUB_PROTOCOLS:
        return []
    rx = tx = 0
    for pid in SUB_PROTOCOLS:
        a, b = proto_traffic(chat_id, pid)
        rx, tx = rx + a, tx + b
    return [(f"{em('subscription')} Подписка", f"{len(sub_devices(chat_id))} устр. · "
             f"{fmt_traffic(rx, tx)}")]
