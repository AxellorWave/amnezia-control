"""«Моя подписка»: одна ссылка на все устройства (VLESS + Hysteria2), QR, открытие в
приложениях, устройства подписки (HWID), перевыпуск ссылки, инструкции."""
import asyncio
import logging
from datetime import datetime

from aiogram import Bot, F, Router
from aiogram.types import BufferedInputFile, CallbackQuery, InlineKeyboardMarkup

from .. import detect, guides, sub_server
from ..access import device_limit, has_access
from ..db import db, ensure_creds, get_user, sub_devices
from ..protocols.awg import qr_png
from ..protocols.registry import SUB_PROTOCOLS, TITLES
from ..subsync import reissue
from ..traffic import ONLINE_NOW, proto_traffic
from ..ui import btn, em, esc, fmt_traffic, kb, kv, show, table, with_emoji_fallback

log = logging.getLogger("amnezia-bot")
router = Router()

PROTO_ICON = {"xray": "xray", "hy2": "hysteria"}
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


def ru_blocked_protocols() -> list[str]:
    """Протоколы подписки, на которых включён блок RU (российские сайты не открываются)."""
    res = []
    for pid in detect.sub_protocols():
        try:
            if (SUB_PROTOCOLS[pid].settings() or {}).get("block_ru"):
                res.append(pid)
        except Exception as e:
            log.debug("block_ru %s: %s", pid, e)
    return res


HOW_TO_SPLIT = ("«Списки сервисов» → «Российские сервисы» → отметь нужное (или «Все сайты "
                ".ru / .рф / .su») → режим «Всё через VPN, кроме выбранных» → «Получить файлы» → "
                "своё приложение")


def ru_notice() -> str:
    """Предупреждение про российские сайты для экранов подписки."""
    blocked = ru_blocked_protocols()
    if blocked:
        names = " и ".join(TITLES[p] for p in blocked)
        w = em("warn")
        return (f"<blockquote>{w}{w}{w} <b>На {esc(names)} российские сайты ЗАБЛОКИРОВАНЫ!</b> "
                f"{w}{w}{w}<br>Банки, Госуслуги, Яндекс, VK, маркетплейсы и другие российские "
                f"сайты через {'эти протоколы' if len(blocked) > 1 else 'этот протокол'} "
                f"<b>не откроются</b>. Обязательно настрой раздельное туннелирование, чтобы "
                f"они шли напрямую: {HOW_TO_SPLIT}.</blockquote>")
    return (f"<blockquote>{em('idea')} Желательно настроить раздельное туннелирование: "
            f"российские сайты пойдут напрямую — быстрее и без проблем с банками и "
            f"Госуслугами. {HOW_TO_SPLIT}.</blockquote>")


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
    n = len(sub_devices(uid))
    text = (f"<h2>{em('subscription')} Моя подписка</h2>"
            f"<p>Одна ссылка на все устройства: добавь её в приложение — серверы обновятся "
            f"сами. Нажми на ссылку, чтобы скопировать.</p>"
            f"<pre>{esc(url)}</pre>"
            + table(rows_t, head=["Протокол", "Состояние", "Трафик"])
            + ru_notice()
            + kv([(f"{em('sub_devices')} Устройств подписки", f"<b>{n}</b>"
                   + ("" if lim is None else
                      f" <i>(общий лимит {lim} — вместе с устройствами AmneziaWG)</i>"))])
            + f"<footer>{em('lock')} Ссылка — как пароль: не пересылай её другим людям.</footer>")
    t = u["sub_token"]
    rows = [[btn("Открыть в Happ", url=sub_server.open_url("happ", t), icon="play"),
             btn("Открыть в Incy", url=sub_server.open_url("incy", t), icon="play")],
            [btn("v2RayTun", url=sub_server.open_url("v2raytun", t), icon="play"),
             btn("Hiddify", url=sub_server.open_url("hiddify", t), icon="play")],
            [btn("QR-код", "sub:qr", icon="qr"), btn("Как подключиться", "sg", icon="help")],
            [btn("Списки сервисов", "routes", icon="globe",
                 style="danger" if ru_blocked_protocols() else "primary"),
             btn("Раздельное туннелирование", "sgs", icon="ip_change")],
            [btn("Устройства подписки", "subdev", icon="sub_devices")],
            [btn("Перевыпустить ссылку", "sub:reissue", icon="refresh"),
             btn("Не работает VPN", "sos", icon="sos")],
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


def _with_notice(view: tuple[str, InlineKeyboardMarkup]) -> tuple[str, InlineKeyboardMarkup]:
    text, markup = view
    markup.inline_keyboard.insert(0, [btn("Списки сервисов", "routes", icon="globe",
                                          style="danger" if ru_blocked_protocols()
                                          else "primary")])
    return text + ru_notice(), markup


def guides_view() -> tuple[str, InlineKeyboardMarkup]:
    return _with_notice(guides.sub_index())


def guide_view(key: str) -> tuple[str, InlineKeyboardMarkup]:
    return _with_notice(guides.sub_guide(key))


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
    if key not in guides.SUB_CLIENTS:
        return await cb.answer()
    await show(cb, *guide_view(key))
    await cb.answer()


@router.callback_query(F.data == "sgs")
async def cb_split_index(cb: CallbackQuery):
    await show(cb, *guides.sub_split_index())
    await cb.answer()


@router.callback_query(F.data.startswith("sgs:"))
async def cb_split(cb: CallbackQuery):
    key = cb.data[4:]
    if key not in guides.SUB_CLIENTS:
        return await cb.answer()
    await show(cb, *guides.sub_split(key))
    await cb.answer()


# раздельное туннелирование для AmneziaWG (AmneziaVPN, DefaultVPN, AmneziaWG .conf)
@router.callback_query(F.data == "gs")
async def cb_awg_split_index(cb: CallbackQuery):
    await show(cb, *guides.awg_split_index())
    await cb.answer()


@router.callback_query(F.data.startswith("gs:"))
async def cb_awg_split(cb: CallbackQuery):
    key = cb.data[3:]
    if key not in guides.AWG_SPLIT_KEYS:
        return await cb.answer()
    await show(cb, *guides.awg_split(key))
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
