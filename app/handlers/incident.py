"""Кнопка «Не работает VPN» у пользователя и кнопки инцидента у админа."""
import logging
import time
from datetime import datetime

from aiogram import Bot, F, Router
from aiogram.types import CallbackQuery

from .. import blockcheck, detect, health
from ..access import device_limit, has_access, is_admin
from ..db import devices_count, get_user, user_devices
from ..ui import btn, em, esc, fmt_seen, kb, kv, show
from .admin import admin_only

log = logging.getLogger("amnezia-bot")
router = Router()

# Шаги решения: (заголовок кнопки, иконка, инструкция)
STEPS = {
    "upd": ("Обнови подписку", "refresh",
            "<p>Открой приложение (Happ, v2RayTun, Hiddify) и обнови подписку: в списке "
            "серверов нажми ↻ (обновить) или потяни список вниз. Приложение заберёт свежие "
            "настройки сервера.</p>"),
    "switch": ("Другой протокол", "protocols",
               "<p>В подписке несколько серверов: VLESS и Hysteria 2. Если один не "
               "подключается — выбери другой. Если у тебя есть устройство AmneziaWG — попробуй "
               "его.</p>"),
    "toggle": ("Перезапусти VPN", "refresh",
               "<ol><li>Выключи VPN в приложении.</li><li>Полностью закрой приложение "
               "(смахни из списка запущенных).</li><li>Открой снова и подключись.</li></ol>"),
    "net": ("Другая сеть", "globe",
            "<p>Переключись между Wi-Fi и мобильным интернетом. Если в одной сети работает, "
            "а в другой нет — дело в сети (провайдер или роутер), а не в сервере.</p>"),
    "profile": ("Проверь профиль", "question",
                "<p>Убедись, что в приложении выбран именно наш сервер/профиль, а не старый "
                "или чужой. В AmneziaVPN — сервер с нашим именем, в Happ/Hiddify — сервер из "
                "нашей подписки.</p>"),
    "white": ("Работают только некоторые сайты", "warn",
              "<p>Если на мобильном интернете не открывается вообще ничего, кроме отдельных "
              "разрешённых сайтов и сервисов, — это «белые списки» оператора. Это ограничение "
              "самой мобильной сети: VPN тут не поможет, пока оператор его не снимет. "
              "Через Wi-Fi VPN при этом работает.</p>"),
    "reissue": ("Перевыпусти конфиг/ссылку", "key",
                "<p>Если ничего не помогло — выпусти доступ заново. Для подписки — «Перевыпустить "
                "ссылку» (старые подключения перестанут работать, ссылку нужно будет добавить в "
                "приложение заново). Для AmneziaWG — удали устройство и добавь его снова.</p>"),
}


def _iso_ago(s: str | None) -> str:
    if not s:
        return "нет данных"
    try:
        return fmt_seen(int(datetime.fromisoformat(s).timestamp()))
    except ValueError:
        return "нет данных"


def diagnostics(uid: int) -> str:
    """Что известно о доступе и подключениях пользователя."""
    u = get_user(uid)
    rows = []
    if u and u["status"] in ("revoked", "denied") and not is_admin(uid):
        return f"<blockquote>{em('denied')} Доступ к VPN отозван — напиши администратору.</blockquote>"
    devs = user_devices(uid)
    has_sub = bool(u and u["sub_token"] and detect.sub_protocols())
    if detect.installed("awg"):
        rows.append((f"{em('devices')} Устройства AWG", f"<b>{len(devs)}</b>"))
    if detect.sub_protocols():
        rows.append((f"{em('subscription')} Подписка", "есть" if has_sub else "ещё не открыта"))
    lim = device_limit(uid)
    if lim is not None:
        n = devices_count(uid)
        rows.append((f"{em('limit')} Лимит устройств",
                     f"<b>{n} из {lim}</b>" + (f" {em('warn')} достигнут" if n >= lim else "")))
    last = 0
    if devs and detect.running("awg"):
        try:
            from ..protocols.awg import peer_stats
            st = peer_stats()
            last = max([st.get(d["pub"], {}).get("hs", 0) for d in devs] or [0])
        except Exception as e:
            log.debug("peer stats: %s", e)
    seen = fmt_seen(last) if last else _iso_ago(u["last_online"] if u else None)
    rows.append((f"{em('clock')} Последнее подключение", seen))
    text = kv(rows)
    if not devs and not has_sub:
        text += (f"<blockquote>{em('idea')} У тебя пока нет ни одного подключения — "
                 f"добавь устройство или открой «Мою подписку».</blockquote>")
    elif lim is not None and devices_count(uid) >= lim:
        text += (f"<blockquote>{em('limit')} Лимит устройств достигнут — новое устройство не "
                 f"получит подписку. Удали ненужное в боте.</blockquote>")
    return text


def steps_kb(uid: int, partial: bool = False):
    rows = [[btn(STEPS["upd"][0], "sosh:upd", icon=STEPS["upd"][1]),
             btn(STEPS["switch"][0], "sosh:switch", icon=STEPS["switch"][1])],
            [btn(STEPS["toggle"][0], "sosh:toggle", icon=STEPS["toggle"][1]),
             btn(STEPS["net"][0], "sosh:net", icon=STEPS["net"][1])],
            [btn(STEPS["profile"][0], "sosh:profile", icon=STEPS["profile"][1]),
             btn(STEPS["reissue"][0], "sosh:reissue", icon=STEPS["reissue"][1])],
            [btn(STEPS["white"][0], "sosh:white", icon=STEPS["white"][1])],
            [btn("Не помогло — написать администратору", "umsg:sos", icon="message")],
            [btn("Меню", "menu", icon="back")]]
    return kb(*rows)


@router.callback_query(F.data == "sos")
async def cb_sos(cb: CallbackQuery, bot: Bot):
    uid = cb.from_user.id
    if not has_access(uid):
        return await cb.answer("Доступ не выдан", show_alert=True)
    await cb.answer()
    await show(cb, f"<h3>{em('sos')} Не работает VPN</h3><p>{em('pending')} Проверяю сервер "
                   f"из России… Это займёт до минуты.</p>")
    try:
        r = await health.check()
    except Exception as e:
        log.warning("sos check failed: %s", e)
        r = {"status": "unknown", "items": [], "error": str(e)[:200], "ts": time.time(),
             "host": ""}
    st = r["status"]
    if st in ("ip_blocked", "server_down"):
        inc = await health.open_incident(bot, r, by_user=uid)
        health.add_notified(inc["id"], uid)
        what = ("IP сервера заблокирован" if st == "ip_blocked" else "Сервер сейчас недоступен")
        return await show(cb, f"<h3>{em('incident')} {what}</h3>"
                              f"<p>Я уже передал администратору, VPN скоро починят. "
                              f"Сообщу, когда заработает.</p>",
                          kb([btn("Меню", "menu", icon="back")]))
    if st == "partial":
        bad = ", ".join(health.PROTO_TITLE.get(p, p) for p in health.bad_protocols(r))
        good = ", ".join(health.PROTO_TITLE.get(p, p) for p in health.ok_protocols(r)
                         if p != "sub")
        await health.notify_partial(bot, r)
        text = (f"<h3>{em('incident')} Сейчас не работает: {esc(bad)}</h3>"
                f"<p>Администратор уже в курсе. Пока переключись на работающий протокол"
                + (f": <b>{esc(good)}</b>" if good else "") + ".</p>")
        return await show(cb, text + diagnostics(uid), steps_kb(uid, partial=True))
    if st == "ok":
        head = (f"<h3>{em('health_ok')} Сервер работает и доступен из России</h3>"
                f"<p>Значит, дело скорее в устройстве, приложении или сети. Вот что известно:</p>")
    else:
        head = (f"<h3>{em('question')} Не удалось проверить сервер</h3>"
                f"<p>Сервис проверки сейчас не ответил. Попробуй шаги ниже, а если не "
                f"поможет — напиши администратору.</p>")
    text = head + diagnostics(uid) + "<p>Попробуй по шагам 👇</p>"
    await show(cb, text, steps_kb(uid))


@router.callback_query(F.data.startswith("sosh:"))
async def cb_sos_step(cb: CallbackQuery):
    key = cb.data[5:]
    step = STEPS.get(key)
    if not step:
        return await cb.answer()
    uid = cb.from_user.id
    rows = []
    if key == "reissue":
        u = get_user(uid)
        if u and u["sub_token"] and detect.sub_protocols():
            rows.append([btn("Перевыпустить ссылку", "sub:reissue", style="danger", icon="key")])
        if user_devices(uid):
            rows.append([btn("Мои устройства", "devs", icon="devices")])
    elif key == "upd" and detect.sub_protocols():
        rows.append([btn("Моя подписка", "sub", icon="subscription")])
    rows.append([btn("Назад к шагам", "sos", icon="back")])
    await show(cb, f"<h3>{em(step[1])} {step[0]}</h3>{step[2]}", kb(*rows))
    await cb.answer()


# ==================================================================== админ ===

@router.callback_query(F.data.in_({"inc:fixed", "inc:check"}))
@admin_only
async def cb_inc_fixed(cb: CallbackQuery, bot: Bot):
    if not health.open_incident_row():
        await cb.answer("Открытого инцидента нет")
        r = await health.check(force=True)
        return await show(cb, f"<h3>{em('health_ok')} Инцидентов нет</h3>" + health.result_html(r))
    await cb.answer("Проверяю…")
    await show(cb, f"<p>{em('pending')} Проверяю IP, DNS и доступность из России…</p>")
    try:
        status = await health.watch_step(bot, force_check=True)
    except Exception as e:
        status = f"Ошибка проверки: {e}"
    inc = health.open_incident_row()
    if not inc:
        return await show(cb, f"<h3>{em('health_ok')} Инцидент закрыт</h3><p>{esc(status)}</p>")
    await show(cb, f"<h3>{em('incident')} Инцидент ещё открыт</h3><p>{esc(status)}</p>"
                   + health.result_html(health.last_result()), health.admin_kb())


@router.callback_query(F.data == "inc:status")
@admin_only
async def cb_inc_status(cb: CallbackQuery):
    await cb.answer()
    inc = health.open_incident_row()
    r = health.last_result()
    if inc:
        mins = max(1, round((time.time() - inc["started_at"]) / 60))
        text = (f"<h3>{em('incident')} Инцидент #{inc['id']} — {mins} мин</h3>"
                + kv([(f"{em('server')} Старый IP", f"<code>{esc(inc['old_ip'] or '?')}</code>"),
                      (f"{em('ip_change')} Новый IP", f"<code>{esc(inc['new_ip'] or '—')}</code>"),
                      (f"{em('dns')} A-запись", f"<code>{esc(inc['dns_ip'] or '?')}</code>")])
                + health.result_html(r))
        return await show(cb, text, health.admin_kb())
    await show(cb, f"<h3>{em('health_ok')} Инцидентов нет</h3>" + health.result_html(r),
               kb([btn("Проверить сейчас", "inc:check", icon="refresh")]))


@router.callback_query(F.data.in_({"blk", "blk:check"}))
@admin_only
async def cb_blockcheck(cb: CallbackQuery):
    force = cb.data == "blk:check"
    await cb.answer("Проверяю…" if force else "")
    if force or not blockcheck.last_result():
        await show(cb, f"<p>{em('pending')} Проверяю IP и домен по спискам блокировок…</p>")
    r = await blockcheck.check(force=force)
    await show(cb, f"<h3>{em('lock')} Блокировка IP</h3>" + blockcheck.result_html(r),
               kb([btn("Проверить сейчас", "blk:check", icon="refresh")],
                  [btn("Админка", "adm", icon="back")]))
