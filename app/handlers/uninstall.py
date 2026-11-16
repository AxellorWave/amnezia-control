"""Удаление протоколов: три подтверждения, резервная копия, уведомления пользователям.

Экран 1 — что будет потеряно; экран 2 — копия админу файлом и «Точно удалить?»;
экран 3 — прислать название протокола или 4-значный код (2 минуты). Каждый поток
имеет свой nonce в callback-данных: кнопки старых экранов после отмены или
выполнения не срабатывают.
"""
import asyncio
import logging
import secrets
import time

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message

from .. import backup, detect, docker_util
from ..access import is_admin
from ..db import bot_pubs, db
from ..progress import Progress
from ..protocols import awg, awg_install
from ..protocols.hysteria import HY2
from ..protocols.xray import XRAY
from ..traffic import drop_device
from ..ui import btn, em, esc, kb, kv, notify, show
from .admin import admin_only
from .backup_admin import send_backup

log = logging.getLogger("amnezia-bot")
router = Router()
CODE_TTL = 120

TITLES = {"awg": "AmneziaWG", "xray": "VLESS (Xray)", "hy2": "Hysteria 2",
          "amnezia_xray": "XRay от Amnezia"}
SHORT = {"awg": "AWG", "xray": "VLESS", "hy2": "HY2", "amnezia_xray": "XRAY"}
BACKUP_KIND = {"awg": "awg", "xray": "xray", "hy2": "hy2", "amnezia_xray": "amnezia-xray-archive"}
ICON = {"awg": "awg", "xray": "xray", "hy2": "hysteria", "amnezia_xray": "xray"}


class UninstallConfirm(StatesGroup):
    code = State()


def impact(pid: str) -> dict:
    """Кого затронет удаление."""
    res = {"users": 0, "devices": 0, "app_clients": 0}
    if pid == "awg":
        res["devices"] = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        res["users"] = db.execute("SELECT COUNT(DISTINCT chat_id) FROM devices").fetchone()[0]
        if detect.running("awg"):
            try:
                mine = bot_pubs()
                res["app_clients"] = sum(1 for p in awg.server_peers() if p["pub"] not in mine)
            except Exception as e:
                log.debug("impact peers: %s", e)
    elif pid in ("xray", "hy2"):
        res["users"] = db.execute("SELECT COUNT(*) FROM users WHERE status='approved' "
                                  "AND sub_token IS NOT NULL").fetchone()[0]
        res["devices"] = db.execute("SELECT COUNT(*) FROM sub_devices").fetchone()[0]
    elif pid == "amnezia_xray":
        res["app_clients"] = "?"
    return res


async def flow(state: FSMContext, nonce: str) -> dict | None:
    data = await state.get_data()
    f = data.get("un")
    return f if f and f.get("nonce") == nonce else None


def cancel_kb(nonce: str):
    return btn("Отмена", f"unx:{nonce}", icon="no")


@router.callback_query(F.data.startswith("un:"))
@admin_only
async def cb_uninstall_start(cb: CallbackQuery, state: FSMContext):
    pid = cb.data[3:]
    e = detect.get(pid)
    if pid not in TITLES or not e:
        return await cb.answer("Протокол не найден", show_alert=True)
    await state.clear()
    nonce = secrets.token_hex(4)
    await state.update_data(un={"pid": pid, "nonce": nonce, "data": False})
    imp = await asyncio.to_thread(impact, pid)
    origin = {"amnezia": "приложение AmneziaVPN", "bot": "бот"}.get(e["origin"], e["origin"])
    rows = [(f"{em(ICON[pid])} Протокол", f"<b>{TITLES[pid]}</b>"),
            (f"{em('server')} Контейнер", f"<code>{esc(e['container'])}</code>"),
            ("Установлен через", esc(origin))]
    if pid == "awg":
        rows += [(f"{em('users')} Людей с устройствами", str(imp["users"])),
                 (f"{em('devices')} Устройств бота", str(imp["devices"])),
                 (f"{em('app')} Клиентов из приложения", str(imp["app_clients"]))]
        lost = ("Все конфиги AmneziaWG (и из бота, и из приложения) перестанут работать, "
                "устройства удалятся из бота. Трафик останется за людьми.")
    elif pid == "amnezia_xray":
        lost = ("Все клиенты XRay, выпущенные в приложении AmneziaVPN, перестанут работать. "
                "После удаления откроется мастер установки оригинального Xray.")
    else:
        rows += [(f"{em('users')} Людей с подпиской", str(imp["users"])),
                 (f"{em('hwid_device')} Устройств подписки", str(imp["devices"]))]
        lost = (f"{TITLES[pid]} исчезнет из подписок. Ссылки подписки у людей останутся, "
                f"креды сохранятся — при повторной установке всё вернётся.")
    log.info("uninstall %s: step 1 by %s", pid, cb.from_user.id)
    await show(cb, f"<h2>{em('uninstall')} Удаление: {TITLES[pid]}</h2>" + kv(rows)
                   + f"<blockquote>{em('warn')} {lost}</blockquote>"
                   f"<p>Дальше бот сделает резервную копию и пришлёт её файлом.</p>",
               kb([btn("Продолжить", f"un2:{nonce}", style="danger", icon="uninstall"),
                   cancel_kb(nonce)]))
    await cb.answer()


@router.callback_query(F.data.startswith("unx:"))
@admin_only
async def cb_uninstall_cancel(cb: CallbackQuery, state: FSMContext):
    f = await flow(state, cb.data[4:])
    if f:
        log.info("uninstall %s: cancelled by %s", f["pid"], cb.from_user.id)
        await state.clear()
    await show(cb, f"<p>{em('ok')} Удаление отменено, ничего не изменилось.</p>",
               kb([btn("Протоколы", "proto", icon="protocols")]))
    await cb.answer()


@router.callback_query(F.data.startswith("un2:"))
@admin_only
async def cb_uninstall_backup(cb: CallbackQuery, state: FSMContext, bot: Bot):
    nonce = cb.data[4:]
    f = await flow(state, nonce)
    if not f or f.get("stage", 1) != 1:
        return await cb.answer("Этот экран устарел", show_alert=True)
    pid = f["pid"]
    f["stage"] = 2
    await state.update_data(un=f)
    await cb.answer()
    await show(cb, f"<p>{em('pending')} Делаю резервную копию {TITLES[pid]}…</p>")
    try:
        path = await asyncio.to_thread(backup.create_backup, BACKUP_KIND[pid])
        await send_backup(bot, cb.message.chat.id, path,
                          f"{em('backup')} <b>Копия {TITLES[pid]} перед удалением</b>")
        log.info("uninstall %s: backup %s", pid, path)
    except Exception as e:
        log.exception("uninstall backup failed")
        await state.clear()
        return await show(cb, f"<p>{em('error')} Не удалось сделать копию — удаление "
                              f"остановлено.</p><pre>{esc(str(e)[:800])}</pre>",
                          kb([btn("Протоколы", "proto", icon="back")]))
    await show(cb, *screen2(f))


def screen2(f: dict):
    pid, nonce = f["pid"], f["nonce"]
    text = (f"<h2>{em('uninstall')} Точно удалить {TITLES[pid]}?</h2>"
            f"<p>{em('ok')} Резервная копия отправлена файлом выше — из неё можно всё "
            f"восстановить («Восстановить из копии» в «Протоколах»).</p>")
    rows = []
    if pid in ("awg", "amnezia_xray"):
        mark = "ok" if f.get("data") else "no"
        text += kv([("Удалить образ и данные", f"{em(mark)} {'да' if f.get('data') else 'нет'}")])
        rows.append([btn("Удалять образ и данные: вкл/выкл", f"und:{nonce}", icon="edit")])
    rows.append([btn("Да, удалить", f"un3:{nonce}", style="danger", icon="uninstall"),
                 cancel_kb(nonce)])
    return text, kb(*rows)


@router.callback_query(F.data.startswith("und:"))
@admin_only
async def cb_uninstall_toggle_data(cb: CallbackQuery, state: FSMContext):
    f = await flow(state, cb.data[4:])
    if not f or f.get("stage") != 2:
        return await cb.answer("Этот экран устарел", show_alert=True)
    f["data"] = not f.get("data")
    await state.update_data(un=f)
    await show(cb, *screen2(f))
    await cb.answer()


@router.callback_query(F.data.startswith("un3:"))
@admin_only
async def cb_uninstall_code(cb: CallbackQuery, state: FSMContext):
    f = await flow(state, cb.data[4:])
    if not f or f.get("stage") != 2:
        return await cb.answer("Этот экран устарел", show_alert=True)
    f.update(stage=3, code=f"{secrets.randbelow(10000):04d}", until=time.time() + CODE_TTL)
    await state.update_data(un=f)
    await state.set_state(UninstallConfirm.code)
    log.info("uninstall %s: step 3 (code requested)", f["pid"])
    await show(cb, f"<h2>{em('lock')} Последнее подтверждение</h2>"
                   f"<p>Пришли в ответ название протокола <code>{SHORT[f['pid']]}</code> "
                   f"или код <code>{f['code']}</code>.</p>"
                   f"<blockquote>{em('clock')} У тебя 2 минуты. Любой другой ответ — отмена."
                   f"</blockquote>", kb([cancel_kb(f["nonce"])]))
    await cb.answer()


@router.message(UninstallConfirm.code)
async def uninstall_code(m: Message, state: FSMContext, bot: Bot):
    if not is_admin(m.from_user.id):
        return await state.clear()
    f = (await state.get_data()).get("un") or {}
    await state.clear()
    answer = (m.text or "").strip()
    ok = (f.get("stage") == 3 and time.time() <= f.get("until", 0)
          and answer.upper() in (SHORT.get(f.get("pid"), "\0"), f.get("code")))
    if not ok:
        log.info("uninstall %s: cancelled at step 3 (answer mismatch or timeout)", f.get("pid"))
        reason = "время вышло" if time.time() > f.get("until", 0) else "ответ не совпал"
        return await show(m, f"<p>{em('ok')} Удаление отменено ({reason}), ничего не "
                             f"изменилось.</p>", kb([btn("Протоколы", "proto", icon="protocols")]))
    from .protocols_admin import job_lock
    if job_lock.locked():
        return await show(m, f"<p>{em('warn')} Идёт другая операция — попробуй позже.</p>")
    msg = await show_new(m, f"<p>{em('pending')} Удаляю…</p>")
    async with job_lock:
        prog = Progress(msg, f"{em('uninstall')} Удаление: {TITLES[f['pid']]}")
        try:
            affected = await asyncio.to_thread(do_uninstall, f["pid"], bool(f.get("data")), prog)
        except Exception as e:
            log.exception("uninstall %s failed", f["pid"])
            await asyncio.to_thread(detect.refresh)
            return await prog.fail(e, kb([btn("Протоколы", "proto", icon="back")]))
    await asyncio.to_thread(detect.refresh)
    sent = await notify_users(bot, f["pid"], affected)
    log.info("uninstall %s: done, notified %s users", f["pid"], sent)
    rows = [[btn("Протоколы", "proto", icon="protocols")]]
    if f["pid"] == "amnezia_xray":
        rows.insert(0, [btn("Установить оригинальный Xray", "pi:xray", style="primary",
                            icon="install")])
    await prog.show(f"<h3>{em('ok')} {TITLES[f['pid']]} удалён</h3>"
                    + kv([(f"{em('users')} Уведомлено людей", str(sent))]), kb(*rows))


async def show_new(m: Message, text: str):
    from ..ui import send_view
    return await send_view(m.bot, m.chat.id, text)


def do_uninstall(pid: str, remove_data: bool, progress) -> list[int]:
    """Удалить протокол; вернуть chat_id затронутых людей."""
    if pid == "awg":
        container = (detect.get("awg") or {}).get("container", awg.CONTAINER)
        affected = [r[0] for r in db.execute("SELECT DISTINCT chat_id FROM devices")]
        progress(f"Остановка и удаление контейнера {container}")
        docker_util.docker("rm", "-fv", container, check=False, timeout=120)
        if remove_data:
            progress("Удаление образа")
            docker_util.docker("rmi", container, check=False, timeout=120)
        others = [c for c in docker_util.network_containers(awg_install.NETWORK) if c != container]
        if remove_data and not others:
            progress("Удаление сети amnezia-dns-net (к ней больше никто не подключён)")
            docker_util.docker("network", "rm", awg_install.NETWORK, check=False, timeout=60)
        progress("Удаление AWG-устройств из базы (трафик остаётся за людьми)")
        for (dev_id,) in db.execute("SELECT id FROM devices").fetchall():
            drop_device(dev_id)
        db.execute("DELETE FROM protocols WHERE id='awg'")
        db.commit()
        return affected
    if pid == "amnezia_xray":
        progress("Остановка и удаление контейнера amnezia-xray")
        docker_util.docker("rm", "-f", "amnezia-xray", check=False, timeout=120)
        if remove_data:
            progress("Удаление образа и тома amnezia-xray-data")
            docker_util.docker("rmi", "amnezia-xray", check=False, timeout=120)
            docker_util.docker("volume", "rm", "amnezia-xray-data", check=False, timeout=60)
        return []
    proto = XRAY if pid == "xray" else HY2
    affected = [r[0] for r in db.execute("SELECT chat_id FROM users WHERE status='approved' "
                                         "AND sub_token IS NOT NULL")]
    proto.uninstall(progress, remove_data=False)
    db.execute("DELETE FROM protocols WHERE id=?", (pid,))
    db.commit()
    return affected


async def notify_users(bot: Bot, pid: str, chat_ids: list[int]) -> int:
    if not chat_ids:
        return 0
    if pid == "awg":
        what = ("Конфиги AmneziaWG больше не работают."
                + (" Подключись через «Мою подписку» (VLESS / Hysteria2)."
                   if detect.sub_protocols() else " Администратор сообщит, когда будет замена."))
        markup = kb([btn("Моя подписка", "sub", icon="subscription")] if detect.sub_protocols()
                    else [], [btn("Меню", "menu", icon="home")])
    else:
        rest = [TITLES[p] for p in detect.sub_protocols()]
        what = (f"Обнови подписку в приложении — останутся {', '.join(rest)}." if rest
                else "Пока используй другой протокол, если он есть в меню.")
        markup = kb([btn("Меню", "menu", icon="home")])
    sent = 0
    for cid in set(chat_ids):
        if await notify(bot, cid, f"<h3>{em('warn')} {TITLES[pid]} больше не доступен</h3>"
                                  f"<p>{what}</p>", markup):
            sent += 1
        await asyncio.sleep(0.05)
    return sent
