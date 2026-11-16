"""Админка: резервные копии протоколов и всего бота, восстановление из копии, сверка клиентов."""
import asyncio
import logging
import os
import shutil
from datetime import datetime

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message

from .. import backup
from ..access import is_admin
from ..progress import Progress
from ..ui import btn, em, esc, kb, show
from .admin import admin_only

log = logging.getLogger("amnezia-bot")
router = Router()

BACKUP_KINDS = {"awg": "awg", "xray": "xray", "hy2": "hy2", "amnezia": "amnezia-xray-archive"}


class RestoreWait(StatesGroup):
    file = State()


async def send_backup(bot: Bot, chat_id: int, path: str, caption_html: str) -> None:
    """Прислать архив копии (с предупреждением в подписи). Используется и при удалении."""
    await backup.send_archive(bot, chat_id, path, caption_html)


def _back(pid: str | None = None):
    if pid in ("awg", "xray", "hy2"):
        return btn("К протоколу", f"proto:card:{pid}", icon="back")
    return btn("Протоколы", "proto", icon="back")


# ===================================================================== копии ===

@router.callback_query(F.data.startswith("bk:"))
@admin_only
async def cb_backup(cb: CallbackQuery, bot: Bot):
    what = cb.data[3:]
    if what == "full":
        await show(cb, f"<h3>{em('backup')} Полная копия</h3>"
                       f"<p>Все установленные протоколы, база бота и настройки (.env). "
                       f"Подходит для переезда на новый сервер.</p>"
                       f"<blockquote>{em('lock')} Сохранить в копии токен бота? Без него после "
                       f"переезда токен нужно будет вписать в .env вручную.</blockquote>",
                   kb([btn("Без токена", "bkf:0", style="primary", icon="backup"),
                       btn("С токеном", "bkf:1", icon="key")],
                      [_back()]))
        return await cb.answer()
    kind = BACKUP_KINDS.get(what)
    if not kind:
        return await cb.answer("Неизвестная копия", show_alert=True)
    await cb.answer("Делаю копию…")
    await _make_and_send(cb, bot, kind, back_pid=what)


@router.callback_query(F.data.startswith("bkf:"))
@admin_only
async def cb_backup_full(cb: CallbackQuery, bot: Bot):
    await cb.answer("Делаю полную копию…")
    await _make_and_send(cb, bot, "full", include_token=cb.data == "bkf:1")


async def _make_and_send(cb: CallbackQuery, bot: Bot, kind: str, include_token: bool = False,
                         back_pid: str | None = None) -> None:
    title = backup.TITLES.get(kind, kind)
    await show(cb, f"<p>{em('pending')} Делаю копию: {esc(title)}…</p>")
    try:
        path = await asyncio.to_thread(backup.create_backup, kind, include_token)
        size = os.path.getsize(path)
        await send_backup(bot, cb.from_user.id, path,
                          backup.warning_caption(f"Резервная копия: {title}"))
    except Exception as e:
        log.exception("backup %s failed", kind)
        return await show(cb, f"<p>{em('error')} Не получилось сделать копию: "
                              f"<code>{esc(str(e)[:500])}</code></p>", kb([_back(back_pid)]))
    await show(cb, f"<p>{em('ok')} Копия «{esc(title)}» готова ({size // 1024} КБ) и отправлена "
                   f"файлом. На сервере хранятся последние {backup.BACKUP_KEEP}.</p>",
               kb([_back(back_pid)]))


# ============================================================== восстановление ===

@router.callback_query(F.data == "rs")
@admin_only
async def cb_restore_start(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await state.set_state(RestoreWait.file)
    await show(cb, f"<h3>{em('restore_backup')} Восстановить из копии</h3>"
                   f"<p>Пришли файл копии (<code>.tar.gz</code>) — бот проверит его и покажет, "
                   f"что будет восстановлено. Ничего не изменится, пока ты не подтвердишь.</p>"
                   f"<blockquote>{em('warn')} Боты Telegram скачивают файлы до 20 МБ.</blockquote>",
               kb([btn("Отмена", "proto", icon="no")]))
    await cb.answer()


@router.message(RestoreWait.file, F.document)
async def restore_file(m: Message, state: FSMContext, bot: Bot):
    if not is_admin(m.from_user.id):
        return await state.clear()
    doc = m.document
    cancel = kb([btn("Отмена", "proto", icon="no")])
    if doc.file_size and doc.file_size > backup.TG_DOWNLOAD_LIMIT:
        return await show(m, f"<p>{em('error')} Файл больше 20 МБ — бот не может его скачать. "
                             f"Положи архив на сервер в <code>data/backups/archives/</code> и "
                             f"пришли копию поменьше.</p>", cancel)
    d = backup.new_restore_dir()
    archive = os.path.join(d, "archive.tar.gz")
    wait = await m.answer("…")
    try:
        await bot.download(doc, destination=archive)
        manifest = await asyncio.to_thread(backup.safe_extract, archive, os.path.join(d, "data"))
    except Exception as e:
        shutil.rmtree(d, ignore_errors=True)
        await _delete(wait)
        msg = str(e) if isinstance(e, backup.BackupError) else f"не удалось прочитать файл: {e}"
        return await show(m, f"<p>{em('error')} <b>Копия не подходит:</b> {esc(msg[:500])}</p>"
                             f"<p>На сервере ничего не изменилось. Пришли другой файл или нажми "
                             f"«Отмена».</p>", cancel)
    await _delete(wait)
    data_dir = os.path.join(d, "data")
    text = (f"<h3>{em('restore_backup')} Что будет восстановлено</h3>"
            + backup.describe(manifest, data_dir))
    rows = []
    kind = manifest["type"]
    if kind == "amnezia-xray-archive":
        text += (f"<blockquote>{em('warn')} Это архив XRay от Amnezia — он хранится только для "
                 f"истории и ботом не восстанавливается.</blockquote>")
    else:
        busy = backup.conflicts(manifest)
        if busy:
            names = ", ".join(backup.TITLES[p] for p in busy)
            text += (f"<blockquote>{em('warn')} {esc(names)} уже установлен. Поверх не "
                     f"восстанавливаю: сначала удали протокол кнопкой «Удалить» в его карточке "
                     f"(бот сам сделает копию текущего состояния), потом пришли копию снова."
                     f"</blockquote>")
        else:
            if kind == "full":
                text += (f"<blockquote>{em('warn')} База бота будет заменена базой из копии "
                         f"(пользователи, устройства, трафик). Затем протоколы поставятся по "
                         f"очереди с ключами из копии — конфиги и подписки у людей останутся "
                         f"прежними.</blockquote>")
            rows.append([btn("Восстановить", "rsok", style="success", icon="restore_backup")])
    rows.append([btn("Отмена", "proto", icon="no")])
    await state.set_state(None)
    await state.update_data(rs_dir=data_dir, rs_kind=kind)
    await show(m, text, kb(*rows))


@router.message(RestoreWait.file)
async def restore_not_file(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return await state.clear()
    if m.text and m.text.startswith("/"):
        await state.clear()
        return await show(m, "<p>Восстановление отменено.</p>")
    await show(m, f"<p>{em('file')} Жду файл копии <code>.tar.gz</code> документом.</p>",
               kb([btn("Отмена", "proto", icon="no")]))


async def _delete(msg) -> None:
    try:
        await msg.delete()
    except Exception:
        pass


@router.callback_query(F.data == "rsok")
@admin_only
async def cb_restore_go(cb: CallbackQuery, state: FSMContext):
    from .protocols_admin import job_lock
    data = await state.get_data()
    d, kind = data.get("rs_dir"), data.get("rs_kind")
    if not d or not os.path.isdir(d):
        return await cb.answer("Это подтверждение устарело — пришли копию заново", show_alert=True)
    if job_lock.locked():
        return await cb.answer("Уже идёт другая операция — дождись её окончания", show_alert=True)
    await state.clear()                 # повторное нажатие ничего не сделает
    await cb.answer()
    async with job_lock:
        prog = Progress(cb.message, f"{em('restore_backup')} Восстановление: "
                                    f"{backup.TITLES.get(kind, kind)}")
        await prog.show()
        try:
            done = await asyncio.to_thread(backup.restore, kind, d, prog)
        except Exception as e:
            log.exception("restore failed")
            return await prog.fail(e, kb([btn("Протоколы", "proto", icon="back")]))
    log.info("restored %s: %s", kind, done)
    text, rows = await asyncio.to_thread(_reconcile_view, done)
    if kind == "full":
        text += (f"<blockquote>{em('idea')} Если сервер переехал — смени A-запись домена на новый "
                 f"IP и разошли людям напоминание обновить подписку.</blockquote>")
        rows.append([btn("Разослать: обновите подписку", "bc:tpl:sub", style="primary",
                         icon="broadcast")])
    rows.append([btn("Протоколы", "proto", icon="protocols")])
    await prog.show(f"<h3>{em('party')} Восстановлено: "
                    f"{esc(', '.join(backup.TITLES[p] for p in done) or 'база бота')}</h3>" + text,
                    kb(*rows))


def _reconcile_view(pids: list[str]) -> tuple[str, list]:
    """Сверка клиентов в конфигах с базой и кнопки исправления расхождений."""
    text, rows = "", []
    for pid in pids:
        try:
            r = backup.reconcile(pid)
        except Exception as e:
            text += f"<p>{em('warn')} Сверка {backup.TITLES[pid]}: <code>{esc(str(e)[:200])}</code></p>"
            continue
        if not r["missing"] and not r["extra"]:
            text += f"<p>{em('ok')} {backup.TITLES[pid]}: клиенты в конфиге совпадают с базой.</p>"
            continue
        text += f"<p>{em('warn')} <b>{backup.TITLES[pid]}</b>: расхождения с базой</p>"
        if r["missing"]:
            text += ("<p>Есть в базе, нет на сервере: "
                     + esc(", ".join(r["missing"][:20])) + ("…" if len(r["missing"]) > 20 else "")
                     + "</p>")
            rows.append([btn(f"Добавить недостающих ({len(r['missing'])})", f"rc:{pid}:add",
                             icon="add")])
        if r["extra"]:
            hint = " (это могут быть клиенты из приложения)" if pid == "awg" else ""
            text += ("<p>Есть на сервере, нет в базе" + hint + ": "
                     + esc(", ".join(r["extra"][:20])) + ("…" if len(r["extra"]) > 20 else "")
                     + "</p>")
            rows.append([btn(f"Удалить лишних ({len(r['extra'])})", f"rc:{pid}:del",
                             style="danger", icon="trash")])
    return text, rows


@router.callback_query(F.data.startswith("rc:"))
@admin_only
async def cb_reconcile(cb: CallbackQuery):
    from .protocols_admin import job_lock
    _, pid, action = cb.data.split(":")
    if pid not in ("awg", "xray") or action not in ("add", "del"):
        return await cb.answer("Неизвестное действие", show_alert=True)
    if job_lock.locked():
        return await cb.answer("Уже идёт другая операция", show_alert=True)
    await cb.answer("Исправляю…")
    async with job_lock:
        try:
            n = await asyncio.to_thread(backup.apply_reconcile, pid,
                                        "add" if action == "add" else "remove")
        except Exception as e:
            log.exception("reconcile failed")
            return await show(cb, f"<p>{em('error')} Не получилось: <code>{esc(str(e)[:300])}"
                                  f"</code></p>", kb([btn("Протоколы", "proto", icon="back")]))
    text, rows = await asyncio.to_thread(_reconcile_view, [pid])
    rows.append([btn("Протоколы", "proto", icon="protocols")])
    await show(cb, f"<p>{em('ok')} {'Добавлено' if action == 'add' else 'Удалено'}: {n} · "
                   f"{datetime.now().strftime('%H:%M:%S')}</p>" + text, kb(*rows))
