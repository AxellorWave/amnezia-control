"""Админка → «Протоколы»: что установлено на сервере, состояние, порты, клиенты,
мастер установки протоколов."""
import asyncio
import json
import logging
from datetime import datetime

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from .. import detect, ports
from ..access import is_admin
from ..db import db, now
from ..progress import Progress
from ..protocols import awg, awg_install
from ..ui import btn, em, esc, kb, kv, show, table
from .admin import admin_only

log = logging.getLogger("amnezia-bot")
router = Router()

PROTO_ICON = {"awg": "awg", "xray": "xray", "hy2": "hysteria", "amnezia_xray": "xray"}
STATE_TEXT = {"running": "работает", "stopped": "остановлен"}
ORIGIN_TEXT = {"amnezia": "из приложения Amnezia", "bot": "установлен ботом",
               "foreign": "установлен вручную"}


def fmt_ports(ports) -> str:
    return ", ".join(f"{p}/{proto}" for proto, p in ports) or "—"


def state_html(e: dict | None) -> str:
    if not e:
        return f"{em('offline')} нет"
    return (f"{em('online')} {STATE_TEXT['running']}" if e["state"] == "running"
            else f"{em('error')} {STATE_TEXT['stopped']}")


def clients_count(pid: str) -> str:
    try:
        if pid == "awg" and detect.running("awg"):
            return str(len(awg.server_peers()))
        if pid in ("xray", "hy2"):
            col = "uuid" if pid == "xray" else "hy2_pass"
            cols = [r[1] for r in db.execute("PRAGMA table_info(users)")]
            if col in cols:
                return str(db.execute(f"SELECT COUNT(*) FROM users WHERE status='approved' "
                                      f"AND {col} IS NOT NULL").fetchone()[0])
    except Exception as e:
        log.debug("clients count %s: %s", pid, e)
    return "—"


def protocols_view() -> tuple[str, InlineKeyboardMarkup]:
    st = detect.STATE
    text = f"<h2>{em('protocols')} Протоколы</h2>"
    if not st.get("docker"):
        text += (f"<blockquote>{em('error')} Нет доступа к Docker: "
                 f"<code>{esc(st.get('error') or 'неизвестно')}</code></blockquote>")
    rows_t, rows = [], []
    for pid, title in (("awg", "AmneziaWG"), ("xray", "VLESS (Xray)"), ("hy2", "Hysteria 2")):
        e = st.get(pid)
        rows_t.append([f"{em(PROTO_ICON[pid])} <b>{title}</b>", state_html(e),
                       esc(ORIGIN_TEXT.get(e["origin"], "")) if e else "—",
                       fmt_ports(e["ports"]) if e else "—",
                       clients_count(pid) if e else "—"])
        if e:
            rows.append([btn(f"{title}", f"proto:card:{pid}", icon=PROTO_ICON[pid])])
        elif pid in WIZARDS:
            rows.append([btn(f"Установить {title}", f"pi:{pid}", style="primary", icon="install")])
    if st.get("amnezia_xray"):
        e = st["amnezia_xray"]
        rows_t.append([f"{em('xray')} <b>XRay от Amnezia</b>", state_html(e),
                       "не управляется ботом", fmt_ports(e["ports"]), "—"])
    text += table(rows_t, head=["Протокол", "Состояние", "Откуда", "Порты", "Клиентов"])
    others = st.get("others", []) + st.get("foreign", [])
    if others:
        text += table([[esc(o["title"]), f"<code>{esc(o['container'])}</code>", state_html(o),
                        fmt_ports(o["ports"])] for o in others],
                      head=["Ещё на сервере", "Контейнер", "Состояние", "Порты"],
                      caption="Установлено, ботом не поддерживается")
    ts = datetime.fromtimestamp(st["ts"]).strftime("%H:%M:%S") if st.get("ts") else "—"
    text += f"<footer>{em('clock')} проверено {ts}</footer>"
    rows.append([btn("Обновить", "proto:refresh", icon="refresh")])
    rows.append([btn("Админка", "adm", icon="back")])
    return text, kb(*rows)


def protocol_card(pid: str) -> tuple[str, InlineKeyboardMarkup]:
    e = detect.get(pid)
    title = {"awg": "AmneziaWG", "xray": "VLESS (Xray)", "hy2": "Hysteria 2"}.get(pid, pid)
    text = f"<h2>{em(PROTO_ICON.get(pid, 'vpn'))} {title}</h2>"
    if not e:
        text += "<p>Не установлен.</p>"
    else:
        text += kv([("Состояние", state_html(e)),
                    ("Откуда", esc(ORIGIN_TEXT.get(e["origin"], e["origin"]))),
                    (f"{em('server')} Контейнер", f"<code>{esc(e['container'])}</code>"),
                    ("Образ", f"<code>{esc(e['image'])}</code>"),
                    ("Порты", fmt_ports(e["ports"])),
                    (f"{em('users')} Клиентов", clients_count(pid))])
        if e.get("error"):
            text += f"<blockquote>{em('warn')} <code>{esc(e['error'])}</code></blockquote>"
    return text, kb([btn("Протоколы", "proto", icon="back")])


@router.callback_query(F.data.in_({"proto", "proto:refresh"}))
@admin_only
async def cb_protocols(cb: CallbackQuery):
    if cb.data == "proto:refresh" or not detect.STATE.get("ts"):
        await asyncio.to_thread(detect.refresh)
    await show(cb, *(await asyncio.to_thread(protocols_view)))
    await cb.answer()


@router.callback_query(F.data.startswith("proto:card:"))
@admin_only
async def cb_protocol_card(cb: CallbackQuery):
    await show(cb, *(await asyncio.to_thread(protocol_card, cb.data.split(":")[2])))
    await cb.answer()


# ========================================================= мастер установки ===
# Параметры мастера живут в FSM-данных админа; кнопки старого мастера после
# начала нового или после установки не срабатывают (нет данных — «устарело»).

class WizInput(StatesGroup):
    value = State()


job_lock = asyncio.Lock()          # одна установка/удаление/восстановление за раз

WIZARDS: dict[str, dict] = {
    "awg": {
        "title": "AmneziaWG 2.0",
        "about": ("Ставится так же, как из приложения AmneziaVPN: контейнер "
                  "<code>amnezia-awg2</code>, сеть <code>amnezia-dns-net</code>, параметры "
                  "обфускации AWG 2.0. Сервер потом можно добавить и в приложение."),
        "fields": [
            {"key": "port", "label": "Порт", "kind": "port", "proto": "udp",
             "default": awg_install.DEFAULT_PORT},
        ],
    },
}


def wiz_defaults(pid: str) -> dict:
    return {f["key"]: f["default"] for f in WIZARDS[pid]["fields"]}


def wiz_field(pid: str, key: str) -> dict | None:
    return next((f for f in WIZARDS[pid]["fields"] if f["key"] == key), None)


def fmt_value(f: dict, v) -> str:
    if f["kind"] == "bool":
        return f"{em('ok')} да" if v else f"{em('no')} нет"
    if f["kind"] == "choice":
        return esc(dict(f["choices"]).get(v, v))
    if f["kind"] == "port":
        return f"<code>{v}/{f['proto']}</code>"
    return f"<code>{esc(v)}</code>" if v else "<i>не задано</i>"


def wanted_ports(pid: str, p: dict) -> list[tuple[str, int]]:
    res = []
    for f in WIZARDS[pid]["fields"]:
        if f["kind"] == "port" and (not f.get("when") or p.get(f["when"])):
            res.append((f["proto"], int(p[f["key"]])))
    return res


def wizard_view(pid: str, p: dict, note: str = "") -> tuple[str, InlineKeyboardMarkup]:
    w = WIZARDS[pid]
    text = (f"<h2>{em('install')} Установка: {w['title']}</h2><p>{w['about']}</p>"
            + kv([(f["label"], fmt_value(f, p.get(f["key"])))
                  for f in w["fields"] if not f.get("when") or p.get(f["when"])]))
    if w.get("hint"):
        text += f"<blockquote>{em('idea')} {w['hint']}</blockquote>"
    if note:
        text += note
    rows = []
    for f in w["fields"]:
        if f.get("when") and not p.get(f["when"]):
            continue
        label = {"bool": "Вкл/выкл", "choice": "Сменить"}.get(f["kind"], "Изменить")
        rows.append([btn(f"{label}: {f['label'].lower()}", f"pe:{f['key']}", icon="edit")])
    rows.append([btn("Проверить и установить", "pg", style="success", icon="install")])
    rows.append([btn("Отмена", "proto", icon="no")])
    return text, kb(*rows)


async def wiz_data(state: FSMContext) -> tuple[str | None, dict]:
    data = await state.get_data()
    return data.get("wiz"), data.get("p") or {}


@router.callback_query(F.data.startswith("pi:"))
@admin_only
async def cb_install_start(cb: CallbackQuery, state: FSMContext):
    pid = cb.data[3:]
    if pid not in WIZARDS:
        return await cb.answer("Неизвестный протокол", show_alert=True)
    if detect.installed(pid):
        return await cb.answer("Уже установлен", show_alert=True)
    await state.clear()
    p = wiz_defaults(pid)
    await state.update_data(wiz=pid, p=p)
    await show(cb, *wizard_view(pid, p))
    await cb.answer()


@router.callback_query(F.data.startswith("pe:"))
@admin_only
async def cb_install_edit(cb: CallbackQuery, state: FSMContext):
    pid, p = await wiz_data(state)
    f = wiz_field(pid, cb.data[3:]) if pid else None
    if not f:
        return await cb.answer("Мастер устарел — открой его заново", show_alert=True)
    if f["kind"] == "bool":
        p[f["key"]] = not p.get(f["key"])
    elif f["kind"] == "choice":
        keys = [k for k, _ in f["choices"]]
        p[f["key"]] = keys[(keys.index(p.get(f["key"])) + 1) % len(keys)] \
            if p.get(f["key"]) in keys else keys[0]
    else:
        await state.set_state(WizInput.value)
        await state.update_data(field=f["key"])
        prompt = f.get("prompt") or (f"Пришли номер порта ({f['proto'].upper()}), 1–65535."
                                     if f["kind"] == "port" else "Пришли значение текстом.")
        await show(cb, f"<h3>{em('edit')} {f['label']}</h3><p>{prompt}</p>",
                   kb([btn("Назад", "pw", icon="back")]))
        return await cb.answer()
    await state.update_data(p=p)
    await show(cb, *wizard_view(pid, p))
    await cb.answer()


@router.callback_query(F.data == "pw")
@admin_only
async def cb_install_back(cb: CallbackQuery, state: FSMContext):
    pid, p = await wiz_data(state)
    if not pid:
        return await cb.answer("Мастер устарел — открой его заново", show_alert=True)
    await state.set_state(None)
    await show(cb, *wizard_view(pid, p))
    await cb.answer()


@router.message(WizInput.value, F.text)
async def wiz_input(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return await state.clear()
    data = await state.get_data()
    pid, p, key = data.get("wiz"), data.get("p") or {}, data.get("field")
    f = wiz_field(pid, key) if pid else None
    if not f:
        await state.clear()
        return await show(m, "<p>Мастер устарел.</p>")
    raw = m.text.strip()
    if f["kind"] == "port":
        v = ports.valid_port(raw)
        if v is None:
            return await show(m, f"<p>{em('warn')} Нужен номер порта 1–65535.</p>",
                              kb([btn("Назад", "pw", icon="back")]))
    else:
        check = f.get("validate")
        v = check(raw) if check else raw
        if v is None:
            return await show(m, f"<p>{em('warn')} {f.get('invalid', 'Неверное значение.')}</p>",
                              kb([btn("Назад", "pw", icon="back")]))
    p[key] = v
    await state.set_state(None)
    await state.update_data(p=p)
    await show(m, *wizard_view(pid, p))


@router.callback_query(F.data == "pg")
@admin_only
async def cb_install_check(cb: CallbackQuery, state: FSMContext):
    pid, p = await wiz_data(state)
    if not pid:
        return await cb.answer("Мастер устарел — открой его заново", show_alert=True)
    await cb.answer("Проверяю…")
    await show(cb, f"<p>{em('pending')} Проверяю порты и параметры…</p>")
    busy = await asyncio.to_thread(ports.check, wanted_ports(pid, p))
    problems = []
    for (proto, port), who in busy.items():
        problems.append(f"{em('error')} порт <code>{port}/{proto}</code> занят: {esc(who)}")
    pre = WIZARDS[pid].get("precheck")
    if pre:
        problems += await asyncio.to_thread(pre, p)
    if problems:
        note = (f"<blockquote>{em('warn')} <b>Так установить нельзя:</b><br>"
                + "<br>".join(problems) + "</blockquote>")
        return await show(cb, *wizard_view(pid, p, note))
    w = WIZARDS[pid]
    await show(cb, f"<h3>{em('install')} Установить {w['title']}?</h3>"
                   + kv([(f["label"], fmt_value(f, p.get(f["key"])))
                         for f in w["fields"] if not f.get("when") or p.get(f["when"])])
                   + f"<p>{em('ok')} Порты свободны.</p>",
               kb([btn("Установить", "pgo", style="success", icon="install"),
                   btn("Назад", "pw", icon="back")]))


async def finish_install(pid: str, result: dict) -> None:
    db.execute("INSERT OR REPLACE INTO protocols (id, origin, container, settings, installed_at) "
               "VALUES (?, 'bot', ?, ?, ?)",
               (pid, result.get("container", ""), json.dumps(result.get("settings", {})), now()))
    db.commit()
    await asyncio.to_thread(detect.refresh)


def run_install(pid: str, p: dict, progress) -> dict:
    if pid == "awg":
        r = awg_install.install(int(p["port"]), progress)
        return {"container": awg_install.CONTAINER, "settings": {"port": r["port"],
                                                                 "subnet": r["subnet"]},
                "summary": [("Порт", f"<code>{r['port']}/udp</code>"),
                            ("Подсеть", f"<code>{r['subnet']}</code>")]}
    raise RuntimeError("Установка этого протокола не поддерживается")


@router.callback_query(F.data == "pgo")
@admin_only
async def cb_install_go(cb: CallbackQuery, state: FSMContext, bot: Bot):
    pid, p = await wiz_data(state)
    if not pid:
        return await cb.answer("Мастер устарел — открой его заново", show_alert=True)
    if job_lock.locked():
        return await cb.answer("Уже идёт другая операция — дождись её окончания", show_alert=True)
    await state.clear()                  # кнопки этого мастера больше не сработают
    await cb.answer()
    w = WIZARDS[pid]
    async with job_lock:
        prog = Progress(cb.message, f"{em('install')} Установка: {w['title']}")
        await prog.show()
        try:
            result = await asyncio.to_thread(run_install, pid, p, prog)
            await finish_install(pid, result)
        except Exception as e:
            log.exception("install %s failed", pid)
            await asyncio.to_thread(detect.refresh)
            return await prog.fail(e, kb([btn("Протоколы", "proto", icon="back")]))
    await prog.show(f"<h3>{em('party')} {w['title']} установлен</h3>"
                    + kv(result.get("summary", [])) + result.get("note", ""),
                    kb([btn("Протоколы", "proto", icon="protocols")]))
    log.info("installed %s: %s", pid, result.get("settings"))
