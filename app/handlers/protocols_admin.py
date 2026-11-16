"""Админка → «Протоколы»: что установлено на сервере, состояние, порты, клиенты."""
import asyncio
import logging
from datetime import datetime

from aiogram import F, Router
from aiogram.types import CallbackQuery, InlineKeyboardMarkup

from .. import detect
from ..db import db
from ..protocols import awg
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
