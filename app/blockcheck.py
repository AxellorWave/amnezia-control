"""Блокировка IP по реестрам РКН — через публичный API cheburcheck.ru.

Отдельно от проверки доступности (health.py): health смотрит, открываются ли порты из
России, а здесь — числится ли IP сервера (и домен VPN_HOST) в списках блокировок.
Фоновая проверка раз в час; при смене состояния бот пишет админам.
API: GET https://cheburcheck.ru/api/v1/check?target=<ip|домен>, без токена.
"""
import asyncio
import ipaddress
import json
import logging
import time
from datetime import datetime

import aiohttp

from .config import ADMIN_IDS, VPN_HOST
from .db import db
from .ui import em, esc, kv, notify

log = logging.getLogger("amnezia-bot")

API = "https://cheburcheck.ru/api/v1/check"
SITE = "https://cheburcheck.ru"
CHECK_EVERY = 3600
CACHE_SEC = 300
HEADERS = {"Accept": "application/json", "User-Agent": "vpn-blockcheck/1.0"}


def init_tables() -> None:
    db.execute("CREATE TABLE IF NOT EXISTS block_checks (target TEXT PRIMARY KEY, "
               "blocked INTEGER, checked_at REAL, details TEXT)")
    db.commit()


init_tables()


def is_ip(t: str) -> bool:
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def parse(data: dict) -> dict:
    """Ответ API -> {blocked, subnets, cdn, ips, whitelist}."""
    cdn = sorted((data.get("cdn_providers") or {}).keys())
    return {"blocked": bool(data.get("blocked")),
            "subnets": [str(s) for s in data.get("blocked_subnets") or []],
            "cdn": cdn,
            "ips": [str(i) for i in data.get("ips") or []],
            "whitelist": bool(data.get("whitelist"))}


async def check_one(session: aiohttp.ClientSession, target: str) -> dict:
    async with session.get(API, params={"target": target}, headers=HEADERS,
                           timeout=aiohttp.ClientTimeout(total=20)) as r:
        if r.status == 429:
            raise RuntimeError("cheburcheck: слишком много запросов, попробую позже")
        r.raise_for_status()
        return parse(await r.json(content_type=None))


async def server_targets() -> list[str]:
    """IP сервера и домен VPN_HOST (если это домен)."""
    from .health import external_ip
    res = []
    ip = await external_ip()
    if ip:
        res.append(ip)
    if VPN_HOST and VPN_HOST not in res:
        res.append(VPN_HOST)
    return res


_cache: dict = {"ts": 0.0, "result": None}
_lock = asyncio.Lock()


async def check(force: bool = False) -> dict:
    """{ts, items: [{target, blocked, subnets, cdn, ips, error}], blocked: bool|None}"""
    async with _lock:
        c = _cache["result"]
        if not force and c and time.time() - _cache["ts"] < CACHE_SEC:
            return c
        items = []
        targets = await server_targets()
        async with aiohttp.ClientSession() as s:
            for t in targets:
                try:
                    items.append(dict(await check_one(s, t), target=t, error=""))
                except Exception as e:
                    items.append({"target": t, "blocked": None, "error": str(e)[:150]})
        known = [i["blocked"] for i in items if i["blocked"] is not None]
        res = {"ts": time.time(), "items": items,
               "blocked": (any(known) if known else None)}
        _cache.update(ts=time.time(), result=res)
        log.info("blockcheck: %s", {i["target"]: i["blocked"] for i in items})
        return res


def last_result() -> dict | None:
    return _cache["result"]


def item_html(i: dict) -> str:
    if i["blocked"] is None:
        state = f"{em('question')} не удалось проверить: {esc(i['error'])}"
    elif i["blocked"]:
        state = f"{em('health_bad')} <b>в списках блокировок</b>"
    else:
        state = f"{em('health_ok')} не заблокирован"
    rows = [(f"{em('server')} {esc(i['target'])}", state)]
    if i.get("subnets"):
        rows.append(("Подсети", ", ".join(f"<code>{esc(s)}</code>" for s in i["subnets"])))
    if i.get("cdn"):
        rows.append(("CDN", esc(", ".join(i["cdn"]))))
    if not is_ip(i["target"]) and i.get("ips"):
        rows.append(("Указывает на", ", ".join(f"<code>{esc(x)}</code>" for x in i["ips"])))
    return kv(rows)


def result_html(res: dict | None) -> str:
    if not res:
        return "<p>Проверок ещё не было.</p>"
    if not res["items"]:
        return f"<p>{em('warn')} Не удалось узнать IP сервера.</p>"
    when = datetime.fromtimestamp(res["ts"]).strftime("%H:%M:%S")
    text = "".join(item_html(i) for i in res["items"])
    text += (f"<p><i>Проверено в {when} по реестрам РКН через "
             f"<a href=\"{SITE}\">cheburcheck.ru</a>. Это списки блокировок, а не замер "
             f"из России: доступность портов смотри в «Мониторинге».</i></p>")
    return text


def _saved(target: str):
    return db.execute("SELECT blocked FROM block_checks WHERE target=?", (target,)).fetchone()


def changes(res: dict) -> list[dict]:
    """Цели, у которых состояние изменилось с прошлой проверки; запоминает новое."""
    out = []
    for i in res["items"]:
        if i["blocked"] is None:
            continue
        prev = _saved(i["target"])
        if prev is None:
            if i["blocked"]:
                out.append(i)
        elif bool(prev["blocked"]) != i["blocked"]:
            out.append(i)
        db.execute("INSERT OR REPLACE INTO block_checks (target, blocked, checked_at, details) "
                   "VALUES (?, ?, ?, ?)", (i["target"], int(i["blocked"]), res["ts"],
                                           json.dumps(i, ensure_ascii=False)))
    db.commit()
    return out


async def notify_changes(bot, res: dict) -> None:
    for i in changes(res):
        title = (f"{em('health_bad')} {esc(i['target'])} попал в списки блокировок"
                 if i["blocked"] else
                 f"{em('health_ok')} {esc(i['target'])} больше не в списках блокировок")
        for a in ADMIN_IDS:
            await notify(bot, a, f"<h3>{title}</h3>" + item_html(i))


async def blockcheck_loop(bot) -> None:
    await asyncio.sleep(90)
    while True:
        try:
            await notify_changes(bot, await check(force=True))
        except Exception as e:
            log.warning("blockcheck loop: %s", e)
        await asyncio.sleep(CHECK_EVERY)
