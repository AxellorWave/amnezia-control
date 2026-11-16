"""HTTP в том же процессе (aiohttp): auth-хук Hysteria2 (только 127.0.0.1)
и сервер подписок (GET /sub/<token>, учёт устройств по HWID, лимит)."""
import asyncio
import base64
import hashlib
import html
import logging
import os
import ssl
import time
import urllib.parse

from aiohttp import web

from . import detect
from .access import device_limit
from .config import (HWID_REQUIRED, HY2_AUTH_PORT, SERVER_NAME, SUB_HOST, SUB_LISTEN, SUB_PORT)
from .db import db, devices_count, now
from .protocols.registry import SUB_PROTOCOLS

log = logging.getLogger("amnezia-bot")

RATE_WINDOW, RATE_MAX = 600, 60            # запросов с одного IP за 10 минут
NOTICE_EVERY = 3600                       # уведомление о лимите — не чаще раза в час на устройство
_hits: dict[str, list[float]] = {}
_bot = None
_ssl_ctx: ssl.SSLContext | None = None
_runners: list[web.AppRunner] = []

# схемы приложений для кнопок «Открыть в …» (Telegram не пускает такие схемы в кнопки
# напрямую, поэтому кнопка ведёт на /open/<app>/<token>, а страница перенаправляет)
APPS = {
    "happ": ("Happ", "happ://add/{url}"),
    "v2raytun": ("v2RayTun", "v2raytun://import/{url}"),
    "hiddify": ("Hiddify", "hiddify://import/{url}#{name}"),
}


def set_bot(bot) -> None:
    global _bot
    _bot = bot


def tls_paths() -> tuple[str, str] | None:
    from .protocols.hysteria import certs_dir, le_paths
    cert, key = (os.path.join(certs_dir(), p) for p in le_paths(SUB_HOST))
    return (cert, key) if os.path.exists(cert) and os.path.exists(key) else None


def scheme() -> str:
    return "https" if _ssl_ctx else "http"


def sub_url(token: str) -> str:
    port = "" if (scheme(), SUB_PORT) in (("https", 443), ("http", 80)) else f":{SUB_PORT}"
    return f"{scheme()}://{SUB_HOST}{port}/sub/{token}"


def open_url(app: str, token: str) -> str:
    return sub_url(token).replace("/sub/", f"/open/{app}/", 1)


# ================================================================== HWID ===

def device_from_headers(h) -> dict:
    """Happ и другие клиенты шлют x-hwid, x-device-os, x-ver-os, x-device-model;
    без HWID устройство считается «неизвестным» по User-Agent."""
    ua = (h.get("User-Agent") or "").strip()
    app = ua.split()[0] if ua else ""
    hwid = (h.get("x-hwid") or "").strip()[:128]
    known = bool(hwid)
    if not hwid:
        hwid = "ua:" + hashlib.sha256(ua.encode()).hexdigest()[:16]
    os_name = " ".join(x for x in ((h.get("x-device-os") or "").strip(),
                                   (h.get("x-ver-os") or "").strip()) if x)[:64]
    return {"hwid": hwid, "known": known, "os": os_name,
            "model": (h.get("x-device-model") or "").strip()[:64], "app": app[:64]}


def register_device(chat_id: int, dev: dict) -> str:
    """"ok" — устройство учтено; "limit" — новое сверх лимита."""
    row = db.execute("SELECT id FROM sub_devices WHERE chat_id=? AND hwid=?",
                     (chat_id, dev["hwid"])).fetchone()
    if row:
        db.execute("UPDATE sub_devices SET last_seen=?, os=COALESCE(NULLIF(?, ''), os), "
                   "model=COALESCE(NULLIF(?, ''), model), app=COALESCE(NULLIF(?, ''), app) "
                   "WHERE id=?", (now(), dev["os"], dev["model"], dev["app"], row[0]))
        db.commit()
        return "ok"
    lim = device_limit(chat_id)
    if lim is not None and devices_count(chat_id) >= lim:
        return "limit"
    db.execute("INSERT INTO sub_devices (chat_id, hwid, os, model, app, first_seen, last_seen) "
               "VALUES (?, ?, ?, ?, ?, ?, ?)",
               (chat_id, dev["hwid"], dev["os"], dev["model"], dev["app"], now(), now()))
    db.commit()
    return "ok"


def should_notify(chat_id: int, hwid: str) -> bool:
    r = db.execute("SELECT sent_at FROM limit_notices WHERE chat_id=? AND hwid=?",
                   (chat_id, hwid)).fetchone()
    if r and time.time() - r[0] < NOTICE_EVERY:
        return False
    db.execute("INSERT OR REPLACE INTO limit_notices (chat_id, hwid, sent_at) VALUES (?, ?, ?)",
               (chat_id, hwid, time.time()))
    db.commit()
    return True


async def notify_limit(chat_id: int, dev: dict) -> None:
    """Сообщение самому пользователю (не админу)."""
    if not _bot:
        return
    from .ui import btn, em, esc, kb, kv, notify
    what = [x for x in (dev["model"], dev["os"], dev["app"]) if x]
    await notify(_bot, chat_id,
                 f"<h3>{em('limit')} Лимит устройств</h3>"
                 f"<p>Новое устройство пытается получить подписку, а лимит — "
                 f"<b>{device_limit(chat_id)}</b>. Удали ненужное устройство, и оно подключится "
                 f"при следующем обновлении подписки.</p>"
                 + kv([(f"{em('hwid_device')} Устройство", esc(" · ".join(what) or "неизвестно"))]),
                 kb([btn("Мои устройства подписки", "subdev", style="primary", icon="sub_devices")]))


# ============================================================= подписка ===

def b64h(s: str) -> str:
    return "base64:" + base64.b64encode(s.encode()).decode()


def placeholder(title: str) -> str:
    """Недоступный сервер-заглушка с понятным названием (видно в списке приложения)."""
    return ("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&type=tcp"
            f"#{urllib.parse.quote(title)}")


def build_sub(u) -> list[str]:
    links = []
    name = SERVER_NAME
    for pid, proto in SUB_PROTOCOLS.items():
        if detect.running(pid):
            links += proto.links(u, name)
    return links


def rate_ok(ip: str) -> bool:
    t = time.time()
    hits = [x for x in _hits.get(ip, []) if t - x < RATE_WINDOW]
    hits.append(t)
    _hits[ip] = hits
    if len(_hits) > 10000:
        _hits.clear()
    return len(hits) <= RATE_MAX


def client_ip(request: web.Request) -> str:
    return request.remote or "?"


def user_by_token(token: str):
    if not token or len(token) < 20:
        return None
    u = db.execute("SELECT * FROM users WHERE sub_token=?", (token,)).fetchone()
    return u if u and u["status"] == "approved" else None


async def sub_handler(request: web.Request) -> web.Response:
    if not rate_ok(client_ip(request)):
        return web.Response(status=429, text="Too Many Requests")
    u = await asyncio.to_thread(user_by_token, request.match_info["token"])
    if not u:
        return web.Response(status=404, text="Not Found")
    dev = device_from_headers(request.headers)
    title = SERVER_NAME
    if not dev["known"] and HWID_REQUIRED:
        links = [placeholder("Обнови приложение: нужен HWID")]
        title = f"{SERVER_NAME} — обнови приложение"
    else:
        state = await asyncio.to_thread(register_device, u["chat_id"], dev)
        if state == "limit":
            links = [placeholder("Лимит устройств — удали лишнее в боте")]
            title = "Лимит устройств — удали лишнее в боте"
            if await asyncio.to_thread(should_notify, u["chat_id"], dev["hwid"]):
                asyncio.create_task(notify_limit(u["chat_id"], dev))
        else:
            links = await asyncio.to_thread(build_sub, u)
            if not links:
                links = [placeholder("Серверы временно недоступны")]
    from .traffic import proto_traffic
    up = down = 0
    for pid in SUB_PROTOCOLS:
        rx, tx = proto_traffic(u["chat_id"], pid)
        up, down = up + rx, down + tx
    body = base64.b64encode("\n".join(links).encode()).decode()
    headers = {
        "profile-title": b64h(title),
        "profile-update-interval": "1",
        "subscription-userinfo": f"upload={up}; download={down}; total=0; expire=0",
        "content-disposition": f'attachment; filename="{SERVER_NAME}"',
        "Cache-Control": "no-store",
    }
    return web.Response(text=body, headers=headers, content_type="text/plain")


async def open_handler(request: web.Request) -> web.Response:
    if not rate_ok(client_ip(request)):
        return web.Response(status=429, text="Too Many Requests")
    app = APPS.get(request.match_info["app"])
    token = request.match_info["token"]
    if not app or not await asyncio.to_thread(user_by_token, token):
        return web.Response(status=404, text="Not Found")
    title, tpl = app
    target = tpl.format(url=urllib.parse.quote(sub_url(token), safe=""),
                        name=urllib.parse.quote(SERVER_NAME))
    t = html.escape(target, quote=True)
    page = (f"<!doctype html><html lang=ru><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta http-equiv=refresh content='0;url={t}'><title>{html.escape(title)}</title>"
            f"</head><body style='font-family:sans-serif;padding:24px'>"
            f"<p>Открываю {html.escape(title)}…</p><p><a href='{t}'>Нажми, если приложение не "
            f"открылось</a></p></body></html>")
    return web.Response(text=page, content_type="text/html")


async def index(request: web.Request) -> web.Response:
    return web.Response(text="OK", content_type="text/plain")


def public_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/sub/{token}", sub_handler)
    app.router.add_get("/open/{app}/{token}", open_handler)
    app.router.add_get("/", index)
    return app


# ===================================================== auth-хук Hysteria 2 ===

async def hy2_auth(request: web.Request) -> web.Response:
    """Формат — auth type http из документации Hysteria 2:
    запрос {"addr", "auth", "tx"}, ответ {"ok": bool, "id": str}."""
    from .protocols.hysteria import auth_check
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "id": ""})
    uid = await asyncio.to_thread(auth_check, str(data.get("auth") or ""))
    return web.json_response({"ok": bool(uid), "id": uid or ""})


def internal_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/hy2/auth", hy2_auth)
    return app


def reload_tls() -> bool:
    """Перечитать сертификат подписок (после продления)."""
    paths = tls_paths()
    if _ssl_ctx and paths:
        _ssl_ctx.load_cert_chain(*paths)
        return True
    return False


async def start() -> None:
    global _ssl_ctx
    runner = web.AppRunner(internal_app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", HY2_AUTH_PORT).start()
    _runners.append(runner)
    log.info("auth-хук Hysteria2: http://127.0.0.1:%s/hy2/auth", HY2_AUTH_PORT)

    paths = tls_paths()
    if paths:
        _ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        _ssl_ctx.load_cert_chain(*paths)
    runner = web.AppRunner(public_app(), access_log=None)
    await runner.setup()
    try:
        await web.TCPSite(runner, SUB_LISTEN, SUB_PORT, ssl_context=_ssl_ctx).start()
        _runners.append(runner)
        log.info("Подписки: %s://%s:%s/sub/<token>", scheme(), SUB_HOST, SUB_PORT)
    except OSError as e:
        log.error("Сервер подписок не запустился на %s:%s: %s", SUB_LISTEN, SUB_PORT, e)


async def restart_public() -> None:
    """Перезапустить публичный сервер (например, после выпуска сертификата)."""
    for r in _runners[1:]:
        await r.cleanup()
    del _runners[1:]
    global _ssl_ctx
    _ssl_ctx = None
    paths = tls_paths()
    if paths:
        _ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        _ssl_ctx.load_cert_chain(*paths)
    runner = web.AppRunner(public_app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, SUB_LISTEN, SUB_PORT, ssl_context=_ssl_ctx).start()
    _runners.append(runner)
