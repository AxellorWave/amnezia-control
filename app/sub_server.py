"""HTTP в том же процессе (aiohttp): auth-хук Hysteria2 (только 127.0.0.1)
и сервер подписок."""
import asyncio
import logging

from aiohttp import web

from .config import HY2_AUTH_PORT

log = logging.getLogger("amnezia-bot")


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


_runners: list[web.AppRunner] = []


async def start() -> None:
    runner = web.AppRunner(internal_app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", HY2_AUTH_PORT).start()
    _runners.append(runner)
    log.info("auth-хук Hysteria2: http://127.0.0.1:%s/hy2/auth", HY2_AUTH_PORT)
