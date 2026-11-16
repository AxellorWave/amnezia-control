"""Точка входа: бот, фоновые задачи."""
import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.types import BotCommand

from . import backup, broadcast as bcast, detect, geo, health, sub_server, subsync
from .config import ADMIN_IDS, BOT_TOKEN
from .db import touch_bot
from .handlers import (admin, backup_admin, broadcast, incident, protocols_admin, subscription,
                       uninstall, user)
from .protocols import awg, hysteria
from .protocols.awg import server_info
from .traffic import traffic_loop
from .ui import btn, em, kb, notify

log = logging.getLogger("amnezia-bot")
_bg: list[asyncio.Task] = []      # держим ссылки на фоновые задачи


async def touch_middleware(handler, event, data):
    """Запомнить время последнего действия человека в боте (для рассылок и инцидентов)."""
    user = data.get("event_from_user")
    if user:
        try:
            touch_bot(user.id)
        except Exception as e:
            log.debug("touch failed: %s", e)
    return await handler(event, data)


async def main():
    logging.basicConfig(level=logging.INFO)
    st = await asyncio.to_thread(detect.refresh)  # бот стартует и на пустом сервере
    if not st["docker"]:
        log.warning("Docker недоступен: %s", st["error"])
    if detect.running("awg"):
        try:
            info = await asyncio.to_thread(server_info)
            log.info("AWG: %s, контейнер %s, порт %s, AWG2=%s, параметры: %s",
                     info["address"], awg.CONTAINER, info["port"], info["awg2"],
                     ", ".join(info["obf"]))
        except Exception as e:
            log.warning("AWG: не удалось прочитать конфиг сервера: %s", e)
    log.info("Протоколы: %s", {p: (detect.get(p) or {}).get("state") for p in ("awg", "xray", "hy2")})
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    dp = Dispatcher()
    dp.update.outer_middleware(touch_middleware)
    dp.update.outer_middleware(health.incident_middleware)
    dp.include_router(user.router)
    dp.include_router(subscription.router)
    dp.include_router(admin.router)
    dp.include_router(protocols_admin.router)
    dp.include_router(backup_admin.router)
    dp.include_router(uninstall.router)
    dp.include_router(broadcast.router)
    dp.include_router(incident.router)
    await bot.set_my_commands([BotCommand(command="start", description="Главное меню"),
                               BotCommand(command="help", description="Как подключиться")])
    sub_server.set_bot(bot)
    await sub_server.start()
    await backup.resume_pending(bot)
    await bcast.resume(bot)
    await subsync.sync_all()
    if not detect.any_installed():
        for admin_id in ADMIN_IDS:
            await notify(bot, admin_id, f"<h3>{em('protocols')} VPN ещё не настроен</h3>"
                                        f"<p>На сервере не найдено ни одного протокола. Установи "
                                        f"нужный в разделе «Протоколы».</p>",
                         kb([btn("Протоколы", "proto", style="primary", icon="protocols")]))
    await asyncio.to_thread(geo.geoip_update)
    await asyncio.to_thread(geo.refresh_location)
    log.info("Сервер %s: %s", geo.location()["ip"], geo.location()["country"] or "страна неизвестна")
    _bg.extend([asyncio.create_task(geo.geo_loop()),
                asyncio.create_task(traffic_loop()),
                asyncio.create_task(detect.detect_loop()),
                asyncio.create_task(hysteria.renew_loop()),
                asyncio.create_task(backup.backup_loop(bot)),
                asyncio.create_task(bcast.broadcast_loop(bot)),
                asyncio.create_task(health.health_loop(bot)),
                asyncio.create_task(health.incident_watch_loop(bot))])
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
