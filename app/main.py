"""Точка входа: бот, фоновые задачи."""
import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.types import BotCommand

from . import geo
from .config import BOT_TOKEN
from .handlers import admin, user
from .protocols.awg import server_info
from .traffic import traffic_loop

log = logging.getLogger("amnezia-bot")
_bg: list[asyncio.Task] = []      # держим ссылки на фоновые задачи


async def main():
    logging.basicConfig(level=logging.INFO)
    info = await asyncio.to_thread(server_info)   # падаем сразу, если контейнер не найден
    log.info("Сервер: %s, порт %s, AWG2=%s, параметры: %s",
             info["address"], info["port"], info["awg2"], ", ".join(info["obf"]))
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    dp = Dispatcher()
    dp.include_router(user.router)
    dp.include_router(admin.router)
    await bot.set_my_commands([BotCommand(command="start", description="Главное меню"),
                               BotCommand(command="help", description="Как подключиться")])
    await asyncio.to_thread(geo.geoip_update)
    await asyncio.to_thread(geo.refresh_location)
    log.info("Сервер %s: %s", geo.location()["ip"], geo.location()["country"] or "страна неизвестна")
    _bg.extend([asyncio.create_task(geo.geo_loop()),
                asyncio.create_task(traffic_loop())])
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
