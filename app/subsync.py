"""Синхронизация протоколов подписки с базой при выдаче/отзыве доступа и перевыпуске."""
import asyncio
import logging

from . import detect
from .db import db, ensure_creds, get_user, new_token, set_user
from .protocols.registry import SUB_PROTOCOLS

log = logging.getLogger("amnezia-bot")
sync_lock = asyncio.Lock()


def _sync_all() -> None:
    for pid, proto in SUB_PROTOCOLS.items():
        if detect.installed(pid):
            try:
                proto.sync()
            except Exception as e:
                log.warning("%s sync failed: %s", pid, e)


async def sync_all() -> None:
    async with sync_lock:
        await asyncio.to_thread(_sync_all)


async def access_changed(chat_id: int, granted: bool) -> None:
    """Одобрение / возврат доступа — выдать креды и добавить в Xray;
    отзыв — убрать из Xray и разорвать сессии Hysteria2."""
    u = get_user(chat_id)
    if granted and u and detect.sub_protocols():
        await asyncio.to_thread(ensure_creds, chat_id)
    await sync_all()
    if not granted:
        for pid, proto in SUB_PROTOCOLS.items():
            if detect.installed(pid):
                await asyncio.to_thread(proto.kick, [chat_id])
        await asyncio.to_thread(clear_sub_devices, chat_id)
        await sync_all()          # kick в Xray убирает пользователя — вернуть остальных как было


def clear_sub_devices(chat_id: int) -> None:
    db.execute("DELETE FROM sub_devices WHERE chat_id=?", (chat_id,))
    db.commit()


async def reissue(chat_id: int) -> None:
    """Перевыпуск ссылки: новые токен, UUID и пароль; старые подключения рвутся."""
    import secrets
    import uuid
    set_user(chat_id, sub_token=new_token(), uuid=str(uuid.uuid4()),
             hy2_pass=secrets.token_urlsafe(18))
    await asyncio.to_thread(clear_sub_devices, chat_id)
    for pid, proto in SUB_PROTOCOLS.items():
        if detect.installed(pid):
            await asyncio.to_thread(proto.kick, [chat_id])
    await sync_all()
