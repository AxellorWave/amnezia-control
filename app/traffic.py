"""Накопительный учёт трафика (счётчики протоколов сбрасываются — копим дельты)."""
import asyncio
import logging
import threading

from .db import db, get_device
from .protocols import awg

log = logging.getLogger("amnezia-bot")
traffic_lock = threading.Lock()
TRAFFIC_EVERY = 60             # как часто снимать счётчики, сек


def account_traffic(stats: dict | None = None) -> None:
    """Добавить к накопленному трафику устройств прирост счётчиков awg."""
    stats = awg.peer_stats() if stats is None else stats
    if not stats:
        return
    with traffic_lock:
        for d in db.execute("SELECT id, pub, rx_last, tx_last FROM devices").fetchall():
            st = stats.get(d["pub"])
            if not st or (st["rx"] == d["rx_last"] and st["tx"] == d["tx_last"]):
                continue
            # счётчик меньше прошлого — awg перезапускался, считаем с нуля
            drx = st["rx"] - d["rx_last"] if st["rx"] >= d["rx_last"] else st["rx"]
            dtx = st["tx"] - d["tx_last"] if st["tx"] >= d["tx_last"] else st["tx"]
            db.execute("UPDATE devices SET rx_total=rx_total+?, tx_total=tx_total+?, "
                       "rx_last=?, tx_last=? WHERE id=?",
                       (drx, dtx, st["rx"], st["tx"], d["id"]))
        db.commit()


def user_traffic(chat_id: int) -> tuple[int, int]:
    """Весь трафик человека (↓, ↑), включая удалённые устройства."""
    dev = db.execute("SELECT COALESCE(SUM(rx_total), 0), COALESCE(SUM(tx_total), 0) "
                     "FROM devices WHERE chat_id=?", (chat_id,)).fetchone()
    old = db.execute("SELECT rx_deleted, tx_deleted FROM users WHERE chat_id=?",
                     (chat_id,)).fetchone()
    return dev[0] + (old[0] if old else 0), dev[1] + (old[1] if old else 0)


def drop_device(dev_id: int) -> None:
    """Удалить устройство из БД, перенеся его трафик на пользователя."""
    account_traffic()
    with traffic_lock:
        d = get_device(dev_id)
        if d:
            db.execute("UPDATE users SET rx_deleted=rx_deleted+?, tx_deleted=tx_deleted+? "
                       "WHERE chat_id=?", (d["rx_total"], d["tx_total"], d["chat_id"]))
        db.execute("DELETE FROM devices WHERE id=?", (dev_id,))
        db.commit()


async def traffic_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(account_traffic)
        except Exception as e:
            log.warning("traffic accounting failed: %s", e)
        await asyncio.sleep(TRAFFIC_EVERY)
