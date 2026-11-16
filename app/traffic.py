"""Накопительный учёт трафика (счётчики протоколов сбрасываются — копим дельты)."""
import asyncio
import logging
import threading
import time

from .config import ONLINE_SEC
from .db import db, get_device, now
from .protocols import awg

log = logging.getLogger("amnezia-bot")
traffic_lock = threading.Lock()
TRAFFIC_EVERY = 60             # как часто снимать счётчики, сек


def account_traffic(stats: dict | None = None) -> None:
    """Добавить к накопленному трафику устройств прирост счётчиков awg."""
    stats = awg.peer_stats() if stats is None else stats
    if not stats:
        return
    online = []
    with traffic_lock:
        for d in db.execute("SELECT id, chat_id, pub, rx_last, tx_last FROM devices").fetchall():
            st = stats.get(d["pub"])
            if st and st["hs"] and time.time() - st["hs"] < ONLINE_SEC:
                online.append(d["chat_id"])
            if not st or (st["rx"] == d["rx_last"] and st["tx"] == d["tx_last"]):
                continue
            # счётчик меньше прошлого — awg перезапускался, считаем с нуля
            drx = st["rx"] - d["rx_last"] if st["rx"] >= d["rx_last"] else st["rx"]
            dtx = st["tx"] - d["tx_last"] if st["tx"] >= d["tx_last"] else st["tx"]
            db.execute("UPDATE devices SET rx_total=rx_total+?, tx_total=tx_total+?, "
                       "rx_last=?, tx_last=? WHERE id=?",
                       (drx, dtx, st["rx"], st["tx"], d["id"]))
        db.commit()
    if online:
        mark_online(online)


def add_user_traffic(proto: str, deltas: dict[int, tuple[int, int]]) -> None:
    """Прибавить прирост трафика Xray/Hysteria2 по людям: {chat_id: (rx, tx)}.
    rx — принято сервером от клиента, tx — отправлено клиенту (как счётчики awg)."""
    if not deltas:
        return
    with traffic_lock:
        for chat_id, (drx, dtx) in deltas.items():
            if not drx and not dtx:
                continue
            db.execute("INSERT INTO traffic (owner_kind, owner_id, proto) VALUES ('user', ?, ?) "
                       "ON CONFLICT DO NOTHING", (chat_id, proto))
            db.execute("UPDATE traffic SET rx_total=rx_total+?, tx_total=tx_total+? "
                       "WHERE owner_kind='user' AND owner_id=? AND proto=?",
                       (drx, dtx, chat_id, proto))
        db.commit()


def mark_online(chat_ids) -> None:
    ts = now()
    for chat_id in set(chat_ids):
        db.execute("UPDATE users SET last_online=? WHERE chat_id=?", (ts, chat_id))
    db.commit()


def proto_traffic(chat_id: int, proto: str) -> tuple[int, int]:
    r = db.execute("SELECT rx_total, tx_total FROM traffic WHERE owner_kind='user' "
                   "AND owner_id=? AND proto=?", (chat_id, proto)).fetchone()
    return (r[0], r[1]) if r else (0, 0)


def user_traffic(chat_id: int) -> tuple[int, int]:
    """Весь трафик человека (↓, ↑) по всем протоколам, включая удалённые устройства."""
    dev = db.execute("SELECT COALESCE(SUM(rx_total), 0), COALESCE(SUM(tx_total), 0) "
                     "FROM devices WHERE chat_id=?", (chat_id,)).fetchone()
    old = db.execute("SELECT rx_deleted, tx_deleted FROM users WHERE chat_id=?",
                     (chat_id,)).fetchone()
    sub = db.execute("SELECT COALESCE(SUM(rx_total), 0), COALESCE(SUM(tx_total), 0) "
                     "FROM traffic WHERE owner_kind='user' AND owner_id=?", (chat_id,)).fetchone()
    return (dev[0] + (old[0] if old else 0) + sub[0],
            dev[1] + (old[1] if old else 0) + sub[1])


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
