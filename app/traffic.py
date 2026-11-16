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


ONLINE_NOW: dict[str, set[int]] = {}      # протокол -> кто онлайн по последнему опросу
ONLINE_CONNS: dict[str, dict[int, int]] = {}   # протокол -> {chat_id: подключений}
ONLINE_TS: dict[str, float] = {}          # протокол -> время последнего опроса
_sub_lock = threading.Lock()


def mark_proto_seen(proto: str, chat_ids) -> None:
    ts = now()
    with traffic_lock:
        for chat_id in set(chat_ids):
            db.execute("INSERT INTO traffic (owner_kind, owner_id, proto) VALUES ('user', ?, ?) "
                       "ON CONFLICT DO NOTHING", (chat_id, proto))
            db.execute("UPDATE traffic SET last_seen=? WHERE owner_kind='user' AND owner_id=? "
                       "AND proto=?", (ts, chat_id, proto))
        db.commit()


def proto_last_seen(proto: str) -> dict[int, str]:
    return {r[0]: r[1] for r in db.execute(
        "SELECT owner_id, last_seen FROM traffic WHERE owner_kind='user' AND proto=? "
        "AND last_seen IS NOT NULL", (proto,))}


def account_sub_traffic() -> None:
    """Прирост трафика Xray / Hysteria2 по людям (их API отдают и сбрасывают счётчики)."""
    from .protocols import registry
    with _sub_lock:
        for pid, proto in registry.SUB_PROTOCOLS.items():
            try:
                st = proto.stats()
            except Exception as e:
                log.debug("%s stats failed: %s", pid, e)
                continue
            add_user_traffic(pid, {cid: (v["rx"], v["tx"]) for cid, v in st.items()})
            online = {cid for cid, v in st.items() if v.get("online")}
            ONLINE_NOW[pid] = online
            ONLINE_CONNS[pid] = {cid: int(v.get("conns") or 1) for cid, v in st.items()
                                 if v.get("online")}
            ONLINE_TS[pid] = time.time()
            if online:
                mark_online(online)
                mark_proto_seen(pid, online)


def online_users() -> set[int]:
    """Кто сейчас онлайн в любом протоколе (AWG — по устройствам, остальные — из API)."""
    res = set().union(*ONLINE_NOW.values()) if ONLINE_NOW else set()
    stats = awg.peer_stats()
    for d in db.execute("SELECT chat_id, pub FROM devices"):
        st = stats.get(d["pub"])
        if st and st["hs"] and time.time() - st["hs"] < ONLINE_SEC:
            res.add(d["chat_id"])
    return res


async def traffic_loop() -> None:
    while True:
        for job in (account_traffic, account_sub_traffic):
            try:
                await asyncio.to_thread(job)
            except Exception as e:
                log.warning("traffic accounting failed: %s", e)
        await asyncio.sleep(TRAFFIC_EVERY)
