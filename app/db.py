"""SQLite: подключение, миграции и простые хелперы."""
import sqlite3
from datetime import datetime

from .config import DB_PATH

db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row


def init_db():
    cols = [r[1] for r in db.execute("PRAGMA table_info(users)")]
    db.execute("""CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, name TEXT,
        ip TEXT, priv TEXT, pub TEXT, psk TEXT, created TEXT)""")
    if "pub" in cols:   # миграция со старой версии (один конфиг на человека)
        db.execute("""INSERT INTO devices (chat_id, name, ip, priv, pub, psk, created)
                      SELECT chat_id, 'Устройство 1', ip, priv, pub, psk, created
                      FROM users WHERE pub IS NOT NULL""")
        db.execute("ALTER TABLE users RENAME TO users_old")
        db.execute("""CREATE TABLE users (chat_id INTEGER PRIMARY KEY, username TEXT,
                      name TEXT, status TEXT, created TEXT)""")
        db.execute("INSERT INTO users SELECT chat_id, username, name, status, created FROM users_old")
        db.execute("DROP TABLE users_old")
    db.execute("""CREATE TABLE IF NOT EXISTS users (chat_id INTEGER PRIMARY KEY,
                  username TEXT, name TEXT, status TEXT, created TEXT)""")
    # личный лимит устройств (NULL = общий MAX_DEVICES)
    if "max_devices" not in [r[1] for r in db.execute("PRAGMA table_info(users)")]:
        db.execute("ALTER TABLE users ADD COLUMN max_devices INTEGER")
    # учёт трафика: *_total — накоплено, *_last — последнее показание счётчика awg
    # (счётчики awg сбрасываются при перезапуске сервера, поэтому копим дельты);
    # у пользователя — трафик уже удалённых устройств
    for table_, cols_ in (("devices", ("rx_total", "tx_total", "rx_last", "tx_last")),
                          ("users", ("rx_deleted", "tx_deleted"))):
        have = [r[1] for r in db.execute(f"PRAGMA table_info({table_})")]
        for c in cols_:
            if c not in have:
                db.execute(f"ALTER TABLE {table_} ADD COLUMN {c} INTEGER NOT NULL DEFAULT 0")
    db.commit()


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def get_user(chat_id: int):
    return db.execute("SELECT * FROM users WHERE chat_id=?", (chat_id,)).fetchone()


def set_user(chat_id: int, **fields):
    if get_user(chat_id) is None:
        db.execute("INSERT INTO users (chat_id, created) VALUES (?, ?)", (chat_id, now()))
    for k, v in fields.items():
        db.execute(f"UPDATE users SET {k}=? WHERE chat_id=?", (v, chat_id))
    db.commit()


def user_devices(chat_id: int):
    return db.execute("SELECT * FROM devices WHERE chat_id=? ORDER BY id", (chat_id,)).fetchall()


def get_device(dev_id: int):
    return db.execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()


def bot_pubs() -> set[str]:
    return {r["pub"] for r in db.execute("SELECT pub FROM devices")}


init_db()
