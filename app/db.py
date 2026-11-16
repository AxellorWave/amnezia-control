"""SQLite: подключение, миграции и простые хелперы."""
import secrets
import sqlite3
import uuid
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
    # протоколы, установленные/известные боту: порты, ключи, SNI и т.п. в settings (JSON)
    db.execute("""CREATE TABLE IF NOT EXISTS protocols (id TEXT PRIMARY KEY, origin TEXT,
                  container TEXT, settings TEXT, installed_at TEXT)""")
    # подписка (VLESS / Hysteria2): общие для всех устройств человека креды и токен ссылки;
    # last_seen_bot — последнее действие в боте, last_online — последний онлайн в любом протоколе
    have = [r[1] for r in db.execute("PRAGMA table_info(users)")]
    for c, typ in (("uuid", "TEXT"), ("hy2_pass", "TEXT"), ("sub_token", "TEXT"),
                   ("last_seen_bot", "TEXT"), ("last_online", "TEXT"),
                   ("blocked_bot", "INTEGER NOT NULL DEFAULT 0")):
        if c not in have:
            db.execute(f"ALTER TABLE users ADD COLUMN {c} {typ}")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_sub_token ON users(sub_token)")
    # устройства, забиравшие подписку (по HWID из заголовков клиента)
    db.execute("""CREATE TABLE IF NOT EXISTS sub_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, hwid TEXT, os TEXT, model TEXT,
        app TEXT, first_seen TEXT, last_seen TEXT, UNIQUE(chat_id, hwid))""")
    # когда пользователю последний раз писали о превышении лимита устройств
    db.execute("""CREATE TABLE IF NOT EXISTS limit_notices (chat_id INTEGER, hwid TEXT,
                  sent_at REAL, PRIMARY KEY(chat_id, hwid))""")
    # трафик Xray/Hysteria2 — по пользователю (у AWG — по устройствам, в devices);
    # owner_kind: "user" (owner_id = chat_id)
    db.execute("""CREATE TABLE IF NOT EXISTS traffic (owner_kind TEXT, owner_id INTEGER,
                  proto TEXT, rx_total INTEGER NOT NULL DEFAULT 0,
                  tx_total INTEGER NOT NULL DEFAULT 0, rx_last INTEGER NOT NULL DEFAULT 0,
                  tx_last INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(owner_kind, owner_id, proto))""")
    db.commit()


def protocol_row(pid: str):
    return db.execute("SELECT * FROM protocols WHERE id=?", (pid,)).fetchone()


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


def sub_devices(chat_id: int):
    return db.execute("SELECT * FROM sub_devices WHERE chat_id=? ORDER BY last_seen DESC",
                      (chat_id,)).fetchall()


def devices_count(chat_id: int) -> int:
    """Все устройства человека для лимита: AWG-устройства + устройства подписки."""
    return (db.execute("SELECT COUNT(*) FROM devices WHERE chat_id=?", (chat_id,)).fetchone()[0]
            + db.execute("SELECT COUNT(*) FROM sub_devices WHERE chat_id=?",
                         (chat_id,)).fetchone()[0])


def new_token() -> str:
    return secrets.token_urlsafe(32)


def ensure_creds(chat_id: int) -> sqlite3.Row:
    """Сгенерировать UUID (VLESS), пароль Hysteria2 и токен подписки, если их ещё нет."""
    u = get_user(chat_id)
    fields = {}
    if not u["uuid"]:
        fields["uuid"] = str(uuid.uuid4())
    if not u["hy2_pass"]:
        fields["hy2_pass"] = secrets.token_urlsafe(18)
    if not u["sub_token"]:
        fields["sub_token"] = new_token()
    if fields:
        set_user(chat_id, **fields)
    return get_user(chat_id)


def touch_bot(chat_id: int) -> None:
    db.execute("UPDATE users SET last_seen_bot=?, blocked_bot=0 WHERE chat_id=?", (now(), chat_id))
    db.commit()


def bot_pubs() -> set[str]:
    return {r["pub"] for r in db.execute("SELECT pub FROM devices")}


init_db()
