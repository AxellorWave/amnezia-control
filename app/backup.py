"""Резервные копии и восстановление протоколов и всего бота.

Формат: .tar.gz, в корне manifest.json — тип (awg | xray | hy2 | full |
amnezia-xray-archive), версия формата, происхождение протокола, версия бота, дата,
порты и sha256 каждого файла. Распаковка — только обычные файлы, без абсолютных путей,
«..», ссылок и устройств. Приватные ключи внутри: копии получают только админы.
"""
import asyncio
import hashlib
import io
import json
import logging
import os
import posixpath
import shutil
import sqlite3
import tarfile
import tempfile
import time
from datetime import datetime

from . import detect, docker_util
from .config import ADMIN_IDS, BACKUP_EVERY_DAYS, BACKUP_KEEP, DATA_DIR

log = logging.getLogger("amnezia-bot")

BOT_VERSION = "2.0"
FORMAT_VERSION = 1
TYPES = ("awg", "xray", "hy2", "full", "amnezia-xray-archive")
PROTOCOLS = ("awg", "xray", "hy2")
TITLES = {"awg": "AmneziaWG", "xray": "VLESS (Xray)", "hy2": "Hysteria 2", "full": "Полная копия",
          "amnezia-xray-archive": "Архив XRay от Amnezia"}
ARCHIVE_DIR = os.path.join(DATA_DIR, "backups", "archives")
RESTORE_DIR = os.path.join(DATA_DIR, "backups", "restore")
PENDING = os.path.join(DATA_DIR, "restore_pending.json")
TG_DOWNLOAD_LIMIT = 20 * 1024 * 1024        # бот может скачать файл до 20 МБ
TG_UPLOAD_LIMIT = 50 * 1024 * 1024          # и отправить до 50 МБ
MAX_MEMBERS = 5000
MAX_TOTAL = 300 * 1024 * 1024
# переменные окружения бота для полной копии (если .env внутри контейнера не виден)
ENV_KEYS = ("BOT_TOKEN", "ADMIN_IDS", "VPN_HOST", "SERVER_NAME", "CONTAINER", "CONF_DIR", "IFACE",
            "WG_BIN", "WG_QUICK_BIN", "DNS1", "DNS2", "MTU", "KEEPALIVE", "MAX_DEVICES",
            "CUSTOM_EMOJI", "GEOIP_DB", "HOST_DATA_DIR", "SUB_HOST", "SUB_PORT", "SUB_LISTEN",
            "HY2_AUTH_PORT", "HWID_REQUIRED", "BACKUP_EVERY_DAYS", "BACKUP_KEEP", "XRAY_API_PORT",
            "AWG_PROTOCOL_VERSION")


class BackupError(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ============================================================ сборка архива ===

def build_archive(path: str, kind: str, files: dict[str, bytes], meta: dict | None = None) -> dict:
    """Записать архив: manifest.json + файлы (относительные пути, только обычные файлы)."""
    if kind not in TYPES:
        raise BackupError(f"неизвестный тип копии: {kind}")
    meta = dict(meta or {})
    for rel in files:
        if not _safe_name(rel):
            raise BackupError(f"недопустимое имя файла: {rel}")
    manifest = {
        "type": kind, "format_version": FORMAT_VERSION, "bot_version": BOT_VERSION,
        "created": datetime.now().isoformat(timespec="seconds"),
        "origin": meta.pop("origin", ""), "ports": meta.pop("ports", []),
        "files": {rel: sha256(data) for rel, data in sorted(files.items())},
        **meta,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with tarfile.open(tmp, "w:gz") as tar:
        _add(tar, "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode())
        for rel, data in sorted(files.items()):
            _add(tar, rel, data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return manifest


def _add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = 0o600
    ti.mtime = int(time.time())
    tar.addfile(ti, io.BytesIO(data))


def _safe_name(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    norm = posixpath.normpath(name)
    return not (norm.startswith("../") or norm == ".." or norm.startswith("/")
                or any(p == ".." for p in name.split("/")))


# ========================================================== проверка архива ===

def _open(path: str) -> tarfile.TarFile:
    try:
        return tarfile.open(path, "r:gz")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise BackupError("это не архив резервной копии (.tar.gz) или он повреждён") from e


def _read_members(path: str) -> tuple[dict, dict[str, bytes]]:
    """Прочитать и проверить все члены архива; вернуть (manifest, {имя: данные})."""
    data: dict[str, bytes] = {}
    total = 0
    with _open(path) as tar:
        try:
            members = tar.getmembers()
        except (tarfile.TarError, EOFError) as e:
            raise BackupError("архив повреждён") from e
        if len(members) > MAX_MEMBERS:
            raise BackupError("в архиве слишком много файлов")
        for m in members:
            if not _safe_name(m.name):
                raise BackupError(f"опасный путь в архиве: {m.name}")
            if m.isdir():
                continue
            if not m.isfile():
                raise BackupError(f"в архиве недопустимый объект (ссылка/устройство): {m.name}")
            total += m.size
            if total > MAX_TOTAL:
                raise BackupError("архив слишком большой")
            name = posixpath.normpath(m.name)
            if name in data:
                raise BackupError(f"файл повторяется в архиве: {name}")
            f = tar.extractfile(m)
            data[name] = f.read() if f else b""
    raw = data.pop("manifest.json", None)
    if raw is None:
        raise BackupError("в архиве нет manifest.json — это не копия этого бота")
    try:
        manifest = json.loads(raw)
    except ValueError as e:
        raise BackupError("manifest.json повреждён") from e
    if not isinstance(manifest, dict):
        raise BackupError("manifest.json повреждён")
    return manifest, data


def verify_archive(path: str) -> dict:
    """Проверить архив целиком (manifest, версия, хеши, безопасность путей)."""
    manifest, data = _read_members(path)
    _check_manifest(manifest, data)
    return manifest


def _check_manifest(manifest: dict, data: dict[str, bytes]) -> None:
    ver = manifest.get("format_version")
    if not isinstance(ver, int) or ver < 1:
        raise BackupError("в manifest.json нет версии формата")
    if ver > FORMAT_VERSION:
        raise BackupError(f"копия сделана более новой версией бота (формат {ver}) — обнови бота")
    if manifest.get("type") not in TYPES:
        raise BackupError(f"неизвестный тип копии: {manifest.get('type')}")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise BackupError("в manifest.json нет списка файлов")
    for rel, digest in files.items():
        rel_n = posixpath.normpath(rel)
        if rel_n not in data:
            raise BackupError(f"в архиве не хватает файла {rel}")
        if sha256(data[rel_n]) != digest:
            raise BackupError(f"хеш не совпадает: {rel} — файл изменён или повреждён")
    extra = set(data) - {posixpath.normpath(r) for r in files}
    if extra:
        raise BackupError(f"в архиве есть файлы вне manifest.json: {', '.join(sorted(extra)[:5])}")


def safe_extract(path: str, dest: str) -> dict:
    """Проверить и распаковать в dest (только обычные файлы внутри dest)."""
    manifest, data = _read_members(path)
    _check_manifest(manifest, data)
    root = os.path.realpath(dest)
    os.makedirs(root, exist_ok=True)
    for rel, content in data.items():
        target = os.path.realpath(os.path.join(root, rel))
        if not target.startswith(root + os.sep):
            raise BackupError(f"опасный путь в архиве: {rel}")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(content)
        os.chmod(target, 0o600)
    with open(os.path.join(root, "manifest.json"), "w") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return manifest


# ================================================================ сбор файлов ===

def _hy2():
    try:
        from .protocols import hysteria
        return hysteria
    except ImportError:
        return None


def collect_awg() -> tuple[dict[str, bytes], dict]:
    from .protocols import awg
    if not detect.running("awg"):
        raise BackupError("AmneziaWG не запущен — снять копию нельзя")
    info = awg.server_info()
    files: dict[str, bytes] = {f"{awg.IFACE}.conf": info["text"].encode()}
    for name in ("wireguard_server_private_key.key", "wireguard_server_public_key.key",
                 "wireguard_psk.key", "clientsTable"):
        content = awg.read_file(f"{awg.CONF_DIR}/{name}", "")
        if content:
            files[name] = content.encode()
    start = docker_util.read_file(awg.CONTAINER, "/opt/amnezia/start.sh", "")
    if start:
        files["start.sh"] = start.encode()
    params = {"name": awg.CONTAINER, "port": int(info["port"]), "subnet": info["address"],
              "iface": awg.IFACE}
    files["container.json"] = json.dumps(params, indent=2).encode()
    e = detect.get("awg") or {}
    return files, {"origin": e.get("origin", "amnezia"), "ports": [["udp", int(info["port"])]],
                   "clients": len(awg.server_peers())}


def collect_xray() -> tuple[dict[str, bytes], dict]:
    from .protocols import xray
    s = xray.XRAY.settings()
    if not s:
        raise BackupError("Xray не установлен ботом — нет настроек для копии")
    files = {"settings.json": json.dumps(s, indent=2, ensure_ascii=False).encode()}
    cfg = os.path.join(xray.local_dir(), "config.json")
    clients = 0
    if os.path.exists(cfg):
        with open(cfg, "rb") as f:
            files["config.json"] = f.read()
        clients = _xray_clients_count(files["config.json"])
    return files, {"origin": "bot", "ports": s.get("ports", [["tcp", s.get("port")]]),
                   "clients": clients}


def _xray_clients_count(raw: bytes) -> int:
    try:
        return len(json.loads(raw)["inbounds"][0]["settings"]["clients"])
    except (ValueError, KeyError, IndexError, TypeError):
        return 0


def _certs_dir() -> str:
    return os.path.join(DATA_DIR, "certs")


def collect_certs(files: dict[str, bytes], prefix: str = "certs/") -> dict:
    """Каталог сертификатов (certbot): обычные файлы — в архив, ссылки — списком в manifest."""
    links = {}
    base = _certs_dir()
    if not os.path.isdir(base):
        return links
    for d, dirs, names in os.walk(base):
        for n in names + [x for x in dirs if os.path.islink(os.path.join(d, x))]:
            p = os.path.join(d, n)
            rel = os.path.relpath(p, base).replace(os.sep, "/")
            if os.path.islink(p):
                links[prefix + rel] = os.readlink(p)
            elif os.path.isfile(p):
                with open(p, "rb") as f:
                    files[prefix + rel] = f.read()
    return links


def collect_hy2() -> tuple[dict[str, bytes], dict]:
    hy = _hy2()
    s = hy.HY2.settings() if hy else None
    if not s:
        raise BackupError("Hysteria 2 не установлен ботом — нет настроек для копии")
    files = {"settings.json": json.dumps(s, indent=2, ensure_ascii=False).encode()}
    d = hy.local_dir()
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            p = os.path.join(d, n)
            if os.path.isfile(p) and not os.path.islink(p):
                with open(p, "rb") as f:
                    files[f"files/{n}"] = f.read()
    links = collect_certs(files)
    return files, {"origin": "bot", "ports": s.get("ports", [["udp", s.get("port")]]),
                   "self_signed": bool(s.get("self_signed")), "links": links, "clients": None}


def collect_amnezia_xray() -> tuple[dict[str, bytes], dict]:
    e = detect.STATE.get("amnezia_xray")
    if not e:
        raise BackupError("XRay от Amnezia не найден")
    tar = docker_util.docker_bytes("exec", e["container"], "tar", "-C", "/opt/amnezia", "-cf", "-",
                                   "xray", timeout=300)
    return {"amnezia-xray.tar": tar}, {"origin": "amnezia", "ports": e.get("ports", []),
                                        "note": "только для истории, ботом не восстанавливается"}


COLLECTORS = {"awg": collect_awg, "xray": collect_xray, "hy2": collect_hy2,
              "amnezia-xray-archive": collect_amnezia_xray}


def _installed_for_full() -> list[str]:
    res = []
    if detect.running("awg"):
        res.append("awg")
    from .protocols import xray
    if detect.installed("xray") and xray.XRAY.settings():
        res.append("xray")
    hy = _hy2()
    if hy and detect.installed("hy2") and hy.HY2.settings():
        res.append("hy2")
    return res


def db_snapshot() -> bytes:
    """Снимок базы через sqlite3 backup API (не копированием файла на ходу)."""
    from .db import db
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "bot.db")
        dst = sqlite3.connect(p)
        try:
            db.backup(dst)
        finally:
            dst.close()
        with open(p, "rb") as f:
            return f.read()


def env_text(include_token: bool) -> str:
    """.env бота: файл, если виден, иначе — из переменных окружения процесса."""
    path = None
    try:
        from dotenv import find_dotenv
        path = find_dotenv(usecwd=True) or None
    except Exception:
        path = None
    for p in (path, os.path.join(os.getcwd(), ".env")):
        if p and os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                lines = f.read().splitlines()
            break
    else:
        lines = [f"{k}={os.environ[k]}" for k in ENV_KEYS if os.environ.get(k)]
    out = []
    for line in lines:
        if line.strip().startswith("BOT_TOKEN") and "=" in line and not include_token:
            out.append("# BOT_TOKEN не сохранён в копии — впиши токен от @BotFather")
            out.append("BOT_TOKEN=")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def create_backup(kind: str, include_token: bool = False) -> str:
    """Снять копию и вернуть путь к архиву в data/backups/archives (с ротацией)."""
    files: dict[str, bytes] = {}
    if kind == "full":
        meta: dict = {"origin": "bot", "ports": [], "protocols": {}, "links": {},
                      "token_included": include_token}
        for pid in _installed_for_full():
            pf, pm = COLLECTORS[pid]()
            for rel, data in pf.items():
                files[f"{pid}/{rel}"] = data
            for rel, target in (pm.pop("links", None) or {}).items():
                meta["links"][f"{pid}/{rel}"] = target
            meta["protocols"][pid] = pm
            meta["ports"] += pm.get("ports", [])
        files["bot.db"] = db_snapshot()
        files[".env"] = env_text(include_token).encode()
        from .db import db
        meta["users"] = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        meta["devices"] = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    elif kind in COLLECTORS:
        files, meta = COLLECTORS[kind]()
    else:
        raise BackupError(f"неизвестный тип копии: {kind}")
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(ARCHIVE_DIR, f"vpnbot-{kind}-{stamp}.tar.gz")
    build_archive(path, kind, files, meta)
    rotate()
    return path


def rotate(keep: int | None = None) -> None:
    keep = BACKUP_KEEP if keep is None else keep
    if keep <= 0 or not os.path.isdir(ARCHIVE_DIR):
        return
    archives = sorted((os.path.getmtime(os.path.join(ARCHIVE_DIR, n)), n)
                      for n in os.listdir(ARCHIVE_DIR) if n.endswith(".tar.gz"))
    for _, n in archives[:-keep]:
        try:
            os.remove(os.path.join(ARCHIVE_DIR, n))
        except OSError:
            pass


# ============================================================ описание копии ===

def _esc(t) -> str:
    from .ui import esc
    return esc(t)


def _ports(ports) -> str:
    try:
        return ", ".join(f"{p}/{proto}" for proto, p in ports) or "—"
    except (TypeError, ValueError):
        return "—"


def _read(path: str) -> bytes | None:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def _awg_clients(d: str) -> int:
    for name in ("awg0.conf", "wg0.conf"):
        raw = _read(os.path.join(d, name))
        if raw:
            return raw.decode(errors="replace").count("[Peer]")
    return 0


def _proto_rows(pid: str, d: str, meta: dict) -> list[tuple[str, str]]:
    from .ui import em
    rows = [(f"{em(_ICON[pid])} {TITLES[pid]}", "порты " + _ports(meta.get("ports", [])))]
    if pid == "awg":
        rows.append(("Клиентов в конфиге", str(_awg_clients(d))))
    elif pid == "xray":
        raw = _read(os.path.join(d, "config.json"))
        rows.append(("Клиентов в конфиге", str(_xray_clients_count(raw) if raw else 0)))
        try:
            s = json.loads(_read(os.path.join(d, "settings.json")) or b"{}")
            rows.append(("SNI", f"<code>{_esc(s.get('sni', ''))}</code>"))
        except ValueError:
            pass
    elif pid == "hy2":
        rows.append(("Сертификат", "самоподписанный" if meta.get("self_signed") else "по домену"))
    return rows


_ICON = {"awg": "awg", "xray": "xray", "hy2": "hysteria"}


def describe(manifest: dict, extracted_dir: str) -> str:
    from .ui import em, kv
    kind = manifest["type"]
    created = manifest.get("created", "")
    try:
        created = datetime.fromisoformat(created).strftime("%d.%m.%Y %H:%M")
    except ValueError:
        pass
    rows = [("Тип", TITLES.get(kind, kind)), (f"{em('calendar')} Дата копии", _esc(created)),
            ("Версия бота", _esc(manifest.get("bot_version", "?")))]
    if kind == "full":
        for pid, meta in (manifest.get("protocols") or {}).items():
            if pid in PROTOCOLS:
                rows += _proto_rows(pid, os.path.join(extracted_dir, pid), meta)
        users, devices = _db_counts(os.path.join(extracted_dir, "bot.db"))
        rows += [(f"{em('users')} Пользователей в базе", str(users)),
                 (f"{em('devices')} AWG-устройств в базе", str(devices)),
                 ("Токен бота", "есть" if manifest.get("token_included") else "не сохранён")]
    elif kind in PROTOCOLS:
        rows += _proto_rows(kind, extracted_dir, manifest)
    else:
        rows.append(("Примечание", "архив только для истории, ботом не восстанавливается"))
    return kv(rows)


def _db_counts(path: str) -> tuple[int, int]:
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return (c.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                    c.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
        finally:
            c.close()
    except sqlite3.Error:
        return 0, 0


def protocols_in(manifest: dict) -> list[str]:
    kind = manifest["type"]
    if kind == "full":
        return [p for p in PROTOCOLS if p in (manifest.get("protocols") or {})]
    return [kind] if kind in PROTOCOLS else []


def conflicts(manifest: dict) -> list[str]:
    """Протоколы из копии, которые уже стоят на сервере (поверх не восстанавливаем)."""
    res = [p for p in protocols_in(manifest) if detect.installed(p)]
    if "xray" in protocols_in(manifest) and detect.STATE.get("amnezia_xray"):
        # свой Xray можно ставить рядом только на свободный порт — проверит установка
        pass
    return res


# ============================================================== восстановление ===

def restore(kind: str, d: str, progress, manifest: dict | None = None) -> list[str]:
    """Восстановить протокол(ы) из распакованной копии. Возвращает восстановленные pid."""
    manifest = manifest or _load_manifest(d)
    if kind == "amnezia-xray-archive":
        raise BackupError("архив XRay от Amnezia хранится только для истории и не восстанавливается")
    busy = conflicts(manifest)
    if busy:
        names = ", ".join(TITLES[p] for p in busy)
        raise BackupError(f"{names} уже установлен — сначала удали его кнопкой «Удалить» в карточке "
                          f"протокола (при удалении бот сам сделает копию текущего состояния)")
    if kind == "full":
        return restore_full(d, progress, manifest)
    restore_protocol(kind, d, progress, manifest)
    return [kind]


def _load_manifest(d: str) -> dict:
    with open(os.path.join(d, "manifest.json")) as f:
        return json.load(f)


def restore_protocol(pid: str, d: str, progress, meta: dict | None = None) -> None:
    meta = meta or {}
    if pid == "awg":
        _restore_awg(d, progress)
    elif pid == "xray":
        _restore_xray(d, progress)
    elif pid == "hy2":
        _restore_hy2(d, progress, meta)
    else:
        raise BackupError(f"неизвестный протокол: {pid}")
    detect.refresh()


def _restore_awg(d: str, progress) -> None:
    from .db import db, now
    from .protocols import awg_install
    params = json.loads(_read(os.path.join(d, "container.json")) or b"{}")
    files = {}
    for name in awg_install.RESTORE_FILES:
        raw = _read(os.path.join(d, name))
        if raw is not None:
            files["awg0.conf" if name == "wg0.conf" else name] = raw.decode()
    if "awg0.conf" not in files:
        raise BackupError("в копии нет awg0.conf")
    from .protocols import awg
    port = int(params.get("port") or awg.parse_server_conf(files["awg0.conf"])["port"])
    r = awg_install.install(port, progress, restore_files=files)
    db.execute("INSERT OR REPLACE INTO protocols (id, origin, container, settings, installed_at) "
               "VALUES ('awg', 'bot', ?, ?, ?)",
               (awg_install.CONTAINER, json.dumps({"port": r["port"], "subnet": r["subnet"],
                                                    "ports": [["udp", r["port"]]]}), now()))
    db.commit()


def _restore_xray(d: str, progress) -> None:
    from .protocols import xray
    raw = _read(os.path.join(d, "settings.json"))
    if not raw:
        raise BackupError("в копии нет settings.json Xray")
    s = json.loads(raw)
    os.makedirs(xray.local_dir(), exist_ok=True)
    cfg = _read(os.path.join(d, "config.json"))
    if cfg:
        with open(os.path.join(xray.local_dir(), "config.json"), "wb") as f:
            f.write(cfg)
    xray.XRAY.restore(s, progress)


def _restore_certs(d: str, links: dict, prefix: str) -> None:
    src = os.path.join(d, "certs")
    base = _certs_dir()
    if os.path.isdir(src):
        progress_copy(src, base)
    for rel, target in (links or {}).items():
        if not rel.startswith(prefix + "certs/"):
            continue
        p = os.path.join(base, rel[len(prefix + "certs/"):])
        dest = os.path.realpath(os.path.join(os.path.dirname(p), target))
        if not dest.startswith(os.path.realpath(base) + os.sep) or os.path.isabs(target):
            continue                     # ссылка наружу каталога сертификатов — пропускаем
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.lexists(p):
            os.remove(p)
        os.symlink(target, p)


def progress_copy(src: str, dst: str) -> None:
    for root, _, names in os.walk(src):
        for n in names:
            s = os.path.join(root, n)
            t = os.path.join(dst, os.path.relpath(s, src))
            os.makedirs(os.path.dirname(t), exist_ok=True)
            shutil.copyfile(s, t)
            os.chmod(t, 0o600)


def _restore_hy2(d: str, progress, meta: dict) -> None:
    hy = _hy2()
    if not hy:
        raise BackupError("эта версия бота не умеет Hysteria 2")
    raw = _read(os.path.join(d, "settings.json"))
    if not raw:
        raise BackupError("в копии нет settings.json Hysteria 2")
    s = json.loads(raw)
    local = hy.local_dir()
    os.makedirs(local, exist_ok=True)
    fdir = os.path.join(d, "files")
    if os.path.isdir(fdir):
        for n in os.listdir(fdir):
            shutil.copyfile(os.path.join(fdir, n), os.path.join(local, n))
            os.chmod(os.path.join(local, n), 0o600 if n.endswith(".pem") and "key" in n else 0o644)
    prefix = meta.get("_prefix", "")
    _restore_certs(d, meta.get("links") or {}, prefix)
    hy.HY2.restore(s, progress)


def restore_full(d: str, progress, manifest: dict) -> list[str]:
    """База — сразу (backup API в живое подключение), потом протоколы по очереди.
    Список оставшихся протоколов — в restore_pending.json: если бот перезапустится
    посреди восстановления, resume_pending() продолжит."""
    progress("Проверка базы из копии")
    snap = os.path.join(d, "bot.db")
    try:
        src = sqlite3.connect(f"file:{snap}?mode=ro", uri=True)
        ok = src.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.Error as e:
        raise BackupError(f"база в копии повреждена: {e}") from e
    if ok != "ok":
        src.close()
        raise BackupError(f"база в копии повреждена: {ok}")
    protos = protocols_in(manifest)
    _write_pending({"dir": d, "protocols": protos, "done": [], "started": time.time()})
    progress("Замена базы бота")
    from . import db as dbm
    from . import traffic
    with traffic.traffic_lock:
        try:
            src.backup(dbm.db)
        finally:
            src.close()
        dbm.init_db()                         # миграции схемы, если копия старее бота
    done = []
    for pid in protos:
        meta = dict((manifest.get("protocols") or {}).get(pid) or {})
        meta["links"] = manifest.get("links") or {}
        meta["_prefix"] = f"{pid}/"
        progress(f"Восстановление: {TITLES[pid]}")
        restore_protocol(pid, os.path.join(d, pid), progress, meta)
        done.append(pid)
        _write_pending({"dir": d, "protocols": protos, "done": done, "started": time.time()})
    _clear_pending()
    return done


def _write_pending(data: dict) -> None:
    tmp = PENDING + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, PENDING)


def _clear_pending() -> None:
    try:
        os.remove(PENDING)
    except OSError:
        pass


async def resume_pending(bot) -> None:
    """После перезапуска: продолжить прерванное полное восстановление."""
    if not os.path.exists(PENDING):
        return
    from .ui import em, esc, notify
    try:
        with open(PENDING) as f:
            p = json.load(f)
        d = p["dir"]
        manifest = _load_manifest(d)
    except Exception as e:
        log.warning("restore_pending.json unreadable: %s", e)
        _clear_pending()
        return
    left = [x for x in p.get("protocols", []) if x not in p.get("done", [])]
    results = []
    for pid in left:
        if detect.installed(pid):
            results.append(f"{em('warn')} {TITLES[pid]}: уже установлен, пропущен")
            continue
        meta = dict((manifest.get("protocols") or {}).get(pid) or {})
        meta["links"] = manifest.get("links") or {}
        meta["_prefix"] = f"{pid}/"
        try:
            await asyncio.to_thread(restore_protocol, pid, os.path.join(d, pid),
                                    lambda s: log.info("resume restore: %s", s), meta)
            results.append(f"{em('ok')} {TITLES[pid]}: восстановлен")
        except Exception as e:
            log.exception("resume restore %s failed", pid)
            results.append(f"{em('error')} {TITLES[pid]}: <code>{esc(str(e)[:300])}</code>")
    _clear_pending()
    for admin in ADMIN_IDS:
        await notify(bot, admin, f"<h3>{em('restore_backup')} Восстановление продолжено после "
                                 f"перезапуска</h3><p>" + ("<br>".join(results) or "Нечего делать.")
                     + "</p>")


# ==================================================================== сверка ===

def reconcile(pid: str) -> dict:
    """Клиенты в конфиге сервера против базы: missing — есть в базе, нет на сервере;
    extra — есть на сервере, нет в базе."""
    from .db import db
    res = {"pid": pid, "missing": [], "extra": [], "missing_ids": [], "extra_ids": []}
    if pid == "awg":
        from .protocols import awg
        if not detect.running("awg"):
            return res
        peers = {p["pub"]: p for p in awg.server_peers()}
        devs = db.execute("SELECT d.*, u.username FROM devices d "
                          "LEFT JOIN users u ON u.chat_id=d.chat_id").fetchall()
        mine = {d["pub"] for d in devs}
        for d in devs:
            if d["pub"] not in peers:
                who = f"@{d['username']}" if d["username"] else str(d["chat_id"])
                res["missing"].append(f"{who} · {d['name']}")
                res["missing_ids"].append(d["id"])
        for pub, p in peers.items():
            if pub not in mine:
                res["extra"].append(f"{p['name']} ({p['ip']})")
                res["extra_ids"].append(pub)
    elif pid == "xray":
        from .protocols import xray
        cfg = _read(os.path.join(xray.local_dir(), "config.json"))
        have = set()
        if cfg:
            try:
                have = {c["email"] for c in json.loads(cfg)["inbounds"][0]["settings"]["clients"]}
            except (ValueError, KeyError, IndexError, TypeError):
                pass
        want = {xray.email(u["chat_id"]) for u in xray.XRAY.users()}
        res["missing"] = sorted(want - have)
        res["extra"] = sorted(have - want)
        res["missing_ids"], res["extra_ids"] = res["missing"], res["extra"]
    # Hysteria 2: пароли проверяет auth-хук по базе — расхождений не бывает
    return res


def apply_reconcile(pid: str, action: str) -> int:
    """action: "add" — добавить недостающих, "remove" — удалить лишних. Вернуть количество."""
    r = reconcile(pid)
    if pid == "xray":
        from .protocols import xray
        xray.XRAY.sync()                   # config.json и API приводятся к базе целиком
        return len(r["missing"] if action == "add" else r["extra"])
    if pid != "awg":
        return 0
    from .protocols import awg
    from .db import get_device
    if action == "add":
        devs = [get_device(i) for i in r["missing_ids"]]
        awg_add_existing([d for d in devs if d])
        return len(r["missing_ids"])
    for pub in r["extra_ids"]:
        awg.remove_peer(pub)
    return len(r["extra_ids"])


def awg_add_existing(devs) -> None:
    """Вернуть на сервер пиров устройств из базы с прежними ключами и IP."""
    from .protocols import awg
    if not devs:
        return
    info = awg.server_info()
    awg.snapshot_server(info)
    text = info["text"].rstrip("\n")
    table = awg.read_clients_table()
    known = {c.get("clientId") for c in table}
    for d in devs:
        text += (f"\n\n[Peer]\nPublicKey = {d['pub']}\nPresharedKey = {d['psk']}\n"
                 f"AllowedIPs = {d['ip']}/32\n")
        if d["pub"] not in known:
            table.append({"clientId": d["pub"], "userData": {
                "clientName": d["name"],
                "creationDate": datetime.now().strftime("%a %b %d %H:%M:%S %Y")}})
    awg.write_file(awg.SERVER_CONF, text.rstrip("\n") + "\n")
    awg.sync_wg()
    awg.write_file(f"{awg.CONF_DIR}/clientsTable", json.dumps(table, indent=4, ensure_ascii=False))


# ============================================================ по расписанию ===

LAST_AUTO = os.path.join(DATA_DIR, "backups", "last_auto")


async def send_archive(bot, chat_id: int, path: str, caption_html: str, markup=None):
    from aiogram.types import FSInputFile
    from .ui import with_emoji_fallback
    if os.path.getsize(path) > TG_UPLOAD_LIMIT:
        raise BackupError("архив больше 50 МБ — Telegram не даст боту его отправить; "
                          f"он лежит на сервере: {path}")
    return await with_emoji_fallback(
        lambda t, mk: bot.send_document(chat_id, FSInputFile(path, filename=os.path.basename(path)),
                                        caption=t, reply_markup=mk), caption_html, markup)


def warning_caption(title: str) -> str:
    from .ui import em
    return (f"{em('backup')} <b>{title}</b>\n\n{em('lock')} Внутри приватные ключи сервера — "
            f"<b>не пересылай никому</b>. Восстановить: «Протоколы» → «Восстановить из копии».")


async def backup_loop(bot) -> None:
    """Полная копия админам раз в BACKUP_EVERY_DAYS дней (0 — выключено)."""
    if BACKUP_EVERY_DAYS <= 0:
        return
    period = BACKUP_EVERY_DAYS * 86400
    while True:
        try:
            last = float(_read(LAST_AUTO) or b"0")
        except ValueError:
            last = 0.0
        if time.time() - last >= period:
            try:
                path = await asyncio.to_thread(create_backup, "full")
                for admin in ADMIN_IDS:
                    try:
                        await send_archive(bot, admin, path, warning_caption(
                            "Полная копия по расписанию"))
                    except Exception as e:
                        log.warning("auto backup send to %s failed: %s", admin, e)
                os.makedirs(os.path.dirname(LAST_AUTO), exist_ok=True)
                with open(LAST_AUTO, "w") as f:
                    f.write(str(time.time()))
            except Exception as e:
                log.warning("auto backup failed: %s", e)
        await asyncio.sleep(3600)


def new_restore_dir() -> str:
    d = os.path.join(RESTORE_DIR, datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(d, exist_ok=True)
    return d


__all__ = ["BackupError", "build_archive", "verify_archive", "safe_extract", "create_backup",
           "describe", "restore", "reconcile", "apply_reconcile", "resume_pending",
           "backup_loop", "send_archive"]
