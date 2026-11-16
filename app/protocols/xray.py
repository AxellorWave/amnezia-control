"""VLESS на оригинальном XTLS/Xray-core (образ ghcr.io/xtls/xray-core, версия зафиксирована).

Входы: VLESS + REALITY + Vision (TCP, основной) и, по желанию, VLESS + XHTTP + REALITY
(запасной, отдельный порт). Клиенты — из базы бота (email = u<chat_id>), управление —
через API Xray (adu/rmu) без перезапуска, config.json переписывается при каждом изменении.
Образ distroless (без shell), поэтому конфиг лежит в каталоге данных бота на хосте.
"""
import base64
import json
import logging
import os
import secrets
import socket
import ssl
import time
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .. import docker_util
from ..config import DATA_DIR, VPN_HOST
from ..docker_util import docker
from .base import Protocol

log = logging.getLogger("amnezia-bot")

DEFAULT_IMAGE = "ghcr.io/xtls/xray-core:26.11.9"
IMAGE_REPO = "ghcr.io/xtls/xray-core"
CONTAINER = "vpnbot-xray"
LABEL = "vpnbot.proto=xray"
API_PORT = int(os.getenv("XRAY_API_PORT", "10085"))
TAG_VISION = "vless-reality"
TAG_XHTTP = "vless-xhttp"
FLOW = "xtls-rprx-vision"
FINGERPRINT = "chrome"
MOUNT = "/etc/xray"


def local_dir() -> str:
    return os.path.join(DATA_DIR, "xray")


def host_dir() -> str:
    return os.path.join(docker_util.host_data_dir(os.path.dirname(local_dir())), "xray")


# ================================================================ ключи ===

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def x25519() -> tuple[str, str]:
    """Пара ключей REALITY как у `xray x25519`: PrivateKey и Password (PublicKey), base64url."""
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64url(priv), b64url(pub)


def short_ids(n: int = 4) -> list[str]:
    return [secrets.token_hex(k) for k in (8, 4, 6, 2)[:n]]


# ========================================================= проверка цели ===

def check_target(domain: str, timeout: float = 8.0) -> dict:
    """Цель REALITY должна отдавать TLS 1.3 и h2. Проверка с сервера (бот в сети хоста)."""
    res = {"ok": False, "tls13": False, "h2": False, "error": ""}
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((domain, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                res["tls13"] = s.version() == "TLSv1.3"
                res["h2"] = s.selected_alpn_protocol() == "h2"
    except Exception as e:
        res["error"] = str(e)[:200]
    res["ok"] = res["tls13"] and res["h2"]
    return res


def valid_domain(s: str) -> str | None:
    s = s.strip().lower().removeprefix("https://").split("/")[0]
    if not s or len(s) > 253 or "." not in s or s.startswith(".") or ":" in s:
        return None
    if not all(ch.isalnum() or ch in "-." for ch in s):
        return None
    return s


# ================================================================ конфиг ===

def email(chat_id: int) -> str:
    return f"u{chat_id}"


def chat_of(mail: str) -> int | None:
    return int(mail[1:]) if mail.startswith("u") and mail[1:].lstrip("-").isdigit() else None


def clients(users, flow: str | None) -> list[dict]:
    res = []
    for u in users:
        c = {"id": u["uuid"], "email": email(u["chat_id"])}
        if flow:
            c["flow"] = flow
        res.append(c)
    return res


def reality(s: dict) -> dict:
    return {"show": False, "target": f"{s['sni']}:443", "xver": 0, "serverNames": [s["sni"]],
            "privateKey": s["private_key"], "shortIds": s["short_ids"]}


def build_config(s: dict, users) -> dict:
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    inbounds = [{
        "tag": TAG_VISION, "listen": "0.0.0.0", "port": int(s["port"]), "protocol": "vless",
        "settings": {"clients": clients(users, FLOW), "decryption": "none"},
        "streamSettings": {"network": "raw", "security": "reality",
                           "realitySettings": reality(s)},
        "sniffing": sniff,
    }]
    if s.get("xhttp"):
        inbounds.append({
            "tag": TAG_XHTTP, "listen": "0.0.0.0", "port": int(s["xhttp_port"]),
            "protocol": "vless",
            "settings": {"clients": clients(users, None), "decryption": "none"},
            "streamSettings": {"network": "xhttp", "security": "reality",
                               "xhttpSettings": {"path": s["xhttp_path"], "mode": "auto"},
                               "realitySettings": reality(s)},
            "sniffing": sniff,
        })
    rules = [{"inboundTag": ["api"], "outboundTag": "api"},
             {"protocol": ["bittorrent"], "outboundTag": "block"},
             {"ip": ["geoip:private"], "outboundTag": "block"}]
    if s.get("block_ru"):
        rules += [{"domain": ["geosite:category-ru", "regexp:.*\\.ru$", "regexp:.*\\.su$",
                              "regexp:.*\\.xn--p1ai$"], "outboundTag": "block"},
                  {"ip": ["geoip:ru"], "outboundTag": "block"}]
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "api": {"tag": "api", "listen": f"127.0.0.1:{s.get('api_port', API_PORT)}",
                "services": ["HandlerService", "StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True,
                                    "statsUserOnline": True}},
                   "system": {"statsInboundUplink": False, "statsInboundDownlink": False}},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"},
                      {"protocol": "blackhole", "tag": "block"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


def vless_links(s: dict, u, name: str, host: str = VPN_HOST) -> list[str]:
    """Ссылки vless:// в формате share link Xray (XTLS/Xray-core discussions #716)."""
    base = {"encryption": "none", "security": "reality", "sni": s["sni"], "fp": FINGERPRINT,
            "pbk": s["public_key"], "sid": s["short_ids"][0]}
    q1 = dict(base, type="tcp", flow=FLOW)
    links = [f"vless://{u['uuid']}@{host}:{s['port']}?{urllib.parse.urlencode(q1)}"
             f"#{urllib.parse.quote(name + ' · VLESS')}"]
    if s.get("xhttp"):
        q2 = dict(base, type="xhttp", path=s["xhttp_path"], mode="auto")
        links.append(f"vless://{u['uuid']}@{host}:{s['xhttp_port']}?{urllib.parse.urlencode(q2)}"
                     f"#{urllib.parse.quote(name + ' · VLESS XHTTP')}")
    return links


# =========================================================== контейнер ===

def write_config(s: dict, users) -> dict:
    from ..snapshots import snapshot
    os.makedirs(local_dir(), exist_ok=True)
    path = os.path.join(local_dir(), "config.json")
    if os.path.exists(path):
        with open(path) as f:
            snapshot("xray", {"config.json": f.read()})
    cfg = build_config(s, users)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return cfg


def run_container(s: dict) -> None:
    docker_util.remove(CONTAINER)
    # Образ distroless запускается не от root, а такому процессу нельзя слушать порты < 1024
    # (443) — «bind: permission denied». Запускаем от root, как и Hysteria.
    docker("run", "-d", "--name", CONTAINER, "--network", "host", "--restart", "unless-stopped",
           "--user", "0:0", "--label", LABEL, "--log-opt", "max-size=5m", "--log-opt", "max-file=2",
           "-v", f"{host_dir()}:{MOUNT}:ro", s.get("image", DEFAULT_IMAGE),
           "run", "-c", f"{MOUNT}/config.json", timeout=120)


def wait_started(timeout: float = 20) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1.5)
        c = docker_util.inspect(CONTAINER)
        state = (c or {}).get("State") or {}
        if not state.get("Running") and state.get("Status") in ("exited", "dead"):
            break
        logs = docker_util.logs(CONTAINER, 50)
        if "started" in logs.lower():
            return
    logs = docker_util.logs(CONTAINER, 30)
    raise RuntimeError(f"Xray не запустился:\n{logs.strip()[-1200:]}")


def api(*args: str, timeout: float = 20) -> str:
    """xray api <cmd> внутри контейнера (API слушает 127.0.0.1 в сети хоста)."""
    cmd, rest = args[0], args[1:]
    return docker("exec", CONTAINER, "xray", "api", cmd, f"--server=127.0.0.1:{API_PORT}", *rest,
                  timeout=timeout)


class Xray(Protocol):
    id = "xray"
    title = "VLESS (Xray)"
    short = "VLESS"
    icon = "xray"

    # --- настройки и пользователи
    def settings(self) -> dict | None:
        from ..db import protocol_row
        row = protocol_row("xray")
        if not row or not row["settings"]:
            return None
        try:
            return json.loads(row["settings"])
        except ValueError:
            return None

    def save_settings(self, s: dict) -> None:
        from ..db import db, now
        db.execute("INSERT INTO protocols (id, origin, container, settings, installed_at) "
                   "VALUES ('xray', 'bot', ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                   "settings=excluded.settings", (CONTAINER, json.dumps(s), now()))
        db.commit()

    def users(self):
        from ..db import db
        return db.execute("SELECT * FROM users WHERE status='approved' AND uuid IS NOT NULL "
                          "ORDER BY chat_id").fetchall()

    # --- установка
    def install(self, params: dict, progress) -> dict:
        from ..db import active_user_ids, ensure_creds
        s = {"port": int(params["port"]), "xhttp": bool(params.get("xhttp")),
             "xhttp_port": int(params.get("xhttp_port") or 8443),
             "xhttp_path": "/" + secrets.token_hex(6), "sni": params["sni"],
             "block_ru": bool(params.get("block_ru", False)), "api_port": API_PORT,
             "image": params.get("image") or DEFAULT_IMAGE}
        progress(f"Проверка цели REALITY {s['sni']}")
        t = check_target(s["sni"])
        if not t["ok"]:
            raise RuntimeError(f"{s['sni']}: нужны TLS 1.3 и h2 (TLS 1.3: {t['tls13']}, "
                               f"h2: {t['h2']}) {t['error']}")
        progress("Генерация ключей REALITY и shortId")
        s["private_key"], s["public_key"] = x25519()
        s["short_ids"] = short_ids()
        s["ports"] = [("tcp", s["port"])] + ([("tcp", s["xhttp_port"])] if s["xhttp"] else [])
        for uid in active_user_ids():
            ensure_creds(uid)
        progress(f"Скачивание образа {s['image']}")
        docker("pull", s["image"], timeout=900)
        progress("Запись config.json")
        write_config(s, self.users())
        self.save_settings(s)
        progress("Запуск контейнера vpnbot-xray")
        run_container(s)
        progress("Проверка запуска")
        wait_started()
        return s

    def restore(self, s: dict, progress) -> None:
        """Восстановить из копии: ключи и порты из settings, клиенты — из базы."""
        progress(f"Скачивание образа {s.get('image', DEFAULT_IMAGE)}")
        docker("pull", s.get("image", DEFAULT_IMAGE), timeout=900)
        progress("Запись config.json")
        write_config(s, self.users())
        self.save_settings(s)
        progress("Запуск контейнера vpnbot-xray")
        run_container(s)
        progress("Проверка запуска")
        wait_started()

    def update_image(self, image: str, progress) -> None:
        s = self.settings()
        progress(f"Скачивание {image}")
        docker("pull", image, timeout=900)
        s["image"] = image
        progress("Перезапуск с новым образом")
        write_config(s, self.users())
        self.save_settings(s)
        run_container(s)
        wait_started()

    def uninstall(self, progress, remove_data: bool = False) -> None:
        progress("Остановка и удаление контейнера vpnbot-xray")
        docker_util.remove(CONTAINER)
        if remove_data:
            import shutil
            shutil.rmtree(local_dir(), ignore_errors=True)

    def restart(self) -> None:
        docker("restart", CONTAINER, timeout=120)

    def set_block_ru(self, on: bool) -> None:
        s = self.settings()
        s["block_ru"] = bool(on)
        write_config(s, self.users())
        self.save_settings(s)
        self.restart()
        wait_started()

    # --- клиенты
    def sync(self) -> str:
        """Привести клиентов Xray к базе. Через API без перезапуска; при ошибке — перезапуск.
        Возвращает "api" | "restart" | "" (не установлен)."""
        s = self.settings()
        if not s or not docker_util.is_running(CONTAINER):
            return ""
        users = self.users()
        old_path = os.path.join(local_dir(), "config.json")
        old = set()
        try:
            with open(old_path) as f:
                for c in json.load(f)["inbounds"][0]["settings"]["clients"]:
                    old.add((c["email"], c["id"]))
        except (OSError, ValueError, KeyError, IndexError):
            pass
        write_config(s, users)
        new = {(email(u["chat_id"]), u["uuid"]) for u in users}
        if old == new:
            return "api"
        tags = [TAG_VISION] + ([TAG_XHTTP] if s.get("xhttp") else [])
        removed = {e for e, _ in old - new}
        added = [u for u in users if (email(u["chat_id"]), u["uuid"]) not in old]
        try:
            if removed:
                for tag in tags:
                    api("rmu", f"-tag={tag}", *sorted(removed))
            if added:
                cfg = build_config(s, added)
                add = {"inbounds": [{k: ib[k] for k in ("tag", "protocol", "settings", "port")}
                                    for ib in cfg["inbounds"]]}
                path = os.path.join(local_dir(), "adu.json")
                with open(path, "w") as f:
                    json.dump(add, f)
                os.chmod(path, 0o644)
                api("adu", f"{MOUNT}/adu.json")
            return "api"
        except Exception as e:
            log.warning("xray api sync failed, restarting: %s", e)
            self.restart()
            return "restart"

    def kick(self, chat_ids) -> None:
        """Разорвать сессии: убрать пользователя из inbound'ов (rmu); sync вернёт актуальных."""
        s = self.settings()
        if not s or not docker_util.is_running(CONTAINER):
            return
        tags = [TAG_VISION] + ([TAG_XHTTP] if s.get("xhttp") else [])
        for tag in tags:
            try:
                api("rmu", f"-tag={tag}", *[email(c) for c in chat_ids])
            except Exception as e:
                log.debug("rmu: %s", e)

    def stats(self) -> dict[int, dict]:
        """{chat_id: {rx, tx, online}} — прирост с прошлого опроса (счётчики сбрасываются)."""
        res: dict[int, dict] = {}
        if not docker_util.is_running(CONTAINER):
            return res
        try:
            data = json.loads(api("statsquery", "-pattern", "user>>>", "-reset") or "{}")
        except Exception as e:
            log.debug("xray stats: %s", e)
            return res
        for st in data.get("stat") or []:
            parts = st.get("name", "").split(">>>")
            if len(parts) != 4 or parts[0] != "user":
                continue
            cid = chat_of(parts[1])
            if cid is None:
                continue
            r = res.setdefault(cid, {"rx": 0, "tx": 0, "online": False})
            v = int(st.get("value") or 0)
            if parts[3] == "uplink":
                r["rx"] += v            # от клиента к серверу — как rx у awg
            elif parts[3] == "downlink":
                r["tx"] += v
        try:
            online = json.loads(api("statsgetallonlineusers") or "{}")
            for name in online.get("users") or []:
                cid = chat_of(name.split(">>>")[1] if ">>>" in name else name)
                if cid is not None:
                    res.setdefault(cid, {"rx": 0, "tx": 0, "online": False})["online"] = True
        except Exception as e:
            log.debug("xray online: %s", e)
        return res

    def links(self, user, name: str = "") -> list[str]:
        s = self.settings()
        if not s or not user["uuid"]:
            return []
        return vless_links(s, user, name or "VPN")

    def latest_versions(self, n: int = 5) -> list[dict]:
        import urllib.request
        req = urllib.request.Request("https://api.github.com/repos/XTLS/Xray-core/releases"
                                     f"?per_page={n * 2}",
                                     headers={"User-Agent": "vpn-control-bot"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        return [{"tag": x["tag_name"], "date": x["published_at"][:10],
                 "body": (x.get("body") or "")[:1500], "url": x["html_url"]}
                for x in data if not x.get("prerelease") and not x.get("draft")][:n]


XRAY = Xray()
