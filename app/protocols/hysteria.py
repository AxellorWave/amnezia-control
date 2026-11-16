"""Hysteria 2 (официальный образ tobyxdd/hysteria, версия зафиксирована).

Аутентификация — HTTP-хук бота на 127.0.0.1 (пароль из базы → id "u<chat_id>"),
статистика и kick — trafficStats API на 127.0.0.1 с секретом, обфускация Salamander,
congestion — BBR (Brutal не включаем: плохо ведёт себя при джиттере).
Сертификат — Let's Encrypt по домену (certbot одноразовым контейнером, порт 80/TCP,
автопродление — фоновая задача бота) или самоподписанный с pinSHA256 в ссылке.
"""
import datetime as dt
import hashlib
import json
import logging
import os
import secrets
import shutil
import time
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .. import docker_util
from ..config import DATA_DIR, HY2_AUTH_PORT, VPN_HOST
from ..docker_util import docker
from .base import Protocol

log = logging.getLogger("amnezia-bot")

DEFAULT_IMAGE = "tobyxdd/hysteria:v2.13.0"
CERTBOT_IMAGE = "certbot/certbot:v3.0.1"
CONTAINER = "vpnbot-hysteria"
LABEL = "vpnbot.proto=hy2"
STATS_PORT = int(os.getenv("HY2_STATS_PORT", "18082"))
MOUNT = "/etc/hysteria"
CERTS_MOUNT = "/certs"


def local_dir() -> str:
    return os.path.join(DATA_DIR, "hy2")


def certs_dir() -> str:
    return os.path.join(DATA_DIR, "certs")


def host_path(sub: str) -> str:
    return os.path.join(docker_util.host_data_dir(DATA_DIR), sub)


def is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ============================================================ сертификаты ===

def self_signed(host: str = VPN_HOST, days: int = 3650) -> tuple[bytes, bytes, str]:
    """(cert_pem, key_pem, pinSHA256 — sha256 DER сертификата, hex)."""
    import ipaddress
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    san = (x509.IPAddress(ipaddress.ip_address(host)) if is_ip(host) else x509.DNSName(host))
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            hashlib.sha256(der).hexdigest())


def le_paths(domain: str) -> tuple[str, str]:
    """Пути Let's Encrypt внутри каталога certs (live/<домен>/...)."""
    return (f"live/{domain}/fullchain.pem", f"live/{domain}/privkey.pem")


def obtain_le(domain: str) -> None:
    """certbot certonly --standalone на 80/TCP (одноразовый контейнер в сети хоста)."""
    os.makedirs(certs_dir(), exist_ok=True)
    out = docker_util.run_oneoff(
        CERTBOT_IMAGE, "certonly", "--standalone", "--non-interactive", "--agree-tos",
        "--register-unsafely-without-email", "--preferred-challenges", "http",
        "--http-01-port", "80", "-d", domain, "--keep-until-expiring",
        opts=("--network", "host", "-v", f"{host_path('certs')}:/etc/letsencrypt"),
        timeout=600, check=False)
    if not os.path.exists(os.path.join(certs_dir(), le_paths(domain)[0])):
        raise RuntimeError(f"Let's Encrypt: сертификат не получен:\n{out.strip()[-1500:]}")


def renew_le() -> bool:
    """certbot renew; True — если какой-то сертификат обновился."""
    if not os.path.isdir(os.path.join(certs_dir(), "live")):
        return False
    before = cert_mtimes()
    docker_util.run_oneoff(CERTBOT_IMAGE, "renew", "--non-interactive",
                           opts=("--network", "host", "-v", f"{host_path('certs')}:/etc/letsencrypt"),
                           timeout=600, check=False)
    return cert_mtimes() != before


def cert_mtimes() -> dict:
    res = {}
    base = os.path.join(certs_dir(), "archive")
    for root, _, files in os.walk(base):
        for f in files:
            p = os.path.join(root, f)
            res[p] = os.path.getmtime(p)
    return res


def cert_expiry(path: str) -> dt.datetime | None:
    try:
        with open(path, "rb") as f:
            c = x509.load_pem_x509_certificate(f.read())
        return c.not_valid_after_utc
    except Exception:
        return None


# ================================================================ конфиг ===

def build_config(s: dict) -> dict:
    if s.get("self_signed"):
        tls = {"cert": f"{MOUNT}/cert.pem", "key": f"{MOUNT}/key.pem"}
    else:
        cert, key = le_paths(s["domain"])
        tls = {"cert": f"{CERTS_MOUNT}/{cert}", "key": f"{CERTS_MOUNT}/{key}"}
    cfg = {
        "listen": f":{int(s['port'])}",
        "tls": tls,
        "auth": {"type": "http",
                 "http": {"url": f"http://127.0.0.1:{s.get('auth_port', HY2_AUTH_PORT)}/hy2/auth",
                          "insecure": False}},
        "trafficStats": {"listen": f"127.0.0.1:{s.get('stats_port', STATS_PORT)}",
                         "secret": s["stats_secret"]},
        "congestion": {"type": "bbr"},
        "ignoreClientBandwidth": False,
    }
    if s.get("obfs"):
        cfg["obfs"] = {"type": "salamander", "salamander": {"password": s["obfs_password"]}}
    if s.get("block_ru"):
        cfg["acl"] = {"inline": ["reject(geoip:ru)", "reject(geosite:category-ru)",
                                 "reject(suffix:ru)", "reject(suffix:su)",
                                 "reject(suffix:xn--p1ai)", "reject(geoip:private)",
                                 "direct(all)"]}
    return cfg


def hy2_link(s: dict, password: str, name: str, host: str = VPN_HOST) -> str:
    """URI по документации Hysteria 2 (hysteria2://auth@host:port/?…#name)."""
    q = {}
    if s.get("obfs"):
        q["obfs"] = "salamander"
        q["obfs-password"] = s["obfs_password"]
    q["sni"] = s.get("sni") or host
    if s.get("self_signed"):
        q["insecure"] = "1"
        q["pinSHA256"] = s["pin_sha256"]
    return (f"hysteria2://{urllib.parse.quote(password, safe='')}@{host}:{s['port']}/?"
            f"{urllib.parse.urlencode(q)}#{urllib.parse.quote(name + ' · Hysteria2')}")


def write_config(s: dict) -> None:
    from ..snapshots import snapshot
    os.makedirs(local_dir(), exist_ok=True)
    path = os.path.join(local_dir(), "config.json")
    if os.path.exists(path):
        with open(path) as f:
            snapshot("hy2", {"config.json": f.read()})
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(build_config(s), f, indent=2)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def run_container(s: dict) -> None:
    docker_util.remove(CONTAINER)
    os.makedirs(certs_dir(), exist_ok=True)
    docker("run", "-d", "--name", CONTAINER, "--network", "host", "--restart", "unless-stopped",
           "--label", LABEL, "--log-opt", "max-size=5m", "--log-opt", "max-file=2",
           "-v", f"{host_path('hy2')}:{MOUNT}:ro", "-v", f"{host_path('certs')}:{CERTS_MOUNT}:ro",
           s.get("image", DEFAULT_IMAGE), "server", "-c", f"{MOUNT}/config.json", timeout=120)


def wait_started(timeout: float = 25) -> None:
    deadline = time.time() + timeout
    logs = ""
    while time.time() < deadline:
        time.sleep(1.5)
        logs = docker_util.logs(CONTAINER, 40)
        if "server up and running" in logs.lower():
            return
        state = ((docker_util.inspect(CONTAINER) or {}).get("State") or {})
        if state.get("Status") in ("exited", "dead"):
            break
    raise RuntimeError(f"Hysteria не запустилась:\n{logs.strip()[-1200:]}")


def stats_api(path: str, method: str = "GET", body=None, s: dict | None = None):
    s = s or HY2.settings() or {}
    req = urllib.request.Request(
        f"http://127.0.0.1:{s.get('stats_port', STATS_PORT)}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": s.get("stats_secret", ""), "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read()
    return json.loads(raw) if raw.strip() else None


def chat_of(uid: str) -> int | None:
    return int(uid[1:]) if uid.startswith("u") and uid[1:].lstrip("-").isdigit() else None


class Hysteria(Protocol):
    id = "hy2"
    title = "Hysteria 2"
    short = "HY2"
    icon = "hysteria"

    def settings(self) -> dict | None:
        from ..db import protocol_row
        row = protocol_row("hy2")
        if not row or not row["settings"]:
            return None
        try:
            return json.loads(row["settings"])
        except ValueError:
            return None

    def save_settings(self, s: dict) -> None:
        from ..db import db, now
        db.execute("INSERT INTO protocols (id, origin, container, settings, installed_at) "
                   "VALUES ('hy2', 'bot', ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                   "settings=excluded.settings", (CONTAINER, json.dumps(s), now()))
        db.commit()

    def install(self, params: dict, progress) -> dict:
        from ..db import active_user_ids, ensure_creds
        s = {"port": int(params["port"]), "obfs": bool(params.get("obfs", True)),
             "obfs_password": secrets.token_urlsafe(18), "stats_secret": secrets.token_urlsafe(24),
             "stats_port": STATS_PORT, "auth_port": HY2_AUTH_PORT,
             "self_signed": params.get("cert") != "domain",
             "block_ru": bool(params.get("block_ru", False)),
             "image": params.get("image") or DEFAULT_IMAGE, "domain": VPN_HOST}
        s["ports"] = [("udp", s["port"])]
        os.makedirs(local_dir(), exist_ok=True)
        if s["self_signed"]:
            progress("Самоподписанный сертификат")
            cert, key, pin = self_signed()
            for name, data in (("cert.pem", cert), ("key.pem", key)):
                with open(os.path.join(local_dir(), name), "wb") as f:
                    f.write(data)
                os.chmod(os.path.join(local_dir(), name), 0o644)
            s["pin_sha256"] = pin
            s["sni"] = VPN_HOST if not is_ip(VPN_HOST) else "www.bing.com"
        else:
            if is_ip(VPN_HOST):
                raise RuntimeError("Для сертификата Let's Encrypt VPN_HOST должен быть доменом")
            progress(f"Сертификат Let's Encrypt для {VPN_HOST} (порт 80/TCP)")
            obtain_le(VPN_HOST)
            s["sni"] = VPN_HOST
        for uid in active_user_ids():
            ensure_creds(uid)
        progress(f"Скачивание образа {s['image']}")
        docker("pull", s["image"], timeout=900)
        progress("Запись конфига")
        write_config(s)
        self.save_settings(s)
        progress("Запуск контейнера vpnbot-hysteria")
        run_container(s)
        progress("Проверка запуска")
        wait_started()
        return s

    def restore(self, s: dict, progress) -> None:
        """Файлы (cert/key, certs/) уже лежат на месте; конфиг пересобирается из settings."""
        if not s.get("self_signed"):
            cert = os.path.join(certs_dir(), le_paths(s["domain"])[0])
            exp = cert_expiry(cert)
            if not exp or exp < dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3):
                progress("Сертификат истёк или отсутствует — перевыпуск")
                obtain_le(s["domain"])
        progress(f"Скачивание образа {s.get('image', DEFAULT_IMAGE)}")
        docker("pull", s.get("image", DEFAULT_IMAGE), timeout=900)
        progress("Запись конфига")
        write_config(s)
        self.save_settings(s)
        progress("Запуск контейнера vpnbot-hysteria")
        run_container(s)
        progress("Проверка запуска")
        wait_started()

    def uninstall(self, progress, remove_data: bool = False) -> None:
        progress("Остановка и удаление контейнера vpnbot-hysteria")
        docker_util.remove(CONTAINER)
        if remove_data:
            shutil.rmtree(local_dir(), ignore_errors=True)

    def restart(self) -> None:
        docker("restart", CONTAINER, timeout=120)

    def set_block_ru(self, on: bool) -> None:
        s = self.settings()
        s["block_ru"] = bool(on)
        write_config(s)
        self.save_settings(s)
        self.restart()
        wait_started()

    def sync(self) -> str:
        """Клиенты проверяются хуком по базе — синхронизировать нечего."""
        return "api" if docker_util.is_running(CONTAINER) else ""

    def kick(self, chat_ids) -> None:
        if not docker_util.is_running(CONTAINER):
            return
        try:
            stats_api("/kick", "POST", [f"u{c}" for c in chat_ids])
        except Exception as e:
            log.warning("hysteria kick failed: %s", e)

    def stats(self) -> dict[int, dict]:
        res: dict[int, dict] = {}
        if not self.settings() or not docker_util.is_running(CONTAINER):
            return res
        try:
            traffic = stats_api("/traffic?clear=1") or {}
            online = stats_api("/online") or {}
        except Exception as e:
            log.debug("hysteria stats: %s", e)
            return res
        for uid, v in traffic.items():
            cid = chat_of(uid)
            if cid is not None:
                # tx — от клиента (upload), rx — клиенту (см. core/server/copy.go)
                res[cid] = {"rx": int(v.get("tx") or 0), "tx": int(v.get("rx") or 0),
                            "online": False}
        for uid, n in online.items():
            cid = chat_of(uid)
            if cid is not None and n:
                r = res.setdefault(cid, {"rx": 0, "tx": 0, "online": False})
                r["online"], r["conns"] = True, int(n)
        return res

    def links(self, user, name: str = "") -> list[str]:
        s = self.settings()
        if not s or not user["hy2_pass"]:
            return []
        name = name or "VPN"
        if s.get("block_ru"):
            name += " · без RU"   # видно в списке серверов приложения
        return [hy2_link(s, user["hy2_pass"], name)]


def auth_check(password: str) -> str | None:
    """Хук аутентификации: пароль из базы → "u<chat_id>" (только одобренные)."""
    from ..db import db
    if not password:
        return None
    r = db.execute("SELECT chat_id FROM users WHERE hy2_pass=? AND status='approved'",
                   (password,)).fetchone()
    return f"u{r[0]}" if r else None


async def renew_loop() -> None:
    """Раз в сутки — certbot renew; если сертификат обновился — перезапуск Hysteria."""
    import asyncio
    while True:
        await asyncio.sleep(86400)
        s = HY2.settings()
        if (not s or s.get("self_signed")) and not os.path.isdir(os.path.join(certs_dir(), "live")):
            continue
        try:
            if await asyncio.to_thread(renew_le):
                from ..sub_server import reload_tls
                reload_tls()
                if s and not s.get("self_signed"):
                    await asyncio.to_thread(HY2.restart)
                log.info("Сертификат обновлён, Hysteria перезапущена")
        except Exception as e:
            log.warning("cert renew failed: %s", e)


HY2 = Hysteria()
