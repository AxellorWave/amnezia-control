"""AmneziaWG: конфиг сервера в контейнере Amnezia, клиенты (пиры), ключи и форматы."""
import asyncio
import base64
import io
import ipaddress
import json
import os
import struct
import zlib
from datetime import datetime

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .. import docker_util
from ..config import DNS1, DNS2, KEEPALIVE, MTU, SERVER_NAME, VPN_HOST

# Контейнер, каталог и утилиты определяются автоматически (detect.py) по найденному
# контейнеру Amnezia; переменные окружения — только чтобы задать их явно.
ENV_FIXED = bool(os.getenv("CONTAINER", "").strip())
CONTAINER = os.getenv("CONTAINER", "").strip() or "amnezia-awg2"
CONF_DIR = os.getenv("CONF_DIR", "").strip() or "/opt/amnezia/awg"
IFACE = os.getenv("IFACE", "").strip() or "awg0"
WG_BIN = os.getenv("WG_BIN", "").strip() or "awg"
WG_QUICK_BIN = os.getenv("WG_QUICK_BIN", "").strip() or "awg-quick"
SERVER_CONF = f"{CONF_DIR}/{IFACE}.conf"
CONTAINERS = ("amnezia-awg2", "amnezia-awg")       # AWG 2.0 и старый AWG
# параметры [Interface] сервера, которые НЕ переносятся в конфиг клиента
SERVER_ONLY = {"address", "listenport", "privatekey", "postup", "postdown", "preup",
               "predown", "saveconfig", "table", "mtu", "dns", "fwmark"}

wg_lock = asyncio.Lock()


def configure(container: str | None = None, conf_dir: str | None = None, iface: str | None = None,
              wg_bin: str | None = None, wg_quick_bin: str | None = None) -> None:
    """Задать контейнер AWG и пути (явные значения из env имеют приоритет)."""
    global CONTAINER, CONF_DIR, IFACE, WG_BIN, WG_QUICK_BIN, SERVER_CONF
    env = lambda k: os.getenv(k, "").strip()
    CONTAINER = env("CONTAINER") or container or CONTAINER
    CONF_DIR = env("CONF_DIR") or conf_dir or CONF_DIR
    IFACE = env("IFACE") or iface or IFACE
    WG_BIN = env("WG_BIN") or wg_bin or WG_BIN
    WG_QUICK_BIN = env("WG_QUICK_BIN") or wg_quick_bin or WG_QUICK_BIN
    SERVER_CONF = f"{CONF_DIR}/{IFACE}.conf"


def autodetect(container: str) -> dict:
    """Определить внутри запущенного контейнера: awg0.conf или wg0.conf, awg или wg."""
    out = docker_util.dexec(container, (
        "d=/opt/amnezia/awg; "
        "if [ -f $d/awg0.conf ]; then echo iface=awg0; elif [ -f $d/wg0.conf ]; then echo iface=wg0; fi; "
        "if command -v awg >/dev/null 2>&1; then echo bin=awg; else echo bin=wg; fi; "
        "if command -v awg-quick >/dev/null 2>&1; then echo quick=awg-quick; else echo quick=wg-quick; fi"))
    kv_ = dict(line.split("=", 1) for line in out.split() if "=" in line)
    res = {"container": container, "conf_dir": "/opt/amnezia/awg",
           "iface": kv_.get("iface") or ("awg0" if container == "amnezia-awg2" else "wg0"),
           "wg_bin": kv_.get("bin", "awg"), "wg_quick_bin": kv_.get("quick", "awg-quick")}
    configure(**res)
    return res


def dexec(cmd: str, stdin: str | None = None) -> str:
    return docker_util.dexec(CONTAINER, cmd, stdin)


def read_file(path: str, default: str | None = None) -> str:
    return docker_util.read_file(CONTAINER, path, default)


def write_file(path: str, content: str) -> None:
    docker_util.write_file(CONTAINER, path, content)


def sync_wg() -> None:
    dexec(f"{WG_QUICK_BIN} strip '{SERVER_CONF}' > /tmp/bot_strip.conf && "
          f"{WG_BIN} syncconf {IFACE} /tmp/bot_strip.conf && rm -f /tmp/bot_strip.conf")


# ============================================================= wireguard ===

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def gen_keypair() -> tuple[str, str]:
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64(priv), b64(pub)


def pub_from_priv(priv: str) -> str:
    k = X25519PrivateKey.from_private_bytes(base64.b64decode(priv))
    return b64(k.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw))


def split_sections(text: str) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = [("", [])]
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            sections.append((s.lower(), [line]))
        else:
            sections[-1][1].append(line)
    return sections


def section_kv(lines: list[str]) -> dict[str, str]:
    kv = {}
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s and not s.startswith("["):
            k, v = s.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def parse_server_conf(text: str, spub: str = "", psk: str = "") -> dict:
    iface, used_ips = {}, set()
    for name, lines in split_sections(text):
        kv = section_kv(lines)
        if name == "[interface]":
            iface = kv
        elif name == "[peer]" and "AllowedIPs" in kv:
            for ip in kv["AllowedIPs"].split(","):
                used_ips.add(ip.strip().split("/")[0])
    if not spub:
        spub = pub_from_priv(iface["PrivateKey"])
    params = {k: v for k, v in iface.items() if k.lower() not in SERVER_ONLY}
    awg2 = "HeaderProtectionKey" in params or "S3" in params
    return {
        "text": text,
        "address": iface["Address"].split(",")[0].strip(),
        "port": iface["ListenPort"],
        "obf": params,                 # всё, что клиент должен знать (Jc, S1.., H1.., ...)
        "awg2": awg2,
        "keepalive": KEEPALIVE or ("25-35" if awg2 else "25"),
        "server_pub": spub,
        "psk": psk,
        "used_ips": used_ips,
    }


def server_info() -> dict:
    text = read_file(SERVER_CONF)
    spub = read_file(f"{CONF_DIR}/wireguard_server_public_key.key", "").strip()
    psk = read_file(f"{CONF_DIR}/wireguard_psk.key", "").strip()
    return parse_server_conf(text, spub, psk)


def next_free_ip(info: dict) -> str:
    net = ipaddress.ip_interface(info["address"]).network
    taken = set(info["used_ips"]) | {info["address"].split("/")[0]}
    for i, host in enumerate(net.hosts()):
        if i == 0:
            continue
        if str(host) not in taken:
            return str(host)
    raise RuntimeError("В подсети закончились адреса")


def read_clients_table() -> list:
    try:
        return json.loads(read_file(f"{CONF_DIR}/clientsTable", "[]") or "[]")
    except json.JSONDecodeError:
        return []


def add_peer(name: str) -> dict:
    info = server_info()
    priv, pub = gen_keypair()
    psk = info["psk"] or b64(os.urandom(32))
    ip = next_free_ip(info)

    text = info["text"].rstrip("\n") + (
        f"\n\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {ip}/32\n")
    write_file(SERVER_CONF, text)
    sync_wg()

    table = read_clients_table()
    table.append({"clientId": pub, "userData": {
        "clientName": name, "creationDate": datetime.now().strftime("%a %b %d %H:%M:%S %Y")}})
    write_file(f"{CONF_DIR}/clientsTable", json.dumps(table, indent=4, ensure_ascii=False))
    return {"priv": priv, "pub": pub, "psk": psk, "ip": ip}


def remove_peer(pub: str) -> None:
    info = server_info()
    out = []
    for name, lines in split_sections(info["text"]):
        if name == "[peer]" and section_kv(lines).get("PublicKey") == pub:
            continue
        out.extend(lines)
    write_file(SERVER_CONF, "\n".join(out).rstrip("\n") + "\n")
    sync_wg()
    table = [c for c in read_clients_table() if c.get("clientId") != pub]
    write_file(f"{CONF_DIR}/clientsTable", json.dumps(table, indent=4, ensure_ascii=False))


def server_peers() -> list[dict]:
    """Все клиенты сервера с именами из clientsTable (как в приложении AmneziaVPN)."""
    info = server_info()
    names = {c.get("clientId"): (c.get("userData") or {}).get("clientName", "")
             for c in read_clients_table()}
    peers = []
    for name, lines in split_sections(info["text"]):
        if name != "[peer]":
            continue
        kv = section_kv(lines)
        if kv.get("PublicKey"):
            ip = kv.get("AllowedIPs", "").split(",")[0].split("/")[0].strip()
            peers.append({"pub": kv["PublicKey"], "ip": ip,
                          "name": names.get(kv["PublicKey"]) or "без имени"})
    return peers


def peer_stats() -> dict[str, dict]:
    """pub -> {hs: unix-время последнего handshake, rx, tx}"""
    stats = {}
    try:
        out = dexec(f"{WG_BIN} show {IFACE} dump")
    except RuntimeError:
        return stats
    for line in out.splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 7:
            stats[p[0]] = {"hs": int(p[4] or 0), "rx": int(p[5] or 0), "tx": int(p[6] or 0)}
    return stats


# =============================================================== форматы ===

def client_conf(c, info: dict, dns: str | None = None) -> str:
    params = "".join(f"{k} = {v}\n" for k, v in info["obf"].items())
    return (
        "[Interface]\n"
        f"Address = {c['ip']}/32\n"
        f"DNS = {dns or f'{DNS1}, {DNS2}'}\n"
        f"PrivateKey = {c['priv']}\n"
        f"{params}\n"
        "[Peer]\n"
        f"PublicKey = {info['server_pub']}\n"
        f"PresharedKey = {c['psk']}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {VPN_HOST}:{info['port']}\n"
        f"PersistentKeepalive = {info['keepalive']}\n"
    )


def amnezia_key(c, info: dict) -> str:
    """Ключ vpn:// в том же формате, что «Поделиться» в AmneziaVPN."""
    obf = info["obf"]
    last_config = {
        **obf,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "clientId": c["pub"],
        "client_ip": c["ip"],
        "client_priv_key": c["priv"],
        "client_pub_key": c["pub"],
        "config": client_conf(c, info, dns="$PRIMARY_DNS, $SECONDARY_DNS"),
        "hostName": VPN_HOST,
        "mtu": MTU,
        "persistent_keep_alive": info["keepalive"],
        "port": int(info["port"]),
        "psk_key": c["psk"],
        "server_pub_key": info["server_pub"],
    }
    awg = {**obf,
           "last_config": json.dumps(last_config, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False),
           "port": str(info["port"]),
           "subnet_address": str(ipaddress.ip_interface(info["address"]).network.network_address),
           "transport_proto": "udp"}
    if info["awg2"]:
        for k in ("I1", "I2", "I3", "I4", "I5"):
            awg.setdefault(k, "")
        awg["protocol_version"] = os.getenv("AWG_PROTOCOL_VERSION", "3.1")
    data = {
        "containers": [{"awg": awg, "container": CONTAINER}],
        "defaultContainer": CONTAINER,
        "description": SERVER_NAME,
        "dns1": DNS1,
        "dns2": DNS2,
        "format_version": 1,
        "hostName": VPN_HOST,
    }
    raw = json.dumps(data, indent=4, sort_keys=True, ensure_ascii=False).encode()
    packed = struct.pack(">I", len(raw)) + zlib.compress(raw, 8)
    return "vpn://" + base64.urlsafe_b64encode(packed).decode().rstrip("=")


def qr_png(data: str) -> bytes:
    img = qrcode.make(data, error_correction=qrcode.constants.ERROR_CORRECT_L, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
