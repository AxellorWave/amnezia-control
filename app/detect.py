"""Автоопределение того, что стоит на сервере: контейнеры Amnezia и контейнеры бота.

Перепроверка — при старте, раз в 5 минут и по кнопке «Обновить» в админке.
"""
import asyncio
import logging
import time

from . import docker_util
from .protocols import awg

log = logging.getLogger("amnezia-bot")

DETECT_EVERY = 300
BOT_LABEL = "vpnbot.proto"

# контейнеры, которые ставит приложение AmneziaVPN
AMNEZIA_TITLES = {
    "amnezia-awg2": "AmneziaWG 2.0",
    "amnezia-awg": "AmneziaWG (старый)",
    "amnezia-xray": "XRay (Amnezia)",
    "amnezia-ssxray": "Shadowsocks (Xray)",
    "amnezia-openvpn": "OpenVPN",
    "amnezia-openvpn-cloak": "OpenVPN over Cloak",
    "amnezia-shadowsocks": "OpenVPN over Shadowsocks",
    "amnezia-wireguard": "WireGuard",
    "amnezia-ipsec": "IPsec / IKEv2",
    "amnezia-dns": "AmneziaDNS",
    "amnezia-sftp": "SFTP",
    "amnezia-tor": "Tor (сайт)",
    "amnezia-socks5proxy": "SOCKS5",
    "amnezia-mtproxy": "MTProxy",
    "amnezia-telemt": "Telemt",
    "amnezia-tproxy": "TProxy",
}

STATE: dict = {"ts": 0.0, "docker": False, "error": "", "awg": None, "xray": None,
               "amnezia_xray": None, "hy2": None, "foreign": [], "others": []}
_listeners: list = []          # колбэки при изменении состава протоколов


def _state_of(c: dict) -> str:
    return "running" if c["state"] == "running" else "stopped"


def _entry(c: dict, origin: str, title: str, **extra) -> dict:
    return {"container": c["name"], "image": c["image"], "origin": origin, "title": title,
            "state": _state_of(c), "status": c["status"],
            "ports": docker_util.ports_from_ps(c["ports"]), **extra}


def scan() -> dict:
    """Опросить Docker и вернуть новое состояние (без побочных эффектов, кроме настройки AWG)."""
    from .db import protocol_row          # поздний импорт: db -> config
    st = {"ts": time.time(), "docker": True, "error": "", "awg": None, "xray": None,
          "amnezia_xray": None, "hy2": None, "foreign": [], "others": []}
    try:
        containers = docker_util.ps_all()
    except Exception as e:
        st.update(docker=False, error=str(e)[:300])
        return st
    by_name = {c["name"]: c for c in containers}

    # AWG: amnezia-awg2 (AWG 2.0) или старый amnezia-awg; CONTAINER из env — явный выбор
    names = ([awg.CONTAINER] if awg.ENV_FIXED else []) + list(awg.CONTAINERS)
    for name in names:
        c = by_name.get(name)
        if not c:
            continue
        row = protocol_row("awg")
        origin = row["origin"] if row and row["container"] == name else "amnezia"
        e = _entry(c, origin, "AmneziaWG 2.0" if name != "amnezia-awg" else "AmneziaWG (старый)")
        if e["state"] == "running":
            try:
                e.update(awg.autodetect(name))
            except Exception as ex:
                e["error"] = str(ex)[:200]
        st["awg"] = e
        break

    for c in containers:
        name, proto = c["name"], c["labels"].get(BOT_LABEL)
        if proto in ("xray", "hy2"):
            st[proto] = _entry(c, "bot", "VLESS (Xray)" if proto == "xray" else "Hysteria 2")
        elif name == "amnezia-xray":
            st["amnezia_xray"] = _entry(c, "amnezia", "XRay (Amnezia)")
        elif name.startswith("amnezia-") and (st["awg"] or {}).get("container") != name \
                and name != "amnezia-bot":
            st["others"].append(_entry(c, "amnezia", AMNEZIA_TITLES.get(name, name)))
        elif "hysteria" in c["image"].lower() and not proto:
            st["foreign"].append(_entry(c, "foreign", "Hysteria (не управляется)"))
        elif "xray" in c["image"].lower() and not proto and not name.startswith("amnezia-"):
            st["foreign"].append(_entry(c, "foreign", "Xray (не управляется)"))
    return st


def refresh() -> dict:
    old = {k: (STATE.get(k) or {}).get("state") for k in ("awg", "xray", "hy2")}
    STATE.update(scan())
    new = {k: (STATE.get(k) or {}).get("state") for k in ("awg", "xray", "hy2")}
    if old != new:
        log.info("Протоколы: %s", new)
        for cb in _listeners:
            try:
                cb(old, new)
            except Exception as e:
                log.warning("detect listener failed: %s", e)
    return STATE


def on_change(cb) -> None:
    _listeners.append(cb)


def get(pid: str) -> dict | None:
    return STATE.get(pid)


def installed(pid: str) -> bool:
    return bool(STATE.get(pid))


def running(pid: str) -> bool:
    return bool(STATE.get(pid) and STATE[pid]["state"] == "running")


def any_installed() -> bool:
    return any(installed(p) for p in ("awg", "xray", "hy2"))


def sub_protocols() -> list[str]:
    """Протоколы подписки, которые установлены (Xray / Hysteria2)."""
    return [p for p in ("xray", "hy2") if installed(p)]


async def detect_loop() -> None:
    while True:
        await asyncio.sleep(DETECT_EVERY)
        try:
            await asyncio.to_thread(refresh)
        except Exception as e:
            log.warning("detect failed: %s", e)
