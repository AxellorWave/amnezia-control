"""Файрвол хоста (ufw / firewalld): узнать, включён ли, и по кнопке открыть порт.

Команды выполняются в пространствах имён хоста (nsenter -t 1) из одноразового
привилегированного контейнера — бот сам в контейнере. Молча ничего не открываем."""
import logging
import shlex

from . import docker_util

log = logging.getLogger("amnezia-bot")


def _host(cmd: str, timeout: float = 120) -> str:
    return docker_util.host_sh(f"nsenter -t 1 -m -u -n -i sh -c {shlex.quote(cmd)} 2>&1",
                               timeout=timeout)


def status() -> dict:
    """{"kind": "ufw"|"firewalld"|None, "active": bool, "text": str}"""
    try:
        out = _host("if command -v ufw >/dev/null; then echo KIND=ufw; ufw status; fi; "
                    "if command -v firewall-cmd >/dev/null; then echo KIND=firewalld; "
                    "firewall-cmd --state; fi; true")
    except Exception as e:
        log.warning("host firewall status failed: %s", e)
        return {"kind": None, "active": False, "text": str(e)}
    kind, active = None, False
    if "KIND=ufw" in out and "Status: active" in out:
        kind, active = "ufw", True
    elif "KIND=firewalld" in out and "\nrunning" in out:
        kind, active = "firewalld", True
    elif "KIND=ufw" in out:
        kind = "ufw"
    elif "KIND=firewalld" in out:
        kind = "firewalld"
    return {"kind": kind, "active": active, "text": out[-1500:]}


def open_ports(wanted: list[tuple[str, int]]) -> str:
    st = status()
    if not st["active"]:
        return "Файрвол хоста не включён — открывать нечего."
    if st["kind"] == "ufw":
        cmd = "; ".join(f"ufw allow {port}/{proto}" for proto, port in wanted)
    else:
        cmd = ("; ".join(f"firewall-cmd --permanent --add-port={port}/{proto}"
                         for proto, port in wanted) + "; firewall-cmd --reload")
    return _host(cmd)
