"""Проверка занятости портов на хосте (TCP/UDP) и кто их занимает."""
import logging
import re

from . import docker_util

log = logging.getLogger("amnezia-bot")


def busy_ports() -> dict[tuple[str, int], str]:
    """{(proto, port): кто занимает} — опубликованные порты контейнеров и слушающие
    процессы хоста (netstat в одноразовом контейнере с --net host --pid host)."""
    res: dict[tuple[str, int], str] = {}
    try:
        for c in docker_util.ps_all():
            if c["state"] != "running":
                continue
            for key in docker_util.ports_from_ps(c["ports"]):
                res[key] = f"контейнер {c['name']}"
    except Exception as e:
        log.warning("ports: docker ps failed: %s", e)
    try:
        out = docker_util.host_sh("netstat -lntup 2>/dev/null", timeout=120)
    except Exception as e:
        log.warning("ports: netstat failed: %s", e)
        return res
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4 or not p[0].startswith(("tcp", "udp")):
            continue
        m = re.search(r":(\d+)$", p[3])
        if not m:
            continue
        key = ("tcp" if p[0].startswith("tcp") else "udp", int(m.group(1)))
        prog = p[-1].split("/", 1)[1] if "/" in p[-1] else ""
        if prog == "docker-proxy":          # порт контейнера — уже записан выше
            continue
        res.setdefault(key, f"процесс {prog}" if prog else "процесс на хосте")
    return res


def check(wanted: list[tuple[str, int]], busy: dict | None = None,
          ignore_containers: tuple[str, ...] = ()) -> dict[tuple[str, int], str]:
    """Какие из нужных портов заняты: {(proto, port): кто}."""
    busy = busy_ports() if busy is None else busy
    res = {}
    for key in wanted:
        who = busy.get(key)
        if who and not any(who == f"контейнер {c}" for c in ignore_containers):
            res[key] = who
    return res


def valid_port(s: str) -> int | None:
    s = s.strip()
    return int(s) if s.isdigit() and 1 <= int(s) <= 65535 else None
