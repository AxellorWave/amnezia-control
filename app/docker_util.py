"""Работа с Docker через docker.sock (docker CLI внутри контейнера бота)."""
import json
import logging
import os
import re
import shlex
import subprocess

log = logging.getLogger("amnezia-bot")


class DockerError(RuntimeError):
    pass


def docker(*args: str, stdin: str | bytes | None = None, check: bool = True,
           timeout: float | None = 600) -> str:
    """Выполнить `docker <args>` и вернуть stdout."""
    binary = isinstance(stdin, bytes)
    try:
        r = subprocess.run(["docker", *args], input=stdin, capture_output=True,
                           text=not binary, timeout=timeout)
    except FileNotFoundError as e:
        raise DockerError("docker CLI не найден") from e
    except subprocess.TimeoutExpired as e:
        raise DockerError(f"docker {' '.join(args[:3])}: таймаут") from e
    out = r.stdout.decode(errors="replace") if binary else r.stdout
    err = r.stderr.decode(errors="replace") if binary else r.stderr
    if check and r.returncode != 0:
        raise DockerError(f"docker {' '.join(args[:4])} failed: {err.strip() or out.strip()}")
    return out


def logs(container: str, tail: int = 50) -> str:
    """Логи контейнера (stdout и stderr вместе)."""
    r = subprocess.run(["docker", "logs", "--tail", str(tail), container], capture_output=True,
                       text=True, timeout=30)
    return re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)


def docker_bytes(*args: str, timeout: float | None = 600) -> bytes:
    r = subprocess.run(["docker", *args], capture_output=True, timeout=timeout)
    if r.returncode != 0:
        raise DockerError(f"docker {' '.join(args[:4])} failed: "
                          f"{r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def dexec(container: str, cmd: str, stdin: str | None = None) -> str:
    r = subprocess.run(["docker", "exec", "-i", container, "sh", "-c", cmd],
                       input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"docker exec failed: {cmd}\n{r.stderr.strip()}")
    return r.stdout


def read_file(container: str, path: str, default: str | None = None) -> str:
    try:
        return dexec(container, f"cat {shlex.quote(path)}")
    except RuntimeError:
        if default is not None:
            return default
        raise


def write_file(container: str, path: str, content: str) -> None:
    dexec(container, f"cat > {shlex.quote(path)}", stdin=content)


# ================================================================ состояние ===

def ps_all() -> list[dict]:
    """Все контейнеры: name, image, state (running/exited/...), status, labels, ports."""
    out = docker("ps", "-a", "--no-trunc", "--format", "{{json .}}", timeout=30)
    res = []
    for line in out.splitlines():
        try:
            c = json.loads(line)
        except json.JSONDecodeError:
            continue
        labels = {}
        for part in (c.get("Labels") or "").split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                labels[k] = v
        res.append({"name": c.get("Names", ""), "image": c.get("Image", ""),
                    "state": c.get("State", ""), "status": c.get("Status", ""),
                    "labels": labels, "ports": c.get("Ports", "")})
    return res


def inspect(name: str) -> dict | None:
    try:
        data = json.loads(docker("inspect", "--type", "container", name, timeout=30))
    except (DockerError, json.JSONDecodeError):
        return None
    return data[0] if data else None


def exists(name: str) -> bool:
    return inspect(name) is not None


def is_running(name: str) -> bool:
    c = inspect(name)
    return bool(c and (c.get("State") or {}).get("Running"))


def published_ports(c: dict) -> list[tuple[str, int]]:
    """[(proto, port)] — опубликованные порты контейнера (или слушаемые при --network host
    не видны — для них порты берутся из настроек протокола)."""
    res = []
    for key, binds in ((c.get("HostConfig") or {}).get("PortBindings") or {}).items():
        port, _, proto = key.partition("/")
        for b in binds or [{}]:
            hp = b.get("HostPort") or port
            if str(hp).isdigit():
                res.append((proto or "tcp", int(hp)))
    return sorted(set(res))


def ports_from_ps(ports: str) -> list[tuple[str, int]]:
    """Разбор колонки Ports из `docker ps`: 0.0.0.0:55424->55424/udp, ..."""
    res = set()
    for m in re.finditer(r"(?:[\d.:\[\]a-f]*:)?(\d+)(?:-(\d+))?->\d+(?:-\d+)?/(tcp|udp)", ports):
        a, b, proto = int(m.group(1)), m.group(2), m.group(3)
        for p in range(a, (int(b) if b else a) + 1):
            res.add((proto, p))
    return sorted(res)


def remove(name: str, volumes: bool = False) -> None:
    docker("rm", "-f" + ("v" if volumes else ""), name, check=False, timeout=120)


def image_exists(image: str) -> bool:
    return bool(docker("images", "-q", image, check=False, timeout=30).strip())


def network_exists(name: str) -> bool:
    return bool(docker("network", "ls", "-q", "--filter", f"name=^{name}$",
                       check=False, timeout=30).strip())


def network_containers(name: str) -> list[str]:
    try:
        data = json.loads(docker("network", "inspect", name, timeout=30))
    except (DockerError, json.JSONDecodeError):
        return []
    return [c.get("Name", "") for c in ((data[0] if data else {}).get("Containers") or {}).values()]


def run_oneoff(image: str, *args: str, opts: tuple[str, ...] = (), stdin: str | None = None,
               timeout: float = 600, check: bool = True) -> str:
    """Одноразовый контейнер `docker run --rm`."""
    return docker("run", "--rm", "-i", *opts, image, *args, stdin=stdin, timeout=timeout,
                  check=check)


def host_sh(script: str, timeout: float = 300) -> str:
    """Выполнить скрипт на хосте: одноразовый привилегированный контейнер с --net host
    и общим с хостом пространством PID (как setup_host_firewall.sh в приложении Amnezia)."""
    return run_oneoff("alpine:3.20", "sh", "-c", script,
                      opts=("--privileged", "--net", "host", "--pid", "host"), timeout=timeout)


# ================================================== каталог данных на хосте ===
# Бот сам работает в контейнере, а для -v у своих контейнеров нужен путь на хосте.

_host_data_dir: str | None = None


def _self_container_id() -> str | None:
    try:
        with open("/proc/self/mountinfo") as f:
            m = re.search(r"/containers/([0-9a-f]{64})/", f.read())
        return m.group(1) if m else None
    except OSError:
        return None


def host_data_dir(data_dir: str) -> str:
    """Путь на хосте к каталогу данных бота (смонтирован в контейнер как data_dir).
    HOST_DATA_DIR из окружения, иначе — из `docker inspect` самого бота."""
    global _host_data_dir
    if _host_data_dir:
        return _host_data_dir
    env = os.getenv("HOST_DATA_DIR", "").strip()
    if env:
        _host_data_dir = env.rstrip("/")
        return _host_data_dir
    for ref in (_self_container_id(), os.getenv("BOT_CONTAINER", "amnezia-bot")):
        c = inspect(ref) if ref else None
        for m in (c or {}).get("Mounts") or []:
            if m.get("Destination") == data_dir and m.get("Source"):
                _host_data_dir = m["Source"].rstrip("/")
                return _host_data_dir
    # бот запущен не в контейнере — путь совпадает
    _host_data_dir = data_dir
    return _host_data_dir
