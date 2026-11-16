"""Установка AmneziaWG 2.0 из бота — те же шаги, что у приложения AmneziaVPN.

Сверено с amnezia-vpn/amnezia-client (коммит f0b12257ab5c42730f2dd264fc403aeb98ee1e45):
InstallController::setupContainer -> prepareHost, isServerPortBusy, buildContainer,
runContainer, configureContainer, setupServerFirewall, startupContainer;
параметры — AwgInstaller::generateAwgParameters и protocolConstants.h (namespace awg).
Контейнер получается неотличимым от установленного приложением, поэтому остальной
код AWG работает с ним без изменений, а сервер можно добавить и в приложение.
"""
import json
import os
import random
import re
import time

from .. import docker_util
from ..docker_util import DockerError, docker
from . import awg

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "amnezia_scripts", "awg")
CONTAINER = "amnezia-awg2"
IMAGE = "amnezia-awg2"
NETWORK = "amnezia-dns-net"
DEFAULT_PORT = 55424                     # protocols::awg::defaultPort
DEFAULT_SUBNET_IP = "10.8.1.0"           # protocols::wireguard::defaultSubnetAddress
DEFAULT_SUBNET_CIDR = "24"               # protocols::wireguard::defaultSubnetCidr
PROTOCOL_VERSION = "3.1"                 # protocols::awg::awgV3

# protocolConstants.h, namespace awg
DEFAULT_PADDING = "12"
MAGIC_HEADERS = ("1", "2", "3", "4")
REKEY_AFTER_TIME = "100-120"
REKEY_TIMEOUT = "3-7"
REJECT_AFTER_TIME = "150-180"
KEEPALIVE_TIMEOUT = "5-15"
MAX_HANDSHAKE_ATTEMPTS = "15-20"
RANDOM_TRAILERS = "on"
DISABLE_COOKIES = "on"


def script(name: str) -> str:
    with open(os.path.join(SCRIPTS, name), encoding="utf-8") as f:
        return f.read()


def generate_params() -> dict:
    """AwgInstaller::generateAwgParameters. ContentPaddingAddition и I1–I5 приложение
    не заполняет — пустые строки configure_container.sh удаляет из awg0.conf."""
    return {
        "JUNK_PACKET_COUNT": str(random.randint(4, 6)),   # QRandomGenerator::bounded(4, 7)
        "JUNK_PACKET_MIN_SIZE": "10",
        "JUNK_PACKET_MAX_SIZE": "50",
        "INIT_PACKET_JUNK_SIZE": DEFAULT_PADDING,
        "RESPONSE_PACKET_JUNK_SIZE": DEFAULT_PADDING,
        "COOKIE_REPLY_PACKET_JUNK_SIZE": DEFAULT_PADDING,
        "TRANSPORT_PACKET_JUNK_SIZE": DEFAULT_PADDING,
        "INIT_PACKET_MAGIC_HEADER": MAGIC_HEADERS[0],
        "RESPONSE_PACKET_MAGIC_HEADER": MAGIC_HEADERS[1],
        "UNDERLOAD_PACKET_MAGIC_HEADER": MAGIC_HEADERS[2],
        "TRANSPORT_PACKET_MAGIC_HEADER": MAGIC_HEADERS[3],
        "HEADER_PROTECTION_KEY": awg.gen_keypair()[0],      # genClientKeys().clientPrivKey
        "CONTENT_PADDING_ADDITION": "",
        "REKEY_AFTER_TIME": REKEY_AFTER_TIME,
        "REKEY_TIMEOUT": REKEY_TIMEOUT,
        "REJECT_AFTER_TIME": REJECT_AFTER_TIME,
        "KEEPALIVE_TIMEOUT": KEEPALIVE_TIMEOUT,
        "MAX_HANDSHAKE_ATTEMPTS": MAX_HANDSHAKE_ATTEMPTS,
        "RANDOM_TRAILERS": RANDOM_TRAILERS,
        "DISABLE_COOKIES": DISABLE_COOKIES,
        "SPECIAL_JUNK_1": "", "SPECIAL_JUNK_2": "", "SPECIAL_JUNK_3": "",
        "SPECIAL_JUNK_4": "", "SPECIAL_JUNK_5": "",
    }


def script_vars(port: int, subnet_ip: str = DEFAULT_SUBNET_IP,
                cidr: str = DEFAULT_SUBNET_CIDR, params: dict | None = None) -> dict:
    v = {"AWG_SUBNET_IP": subnet_ip, "WIREGUARD_SUBNET_CIDR": cidr,
         "AWG_SERVER_PORT": str(port), "CONTAINER_NAME": CONTAINER}
    v.update(params or {})
    return v


def replace_vars(text: str, variables: dict) -> str:
    """SshSession::replaceVars — текстовая подстановка $NAME (длинные имена первыми)."""
    for k in sorted(variables, key=len, reverse=True):
        text = text.replace(f"${k}", variables[k])
    return text


def render_server_conf(variables: dict, priv: str) -> str:
    """То же, что пишет configure_container.sh (для тестов и сверки)."""
    body = script("configure_container.sh")
    tpl = body[body.index("[Interface]"):body.index("EOF\n", body.index("[Interface]"))]
    v = dict(variables, WIREGUARD_SERVER_PRIVATE_KEY=priv)
    lines = replace_vars(tpl, v).splitlines()
    return "\n".join(l for l in lines if not re.match(r"^[^=]*= *$", l)) + "\n"


# ================================================================= шаги ===

def prepare_host() -> None:
    """prepare_host.sh: сеть amnezia-dns-net, если её нет."""
    if not docker_util.network_exists(NETWORK):
        docker("network", "create", "--driver", "bridge", "--subnet=172.29.172.0/24",
               "--opt", "com.docker.network.bridge.name=amn0", NETWORK, timeout=60)


def remove_old() -> None:
    """remove_container.sh: остановить и удалить старый контейнер и образ."""
    docker("stop", CONTAINER, check=False, timeout=120)
    docker("rm", "-fv", CONTAINER, check=False, timeout=120)
    docker("rmi", IMAGE, check=False, timeout=120)


def build() -> None:
    """build_container.sh: docker build --no-cache --pull (Dockerfile без COPY — из stdin)."""
    out = docker("build", "--no-cache", "--pull", "-t", IMAGE, "-", stdin=script("Dockerfile"),
                 timeout=1200)
    if "pull rate limit" in out:
        raise DockerError("Docker Hub: превышен лимит скачиваний, попробуй позже")


def run(port: int) -> None:
    """run_container.sh."""
    docker("run", "-d", "--log-driver", "none", "--restart", "always", "--privileged",
           "--cap-add=NET_ADMIN", "--cap-add=SYS_MODULE",
           "-p", f"{port}:{port}/udp", "-v", "/lib/modules:/lib/modules",
           "--sysctl=net.ipv4.conf.all.src_valid_mark=1", "--name", CONTAINER, IMAGE, timeout=120)
    docker("network", "connect", NETWORK, CONTAINER, check=False, timeout=60)


def configure(variables: dict) -> None:
    """configure_container.sh внутри контейнера: ключи сервера, PSK, awg0.conf."""
    docker_util.docker("exec", "-i", CONTAINER, "bash", "-s",
                       stdin=replace_vars(script("configure_container.sh"), variables), timeout=120)


def setup_firewall() -> None:
    """setup_host_firewall.sh на хосте (одноразовый привилегированный контейнер)."""
    body = script("setup_host_firewall.sh")
    docker_util.run_oneoff("alpine:3.20", "sh", "-c",
                           "apk add --no-cache -q bash iptables >/dev/null && bash -s",
                           opts=("--privileged", "--net", "host"), stdin=body, timeout=300)


def startup(variables: dict) -> None:
    """start.sh в /opt/amnezia/start.sh и запуск, как startupContainerWorker."""
    docker_util.write_file(CONTAINER, "/opt/amnezia/start.sh",
                           replace_vars(script("start.sh"), variables))
    docker("exec", "-d", CONTAINER, "sh", "-c",
           "chmod a+x /opt/amnezia/start.sh && /opt/amnezia/start.sh", timeout=60)


def ensure_clients_table() -> None:
    docker_util.dexec(CONTAINER, "[ -f /opt/amnezia/awg/clientsTable ] || "
                                 "echo '[]' > /opt/amnezia/awg/clientsTable")


def verify(port: int, attempts: int = 15) -> str:
    last = ""
    for _ in range(attempts):
        try:
            out = docker_util.dexec(CONTAINER, "awg show awg0")
            if f"listening port: {port}" in out:
                return out
            last = out
        except RuntimeError as e:
            last = str(e)
        time.sleep(2)
    raise RuntimeError(f"awg0 не поднялся: {last.strip()[:500]}")


def install(port: int = DEFAULT_PORT, progress=lambda s: None, firewall: bool = True,
            restore_files: dict[str, str] | None = None) -> dict:
    """Полная установка. restore_files — {имя: содержимое} для восстановления из копии:
    ключи и awg0.conf берутся из копии, configure_container.sh не запускается."""
    params = generate_params()
    variables = script_vars(port, params=params)
    if restore_files and "awg0.conf" in restore_files:
        info = awg.parse_server_conf(restore_files["awg0.conf"])
        net = info["address"]
        ip, _, cidr = net.partition("/")
        variables = script_vars(port, ip, cidr or DEFAULT_SUBNET_CIDR)

    progress("Подготовка хоста (сеть amnezia-dns-net)")
    prepare_host()
    progress("Удаление старого контейнера, если он есть")
    remove_old()
    progress("Сборка образа amnezia-awg2 (может занять пару минут)")
    build()
    progress(f"Запуск контейнера, порт {port}/udp")
    run(port)
    if restore_files:
        progress("Запись ключей и конфига из резервной копии")
        docker_util.dexec(CONTAINER, "mkdir -p /opt/amnezia/awg")
        for name, content in restore_files.items():
            if name in RESTORE_FILES:
                docker_util.write_file(CONTAINER, f"/opt/amnezia/awg/{name}", content)
    else:
        progress("Генерация ключей и awg0.conf")
        configure(variables)
    if firewall:
        progress("Настройка файрвола хоста")
        setup_firewall()
    progress("Запуск AmneziaWG")
    startup(variables)
    ensure_clients_table()
    progress("Проверка интерфейса awg0")
    verify(port)
    awg.autodetect(CONTAINER)
    return {"port": port, "subnet": f"{variables['AWG_SUBNET_IP']}/{variables['WIREGUARD_SUBNET_CIDR']}",
            "params": {k: v for k, v in params.items() if v} if not restore_files else {}}


RESTORE_FILES = ("awg0.conf", "wg0.conf", "wireguard_server_private_key.key",
                 "wireguard_server_public_key.key", "wireguard_psk.key", "clientsTable")


def settings_json(result: dict) -> str:
    return json.dumps({"port": result["port"], "subnet": result["subnet"]})
