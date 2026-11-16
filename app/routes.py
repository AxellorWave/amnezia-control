"""«Списки сервисов»: домены и IP заблокированных (и российских) сервисов по темам,
выбор человека и готовые файлы раздельного туннелирования для клиентов.

Режимы:
  "include" — через VPN только выбранные сервисы, остальное напрямую;
  "exclude" — всё через VPN, кроме выбранных (обход).

Источники (обновление раз в сутки, кэш в DATA_DIR/routes/, при недоступности —
встроенный каталог ниже; поверх — правки админа из таблицы route_overrides):
  * itdoginfo/allow-domains — домены и подсети сервисов
    https://github.com/itdoginfo/allow-domains (Services/*.lst, Subnets/IPv4/*.lst);
  * iplist.opencck.org — домены и CIDR по сайту (format=text);
  * core.telegram.org/resources/cidr.txt — официальные подсети Telegram;
  * ipdeny.com — агрегированные подсети РФ (для «Всех сайтов .ru»).

Форматы файлов:
  * AmneziaVPN «Раздельное туннелирование» → импорт: JSON-массив
    [{"hostname": "<домен или CIDR>", "ip": ""}] (amnezia-client,
    IpSplitTunnelingController::importSitesFromJson);
  * AmneziaWG / DefaultVPN / WireGuard — .conf устройства с вычисленными AllowedIPs;
  * Happ и Incy — профиль маршрутизации JSON (GlobalProxy, DirectSites/DirectIp,
    ProxySites/ProxyIp) и ссылки happ://routing/onadd/<base64>, incy://routing/onadd/<base64>
    (https://www.happ.su/main/dev-docs/routing, https://docs.incy.cc/en/routing/);
  * Hiddify и другие на sing-box — rule-set в исходном формате (version 2);
  * v2RayTun и другие на Xray — правила routing (domain/ip) в JSON;
  * простые списки .txt (домены, подсети).
"""
import asyncio
import base64
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait

from .config import DATA_DIR
from .db import db

log = logging.getLogger("amnezia-bot")

REFRESH_EVERY = 86400
UA = "Mozilla/5.0 (compatible; vpn-routes/1.0)"
MAX_DOMAINS = 3000
MAX_CIDRS = 20000
RESOLVE_MAX = 150                 # сколько доменов сервиса резолвить в IP для WireGuard
AWG_WARN_ROUTES = 1500            # больше — некоторые клиенты (iOS, Windows) тормозят

ITDOG = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main"
OPENCCK = "https://iplist.opencck.org/?format=text&data={data}&site={site}"

PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
              "127.0.0.0/8", "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32")

# ================================================================= каталог ===
# key: (название, домены по умолчанию, подсети по умолчанию, источники)
# источник: ("domains"|"cidr", url)

TG_CIDR = ["91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
           "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22", "95.161.64.0/20",
           "149.154.160.0/20", "185.76.151.0/24"]


def _itdog(name: str, subnets: bool = False) -> list[tuple[str, str]]:
    src = [("domains", f"{ITDOG}/Services/{name}.lst")]
    if subnets:
        src.append(("cidr", f"{ITDOG}/Subnets/IPv4/{name}.lst"))
    return src


def _cck(site: str) -> list[tuple[str, str]]:
    return [("domains", OPENCCK.format(data="domains", site=site)),
            ("cidr", OPENCCK.format(data="cidr4", site=site))]


SERVICES: dict[str, dict] = {
    # --- Видео
    "youtube": {"title": "YouTube", "domains": [
        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
        "youtube-nocookie.com", "youtubei.googleapis.com", "yt.be", "youtubekids.com"],
        "sources": _itdog("youtube") + _cck("youtube.com")},
    # --- Соцсети
    "instagram": {"title": "Instagram", "domains": [
        "instagram.com", "cdninstagram.com", "ig.me", "instagr.am", "igcdn.com"],
        "sources": _itdog("meta", subnets=True) + _cck("instagram.com")},
    "facebook": {"title": "Facebook", "domains": [
        "facebook.com", "fb.com", "fb.me", "fbcdn.net", "facebook.net", "fbsbx.com",
        "messenger.com", "m.me"],
        "sources": _itdog("meta", subnets=True) + _cck("facebook.com")},
    "twitter": {"title": "X (Twitter)", "domains": [
        "twitter.com", "x.com", "twimg.com", "t.co", "twitpic.com", "twttr.com"],
        "sources": _itdog("twitter", subnets=True) + _cck("x.com")},
    "linkedin": {"title": "LinkedIn", "domains": ["linkedin.com", "licdn.com", "lnkd.in"],
                 "sources": _cck("linkedin.com")},
    "tiktok": {"title": "TikTok", "domains": [
        "tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokcdn-us.com", "byteoversea.com",
        "ibytedtos.com", "ttwstatic.com", "muscdn.com"],
        "sources": _itdog("tiktok") + _cck("tiktok.com")},
    # --- Мессенджеры
    "telegram": {"title": "Telegram", "domains": [
        "telegram.org", "t.me", "telegram.me", "telegra.ph", "telesco.pe", "tdesktop.com",
        "cdn-telegram.org", "graph.org", "tx.me"], "cidrs": TG_CIDR,
        "sources": _itdog("telegram", subnets=True)
        + [("cidr", "https://core.telegram.org/resources/cidr.txt")]},
    "whatsapp": {"title": "WhatsApp", "domains": [
        "whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.biz"],
        "sources": _itdog("meta", subnets=True) + _cck("whatsapp.com")},
    "discord": {"title": "Discord", "domains": [
        "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
        "discordcdn.com", "discord.dev", "discord.new", "discordstatus.com", "dis.gd"],
        "sources": _itdog("discord", subnets=True) + _cck("discord.com")},
    "signal": {"title": "Signal", "domains": [
        "signal.org", "whispersystems.org", "signal.art", "signal.me"],
        "sources": _cck("signal.org")},
    "viber": {"title": "Viber", "domains": ["viber.com", "vb.me"], "sources": _cck("viber.com")},
    # --- Нейросети
    "openai": {"title": "ChatGPT / OpenAI", "domains": [
        "openai.com", "chatgpt.com", "chat.com", "oaistatic.com", "oaiusercontent.com",
        "sora.com", "openai.org"], "sources": _cck("chatgpt.com")},
    "gemini": {"title": "Gemini / AI Studio", "domains": [
        "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
        "notebooklm.google.com", "bard.google.com", "makersuite.google.com"],
        "sources": []},
    "copilot": {"title": "Microsoft Copilot", "domains": [
        "copilot.microsoft.com", "sydney.bing.com", "edgeservices.bing.com"], "sources": []},
    "perplexity": {"title": "Perplexity", "domains": ["perplexity.ai", "pplx.ai"],
                   "sources": _cck("perplexity.ai")},
    "grok": {"title": "Grok", "domains": ["grok.com", "x.ai"], "sources": _cck("grok.com")},
    # --- Игры
    "roblox": {"title": "Roblox", "domains": [
        "roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com", "roblox.qq.com"],
        "sources": _itdog("roblox") + _cck("roblox.com")},
    "supercell": {"title": "Supercell (Brawl Stars, Clash)", "domains": [
        "supercell.com", "supercellid.com", "supercell.net", "brawlstars.com",
        "clashofclans.com", "clashroyale.com"], "sources": _cck("supercell.com")},
    "playstation": {"title": "PlayStation Network", "domains": [
        "playstation.com", "playstation.net", "sonyentertainmentnetwork.com"],
        "sources": _cck("playstation.com")},
    # --- Разработка
    "docker": {"title": "Docker Hub", "domains": [
        "docker.com", "docker.io", "registry-1.docker.io", "production.cloudflare.docker.com",
        "hub.docker.com", "dockerhub.com"], "sources": _cck("docker.com")},
    "github": {"title": "GitHub", "domains": [
        "github.com", "githubusercontent.com", "github.io", "githubassets.com", "ghcr.io",
        "github.dev"], "sources": _cck("github.com")},
    "jetbrains": {"title": "JetBrains", "domains": ["jetbrains.com", "jetbrains.space",
                                                   "intellij.net"],
                  "sources": _cck("jetbrains.com")},
    # --- Музыка и прочее
    "spotify": {"title": "Spotify", "domains": [
        "spotify.com", "scdn.co", "spotifycdn.com", "spotify.design", "spoti.fi"],
        "sources": _cck("spotify.com")},
    "soundcloud": {"title": "SoundCloud", "domains": ["soundcloud.com", "sndcdn.com"],
                   "sources": _cck("soundcloud.com")},
    "patreon": {"title": "Patreon", "domains": ["patreon.com", "patreonusercontent.com"],
                "sources": _cck("patreon.com")},
    "medium": {"title": "Medium", "domains": ["medium.com"], "sources": _cck("medium.com")},
    # --- Российские сервисы (обычно — в обход VPN)
    "yandex": {"title": "Яндекс", "domains": [
        "yandex.ru", "ya.ru", "yandex.net", "yastatic.net", "yandex.com", "yandex.by",
        "yandex.kz", "kinopoisk.ru", "dzen.ru", "yandexcloud.net"],
        "sources": _cck("yandex.ru")},
    "vk": {"title": "VK, Mail.ru, Одноклассники", "domains": [
        "vk.com", "vk.ru", "vkuser.net", "userapi.com", "vk-cdn.net", "mail.ru", "ok.ru",
        "mycdn.me", "vkvideo.ru", "max.ru"], "sources": _cck("vk.com")},
    "gosuslugi": {"title": "Госуслуги и госсайты", "domains": [
        "gosuslugi.ru", "nalog.gov.ru", "mos.ru", "pfr.gov.ru", "sfr.gov.ru", "gov.ru"],
        "sources": _cck("gosuslugi.ru")},
    "banks": {"title": "Банки", "domains": [
        "sberbank.ru", "sber.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru",
        "raiffeisen.ru", "gazprombank.ru", "pochtabank.ru", "nspk.ru", "sbp.nspk.ru"],
        "sources": []},
    "shops": {"title": "Маркетплейсы", "domains": [
        "ozon.ru", "ozone.ru", "wildberries.ru", "wb.ru", "wbstatic.net", "avito.ru",
        "avito.st", "megamarket.ru", "lamoda.ru"], "sources": []},
    "ru_all": {"title": "Все сайты .ru / .рф / .su", "domains": ["ru", "xn--p1ai", "su"],
               "suffix_only": True,
               "sources": [("cidr", "https://www.ipdeny.com/ipblocks/data/aggregated/"
                                    "ru-aggregated.zone")]},
}

TOPICS: list[tuple[str, str, list[str]]] = [
    ("video", "Видео", ["youtube"]),
    ("social", "Соцсети", ["instagram", "facebook", "twitter", "linkedin", "tiktok"]),
    ("messengers", "Мессенджеры", ["telegram", "whatsapp", "discord", "signal", "viber"]),
    ("ai", "Нейросети", ["openai", "gemini", "copilot", "perplexity", "grok"]),
    ("games", "Игры", ["roblox", "supercell", "playstation"]),
    ("dev", "Разработка", ["docker", "github", "jetbrains"]),
    ("other", "Музыка и прочее", ["spotify", "soundcloud", "patreon", "medium"]),
    ("ru", "Российские сервисы", ["yandex", "vk", "gosuslugi", "banks", "shops", "ru_all"]),
]
TOPIC_OF = {s: t for t, _, svcs in TOPICS for s in svcs}

MODES = {"include": "Через VPN — только выбранные", "exclude": "Всё через VPN, кроме выбранных"}


# ============================================================= разбор и кэш ===

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})*$")


def parse_list(text: str) -> tuple[list[str], list[str]]:
    """Нестрогий разбор списка: домены и подсети (IPv4/IPv6), по одному в строке,
    допускаются комментарии и префиксы domain:/full:/*./+./DOMAIN-SUFFIX,…"""
    domains, cidrs = [], []
    for raw in re.split(r"[\s,;]+", text or ""):
        t = raw.strip().strip('"').strip("'")
        if not t or t.startswith(("#", "//", "!")):
            continue
        t = re.sub(r"^(domain|full|domain-suffix|domain_suffix|host-suffix|ip-cidr|"
                   r"ip_cidr|suffix)[:,]", "", t, flags=re.I)
        t = t.lstrip("*+.").rstrip(".").lower()
        try:
            net = ipaddress.ip_network(t, strict=False)
            cidrs.append(str(net))
            continue
        except ValueError:
            pass
        if DOMAIN_RE.match(t) and "." in t:
            domains.append(t)
    return domains, cidrs


def cache_dir() -> str:
    return os.path.join(DATA_DIR, "routes")


def _cache_path(key: str) -> str:
    return os.path.join(cache_dir(), f"{key}.json")


_lock = threading.Lock()
_mem: dict[str, dict] = {}


def fetch(url: str, timeout: float = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/plain, */*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(8 * 1024 * 1024)
    return data.decode("utf-8", errors="replace")


def resolve(domains: list[str], limit: int = RESOLVE_MAX, timeout: float = 15) -> list[str]:
    """A-записи доменов (для WireGuard, где маршрутизация только по IP)."""
    res: set[str] = set()

    def one(d: str):
        try:
            for info in socket.getaddrinfo(d, 443, socket.AF_INET, socket.SOCK_STREAM):
                res.add(info[4][0] + "/32")
        except OSError:
            pass

    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = [ex.submit(one, d) for d in domains[:limit]]
        wait(futs, timeout=timeout)
    return sorted(res)


def refresh_service(key: str, do_resolve: bool = True) -> dict:
    svc = SERVICES[key]
    domains, cidrs, ok = list(svc.get("domains", [])), list(svc.get("cidrs", [])), []
    for kind, url in svc.get("sources", []):
        try:
            d, c = parse_list(fetch(url))
        except Exception as e:
            log.debug("routes %s: %s: %s", key, url, e)
            continue
        if kind == "domains":
            domains += d
            cidrs += c
        else:
            cidrs += c
        ok.append(url)
    if svc.get("suffix_only"):
        domains = list(svc["domains"])
    domains = list(dict.fromkeys(domains))[:MAX_DOMAINS]
    cidrs = [str(n) for n in collapse(cidrs)][:MAX_CIDRS]
    resolved = []
    if do_resolve and not svc.get("suffix_only"):
        extra = [d for d in svc.get("extra_domains", []) if d not in domains]
        resolved = resolve(extra + domains)
    entry = {"domains": domains, "cidrs": cidrs, "resolved": resolved, "ts": time.time(),
             "sources": ok}
    os.makedirs(cache_dir(), exist_ok=True)
    tmp = _cache_path(key) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(entry, f)
    os.replace(tmp, _cache_path(key))
    with _lock:
        _mem[key] = entry
    return entry


def _base_entry(key: str) -> dict:
    """Данные сервиса из источников: память, кэш на диске или встроенный каталог."""
    with _lock:
        if key in _mem:
            return _mem[key]
    try:
        with open(_cache_path(key)) as f:
            entry = json.load(f)
    except (OSError, ValueError):
        svc = SERVICES[key]
        entry = {"domains": list(svc.get("domains", [])), "cidrs": list(svc.get("cidrs", [])),
                 "resolved": [], "ts": 0, "sources": []}
    with _lock:
        _mem[key] = entry
    return entry


def get_service(key: str) -> dict:
    """Данные сервиса с правками админа: добавленные адреса плюс, убранные минус."""
    e = _base_entry(key)
    svc = SERVICES.get(key, {})
    ex_d, ex_c = set(svc.get("excluded_domains", [])), set(svc.get("excluded_cidrs", []))
    add_d, add_c = svc.get("extra_domains", []), svc.get("extra_cidrs", [])
    if not (ex_d or ex_c or add_d or add_c):
        return e
    domains = [d for d in dict.fromkeys(add_d + e["domains"]) if d not in ex_d]
    cidrs = [c for c in dict.fromkeys(add_c + e["cidrs"]) if c not in ex_c]
    resolved = [r for r in e.get("resolved", []) if r not in ex_c]
    return dict(e, domains=domains, cidrs=cidrs, resolved=resolved)


def refresh_all() -> None:
    for key in list(SERVICES):
        try:
            refresh_service(key)
        except Exception as e:
            log.warning("routes refresh %s failed: %s", key, e)


def last_update() -> float:
    ts = [_base_entry(k).get("ts", 0) for k in list(SERVICES)]
    return max(ts) if ts else 0


async def routes_loop() -> None:
    """Раз в сутки обновлять списки (первый раз — через минуту после старта)."""
    await asyncio.sleep(60)
    while True:
        if time.time() - last_update() > REFRESH_EVERY - 600:
            await asyncio.to_thread(refresh_all)
        await asyncio.sleep(3600)


# =========================================================== правки админа ===
# Встроенный каталог можно дополнять из админки: свои сервисы, свои домены и подсети
# у любого сервиса, убрать адреса из источников, скрыть встроенный сервис.
# Всё хранится в таблице route_overrides и накладывается на каталог при старте и после
# каждой правки (SERVICES / TOPICS / TOPIC_OF меняются на месте).

BUILTIN_SERVICES = {k: dict(v) for k, v in SERVICES.items()}
BUILTIN_TOPICS = [(t, title, list(keys)) for t, title, keys in TOPICS]
MAX_TITLE = 40

db.execute("""CREATE TABLE IF NOT EXISTS route_overrides (key TEXT PRIMARY KEY,
              custom INTEGER NOT NULL DEFAULT 0, title TEXT, topic TEXT,
              extra_domains TEXT NOT NULL DEFAULT '[]', extra_cidrs TEXT NOT NULL DEFAULT '[]',
              excluded_domains TEXT NOT NULL DEFAULT '[]',
              excluded_cidrs TEXT NOT NULL DEFAULT '[]', hidden INTEGER NOT NULL DEFAULT 0)""")
db.commit()

LIST_FIELDS = ("extra_domains", "extra_cidrs", "excluded_domains", "excluded_cidrs")


def _jl(v) -> list:
    try:
        return [str(x) for x in json.loads(v or "[]")]
    except ValueError:
        return []


def override(key: str) -> dict:
    r = db.execute("SELECT * FROM route_overrides WHERE key=?", (key,)).fetchone()
    if not r:
        return {"key": key, "custom": 0, "title": None, "topic": None, "hidden": 0,
                **{f: [] for f in LIST_FIELDS}}
    return {"key": key, "custom": r["custom"], "title": r["title"], "topic": r["topic"],
            "hidden": r["hidden"], **{f: _jl(r[f]) for f in LIST_FIELDS}}


def _save_override(o: dict) -> None:
    db.execute("INSERT OR REPLACE INTO route_overrides (key, custom, title, topic, "
               "extra_domains, extra_cidrs, excluded_domains, excluded_cidrs, hidden) "
               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (o["key"], o["custom"], o["title"], o["topic"],
                *[json.dumps(o[f]) for f in LIST_FIELDS], o["hidden"]))
    db.commit()


def apply_overrides() -> None:
    """Собрать SERVICES / TOPICS заново: встроенный каталог + правки из БД."""
    services = {k: dict(v) for k, v in BUILTIN_SERVICES.items()}
    topics = [(t, title, list(keys)) for t, title, keys in BUILTIN_TOPICS]
    by_topic = {t: keys for t, _, keys in topics}
    for r in db.execute("SELECT key FROM route_overrides ORDER BY rowid"):
        o = override(r["key"])
        key = o["key"]
        if o["custom"]:
            topic = o["topic"] if o["topic"] in by_topic else "other"
            services[key] = {"title": o["title"] or key, "domains": [], "sources": [],
                             "custom": True}
            by_topic[topic].append(key)
        elif key not in services:
            continue
        if o["hidden"] and not o["custom"]:
            services.pop(key)
            for keys in by_topic.values():
                if key in keys:
                    keys.remove(key)
            continue
        for f in LIST_FIELDS:
            services[key][f] = o[f]
    with _lock:
        SERVICES.clear()
        SERVICES.update(services)
        TOPICS[:] = topics
        TOPIC_OF.clear()
        TOPIC_OF.update({s: t for t, _, svcs in topics for s in svcs})


def hidden_services() -> list[str]:
    return [r["key"] for r in db.execute("SELECT key FROM route_overrides WHERE hidden=1 "
                                         "AND custom=0") if r["key"] in BUILTIN_SERVICES]


def _new_key() -> str:
    n = 1
    while f"c{n}" in SERVICES or override(f"c{n}")["custom"]:
        n += 1
    return f"c{n}"


def _refresh_later(key: str) -> None:
    """IP доменов для WireGuard — в фоне, чтобы не держать кнопку."""
    def run():
        try:
            if key in SERVICES:
                refresh_service(key)
        except Exception as e:
            log.debug("routes refresh %s: %s", key, e)
    threading.Thread(target=run, daemon=True).start()


def add_custom(title: str, topic: str, text: str) -> str:
    """Новый сервис со своими доменами и подсетями. -> ключ."""
    domains, cidrs = parse_list(text)
    if not (domains or cidrs):
        raise ValueError("Не нашёл ни одного домена или IP-адреса")
    title = " ".join((title or "").split())[:MAX_TITLE]
    if not title:
        raise ValueError("Пустое название")
    key = _new_key()
    o = override(key)
    topics = {t for t, _, _ in BUILTIN_TOPICS}
    o.update(custom=1, title=title, topic=topic if topic in topics else "other",
             extra_domains=domains, extra_cidrs=[str(n) for n in collapse(cidrs)])
    _save_override(o)
    apply_overrides()
    _refresh_later(key)
    return key


def add_entries(key: str, text: str) -> tuple[int, int]:
    """Добавить домены/подсети к сервису. -> (доменов, подсетей) новых."""
    if key not in SERVICES:
        raise KeyError(key)
    domains, cidrs = parse_list(text)
    if not (domains or cidrs):
        raise ValueError("Не нашёл ни одного домена или IP-адреса")
    cidrs = [str(n) for n in collapse(cidrs)]
    o = override(key)
    nd = [d for d in domains if d not in o["extra_domains"]]
    nc = [c for c in cidrs if c not in o["extra_cidrs"]]
    o["extra_domains"] += nd
    o["extra_cidrs"] += nc
    o["excluded_domains"] = [d for d in o["excluded_domains"] if d not in domains]
    o["excluded_cidrs"] = [c for c in o["excluded_cidrs"] if c not in cidrs]
    _save_override(o)
    apply_overrides()
    if nd:
        _refresh_later(key)
    return len(nd), len(nc)


def remove_entries(key: str, text: str) -> tuple[int, int]:
    """Убрать домены/подсети: добавленные админом удаляются, остальные (из источников)
    запоминаются как исключённые. -> (доменов, подсетей)."""
    if key not in SERVICES:
        raise KeyError(key)
    domains, cidrs = parse_list(text)
    if not (domains or cidrs):
        raise ValueError("Не нашёл ни одного домена или IP-адреса")
    cidrs = [str(n) for n in collapse(cidrs)]
    o = override(key)
    o["extra_domains"] = [d for d in o["extra_domains"] if d not in domains]
    o["extra_cidrs"] = [c for c in o["extra_cidrs"] if c not in cidrs]
    o["excluded_domains"] = list(dict.fromkeys(o["excluded_domains"] + domains))
    o["excluded_cidrs"] = list(dict.fromkeys(o["excluded_cidrs"] + cidrs))
    _save_override(o)
    apply_overrides()
    return len(domains), len(cidrs)


def reset_service(key: str) -> None:
    """Убрать все правки встроенного сервиса (вернуть как в каталоге)."""
    db.execute("DELETE FROM route_overrides WHERE key=? AND custom=0", (key,))
    db.commit()
    apply_overrides()


def delete_service(key: str) -> None:
    """Свой сервис — удалить совсем, встроенный — скрыть (можно вернуть)."""
    o = override(key)
    if o["custom"]:
        db.execute("DELETE FROM route_overrides WHERE key=?", (key,))
        db.commit()
        with _lock:
            _mem.pop(key, None)
        try:
            os.remove(_cache_path(key))
        except OSError:
            pass
    elif key in BUILTIN_SERVICES:
        o["hidden"] = 1
        _save_override(o)
    apply_overrides()


def restore_service(key: str) -> None:
    o = override(key)
    if key in BUILTIN_SERVICES and o["hidden"]:
        o["hidden"] = 0
        _save_override(o)
        apply_overrides()


def is_custom(key: str) -> bool:
    return bool(SERVICES.get(key, {}).get("custom"))


apply_overrides()


# ================================================================ подсети ===

def collapse(cidrs) -> list:
    v4, v6 = [], []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        (v4 if n.version == 4 else v6).append(n)
    return list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))


def complement_v4(excluded) -> list[ipaddress.IPv4Network]:
    """0.0.0.0/0 минус исключённые IPv4-подсети (минимальный набор CIDR)."""
    nets = [n for n in collapse(excluded) if n.version == 4]
    result = [ipaddress.ip_network("0.0.0.0/0")]
    for ex in nets:
        nxt = []
        for r in result:
            if ex.subnet_of(r):
                nxt.extend(r.address_exclude(ex))
            elif r.subnet_of(ex):
                continue
            else:
                nxt.append(r)
        result = nxt
    return sorted(ipaddress.collapse_addresses(result))


def aggregate_v4(cidrs, max_routes: int) -> list[ipaddress.IPv4Network]:
    """Сжать список, расширяя префиксы, пока маршрутов не станет не больше max_routes."""
    nets = [n for n in collapse(cidrs) if n.version == 4]
    plen = 32
    while len(nets) > max_routes and plen > 8:
        plen -= 1
        nets = list(ipaddress.collapse_addresses(
            n.supernet(new_prefix=plen) if n.prefixlen > plen else n for n in nets))
    return nets


# ================================================================ выбор ===

db.execute("""CREATE TABLE IF NOT EXISTS route_prefs (chat_id INTEGER PRIMARY KEY,
              mode TEXT NOT NULL DEFAULT 'include', services TEXT NOT NULL DEFAULT '[]',
              updated TEXT)""")
db.commit()


def get_prefs(chat_id: int) -> dict:
    r = db.execute("SELECT mode, services FROM route_prefs WHERE chat_id=?",
                   (chat_id,)).fetchone()
    if not r:
        return {"mode": "include", "services": []}
    try:
        svcs = [s for s in json.loads(r["services"]) if s in SERVICES]
    except ValueError:
        svcs = []
    return {"mode": r["mode"] if r["mode"] in MODES else "include", "services": svcs}


def save_prefs(chat_id: int, mode: str, services) -> None:
    from .db import now
    svcs = [s for s in dict.fromkeys(services) if s in SERVICES]
    db.execute("INSERT INTO route_prefs (chat_id, mode, services, updated) VALUES (?, ?, ?, ?) "
               "ON CONFLICT(chat_id) DO UPDATE SET mode=excluded.mode, "
               "services=excluded.services, updated=excluded.updated",
               (chat_id, mode if mode in MODES else "include", json.dumps(svcs), now()))
    db.commit()


def toggle(chat_id: int, key: str) -> dict:
    p = get_prefs(chat_id)
    svcs = p["services"]
    if key in svcs:
        svcs.remove(key)
    elif key in SERVICES:
        svcs.append(key)
    save_prefs(chat_id, p["mode"], svcs)
    return get_prefs(chat_id)


def toggle_topic(chat_id: int, topic: str) -> dict:
    p = get_prefs(chat_id)
    keys = next((s for t, _, s in TOPICS if t == topic), [])
    if all(k in p["services"] for k in keys):
        svcs = [s for s in p["services"] if s not in keys]
    else:
        svcs = p["services"] + [k for k in keys if k not in p["services"]]
    save_prefs(chat_id, p["mode"], svcs)
    return get_prefs(chat_id)


def set_mode(chat_id: int, mode: str) -> dict:
    p = get_prefs(chat_id)
    save_prefs(chat_id, mode, p["services"])
    return get_prefs(chat_id)


# ================================================================ сборка ===

def collect(services) -> dict:
    """Объединённые домены, домены-суффиксы (зоны), подсети и IP доменов."""
    domains, zones, cidrs, resolved = [], [], [], []
    for key in services:
        e = get_service(key)
        if SERVICES[key].get("suffix_only"):
            zones += e["domains"]
        else:
            domains += e["domains"]
        cidrs += e["cidrs"]
        resolved += e.get("resolved", [])
    return {"domains": list(dict.fromkeys(domains)), "zones": list(dict.fromkeys(zones)),
            "cidrs": [str(n) for n in collapse(cidrs)],
            "resolved": [str(n) for n in collapse(resolved)]}


def amnezia_json(data: dict) -> str:
    """AmneziaVPN → Раздельное туннелирование → Импорт: [{"hostname", "ip"}]."""
    items = [{"hostname": d, "ip": ""} for d in data["domains"]]
    items += [{"hostname": c, "ip": ""} for c in data["cidrs"] if ":" not in c]
    return json.dumps(items, ensure_ascii=False, indent=1)


def wg_allowed_ips(data: dict, mode: str, max_routes: int = AWG_WARN_ROUTES) -> tuple[str, int, bool]:
    """AllowedIPs для конфига AmneziaWG/WireGuard. -> (строка, число маршрутов, сжато ли)."""
    nets = data["cidrs"] + data["resolved"]
    if mode == "include":
        v4 = [n for n in collapse(nets) if n.version == 4]
        v6 = [n for n in collapse(nets) if n.version == 6]
        squeezed = len(v4) > max_routes
        if squeezed:
            v4 = aggregate_v4(v4, max_routes)
        routes = [str(n) for n in v4 + v6]
    else:
        excluded = [n for n in collapse(nets) if n.version == 4] + \
            [ipaddress.ip_network(p) for p in PRIVATE_V4]
        squeezed = False
        comp = complement_v4(excluded)
        if len(comp) > max_routes:
            # исключения сжимаем, пока дополнение не станет приемлемым по размеру
            squeezed = True
            for limit in (max_routes, max_routes // 2, max_routes // 4, max_routes // 8, 64):
                comp = complement_v4(aggregate_v4(excluded, limit))
                if len(comp) <= max_routes:
                    break
        routes = [str(n) for n in comp] + ["::/0"]
    return ", ".join(routes), len(routes), squeezed


def awg_conf(conf_text: str, allowed: str) -> str:
    """Подменить AllowedIPs в [Peer] клиентского конфига."""
    return re.sub(r"(?m)^AllowedIPs\s*=.*$", f"AllowedIPs = {allowed}", conf_text, count=1)


def xray_domain_rules(data: dict) -> list[str]:
    return [f"domain:{d}" for d in data["domains"]] + [f"domain:{z}" for z in data["zones"]]


def happ_profile(data: dict, mode: str, name: str = "VPN") -> dict:
    """Профиль маршрутизации Happ / Incy (https://www.happ.su/main/dev-docs/routing)."""
    private = list(PRIVATE_V4)
    sites = xray_domain_rules(data)
    ips = data["cidrs"]
    prof = {
        "Name": name,
        "GlobalProxy": "true" if mode == "exclude" else "false",
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
        "RemoteDNSIP": "1.1.1.1",
        "DomesticDNSType": "DoH",
        "DomesticDNSDomain": "https://dns.google/dns-query",
        "DomesticDNSIP": "8.8.8.8",
        "DnsHosts": {"cloudflare-dns.com": "1.1.1.1", "dns.google": "8.8.8.8"},
        "DirectSites": sites if mode == "exclude" else [],
        "DirectIp": (ips if mode == "exclude" else []) + private,
        "ProxySites": sites if mode == "include" else [],
        "ProxyIp": ips if mode == "include" else [],
        "BlockSites": [],
        "BlockIp": [],
        "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "false",
        "LastUpdated": str(int(time.time())),
    }
    return prof


def happ_link(profile: dict, scheme: str = "happ") -> str:
    raw = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode()
    return f"{scheme}://routing/onadd/{base64.b64encode(raw).decode()}"


def singbox_ruleset(data: dict) -> str:
    """sing-box rule-set, исходный формат (version 2) — Hiddify и др."""
    rule = {}
    if data["domains"] or data["zones"]:
        rule["domain_suffix"] = data["domains"] + data["zones"]
    if data["cidrs"]:
        rule["ip_cidr"] = data["cidrs"]
    return json.dumps({"version": 2, "rules": [rule] if rule else []}, indent=1)


def xray_rules(data: dict, mode: str) -> str:
    """Правила routing Xray (v2RayTun и др.): выбранное — в proxy или в direct."""
    tag = "proxy" if mode == "include" else "direct"
    rules = []
    if data["domains"] or data["zones"]:
        rules.append({"type": "field", "domain": xray_domain_rules(data), "outboundTag": tag})
    if data["cidrs"]:
        rules.append({"type": "field", "ip": data["cidrs"], "outboundTag": tag})
    rules.append({"type": "field", "ip": list(PRIVATE_V4), "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp",
                  "outboundTag": "direct" if mode == "include" else "proxy"})
    return json.dumps({"domainStrategy": "IPIfNonMatch", "rules": rules}, indent=1)


def plain_lists(data: dict) -> tuple[str, str]:
    doms = "\n".join(data["domains"] + data["zones"]) + "\n"
    ips = "\n".join(data["cidrs"]) + "\n"
    return doms, ips


def selection_title(services) -> str:
    return ", ".join(SERVICES[s]["title"] for s in services) or "ничего"
