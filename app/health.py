"""Мониторинг доступности сервера из России, режим инцидента и слежение за сменой IP.

Проверка — через публичный API check-host.net (узлы в РФ + зарубежные, чтобы отличить
блокировку IP от падения сервера). TCP-порты (Xray, подписка) дают однозначный ответ;
UDP (AWG, Hysteria2) check-host проверяет «отправкой пакета»: VPN-сервер на мусор не
отвечает, поэтому отсутствие ответа по UDP — не ошибка, а «нет данных».

Итог проверки: ok / ip_blocked / server_down / partial / unknown.
Инцидент открывается одинаково — фоновой проверкой или кнопкой «Не работает VPN»;
открыт может быть только один. Пока он открыт, бот раз в ~45 с смотрит внешний IP
сервера и A-запись VPN_HOST на публичных резолверах и закрывает инцидент сам, когда
сервис снова доступен из РФ.
"""
import asyncio
import json
import logging
import random
import socket
import struct
import time
from datetime import datetime

import aiohttp

from . import detect
from .config import ADMIN_IDS, SUB_PORT, VPN_HOST
from .db import db, protocol_row
from .ui import btn, em, esc, kb, kv, notify, table

log = logging.getLogger("amnezia-bot")

API = "https://check-host.net"
HEADERS = {"Accept": "application/json", "User-Agent": "Mozilla/5.0 (compatible; vpn-health/1.0)"}
CACHE_SEC = 120                  # одна проверка на весь бот не чаще раза в 2 минуты
HEALTH_EVERY = 7 * 60            # фоновая проверка
WATCH_EVERY = 45                 # слежение за IP/DNS во время инцидента
WATCH_RECHECK = 180              # проверка из РФ во время инцидента без смены IP
ACTIVE_SEC = 600                 # «активные» пользователи — действие не позднее 10 минут назад
PARTIAL_NOTICE_SEC = 3600
FALLBACK_RU = ["ru1.node.check-host.net", "ru2.node.check-host.net", "ru3.node.check-host.net"]
FALLBACK_FOREIGN = ["de1.node.check-host.net", "nl1.node.check-host.net",
                    "uk1.node.check-host.net"]
FOREIGN_PREF = ("de", "nl", "fi", "se", "pl", "gb", "fr", "at", "ch")
RESOLVERS = {"8.8.8.8": "Google", "1.1.1.1": "Cloudflare", "77.88.8.8": "Яндекс"}
YANDEX = "77.88.8.8"
IP_SERVICES = ("https://api.ipify.org", "https://ifconfig.me/ip", "https://ipv4.icanhazip.com")
PROTO_TITLE = {"awg": "AmneziaWG", "xray": "VLESS (Xray)", "hy2": "Hysteria 2",
               "sub": "Подписка (HTTPS)"}
STATUS_TEXT = {"ok": "доступен из России", "ip_blocked": "IP заблокирован в России",
               "server_down": "сервер недоступен отовсюду",
               "partial": "часть протоколов недоступна", "unknown": "не удалось проверить"}
TTL_MIN_WAIT = 600               # у Timeweb минимальный TTL — 600 с
AWG_HS_FRESH = 300               # рукопожатие клиента AWG моложе 5 мин — протокол работает


# ==================================================================== БД ===

def init_tables() -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, started_at REAL, closed_at REAL,
        old_ip TEXT, dns_ip TEXT, protocols TEXT, new_ip TEXT, notified_dns TEXT,
        notified_bad_ip TEXT, wrong_dns TEXT, last_check REAL, details TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS incident_notified (incident_id INTEGER,
                  chat_id INTEGER, PRIMARY KEY(incident_id, chat_id))""")
    db.commit()


init_tables()


def open_incident_row():
    return db.execute("SELECT * FROM incidents WHERE closed_at IS NULL "
                      "ORDER BY id DESC LIMIT 1").fetchone()


def set_incident(inc_id: int, **fields) -> None:
    for k, v in fields.items():
        db.execute(f"UPDATE incidents SET {k}=? WHERE id=?", (v, inc_id))
    db.commit()


def add_notified(inc_id: int, chat_id: int) -> bool:
    """True — если человека ещё не было в списке."""
    cur = db.execute("INSERT OR IGNORE INTO incident_notified (incident_id, chat_id) "
                     "VALUES (?, ?)", (inc_id, chat_id))
    db.commit()
    return cur.rowcount > 0


def was_notified(inc_id: int, chat_id: int) -> bool:
    return db.execute("SELECT 1 FROM incident_notified WHERE incident_id=? AND chat_id=?",
                      (inc_id, chat_id)).fetchone() is not None


# ============================================================= цели проверки ===

def _settings_ports(pid: str) -> list[tuple[str, int]]:
    row = protocol_row(pid)
    try:
        return [(str(p[0]), int(p[1])) for p in json.loads(row["settings"]).get("ports", [])] \
            if row and row["settings"] else []
    except (TypeError, ValueError, IndexError, KeyError):
        return []


def targets() -> list[dict]:
    """[{pid, proto, port}] — порты установленных протоколов и сервера подписок.

    Сервер подписок проверяется, только если установлен Xray или Hysteria 2: без них
    подпиской никто не пользуется, и её недоступность не должна открывать инцидент."""
    res = []
    for pid in ("awg", "xray", "hy2"):
        e = detect.get(pid)
        if not e:
            continue
        ports = list(e.get("ports") or []) or _settings_ports(pid)
        for proto, port in ports:
            res.append({"pid": pid, "proto": proto, "port": int(port)})
    if SUB_PORT and detect.sub_protocols():
        res.append({"pid": "sub", "proto": "tcp", "port": int(SUB_PORT)})
    seen, out = set(), []
    for t in res:
        k = (t["proto"], t["port"])
        if k not in seen:
            seen.add(k)
            out.append(t)
    return out


# ============================================================ check-host.net ===

_nodes_cache = {"ts": 0.0, "ru": FALLBACK_RU, "foreign": FALLBACK_FOREIGN}


async def _get_json(session: aiohttp.ClientSession, url: str):
    async with session.get(url, headers=HEADERS,
                           timeout=aiohttp.ClientTimeout(total=20)) as r:
        r.raise_for_status()
        return await r.json(content_type=None)


async def nodes(session: aiohttp.ClientSession) -> tuple[list[str], list[str]]:
    if time.time() - _nodes_cache["ts"] < 86400:
        return _nodes_cache["ru"], _nodes_cache["foreign"]
    try:
        data = (await _get_json(session, f"{API}/nodes/hosts")).get("nodes") or {}
        ru = sorted(n for n, v in data.items() if (v.get("location") or [""])[0] == "ru")
        foreign = []
        for cc in FOREIGN_PREF:
            foreign += sorted(n for n, v in data.items() if (v.get("location") or [""])[0] == cc)[:1]
        if ru and foreign:
            _nodes_cache.update(ts=time.time(), ru=ru[:3], foreign=foreign[:3])
    except Exception as e:
        log.debug("check-host nodes: %s", e)
    return _nodes_cache["ru"], _nodes_cache["foreign"]


def node_status(kind: str, res) -> str:
    """Один узел: ok | fail | noreply (UDP без ответа) | unknown (нет данных)."""
    if res is None or not isinstance(res, list) or not res:
        return "unknown"
    r = res[0]
    if r is None:
        return "unknown"
    if isinstance(r, dict):
        if "time" in r:
            return "ok"
        if r.get("timeout"):
            return "noreply" if kind == "udp" else "fail"
        if r.get("error"):
            return "fail"
    return "unknown"


async def _run_check(session, kind: str, host: str, port: int, node_list: list[str],
                     wait: float = 25) -> dict[str, str]:
    q = "&".join([f"host={host}:{port}"] + [f"node={n}" for n in node_list])
    start = await _get_json(session, f"{API}/check-{kind}?{q}")
    rid = start.get("request_id")
    if not rid:
        raise RuntimeError(f"check-host: {start}")
    deadline = time.time() + wait
    res: dict = {}
    while time.time() < deadline:
        await asyncio.sleep(3)
        res = await _get_json(session, f"{API}/check-result/{rid}") or {}
        if node_list and all(res.get(n) is not None for n in node_list):
            break
    return {n: node_status(kind, res.get(n)) for n in node_list}


def target_state(ru: list[str], foreign: list[str]) -> str:
    """ok | blocked (из РФ нет, из-за рубежа есть) | down (нигде) | unknown."""
    if "ok" in ru:
        return "ok"
    ru_fail = bool(ru) and all(s == "fail" for s in ru if s != "unknown") and "fail" in ru
    if not ru_fail:
        return "unknown"
    if "ok" in foreign:
        return "blocked"
    if foreign and "fail" in foreign and all(s in ("fail", "unknown") for s in foreign):
        return "down"
    return "unknown"


def classify(items: list[dict]) -> str:
    """items: [{pid, state}] -> ok | ip_blocked | server_down | partial | unknown."""
    known = [i for i in items if i["state"] != "unknown"]
    if not known:
        return "unknown"
    states = {i["state"] for i in known}
    if states == {"ok"}:
        return "ok"
    if "ok" in states:
        return "partial"
    if "blocked" in states:
        return "ip_blocked"
    return "server_down"


_cache: dict = {"ts": 0.0, "result": None}
_check_lock = asyncio.Lock()


async def _do_check(host: str) -> dict:
    tg = targets()
    result = {"ts": time.time(), "host": host, "status": "unknown", "items": [], "error": ""}
    if not tg:
        result["error"] = "нет протоколов для проверки"
        return result
    try:
        async with aiohttp.ClientSession() as s:
            ru, foreign = await nodes(s)
            jobs = [_run_check(s, t["proto"], host, t["port"], ru + foreign) for t in tg]
            outs = await asyncio.gather(*jobs, return_exceptions=True)
    except Exception as e:
        result["error"] = str(e)[:200]
        return result
    for t, out in zip(tg, outs):
        if isinstance(out, Exception):
            item = dict(t, state="unknown", ru={}, foreign={}, error=str(out)[:120])
        else:
            r = {n: out.get(n, "unknown") for n in ru}
            f = {n: out.get(n, "unknown") for n in foreign}
            item = dict(t, state=target_state(list(r.values()), list(f.values())), ru=r, foreign=f)
        result["items"].append(item)
    await apply_awg_handshakes(result["items"])
    result["status"] = classify(result["items"])
    return result


def last_awg_handshake() -> float:
    """Unix-время самого свежего рукопожатия клиента AmneziaWG (0 — нет данных)."""
    from .protocols import awg
    return max((st["hs"] for st in awg.peer_stats().values() if st.get("hs")), default=0)


async def apply_awg_handshakes(items: list[dict]) -> None:
    """UDP снаружи не проверить: если клиенты AWG недавно делали рукопожатие — протокол
    работает. Нет свежих рукопожатий — оставляем «нет данных», как и было."""
    awg_items = [i for i in items if i["pid"] == "awg" and i["state"] == "unknown"]
    if not awg_items:
        return
    try:
        hs = await asyncio.to_thread(last_awg_handshake)
    except Exception as e:
        log.debug("awg handshakes: %s", e)
        return
    if hs and time.time() - hs < AWG_HS_FRESH:
        for i in awg_items:
            i.update(state="ok", handshake=hs)


async def check(force: bool = False, host: str | None = None,
                max_age: float = CACHE_SEC) -> dict:
    """Проверка доступности (с кэшем на весь бот: много нажатий — одна проверка)."""
    host = host or VPN_HOST
    c = _cache["result"]
    if not force and c and c["host"] == host and time.time() - _cache["ts"] < max_age:
        return c
    async with _check_lock:
        c = _cache["result"]
        if not force and c and c["host"] == host and time.time() - _cache["ts"] < max_age:
            return c
        res = await _do_check(host)
        _cache.update(ts=time.time(), result=res)
        log.info("health %s: %s", host, res["status"])
        return res


def last_result() -> dict | None:
    return _cache["result"]


def bad_protocols(result: dict) -> list[str]:
    return sorted({i["pid"] for i in result.get("items", []) if i["state"] in ("blocked", "down")})


def ok_protocols(result: dict) -> list[str]:
    return sorted({i["pid"] for i in result.get("items", []) if i["state"] == "ok"})


NODE_MARK = {"ok": "ok", "fail": "error", "noreply": "question", "unknown": "question"}


def result_html(result: dict | None, nodes_detail: bool = True) -> str:
    if not result:
        return "<p>Проверок ещё не было.</p>"
    when = datetime.fromtimestamp(result["ts"]).strftime("%H:%M:%S")
    ok = result["status"] == "ok"
    text = kv([(f"{em('health_ok' if ok else 'health_bad')} Итог",
                f"<b>{STATUS_TEXT.get(result['status'], result['status'])}</b>"),
               (f"{em('server')} Адрес", f"<code>{esc(result['host'])}</code>"),
               (f"{em('clock')} Проверено", when)])
    if result.get("error"):
        text += f"<blockquote>{em('warn')} {esc(result['error'])}</blockquote>"
    rows = []
    for i in result.get("items", []):
        st = {"ok": "ok", "blocked": "health_bad", "down": "error"}.get(i["state"], "question")
        row = [PROTO_TITLE.get(i["pid"], i["pid"]), f"<code>{i['port']}/{i['proto']}</code>",
               em(st)]
        if nodes_detail:
            row.append(" ".join(em(NODE_MARK[v]) for v in (i.get("ru") or {}).values()) or "—")
            row.append(" ".join(em(NODE_MARK[v]) for v in (i.get("foreign") or {}).values())
                       or "—")
        rows.append(row)
    if rows:
        head = ["Протокол", "Порт", "Итог"] + (["Из РФ", "Из-за рубежа"] if nodes_detail else [])
        text += table(rows, head=head)
        for i in result.get("items", []):
            if i.get("handshake"):
                ago = max(1, round((result["ts"] - i["handshake"]) / 60))
                text += (f"<p>{em('ok')} {PROTO_TITLE.get(i['pid'], i['pid'])}: клиенты "
                         f"подключались {ago} мин назад — протокол работает.</p>")
        if any(i["proto"] == "udp" for i in result.get("items", [])):
            text += (f"<p><i>{em('question')} UDP: VPN-сервер не отвечает на пробные пакеты, "
                     f"поэтому «нет ответа» по UDP — это норма, а не ошибка.</i></p>")
    return text


def last_result_text() -> str:
    """Краткий HTML последней проверки — для сообщения администратору."""
    return result_html(_cache["result"], nodes_detail=False)


# ======================================================================= DNS ===

def build_query(name: str, qid: int | None = None) -> bytes:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split("."))
    return header + qname + b"\x00" + struct.pack(">HH", 1, 1)


def _skip_name(data: bytes, off: int) -> int:
    while True:
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += ln + 1


def parse_response(data: bytes, qid: int | None = None) -> tuple[list[str], int]:
    """(список A-записей, минимальный TTL)."""
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if qid is not None and rid != qid:
        raise ValueError("DNS: чужой ответ")
    if flags & 0x000F not in (0, 3):
        raise ValueError(f"DNS rcode {flags & 0xF}")
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    ips, ttl = [], None
    for _ in range(an):
        off = _skip_name(data, off)
        typ, cls, t, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if typ == 1 and cls == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[off:off + 4]))
            ttl = t if ttl is None else min(ttl, t)
        off += rdlen
    return ips, ttl or 0


def resolve_a(name: str, server: str, timeout: float = 3.0) -> tuple[list[str], int]:
    qid = random.randint(0, 0xFFFF)
    q = build_query(name, qid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for _ in range(2):
            try:
                s.sendto(q, (server, 53))
                data, _ = s.recvfrom(2048)
                return parse_response(data, qid)
            except socket.timeout:
                continue
    raise TimeoutError(f"{server}: нет ответа")


def resolve_all(name: str = VPN_HOST) -> dict[str, dict]:
    res = {}
    for server in RESOLVERS:
        try:
            ips, ttl = resolve_a(name, server)
            res[server] = {"ips": ips, "ttl": ttl}
        except Exception as e:
            res[server] = {"ips": [], "ttl": 0, "error": str(e)[:80]}
    return res


def dns_majority(res: dict[str, dict]) -> str | None:
    """IP, который отдаёт большинство резолверов (иначе None)."""
    votes: dict[str, int] = {}
    for r in res.values():
        for ip in set(r.get("ips") or []):
            votes[ip] = votes.get(ip, 0) + 1
    if not votes:
        return None
    ip, n = max(votes.items(), key=lambda x: x[1])
    return ip if n * 2 > len(res) else None


def dns_updated(res: dict[str, dict], ip: str) -> bool:
    """Большинство резолверов, включая Яндекс, отдают ip."""
    return dns_majority(res) == ip and ip in (res.get(YANDEX) or {}).get("ips", [])


def majority_ip(answers: list[str | None]) -> str | None:
    votes: dict[str, int] = {}
    for a in answers:
        if a:
            votes[a] = votes.get(a, 0) + 1
    best = max(votes.items(), key=lambda x: x[1]) if votes else None
    return best[0] if best and best[1] >= 2 else None


def is_public_ip(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global


def interface_ips() -> set[str]:
    """Локальные IPv4 хоста (бот в сети хоста) из /proc/net/fib_trie."""
    res, last = set(), None
    try:
        with open("/proc/net/fib_trie") as f:
            for line in f:
                s = line.strip()
                if s.startswith("|--"):
                    last = s[3:].strip()
                elif "/32 host LOCAL" in s and last:
                    res.add(last)
    except OSError:
        pass
    return {ip for ip in res if is_public_ip(ip)}


async def external_ip() -> str | None:
    async def one(session, url):
        try:
            async with session.get(url, headers={"User-Agent": "curl/8"},
                                   timeout=aiohttp.ClientTimeout(total=10)) as r:
                ip = (await r.text()).strip()
                return ip if is_public_ip(ip) else None
        except Exception:
            return None
    async with aiohttp.ClientSession() as s:
        answers = await asyncio.gather(*(one(s, u) for u in IP_SERVICES))
    ip = majority_ip(list(answers))
    local = interface_ips()
    if ip:
        return ip
    if len(local) == 1:
        return next(iter(local))
    return None


def wait_hint(ttl: int) -> str:
    t = max(ttl or 0, 60)
    return f"TTL записи — {t} с, обновление дойдёт примерно за {max(1, round(t / 60))} мин"


# ================================================================= инцидент ===

def _parse_iso(s: str | None) -> float:
    if not s:
        return 0.0
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return 0.0


def active_user_ids(online: set[int] | None = None) -> list[int]:
    """Одобренные не-админы: онлайн в VPN или действие в боте не позднее 10 минут назад."""
    online = online or set()
    res = []
    for u in db.execute("SELECT chat_id, last_online, last_seen_bot, blocked_bot FROM users "
                        "WHERE status='approved'"):
        if u["chat_id"] in ADMIN_IDS or u["blocked_bot"]:
            continue
        recent = max(_parse_iso(u["last_online"]), _parse_iso(u["last_seen_bot"]))
        if u["chat_id"] in online or time.time() - recent < ACTIVE_SEC:
            res.append(u["chat_id"])
    return res


def user_incident_text(kind: str) -> str:
    what = ("IP сервера заблокирован" if kind == "ip_blocked" else "Сервер сейчас недоступен")
    return (f"<h3>{em('incident')} {what}</h3>"
            f"<p>Администратор уже чинит, VPN скоро заработает. Сообщим, когда всё "
            f"восстановится.</p>")


def sos_kb():
    return kb([btn("Не работает VPN", "sos", icon="sos")])


def admin_kb():
    return kb([btn("Починил", "inc:fixed", style="success", icon="repaired")],
              [btn("Проверить сейчас", "inc:check", icon="refresh")],
              [btn("Админка", "adm", icon="back")])


async def open_incident(bot, result: dict, by_user: int | None = None):
    """Открыть инцидент (если ещё не открыт) со всеми уведомлениями. Возвращает строку БД."""
    inc = open_incident_row()
    if inc:
        return inc
    from .geo import location
    old_ip = location().get("ip") or ""
    try:
        dns = await asyncio.to_thread(resolve_all)
        dns_ip = dns_majority(dns) or ""
    except Exception:
        dns, dns_ip = {}, ""
    cur = await external_ip()
    if cur:
        old_ip = cur
    kind = result["status"] if result["status"] in ("ip_blocked", "server_down") else "server_down"
    db.execute("INSERT INTO incidents (kind, started_at, old_ip, dns_ip, protocols, details, "
               "last_check) VALUES (?, ?, ?, ?, ?, ?, ?)",
               (kind, time.time(), old_ip, dns_ip, json.dumps(bad_protocols(result)),
                json.dumps(result, ensure_ascii=False)[:20000], time.time()))
    db.commit()
    inc = open_incident_row()
    log.warning("incident #%s opened: %s, ip %s", inc["id"], kind, old_ip)

    ttl = max([r.get("ttl", 0) for r in dns.values()] or [0])
    who = " (сообщил пользователь)" if by_user else ""
    hint = ("Смени IP сервера у хостера и обнови A-запись "
            f"<code>{esc(VPN_HOST)}</code> — дальше я сам проверю и всем сообщу."
            if kind == "ip_blocked" else
            "Проверь, что сервер и контейнеры запущены. Если IP заблокирован — смени его и "
            f"обнови A-запись <code>{esc(VPN_HOST)}</code>, дальше я сам проверю и всем сообщу.")
    text = (f"<h2>{em('incident')} {STATUS_TEXT[kind].capitalize()}{who}</h2>"
            + kv([(f"{em('server')} IP сервера", f"<code>{esc(old_ip or '?')}</code>"),
                  (f"{em('dns')} A-запись", f"<code>{esc(dns_ip or '?')}</code>"),
                  (f"{em('clock')} TTL", f"{ttl} с" if ttl else "—")])
            + result_html(result)
            + f"<blockquote>{em('idea')} {hint}</blockquote>")
    for a in ADMIN_IDS:
        await notify(bot, a, text, admin_kb())

    online = set()
    try:
        from .traffic import online_users
        online = await asyncio.to_thread(online_users)
    except Exception as e:
        log.debug("online users: %s", e)
    for uid in active_user_ids(online):
        if add_notified(inc["id"], uid):
            await notify(bot, uid, user_incident_text(kind))
            await asyncio.sleep(0.05)
    return inc


async def close_incident(bot, inc, result: dict, new_ip: str | None) -> None:
    set_incident(inc["id"], closed_at=time.time())
    minutes = max(1, round((time.time() - inc["started_at"]) / 60))
    ip = new_ip or inc["old_ip"] or ""
    try:
        from .geo import refresh_location
        await asyncio.to_thread(refresh_location)
    except Exception as e:
        log.debug("refresh location: %s", e)
    changed = bool(new_ip and new_ip != inc["old_ip"])
    log.warning("incident #%s closed after %s min", inc["id"], minutes)
    details = [(f"{em('server')} IP", f"<code>{esc(ip)}</code>"),
               (f"{em('clock')} Простой", f"{minutes} мин")]
    if changed:
        details.insert(1, (f"{em('dns')} DNS", "обновлён"))
    text = (f"<h2>{em('health_ok')} Сервис снова доступен</h2>" + kv(details)
            + "<p>Проверка из РФ пройдена.</p>")
    for a in ADMIN_IDS:
        await notify(bot, a, text)
    rows = db.execute("SELECT chat_id FROM incident_notified WHERE incident_id=?",
                      (inc["id"],)).fetchall()
    for r in rows:
        if r["chat_id"] in ADMIN_IDS:
            continue
        await notify(bot, r["chat_id"],
                     f"<h3>{em('health_ok')} VPN снова работает</h3>"
                     f"<p>Если не подключается — переподключись или обнови подписку в "
                     f"приложении.</p>", sos_kb())
        await asyncio.sleep(0.05)


async def handle_result(bot, result: dict, by_user: int | None = None):
    """Открыть инцидент при ip_blocked / server_down; админу — о partial (не чаще раза в час)."""
    if result["status"] in ("ip_blocked", "server_down"):
        return await open_incident(bot, result, by_user)
    if result["status"] == "partial":
        await notify_partial(bot, result)
    return None


_partial_sent: dict[str, float] = {}


async def notify_partial(bot, result: dict) -> None:
    key = ",".join(bad_protocols(result))
    if not key or time.time() - _partial_sent.get(key, 0) < PARTIAL_NOTICE_SEC:
        return
    _partial_sent[key] = time.time()
    names = ", ".join(PROTO_TITLE.get(p, p) for p in bad_protocols(result))
    for a in ADMIN_IDS:
        await notify(bot, a, f"<h3>{em('incident')} Недоступна часть протоколов: {names}</h3>"
                             + result_html(result))


# ============================================================ фоновые задачи ===

async def health_loop(bot) -> None:
    """Фоновая проверка раз в ~7 минут. Плохой результат перепроверяется сразу же —
    инцидент открывается только при повторе (защита от сбоя узлов check-host)."""
    await asyncio.sleep(60)
    while True:
        try:
            if not open_incident_row() and targets():
                r = await check(force=True)
                if r["status"] in ("ip_blocked", "server_down"):
                    await asyncio.sleep(20)
                    r = await check(force=True)
                await handle_result(bot, r)
        except Exception as e:
            log.warning("health loop: %s", e)
        await asyncio.sleep(HEALTH_EVERY)


_watch_lock = asyncio.Lock()


async def watch_step(bot, force_check: bool = False) -> str:
    """Один шаг слежения за открытым инцидентом. Возвращает краткий статус для админа."""
    async with _watch_lock:
        inc = open_incident_row()
        if not inc:
            return "Инцидент уже закрыт."
        cur_ip = await external_ip()
        if cur_ip and cur_ip != inc["old_ip"] and cur_ip != inc["new_ip"]:
            set_incident(inc["id"], new_ip=cur_ip)
            dns = await asyncio.to_thread(resolve_all)
            ttl = max([r.get("ttl", 0) for r in dns.values()] or [0])
            for a in ADMIN_IDS:
                await notify(bot, a, f"<h3>{em('ip_change')} Вижу новый IP "
                                     f"<code>{esc(cur_ip)}</code></h3>"
                                     f"<p>Жду, когда A-запись <code>{esc(VPN_HOST)}</code> укажет "
                                     f"на него. {wait_hint(max(ttl, TTL_MIN_WAIT))}.</p>")
            inc = open_incident_row()

        dns = await asyncio.to_thread(resolve_all)
        dns_ip = dns_majority(dns)
        server_ip = cur_ip or inc["new_ip"] or inc["old_ip"]
        new_ip = inc["new_ip"]

        # A-запись сменили, а IP сервера тот же — ошибка в записи
        if dns_ip and server_ip and dns_ip != server_ip and dns_ip != inc["old_ip"] \
                and inc["wrong_dns"] != dns_ip:
            set_incident(inc["id"], wrong_dns=dns_ip)
            for a in ADMIN_IDS:
                await notify(bot, a, f"<h3>{em('warn')} A-запись указывает не туда</h3>"
                                     f"<p>A-запись <code>{esc(VPN_HOST)}</code> указывает на "
                                     f"<code>{esc(dns_ip)}</code>, а у сервера IP "
                                     f"<code>{esc(server_ip)}</code>.</p>")

        due = force_check or time.time() - (inc["last_check"] or 0) >= WATCH_RECHECK
        if new_ip:
            if not dns_updated(dns, new_ip):
                got = ", ".join(f"{RESOLVERS[s]}: {', '.join(r['ips']) or '—'}"
                                for s, r in dns.items())
                return f"Жду обновления DNS ({got})."
            if inc["notified_dns"] != new_ip:
                set_incident(inc["id"], notified_dns=new_ip)
                for a in ADMIN_IDS:
                    await notify(bot, a, f"<p>{em('dns')} DNS обновился: <code>{esc(VPN_HOST)}"
                                         f"</code> → <code>{esc(new_ip)}</code>. Проверяю "
                                         f"доступность из России…</p>")
                due = True
            if not due:
                return "DNS обновился, жду следующей проверки из РФ."
            set_incident(inc["id"], last_check=time.time())
            r = await check(force=True, host=new_ip)
            if r["status"] == "ok":
                await close_incident(bot, inc, r, new_ip)
                return "Инцидент закрыт."
            if inc["notified_bad_ip"] != new_ip and r["status"] in ("ip_blocked", "server_down"):
                set_incident(inc["id"], notified_bad_ip=new_ip)
                for a in ADMIN_IDS:
                    await notify(bot, a, f"<h3>{em('health_bad')} Новый IP <code>{esc(new_ip)}"
                                         f"</code> недоступен из РФ</h3>" + result_html(r),
                                 admin_kb())
            return f"Новый IP: {STATUS_TEXT.get(r['status'], r['status'])}."

        # IP не менялся: возможно, бан сняли или сервер поднялся
        if not due:
            return "Жду смены IP или следующей проверки."
        set_incident(inc["id"], last_check=time.time())
        r = await check(force=True)
        if r["status"] == "ok":
            await close_incident(bot, inc, r, None)
            return "Инцидент закрыт."
        return f"Проверка из РФ: {STATUS_TEXT.get(r['status'], r['status'])}."


async def incident_watch_loop(bot) -> None:
    while True:
        await asyncio.sleep(WATCH_EVERY)
        try:
            if open_incident_row():
                await watch_step(bot)
        except Exception as e:
            log.warning("incident watch: %s", e)


# ================================================================ middleware ===

async def incident_middleware(handler, event, data):
    """Во время инцидента — баннер над обычным экраном, один раз за инцидент."""
    try:
        user = data.get("event_from_user")
        inc = open_incident_row() if user else None
        if inc and user.id not in ADMIN_IDS and not was_notified(inc["id"], user.id):
            u = db.execute("SELECT status FROM users WHERE chat_id=?", (user.id,)).fetchone()
            if u and u["status"] == "approved":
                add_notified(inc["id"], user.id)
                await notify(data["bot"], user.id, user_incident_text(inc["kind"]))
    except Exception as e:
        log.debug("incident banner: %s", e)
    return await handler(event, data)

