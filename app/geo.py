"""Страна сервера по IP из локальной базы DB-IP Lite (.mmdb). База скачивается
при старте, если её нет или она старше месяца; обновляется раз в сутки в фоне."""
import asyncio
import gzip
import ipaddress
import logging
import os
import socket
import time
import urllib.request
from datetime import date

import maxminddb

from .config import GEOIP_DB, VPN_HOST
from .ui import esc

log = logging.getLogger("amnezia-bot")

GEOIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{}.mmdb.gz"
GEO_REFRESH = 600              # как часто перепроверять IP сервера, сек
_geo_reader = None
_location = {"ip": VPN_HOST, "code": "", "country": "", "ts": 0.0}


def server_ip() -> str:
    """Текущий публичный IP сервера: VPN_HOST, а если это домен — его A-запись."""
    try:
        ipaddress.ip_address(VPN_HOST)
        return VPN_HOST
    except ValueError:
        pass
    try:
        return socket.gethostbyname(VPN_HOST)
    except OSError:
        return VPN_HOST


def geoip_update(force: bool = False) -> None:
    """Скачать свежую базу DB-IP, если файла нет или он старше 30 дней."""
    global _geo_reader
    try:
        if not force and time.time() - os.path.getmtime(GEOIP_DB) < 30 * 86400:
            return
    except OSError:
        pass
    today = date.today()
    prev = date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1)
    for d in (today, prev):           # в начале месяца свежей базы может ещё не быть
        url = GEOIP_URL.format(d.strftime("%Y-%m"))
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "amnezia-control-bot/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = gzip.decompress(resp.read())
            tmp = GEOIP_DB + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, GEOIP_DB)
            _geo_reader = None        # переоткрыть с новым файлом
            log.info("GeoIP: база обновлена (%s)", url)
            return
        except Exception as e:
            log.warning("GeoIP: не удалось скачать %s: %s", url, e)


def geo_reader():
    global _geo_reader
    if _geo_reader is None and os.path.exists(GEOIP_DB):
        try:
            _geo_reader = maxminddb.open_database(GEOIP_DB)
        except Exception as e:
            log.warning("GeoIP: не удалось открыть базу: %s", e)
    return _geo_reader


def ip_country(ip: str) -> tuple[str, str]:
    """(ISO-код, название по-русски) или ("", "")."""
    try:
        rec = (geo_reader() or {}).get(ip) or {}
    except Exception:
        return "", ""
    c = rec.get("country") or {}
    names = c.get("names") or {}
    return c.get("iso_code", ""), names.get("ru") or names.get("en", "")


def flag(code: str) -> str:
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in code.upper()) if len(code) == 2 else ""


def refresh_location() -> dict:
    ip = server_ip()
    code, country = ip_country(ip)
    _location.update(ip=ip, code=code, country=country, ts=time.time())
    return _location


def location() -> dict:
    return _location


def server_location_html() -> str:
    """«🇩🇪 Германия · 1.2.3.4» — из кэша (обновляется в фоне), без блокировок."""
    loc = _location
    ip = f"<code>{esc(loc['ip'])}</code>"
    if not loc["country"]:
        return ip
    return f"{flag(loc['code'])} {esc(loc['country'])} · {ip}"


async def geo_loop() -> None:
    """Фон: IP сервера — каждые 10 минут, база стран — раз в сутки проверить возраст."""
    last_db = 0.0
    while True:
        try:
            if time.time() - last_db > 86400:
                await asyncio.to_thread(geoip_update)
                last_db = time.time()
            await asyncio.to_thread(refresh_location)
        except Exception as e:
            log.warning("geo refresh failed: %s", e)
        await asyncio.sleep(GEO_REFRESH)
