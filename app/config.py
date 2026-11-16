"""Настройки из окружения (.env)."""
import os

from dotenv import load_dotenv

load_dotenv()


def _flag(name: str, default: str = "1") -> bool:
    return os.getenv(name, default).strip().lower() not in ("0", "false", "no", "off", "")


BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = {int(x) for x in os.environ["ADMIN_IDS"].split(",") if x.strip()}
VPN_HOST = os.environ["VPN_HOST"]
SERVER_NAME = os.getenv("SERVER_NAME", "").strip() or "vpn"   # имя сервера в AmneziaVPN

DNS1 = os.getenv("DNS1", "1.1.1.1")
DNS2 = os.getenv("DNS2", "1.0.0.1")
MTU = os.getenv("MTU", "1280")
KEEPALIVE = os.getenv("KEEPALIVE", "")          # пусто = как в приложении (25-35 для AWG 2)
MAX_DEVICES = int(os.getenv("MAX_DEVICES", "5"))
DB_PATH = os.getenv("DB_PATH", "bot.db")
DATA_DIR = os.path.dirname(os.path.abspath(DB_PATH))
# локальная база стран по IP (DB-IP Lite, CC BY 4.0, https://db-ip.com) — бот скачивает сам
GEOIP_DB = os.getenv("GEOIP_DB") or os.path.join(DATA_DIR, "dbip-country-lite.mmdb")
CUSTOM_EMOJI = _flag("CUSTOM_EMOJI")

ANDROID_URL = "https://play.google.com/store/apps/details?id=org.amnezia.vpn"
IOS_URL = "https://apps.apple.com/app/defaultvpn/id6744725017"
DESKTOP_URL = "https://github.com/amnezia-vpn/amnezia-client/releases/latest"
DESKTOP_SITE_URL = "https://amnezia.org/ru/downloads"

ONLINE_SEC = 180

# сервер подписок (HTTP(S) в том же процессе) и auth-хук Hysteria2 (только 127.0.0.1)
SUB_HOST = os.getenv("SUB_HOST", "").strip() or VPN_HOST
SUB_PORT = int(os.getenv("SUB_PORT", "2096"))
SUB_LISTEN = os.getenv("SUB_LISTEN", "0.0.0.0").strip()
HY2_AUTH_PORT = int(os.getenv("HY2_AUTH_PORT", "18081"))
HWID_REQUIRED = _flag("HWID_REQUIRED", "0")
# резервные копии: полная копия админам раз в N дней (0 — выключено), хранить последние N
BACKUP_EVERY_DAYS = float(os.getenv("BACKUP_EVERY_DAYS", "0") or 0)
BACKUP_KEEP = int(os.getenv("BACKUP_KEEP", "7"))
