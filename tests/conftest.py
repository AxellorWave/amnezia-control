import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_tmp = tempfile.mkdtemp(prefix="vpnbot-test-")
os.environ.setdefault("BOT_TOKEN", "1:test")
os.environ.setdefault("ADMIN_IDS", "1")
os.environ.setdefault("VPN_HOST", "vpn.example.com")
os.environ["DB_PATH"] = os.path.join(_tmp, "bot.db")
os.environ.setdefault("HOST_DATA_DIR", _tmp)
