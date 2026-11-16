"""Генерация конфигов и ссылок (без Docker): AWG, Xray, Hysteria2, подписка, HWID."""
import base64
import hashlib
import json
import re
import struct
import urllib.parse
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.protocols import awg, awg_install, hysteria, xray


# ===================================================================== AWG ===

def _server_conf():
    params = awg_install.generate_params()
    v = awg_install.script_vars(55424, params=params)
    priv, _ = awg.gen_keypair()
    return awg_install.render_server_conf(v, priv), params


def test_awg_params_like_app():
    p = awg_install.generate_params()
    assert 4 <= int(p["JUNK_PACKET_COUNT"]) <= 6
    assert (p["JUNK_PACKET_MIN_SIZE"], p["JUNK_PACKET_MAX_SIZE"]) == ("10", "50")
    for k in ("INIT", "RESPONSE", "COOKIE_REPLY", "TRANSPORT"):
        assert p[f"{k}_PACKET_JUNK_SIZE"] == "12"
    assert [p[f"{k}_PACKET_MAGIC_HEADER"] for k in ("INIT", "RESPONSE", "UNDERLOAD", "TRANSPORT")] \
        == ["1", "2", "3", "4"]
    assert len(base64.b64decode(p["HEADER_PROTECTION_KEY"])) == 32
    assert p["RANDOM_TRAILERS"] == p["DISABLE_COOKIES"] == "on"


def test_awg_server_conf_drops_empty_lines():
    text, _ = _server_conf()
    assert "Address = 10.8.1.0/24" in text and "ListenPort = 55424" in text
    assert "ContentPaddingAddition" not in text          # пустое — удалено, как sed в скрипте
    assert not any(line.lstrip("# ").startswith("I1 ") for line in text.splitlines())
    assert not any(re.match(r"^[^=]*= *$", line) for line in text.splitlines())


def test_awg_client_conf_and_key():
    text, params = _server_conf()
    info = awg.parse_server_conf(text, psk="psk")
    assert info["awg2"] and info["keepalive"] == "25-35"
    priv, pub = awg.gen_keypair()
    c = {"priv": priv, "pub": pub, "psk": "psk", "ip": "10.8.1.2"}
    conf = awg.client_conf(c, info)
    assert f"HeaderProtectionKey = {params['HEADER_PROTECTION_KEY']}" in conf
    assert "Endpoint = vpn.example.com:55424" in conf
    key = awg.amnezia_key(c, info)
    raw = base64.urlsafe_b64decode(key[6:] + "=" * (-len(key[6:]) % 4))
    n = struct.unpack(">I", raw[:4])[0]
    data = json.loads(zlib.decompress(raw[4:]))
    assert len(json.dumps(data, indent=4, sort_keys=True, ensure_ascii=False).encode()) == n
    a = data["containers"][0]["awg"]
    assert a["protocol_version"] == "3.1" and a["subnet_address"] == "10.8.1.0"
    assert json.loads(a["last_config"])["client_ip"] == "10.8.1.2"


def test_replace_vars_longest_first():
    assert awg_install.replace_vars("$AB $A", {"A": "1", "AB": "2"}) == "2 1"


# ==================================================================== Xray ===

def _xs(**kw):
    s = {"port": 443, "xhttp": True, "xhttp_port": 8443, "xhttp_path": "/abc", "sni": "ex.com",
         "block_ru": True, "api_port": 10085, "short_ids": ["aa11", "bb"]}
    s["private_key"], s["public_key"] = xray.x25519()
    s.update(kw)
    return s


USERS = [{"chat_id": 5, "uuid": "11111111-1111-4111-8111-111111111111"}]


def test_xray_config():
    cfg = xray.build_config(_xs(), USERS)
    vis, xh = cfg["inbounds"]
    assert vis["tag"] == xray.TAG_VISION and vis["settings"]["clients"][0] == {
        "id": USERS[0]["uuid"], "email": "u5", "flow": "xtls-rprx-vision"}
    assert "flow" not in xh["settings"]["clients"][0]
    assert xh["streamSettings"]["network"] == "xhttp"
    assert vis["streamSettings"]["realitySettings"]["target"] == "ex.com:443"
    assert cfg["api"]["listen"].startswith("127.0.0.1:")
    assert cfg["policy"]["levels"]["0"]["statsUserUplink"]
    rules = json.dumps(cfg["routing"])
    assert "bittorrent" in rules and "geoip:ru" in rules
    assert "geoip:ru" not in json.dumps(xray.build_config(_xs(block_ru=False), USERS)["routing"])
    assert len(xray.build_config(_xs(xhttp=False), USERS)["inbounds"]) == 1


def test_xray_keys_and_links():
    priv, pub = xray.x25519()
    assert len(base64.urlsafe_b64decode(priv + "=")) == 32
    s = _xs()
    links = xray.vless_links(s, USERS[0], "Мой VPN")
    u = urllib.parse.urlsplit(links[0])
    q = dict(urllib.parse.parse_qsl(u.query))
    assert u.scheme == "vless" and u.port == 443 and u.hostname == "vpn.example.com"
    assert q["security"] == "reality" and q["flow"] == "xtls-rprx-vision" and q["pbk"] == s["public_key"]
    assert q["sid"] == "aa11" and q["type"] == "tcp" and q["fp"] == "chrome"
    q2 = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(links[1]).query))
    assert q2["type"] == "xhttp" and q2["path"] == "/abc" and "flow" not in q2


def test_valid_domain():
    assert xray.valid_domain("https://Www.Example.com/x") == "www.example.com"
    assert xray.valid_domain("bad domain") is None and xray.valid_domain("localhost") is None


# =============================================================== Hysteria 2 ===

def _hs(**kw):
    s = {"port": 443, "obfs": True, "obfs_password": "op", "stats_secret": "sec", "stats_port": 1,
         "auth_port": 2, "self_signed": True, "block_ru": True, "domain": "vpn.example.com",
         "pin_sha256": "ab" * 32, "sni": "vpn.example.com"}
    s.update(kw)
    return s


def test_hysteria_config():
    cfg = hysteria.build_config(_hs())
    assert cfg["listen"] == ":443"
    assert cfg["auth"]["type"] == "http"
    assert cfg["auth"]["http"]["url"] == "http://127.0.0.1:2/hy2/auth"
    assert cfg["trafficStats"] == {"listen": "127.0.0.1:1", "secret": "sec"}
    assert cfg["obfs"]["type"] == "salamander" and cfg["congestion"]["type"] == "bbr"
    assert cfg["tls"]["cert"].startswith(hysteria.MOUNT)
    le = hysteria.build_config(_hs(self_signed=False, obfs=False, block_ru=False))
    assert le["tls"]["cert"] == f"{hysteria.CERTS_MOUNT}/live/vpn.example.com/fullchain.pem"
    assert "obfs" not in le and "acl" not in le


def test_hysteria_link():
    link = hysteria.hy2_link(_hs(), "p@ss", "VPN")
    u = urllib.parse.urlsplit(link)
    q = dict(urllib.parse.parse_qsl(u.query))
    assert u.scheme == "hysteria2" and urllib.parse.unquote(u.username) == "p@ss"
    assert q["obfs"] == "salamander" and q["obfs-password"] == "op"
    assert q["insecure"] == "1" and q["pinSHA256"] == "ab" * 32
    q2 = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(
        hysteria.hy2_link(_hs(self_signed=False), "x", "v")).query))
    assert "pinSHA256" not in q2 and "insecure" not in q2


def test_self_signed_pin():
    cert_pem, key_pem, pin = hysteria.self_signed("vpn.example.com")
    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)
    assert hashlib.sha256(der).hexdigest() == pin
    assert b"PRIVATE KEY" in key_pem


def test_hysteria_auth_check():
    from app import db
    db.set_user(901, name="h", status="approved")
    u = db.ensure_creds(901)
    assert hysteria.auth_check(u["hy2_pass"]) == "u901"
    assert hysteria.auth_check("wrong") is None
    db.set_user(901, status="revoked")
    assert hysteria.auth_check(u["hy2_pass"]) is None


# ========================================================= подписка и HWID ===

def test_hwid_headers():
    from app.sub_server import device_from_headers
    d = device_from_headers({"User-Agent": "Happ/3.2 (iOS)", "x-hwid": "H1", "x-device-os": "iOS",
                             "x-ver-os": "18.1", "x-device-model": "iPhone 15"})
    assert d == {"hwid": "H1", "known": True, "os": "iOS 18.1", "model": "iPhone 15",
                 "app": "Happ/3.2"}
    n = device_from_headers({"User-Agent": "Hiddify/2"})
    assert not n["known"] and n["hwid"].startswith("ua:")
    assert n == device_from_headers({"User-Agent": "Hiddify/2"})


def test_device_limit_and_notices():
    from app import db
    from app.sub_server import register_device, should_notify
    db.set_user(902, name="l", status="approved", max_devices=1)
    dev = {"hwid": "A", "os": "", "model": "", "app": "Happ"}
    assert register_device(902, dev) == "ok"
    assert register_device(902, dev) == "ok"                 # то же устройство
    assert register_device(902, dict(dev, hwid="B")) == "limit"
    assert should_notify(902, "B") and not should_notify(902, "B")


def test_subscription_response():
    import asyncio
    from aiohttp.test_utils import make_mocked_request
    from app import db, sub_server
    db.set_user(903, name="s", status="approved")
    u = db.ensure_creds(903)
    sub_server.build_sub = lambda user: ["vless://x@h:1#a", "hysteria2://y@h:2/#b"]
    req = make_mocked_request("GET", f"/sub/{u['sub_token']}", headers={"x-hwid": "Z"},
                              match_info={"token": u["sub_token"]})
    resp = asyncio.run(sub_server.sub_handler(req))
    assert resp.status == 200
    assert base64.b64decode(resp.text).decode().splitlines() == ["vless://x@h:1#a",
                                                                "hysteria2://y@h:2/#b"]
    assert resp.headers["profile-update-interval"] == "1"
    assert resp.headers["subscription-userinfo"].startswith("upload=")
    bad = make_mocked_request("GET", "/sub/" + "x" * 40, match_info={"token": "x" * 40})
    assert asyncio.run(sub_server.sub_handler(bad)).status == 404
