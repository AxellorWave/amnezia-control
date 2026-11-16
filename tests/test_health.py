"""Мониторинг: классификация результатов, DNS-пакеты, выбор IP, кэш проверки."""
import asyncio
import struct
import time

from app import health


def test_node_status():
    assert health.node_status("tcp", [{"address": "1.1.1.1", "time": 0.01}]) == "ok"
    assert health.node_status("tcp", [{"error": "Connection timed out"}]) == "fail"
    assert health.node_status("tcp", None) == "unknown"
    assert health.node_status("tcp", [None]) == "unknown"
    assert health.node_status("udp", [{"address": "1.1.1.1", "timeout": 1}]) == "noreply"
    assert health.node_status("tcp", [{"address": "1.1.1.1", "timeout": 1}]) == "fail"


def test_target_state():
    ts = health.target_state
    assert ts(["ok", "fail"], ["ok"]) == "ok"
    assert ts(["fail", "fail"], ["ok", "fail"]) == "blocked"
    assert ts(["fail", "unknown"], ["fail", "fail"]) == "down"
    assert ts(["noreply", "noreply"], ["noreply"]) == "unknown"
    assert ts(["unknown"], ["ok"]) == "unknown"
    assert ts(["fail"], ["unknown"]) == "unknown"


def test_classify():
    c = health.classify
    assert c([{"pid": "xray", "state": "ok"}, {"pid": "sub", "state": "ok"}]) == "ok"
    assert c([{"pid": "xray", "state": "blocked"}, {"pid": "sub", "state": "blocked"}]) == "ip_blocked"
    assert c([{"pid": "xray", "state": "down"}, {"pid": "awg", "state": "unknown"}]) == "server_down"
    assert c([{"pid": "xray", "state": "ok"}, {"pid": "hy2", "state": "blocked"}]) == "partial"
    assert c([{"pid": "awg", "state": "unknown"}]) == "unknown"
    assert c([]) == "unknown"


def _answer(qid, name, ips, ttl=600, rcode=0):
    q = health.build_query(name, qid)
    hdr = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(ips), 0, 0)
    body = q[12:]
    for ip in ips:
        body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4) + bytes(map(int, ip.split(".")))
    return hdr + body


def test_dns_build_and_parse():
    q = health.build_query("vpn.example.com", 0x1234)
    assert q[:2] == b"\x12\x34" and b"\x03vpn\x07example\x03com\x00" in q
    ips, ttl = health.parse_response(_answer(0x1234, "vpn.example.com", ["1.2.3.4", "5.6.7.8"], 300),
                                     0x1234)
    assert ips == ["1.2.3.4", "5.6.7.8"] and ttl == 300
    # CNAME перед A-записью
    qid = 7
    q = health.build_query("a.example.com", qid)
    cname = b"\x03b\x07example\x03com\x00"
    body = q[12:] + b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(cname)) + cname
    body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 120, 4) + bytes([9, 9, 9, 9])
    data = struct.pack(">HHHHHH", qid, 0x8180, 1, 2, 0, 0) + body
    assert health.parse_response(data, qid) == (["9.9.9.9"], 120)
    try:
        health.parse_response(_answer(1, "x.com", []), 2)
        assert False
    except ValueError:
        pass


def test_majorities():
    assert health.majority_ip(["1.1.1.1", "1.1.1.1", "2.2.2.2"]) == "1.1.1.1"
    assert health.majority_ip(["1.1.1.1", None, "2.2.2.2"]) is None
    res = {"8.8.8.8": {"ips": ["5.5.5.5"]}, "1.1.1.1": {"ips": ["5.5.5.5"]},
           "77.88.8.8": {"ips": ["4.4.4.4"]}}
    assert health.dns_majority(res) == "5.5.5.5"
    assert not health.dns_updated(res, "5.5.5.5")          # Яндекс ещё отдаёт старый
    res["77.88.8.8"]["ips"] = ["5.5.5.5"]
    assert health.dns_updated(res, "5.5.5.5")
    assert health.dns_majority({"a": {"ips": ["1.1.1.1"]}, "b": {"ips": []}, "c": {"ips": []}}) is None


def test_check_cache(monkeypatch):
    calls = []

    async def fake(host):
        calls.append(host)
        await asyncio.sleep(0.05)
        return {"ts": time.time(), "host": host, "status": "ok", "items": [], "error": ""}

    monkeypatch.setattr(health, "_do_check", fake)
    health._cache.update(ts=0.0, result=None)

    async def many():
        return await asyncio.gather(*(health.check() for _ in range(10)))

    res = asyncio.run(many())
    assert len(calls) == 1 and all(r["status"] == "ok" for r in res)
    asyncio.run(health.check())
    assert len(calls) == 1
    asyncio.run(health.check(force=True))
    assert len(calls) == 2
    health._cache["ts"] = time.time() - health.CACHE_SEC - 1
    asyncio.run(health.check())
    assert len(calls) == 3


def test_active_users():
    from app.db import db, set_user, now
    set_user(501, name="A", status="approved")
    db.execute("UPDATE users SET last_seen_bot=? WHERE chat_id=501", (now(),))
    set_user(502, name="B", status="approved")
    db.execute("UPDATE users SET last_seen_bot='2020-01-01T00:00:00' WHERE chat_id=502")
    set_user(503, name="C", status="approved")
    db.commit()
    ids = health.active_user_ids({503})
    assert 501 in ids and 503 in ids and 502 not in ids


def test_targets_skip_subscription_without_sub_protocols(monkeypatch):
    awg = {"ports": [("udp", 33667)]}
    xray = {"ports": [("tcp", 443)]}
    entries = {"awg": awg}
    monkeypatch.setattr(health.detect, "get", lambda pid: entries.get(pid))
    monkeypatch.setattr(health.detect, "sub_protocols",
                        lambda: [p for p in ("xray", "hy2") if p in entries])
    assert [t["pid"] for t in health.targets()] == ["awg"]
    entries["xray"] = xray
    assert [t["pid"] for t in health.targets()] == ["awg", "xray", "sub"]


def test_awg_handshake_marks_ok(monkeypatch):
    items = [{"pid": "awg", "proto": "udp", "port": 33667, "state": "unknown"}]
    monkeypatch.setattr(health, "last_awg_handshake", lambda: time.time() - 60)
    asyncio.run(health.apply_awg_handshakes(items))
    assert items[0]["state"] == "ok" and items[0]["handshake"]
    assert health.classify(items) == "ok"


def test_awg_without_fresh_handshake_stays_unknown(monkeypatch):
    items = [{"pid": "awg", "proto": "udp", "port": 33667, "state": "unknown"}]
    monkeypatch.setattr(health, "last_awg_handshake", lambda: time.time() - 3600)
    asyncio.run(health.apply_awg_handshakes(items))
    assert items[0]["state"] == "unknown"
    monkeypatch.setattr(health, "last_awg_handshake", lambda: 0)
    asyncio.run(health.apply_awg_handshakes(items))
    assert items[0]["state"] == "unknown"
