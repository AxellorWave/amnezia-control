"""«Списки сервисов»: подсети, форматы файлов, хранение выбора."""
import base64
import ipaddress
import json

from app import routes


def test_parse_list_mixed():
    d, c = routes.parse_list("# c\nyoutube.com\n*.ytimg.com\ndomain:googlevideo.com\n"
                             "full:yt.be\n91.108.4.0/22\n2001:67c:4e8::/48\nbad_entry\n")
    assert d == ["youtube.com", "ytimg.com", "googlevideo.com", "yt.be"]
    assert c == ["91.108.4.0/22", "2001:67c:4e8::/48"]


def test_complement_covers_everything_but_excluded():
    ex = ["10.0.0.0/8", "91.108.4.0/22", "149.154.160.0/20"]
    comp = routes.complement_v4(ex)
    total = sum(n.num_addresses for n in comp) + sum(
        ipaddress.ip_network(x).num_addresses for x in ex)
    assert total == 2 ** 32
    for n in comp:
        for x in ex:
            assert not n.overlaps(ipaddress.ip_network(x))


def test_aggregate_limits_size():
    many = [f"10.{i}.{j}.0/24" for i in range(4) for j in range(0, 256, 2)]
    out = routes.aggregate_v4(many, 50)
    assert len(out) <= 50
    for x in many:
        assert any(ipaddress.ip_network(x).subnet_of(n) for n in out)


def test_wg_allowed_ips_modes():
    data = {"domains": [], "zones": [], "cidrs": ["91.108.4.0/22"], "resolved": ["1.2.3.4/32"]}
    inc, n, sq = routes.wg_allowed_ips(data, "include")
    assert inc == "1.2.3.4/32, 91.108.4.0/22" and n == 2 and not sq
    exc, n2, _ = routes.wg_allowed_ips(data, "exclude")
    assert exc.endswith("::/0") and "0.0.0.0/0" not in exc and n2 > 10
    conf = "[Peer]\nPublicKey = x\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = h:1\n"
    assert "AllowedIPs = 1.2.3.4/32, 91.108.4.0/22\n" in routes.awg_conf(conf, inc)


def test_amnezia_json_format():
    data = {"domains": ["youtube.com"], "zones": ["ru"], "cidrs": ["91.108.4.0/22", "2001::/32"],
            "resolved": []}
    items = json.loads(routes.amnezia_json(data))
    assert items == [{"hostname": "youtube.com", "ip": ""}, {"hostname": "91.108.4.0/22", "ip": ""}]


def test_happ_profile_and_link():
    data = {"domains": ["youtube.com"], "zones": [], "cidrs": ["91.108.4.0/22"], "resolved": []}
    inc = routes.happ_profile(data, "include")
    assert inc["GlobalProxy"] == "false" and inc["ProxySites"] == ["domain:youtube.com"]
    assert inc["ProxyIp"] == ["91.108.4.0/22"] and inc["DirectSites"] == []
    exc = routes.happ_profile(data, "exclude")
    assert exc["GlobalProxy"] == "true" and exc["DirectSites"] == ["domain:youtube.com"]
    link = routes.happ_link(inc, "incy")
    assert link.startswith("incy://routing/onadd/")
    assert json.loads(base64.b64decode(link.split("/")[-1]))["Name"] == "VPN"


def test_singbox_and_xray_rules():
    data = {"domains": ["x.com"], "zones": ["ru"], "cidrs": ["1.0.0.0/24"], "resolved": []}
    sb = json.loads(routes.singbox_ruleset(data))
    assert sb["version"] == 2 and sb["rules"][0]["domain_suffix"] == ["x.com", "ru"]
    xr = json.loads(routes.xray_rules(data, "exclude"))
    assert xr["rules"][0]["outboundTag"] == "direct" and xr["rules"][-1]["outboundTag"] == "proxy"


def test_prefs_storage():
    uid = 424242
    assert routes.get_prefs(uid) == {"mode": "include", "services": []}
    routes.toggle(uid, "youtube")
    routes.toggle_topic(uid, "messengers")
    p = routes.set_mode(uid, "exclude")
    assert p["mode"] == "exclude" and "youtube" in p["services"] and "telegram" in p["services"]
    routes.toggle(uid, "youtube")
    routes.toggle_topic(uid, "messengers")
    assert routes.get_prefs(uid)["services"] == []


def test_catalog_consistency():
    keys = [k for _, _, ks in routes.TOPICS for k in ks]
    assert sorted(keys) == sorted(routes.SERVICES)
    data = routes.collect(["telegram", "ru_all"])
    assert "telegram.org" in data["domains"] and data["zones"] == ["ru", "xn--p1ai", "su"]


def _clean_overrides():
    routes.db.execute("DELETE FROM route_overrides")
    routes.db.commit()
    routes.apply_overrides()


def test_custom_service_add_edit_delete(monkeypatch):
    monkeypatch.setattr(routes, "_refresh_later", lambda key: None)
    _clean_overrides()
    key = routes.add_custom("Мой сервис", "games", "example.com\n203.0.113.10, 198.51.100.0/24")
    assert routes.is_custom(key) and key in routes.TOPIC_OF and routes.TOPIC_OF[key] == "games"
    e = routes.get_service(key)
    assert "example.com" in e["domains"]
    assert "203.0.113.10/32" in e["cidrs"] and "198.51.100.0/24" in e["cidrs"]
    assert routes.add_entries(key, "example.org example.com") == (1, 0)
    assert "example.org" in routes.get_service(key)["domains"]
    routes.remove_entries(key, "203.0.113.10")
    assert "203.0.113.10/32" not in routes.get_service(key)["cidrs"]
    data = routes.collect([key])
    assert "example.org" in data["domains"] and "198.51.100.0/24" in data["cidrs"]
    routes.delete_service(key)
    assert key not in routes.SERVICES and key not in routes.TOPIC_OF
    assert all(key not in ks for _, _, ks in routes.TOPICS)


def test_builtin_service_extras_hide_restore(monkeypatch):
    monkeypatch.setattr(routes, "_refresh_later", lambda key: None)
    _clean_overrides()
    routes.add_entries("youtube", "my-yt-mirror.example 192.0.2.0/24")
    e = routes.get_service("youtube")
    assert "my-yt-mirror.example" in e["domains"] and "192.0.2.0/24" in e["cidrs"]
    routes.remove_entries("youtube", "youtube.com")
    assert "youtube.com" not in routes.get_service("youtube")["domains"]
    routes.reset_service("youtube")
    assert "youtube.com" in routes.get_service("youtube")["domains"]
    assert "my-yt-mirror.example" not in routes.get_service("youtube")["domains"]
    routes.delete_service("youtube")
    assert "youtube" not in routes.SERVICES and routes.hidden_services() == ["youtube"]
    routes.save_prefs(555, "include", ["youtube", "telegram"])
    assert routes.get_prefs(555)["services"] == ["telegram"]
    routes.restore_service("youtube")
    assert "youtube" in routes.SERVICES and routes.TOPIC_OF["youtube"] == "video"
    _clean_overrides()


def test_add_custom_rejects_empty(monkeypatch):
    monkeypatch.setattr(routes, "_refresh_later", lambda key: None)
    import pytest
    with pytest.raises(ValueError):
        routes.add_custom("X", "games", "просто текст")
    with pytest.raises(ValueError):
        routes.add_custom("  ", "games", "example.com")


def test_shared_cdn_domains_filtered_from_sources(monkeypatch, tmp_path):
    assert routes.is_shared("google.com") and routes.is_shared("d1.cloudfront.net")
    assert not routes.is_shared("claude.ai") and not routes.is_shared("notgoogle.com")
    monkeypatch.setattr(routes, "cache_dir", lambda: str(tmp_path))
    monkeypatch.setattr(routes, "fetch", lambda url: "claude.ai\napi.anthropic.com\n"
                                                     "google.com\nx.amazonaws.com\n")
    e = routes.refresh_service("claude", do_resolve=False)
    assert "claude.ai" in e["domains"] and "api.anthropic.com" in e["domains"]
    assert "google.com" not in e["domains"] and "x.amazonaws.com" not in e["domains"]
    with routes._lock:
        routes._mem.pop("claude", None)


def test_every_topic_service_exists():
    for _, _, keys in routes.TOPICS:
        for k in keys:
            assert routes.SERVICES[k]["title"]
