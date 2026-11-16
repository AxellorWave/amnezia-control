"""Онлайн по протоколам подписки: кто в сети, сколько подключений, когда был."""
from app import traffic as T
from app.protocols import registry


def test_account_sub_traffic_tracks_online_and_last_seen(monkeypatch):
    monkeypatch.setattr(registry.SUB_PROTOCOLS["hy2"], "stats",
                        lambda: {9001: {"rx": 10, "tx": 20, "online": True, "conns": 3},
                                 9002: {"rx": 5, "tx": 0, "online": False}})
    monkeypatch.setattr(registry.SUB_PROTOCOLS["xray"], "stats", lambda: {})
    T.account_sub_traffic()
    assert T.ONLINE_NOW["hy2"] == {9001}
    assert T.ONLINE_CONNS["hy2"] == {9001: 3}
    seen = T.proto_last_seen("hy2")
    assert 9001 in seen and 9002 not in seen
    assert T.proto_traffic(9001, "hy2") == (10, 20)
