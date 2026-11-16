"""Блокировка IP через cheburcheck.ru: разбор ответа и уведомления о смене состояния."""
import time

from app import blockcheck as B


def test_parse():
    r = B.parse({"blocked": True, "blocked_subnets": ["1.2.3.0/24"],
                 "cdn_providers": {"cloudflare": []}, "ips": ["1.2.3.4"]})
    assert r["blocked"] and r["subnets"] == ["1.2.3.0/24"] and r["cdn"] == ["cloudflare"]
    assert B.parse({"blocked": False})["blocked"] is False


def test_changes_notify_only_on_switch():
    t = "203.0.113.77"
    B.db.execute("DELETE FROM block_checks WHERE target=?", (t,))
    item = lambda b: {"ts": time.time(), "items": [{"target": t, "blocked": b, "error": ""}]}
    assert B.changes(item(False)) == []          # первая проверка, всё чисто — молчим
    assert B.changes(item(False)) == []
    assert len(B.changes(item(True))) == 1       # попал в списки
    assert B.changes(item(True)) == []
    assert len(B.changes(item(False))) == 1      # убрали из списков
    assert B.changes({"ts": 0, "items": [{"target": t, "blocked": None, "error": "x"}]}) == []


def test_result_html():
    assert "Проверок ещё не было" in B.result_html(None)
    html = B.result_html({"ts": time.time(), "items": [
        {"target": "203.0.113.77", "blocked": True, "subnets": [], "cdn": [], "ips": [],
         "error": ""}]})
    assert "в списках блокировок" in html
