"""Рассылки: сводка черновика, альбомы, группы получателей, очередь."""
import json
import time
from datetime import datetime, timedelta

from app import broadcast as B
from app.db import db, set_user


def _add(bc_id, kind, msg_id, group=None, text=""):
    meta = {"kind": kind, "file_id": "f" if kind != "text" else None, "text": text,
            "entities": [], "html": "", "custom": False}
    db.execute("INSERT INTO bc_items (bc_id, chat_id, message_id, media_group_id, kind, meta) "
               "VALUES (?, 1, ?, ?, ?, ?)", (bc_id, msg_id, group, kind, json.dumps(meta)))
    db.commit()


def test_summary_and_albums():
    bc = B.create("mass", 1)
    _add(bc, "text", 1, text="hi")
    _add(bc, "photo", 2, "g1")
    _add(bc, "photo", 3, "g1")
    _add(bc, "photo", 4, "g1")
    _add(bc, "sticker", 5)
    _add(bc, "text", 6)
    us = B.units(B.items(bc))
    assert [len(u) for u in us] == [1, 3, 1, 1]
    assert B.draft_summary(B.items(bc)) == "2 текста, 3 фото (альбом), 1 стикер"
    assert B.remove_last_unit(bc)
    assert B.remove_last_unit(bc)
    assert B.draft_summary(B.items(bc)) == "1 текст, 3 фото (альбом)"
    assert B.remove_last_unit(bc)          # убирает весь альбом
    assert B.draft_summary(B.items(bc)) == "1 текст"


def test_recipient_groups():
    iso = lambda days: (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    set_user(101, status="approved", last_seen_bot=iso(0.1))
    set_user(102, status="approved", last_online=iso(3))
    set_user(103, status="approved", last_online=iso(40))
    set_user(104, status="pending")
    set_user(105, status="approved", blocked_bot=1, last_seen_bot=iso(0.1))
    set_user(106, status="approved", sub_token="t", uuid="u")
    db.execute("INSERT INTO devices (chat_id, name, pub) VALUES (103, 'pc', 'k')")
    db.commit()
    assert {101} <= set(B.recipients("a24")) and 102 not in B.recipients("a24")
    assert {101, 102} <= set(B.recipients("a7"))
    assert 103 in B.recipients("inactive") and 102 not in B.recipients("inactive")
    assert 103 in B.recipients("awg")
    assert B.recipients("sub") == [106] or 106 in B.recipients("sub")
    assert 104 in B.recipients("pending")
    assert 105 not in B.recipients("all")
    assert B.recipients("manual", [5, 5, 3]) == [3, 5]
    assert B.recipients("online", online={101, 104}) == [101]
    assert B.recipients("admins") == [1]


def test_queue_resume_state():
    bc = B.create("mass", 1)
    assert B.enqueue(bc, [11, 12, 13]) == 3
    db.execute("UPDATE bc_queue SET status='sent' WHERE bc_id=? AND chat_id=11", (bc,))
    db.commit()
    B.set_status(bc, "sending")
    c = B.counts(bc)
    assert c["sent"] == 1 and c["pending"] == 2
    assert B.get(bc)["total"] == 3
    # после «перезапуска» продолжаем с первого неотправленного
    row = db.execute("SELECT chat_id FROM bc_queue WHERE bc_id=? AND status='pending' "
                     "ORDER BY rowid LIMIT 1", (bc,)).fetchone()
    assert row["chat_id"] == 12
    assert bc in [r["id"] for r in db.execute("SELECT id FROM broadcasts WHERE status='sending'")]


def test_parse_msk_future():
    ts = B.parse_msk("23:59")
    assert ts is None or ts > time.time()
    assert B.parse_msk("01.01.2000 10:00") is None
    assert B.parse_msk("ерунда") is None


def test_link_markup():
    assert B.link_markup({}) is None
    mk = B.link_markup({"link": {"text": "Канал", "url": "https://t.me/x"}})
    assert mk.inline_keyboard[0][0].url == "https://t.me/x"
    mk = B.link_markup({"link": {"text": "Подписка", "section": "sub"}})
    assert mk.inline_keyboard[0][0].callback_data == "sub"
