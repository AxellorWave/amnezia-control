"""Словарь EMOJI: формат id, все используемые имена существуют, новые роли — из каталога."""
import json
import os
import re

from app.ui import CATALOG_ROLES, EMOJI

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sources():
    for base, _, files in os.walk(os.path.join(ROOT, "app")):
        for f in files:
            if f.endswith(".py"):
                with open(os.path.join(base, f), encoding="utf-8") as fh:
                    yield f, fh.read()


def test_ids_are_digit_strings():
    for name, (plain, cid) in EMOJI.items():
        assert plain, name
        assert cid is None or cid == "" or (isinstance(cid, str) and cid.isdigit()), name


def test_used_names_exist():
    used = set()
    for _, src in _sources():
        used |= set(re.findall(r"""\bem\(\s*["'](\w+)["']\s*\)""", src))
        used |= set(re.findall(r"""icon\s*=\s*["'](\w+)["']""", src))
    missing = used - set(EMOJI)
    assert not missing, f"нет в EMOJI: {sorted(missing)}"


def test_no_hardcoded_tg_emoji():
    for f, src in _sources():
        if f == "ui.py":
            continue
        assert "<tg-emoji" not in src, f
        assert not re.search(r"emoji-id=\"\d", src), f


def test_catalog_roles_match_profile():
    with open(os.path.join(ROOT, "emoji-style.json"), encoding="utf-8") as fh:
        prof = json.load(fh)
    assert prof["primary_pack"] == "sfsymbols"
    for role in CATALOG_ROLES:
        assert role in EMOJI, role
        assert prof["roles"][role]["id"] == EMOJI[role][1], role


def test_catalog_ids_in_catalog():
    """Если рядом есть клон каталога (EMOJI_CATALOG=путь к emoji-ids.txt) — сверить id."""
    path = os.getenv("EMOJI_CATALOG")
    if not path or not os.path.exists(path):
        import pytest
        pytest.skip("EMOJI_CATALOG не задан")
    with open(path, encoding="utf-8") as fh:
        ids = set(re.findall(r"\b(\d{15,20})\b", fh.read()))
    for role in CATALOG_ROLES:
        assert EMOJI[role][1] in ids, role
