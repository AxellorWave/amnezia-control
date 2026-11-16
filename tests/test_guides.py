"""Инструкции: все экраны рендерятся, влезают в сообщение, кнопки ведут на существующие колбэки."""
import os
import re

from app import guides
from app.ui import rich_to_plain

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTERNAL = {"routes"}          # раздел «Списки сервисов» — отдельный модуль


def _handlers_src() -> str:
    out = []
    base = os.path.join(ROOT, "app", "handlers")
    for f in os.listdir(base):
        if f.endswith(".py"):
            with open(os.path.join(base, f), encoding="utf-8") as fh:
                out.append(fh.read())
    return "\n".join(out)


def _callback_matchers():
    src = _handlers_src()
    exact = set(re.findall(r'F\.data\s*==\s*"([^"]+)"', src))
    prefixes = set(re.findall(r'F\.data\.startswith\(\s*"([^"]+)"', src))
    for group in re.findall(r"F\.data\.in_\(\{([^}]*)\}\)", src):
        exact |= set(re.findall(r'"([^"]+)"', group))
    return exact, prefixes


def _screens():
    yield guides.sub_index()
    yield guides.sub_split_index()
    yield guides.awg_split_index()
    for k in guides.SUB_CLIENTS:
        yield guides.sub_guide(k)
        yield guides.sub_split(k)
    for k in guides.AWG_SPLIT_KEYS:
        yield guides.awg_split(k)


def test_all_render_and_fit():
    for text, markup in _screens():
        assert text.strip()
        assert len(rich_to_plain(text)) < 4000, text[:80]
        assert markup.inline_keyboard


def test_callbacks_exist():
    exact, prefixes = _callback_matchers()
    for _, markup in _screens():
        for row in markup.inline_keyboard:
            for b in row:
                if b.url:
                    assert b.url.startswith("https://"), b.url
                    continue
                data = b.callback_data
                if data in EXTERNAL:
                    continue
                assert data in exact or any(data.startswith(p) for p in prefixes), data


def test_required_clients():
    assert {"happ", "incy"} <= set(guides.SUB_CLIENTS)
    for c in guides.SUB_CLIENTS.values():
        assert c["split"] and c["links"]


def test_incy_deeplink_registered():
    from app.sub_server import APPS
    assert "incy" in APPS and APPS["incy"][1].startswith("incy://")
