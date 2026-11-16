"""Права и лимиты."""
from .config import ADMIN_IDS, MAX_DEVICES
from .db import get_device, get_user


def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS


def has_access(uid: int) -> bool:
    if is_admin(uid):
        return True
    u = get_user(uid)
    return bool(u and u["status"] == "approved")


def device_limit(uid: int) -> int | None:
    """Лимит устройств: личный, если задан, иначе MAX_DEVICES; у админов — без лимита (None)."""
    if is_admin(uid):
        return None
    u = get_user(uid)
    return u["max_devices"] if u and u["max_devices"] is not None else MAX_DEVICES


def own_device(uid: int, dev_id: int):
    d = get_device(dev_id)
    return d if d and (d["chat_id"] == uid or is_admin(uid)) else None
