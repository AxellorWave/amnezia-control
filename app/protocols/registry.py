"""Протоколы подписки (по пользователю): Xray и Hysteria2."""
from .hysteria import HY2
from .xray import XRAY

SUB_PROTOCOLS = {"xray": XRAY, "hy2": HY2}
TITLES = {"awg": "AmneziaWG", "xray": "VLESS (Xray)", "hy2": "Hysteria 2"}
