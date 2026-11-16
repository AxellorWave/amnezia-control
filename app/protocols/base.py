"""Общий интерфейс протокола."""


class Protocol:
    id: str = ""                  # "awg" | "xray" | "hy2"
    title: str = ""
    short: str = ""               # короткое имя для подтверждения удаления (AWG, VLESS, HY2)
    icon: str = "vpn"             # роль из EMOJI
    per_device: bool = False      # AWG — конфиг на устройство; Xray/Hy2 — на пользователя

    def detect(self) -> dict | None:
        """Что найдено на сервере: container, origin ("amnezia"|"bot"), state, ports, version."""
        raise NotImplementedError

    def status(self) -> dict:
        """installed, running, ports, clients."""
        raise NotImplementedError

    def install(self, params: dict, progress) -> None:
        raise NotImplementedError

    def uninstall(self, progress, remove_data: bool = False) -> None:
        raise NotImplementedError

    def restart(self) -> None:
        raise NotImplementedError

    def add_client(self, owner) -> dict:
        raise NotImplementedError

    def remove_client(self, owner) -> None:
        raise NotImplementedError

    def stats(self) -> dict[str, dict]:
        """client_id -> {rx, tx, online, last_seen}"""
        return {}

    def links(self, user) -> list[str]:
        """URI для подписки (у AWG — нет)."""
        return []
