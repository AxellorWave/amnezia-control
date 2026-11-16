"""Снимок файлов конфигурации сервера перед каждой записью: data/backups/<proto>/<ts>/."""
import logging
import os
import shutil
import time

from .config import DATA_DIR

log = logging.getLogger("amnezia-bot")
KEEP_SNAPSHOTS = 50


def snapshot(proto: str, files: dict[str, str | bytes]) -> str | None:
    if not files:
        return None
    base = os.path.join(DATA_DIR, "backups", proto)
    path = os.path.join(base, time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}")
    try:
        os.makedirs(path, exist_ok=True)
        for name, content in files.items():
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(os.path.join(path, os.path.basename(name)), mode) as f:
                f.write(content)
        olds = sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)))
        for d in olds[:-KEEP_SNAPSHOTS]:
            shutil.rmtree(os.path.join(base, d), ignore_errors=True)
        return path
    except OSError as e:
        log.warning("snapshot %s failed: %s", proto, e)
        return None
