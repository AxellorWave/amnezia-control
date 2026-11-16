"""Архивы резервных копий: manifest, хеши, защита от опасных путей (без Docker)."""
import io
import json
import os
import tarfile

import pytest

from app import backup


def _files():
    return {"awg0.conf": b"[Interface]\nAddress = 10.8.1.0/24\nListenPort = 55424\n",
            "clientsTable": b"[]", "container.json": b'{"port": 55424}'}


def test_build_and_verify(tmp_path):
    path = str(tmp_path / "a.tar.gz")
    m = backup.build_archive(path, "awg", _files(), {"origin": "bot", "ports": [["udp", 55424]]})
    got = backup.verify_archive(path)
    assert got["type"] == "awg" and got["format_version"] == backup.FORMAT_VERSION
    assert got["files"] == m["files"] and got["ports"] == [["udp", 55424]]
    out = tmp_path / "x"
    backup.safe_extract(path, str(out))
    assert (out / "awg0.conf").read_bytes() == _files()["awg0.conf"]
    assert json.loads((out / "manifest.json").read_text())["type"] == "awg"


def _raw_archive(path, manifest: dict, members: list[tarfile.TarInfo], datas: list[bytes]):
    with tarfile.open(path, "w:gz") as tar:
        raw = json.dumps(manifest).encode()
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(raw)
        tar.addfile(ti, io.BytesIO(raw))
        for ti, data in zip(members, datas):
            tar.addfile(ti, io.BytesIO(data) if ti.isfile() else None)


def _manifest(files: dict, **kw):
    return {"type": "awg", "format_version": 1, "bot_version": "2.0", "created": "2026-01-01",
            "files": {k: backup.sha256(v) for k, v in files.items()}, **kw}


def test_tampered_hash_rejected(tmp_path):
    path = str(tmp_path / "t.tar.gz")
    files = {"awg0.conf": b"real"}
    m = _manifest(files)
    ti = tarfile.TarInfo("awg0.conf")
    ti.size = 4
    _raw_archive(path, m, [ti], [b"fake"])
    with pytest.raises(backup.BackupError, match="хеш"):
        backup.verify_archive(path)


@pytest.mark.parametrize("name", ["../evil", "/etc/passwd", "a/../../evil"])
def test_traversal_rejected(tmp_path, name):
    path = str(tmp_path / "t.tar.gz")
    files = {name: b"x"}
    ti = tarfile.TarInfo(name)
    ti.size = 1
    _raw_archive(path, _manifest(files), [ti], [b"x"])
    with pytest.raises(backup.BackupError):
        backup.safe_extract(path, str(tmp_path / "out"))
    assert not (tmp_path / "evil").exists()


def test_symlink_rejected(tmp_path):
    path = str(tmp_path / "t.tar.gz")
    ti = tarfile.TarInfo("link")
    ti.type = tarfile.SYMTYPE
    ti.linkname = "/etc/passwd"
    _raw_archive(path, _manifest({}), [ti], [b""])
    with pytest.raises(backup.BackupError, match="ссылка"):
        backup.verify_archive(path)


def test_newer_format_rejected(tmp_path):
    path = str(tmp_path / "t.tar.gz")
    _raw_archive(path, _manifest({}, format_version=99), [], [])
    with pytest.raises(backup.BackupError, match="новой версией"):
        backup.verify_archive(path)


def test_missing_manifest_and_garbage(tmp_path):
    p1 = str(tmp_path / "n.tar.gz")
    with tarfile.open(p1, "w:gz") as tar:
        ti = tarfile.TarInfo("x")
        ti.size = 1
        tar.addfile(ti, io.BytesIO(b"x"))
    with pytest.raises(backup.BackupError, match="manifest"):
        backup.verify_archive(p1)
    p2 = tmp_path / "g.tar.gz"
    p2.write_bytes(b"not an archive")
    with pytest.raises(backup.BackupError):
        backup.verify_archive(str(p2))


def test_unlisted_file_rejected(tmp_path):
    path = str(tmp_path / "t.tar.gz")
    ti = tarfile.TarInfo("extra.txt")
    ti.size = 1
    _raw_archive(path, _manifest({}), [ti], [b"x"])
    with pytest.raises(backup.BackupError, match="вне manifest"):
        backup.verify_archive(path)


def test_unknown_type_rejected(tmp_path):
    path = str(tmp_path / "t.tar.gz")
    _raw_archive(path, _manifest({}, type="mystery"), [], [])
    with pytest.raises(backup.BackupError, match="тип"):
        backup.verify_archive(path)


def test_rotate(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "ARCHIVE_DIR", str(tmp_path))
    for i in range(5):
        p = tmp_path / f"vpnbot-awg-{i}.tar.gz"
        p.write_bytes(b"x")
        os.utime(p, (i, i))
    backup.rotate(2)
    assert sorted(os.listdir(tmp_path)) == ["vpnbot-awg-3.tar.gz", "vpnbot-awg-4.tar.gz"]


def test_env_without_token(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("BOT_TOKEN=123:abc\nVPN_HOST=vpn.example.com\n")
    text = backup.env_text(include_token=False)
    assert "123:abc" not in text and "VPN_HOST=vpn.example.com" in text
    assert "123:abc" in backup.env_text(include_token=True)
