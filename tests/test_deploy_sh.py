"""deploy.sh: синтаксис, проверки ввода и запись .env (функции без побочных эффектов)."""
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "deploy.sh")

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="нет bash")


def run(snippet: str, env: dict | None = None) -> subprocess.CompletedProcess:
    e = dict(os.environ, DEPLOY_LIB_ONLY="1", NONINTERACTIVE="1", **(env or {}))
    return subprocess.run(["bash", "-c", f'source "{SCRIPT}"; {snippet}'], env=e,
                          capture_output=True, text=True, timeout=30)


def test_syntax():
    assert subprocess.run(["bash", "-n", SCRIPT]).returncode == 0


def test_executable():
    assert os.access(SCRIPT, os.X_OK)


@pytest.mark.parametrize("func,value,ok", [
    ("valid_token", "123456:ABCdefGHIjklMNOpqrSTUvwxYZ0123456789", True),
    ("valid_token", "123:short", False),
    ("valid_admins", "111,222", True),
    ("valid_admins", "111, 222", False),
    ("valid_host", "vpn.example.com", True),
    ("valid_host", "1.2.3.4", True),
    ("valid_host", "bad host", False),
    ("valid_port", "2096", True),
    ("valid_port", "70000", False),
    ("valid_bool", "1", True),
    ("valid_bool", "2", False),
])
def test_validators(func, value, ok):
    assert (run(f'{func} "{value}"').returncode == 0) is ok


def test_write_env_keeps_comments(tmp_path):
    example = tmp_path / ".env.example"
    example.write_text("# токен\nBOT_TOKEN=123:ABC\nADMIN_IDS=1\n# SUB_HOST=sub.example.com\n"
                       "SUB_PORT=2096\nCUSTOM_EMOJI=1\n")
    out = tmp_path / ".env"
    r = run(f'VALUES[BOT_TOKEN]="9:x"; VALUES[ADMIN_IDS]="5,6"; VALUES[SUB_PORT]="3000"; '
            f'VALUES[EXTRA]="y"; write_env "{example}" "{out}"')
    assert r.returncode == 0, r.stderr
    text = out.read_text()
    assert "# токен" in text and "BOT_TOKEN=9:x" in text and "ADMIN_IDS=5,6" in text
    assert "SUB_PORT=3000" in text and "CUSTOM_EMOJI=1" in text
    assert "# SUB_HOST=sub.example.com" in text and "EXTRA=y" in text
    assert oct(out.stat().st_mode & 0o777) == "0o600"


def test_initial_value_priority(tmp_path):
    envf = tmp_path / ".env"
    envf.write_text("MAX_DEVICES=9\n")
    assert run(f'initial_value MAX_DEVICES "{envf}"').stdout == "9"
    assert run(f'initial_value MAX_DEVICES "{envf}"', {"MAX_DEVICES": "3"}).stdout == "3"
    assert run(f'initial_value SERVER_NAME "{envf}"').stdout == "vpn"


def test_noninteractive_prompt_fails_on_bad_value():
    r = run('prompt_var ADMIN_IDS "q" "abc"')
    assert r.returncode != 0 and "ADMIN_IDS" in r.stderr
    r = run('prompt_var ADMIN_IDS "q" "42"; echo "${VALUES[ADMIN_IDS]}"')
    assert r.returncode == 0 and r.stdout.strip() == "42"


def test_help():
    r = subprocess.run(["bash", SCRIPT, "-h"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and "--update" in r.stdout
