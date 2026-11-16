"""Работа с Docker через docker.sock (docker CLI внутри контейнера бота)."""
import subprocess


def dexec(container: str, cmd: str, stdin: str | None = None) -> str:
    r = subprocess.run(["docker", "exec", "-i", container, "sh", "-c", cmd],
                       input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"docker exec failed: {cmd}\n{r.stderr.strip()}")
    return r.stdout


def read_file(container: str, path: str, default: str | None = None) -> str:
    try:
        return dexec(container, f"cat '{path}'")
    except RuntimeError:
        if default is not None:
            return default
        raise


def write_file(container: str, path: str, content: str) -> None:
    dexec(container, f"cat > '{path}'", stdin=content)
