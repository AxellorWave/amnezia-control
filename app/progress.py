"""Прогресс долгой операции в одном редактируемом сообщении.

Операция идёт в отдельном потоке и вызывает progress("Шаг…"); сообщение админа
перерисовывается со списком пройденных шагов."""
import asyncio
import logging

from aiogram.types import Message

from .ui import edit_view, em, esc

log = logging.getLogger("amnezia-bot")


class Progress:
    def __init__(self, message: Message, title: str):
        self.message = message
        self.title = title
        self.steps: list[str] = []
        self.loop = asyncio.get_running_loop()

    def render(self, final: str = "") -> str:
        lines = "".join(f"<li>{em('ok')} {esc(s)}</li>" for s in self.steps[:-1])
        if self.steps and not final:
            lines += f"<li>{em('pending')} <b>{esc(self.steps[-1])}</b></li>"
        elif self.steps:
            lines += f"<li>{em('ok')} {esc(self.steps[-1])}</li>"
        return f"<h3>{self.title}</h3><ul>{lines}</ul>{final}"

    async def show(self, final: str = "", markup=None) -> None:
        await edit_view(self.message, self.render(final), markup)

    def __call__(self, step: str) -> None:
        """Вызывается из рабочего потока."""
        log.info("%s: %s", self.title, step)
        self.steps.append(step)
        try:
            asyncio.run_coroutine_threadsafe(self.show(), self.loop).result(timeout=30)
        except Exception as e:
            log.debug("progress edit failed: %s", e)

    async def fail(self, error: Exception | str, markup=None) -> None:
        if self.steps:
            failed = self.steps.pop()
            done = "".join(f"<li>{em('ok')} {esc(s)}</li>" for s in self.steps)
            text = (f"<h3>{self.title}</h3><ul>{done}<li>{em('error')} <b>{esc(failed)}</b></li></ul>"
                    f"<blockquote>{em('warn')} <code>{esc(str(error)[:1500])}</code></blockquote>")
        else:
            text = (f"<h3>{self.title}</h3><blockquote>{em('warn')} "
                    f"<code>{esc(str(error)[:1500])}</code></blockquote>")
        await edit_view(self.message, text, markup)
