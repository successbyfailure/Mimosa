"""Bot de Telegram para notificaciones y acciones rápidas."""
from typing import Callable

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


class MimosaBot:
    """Wrapper simple sobre python-telegram-bot."""

    def __init__(self, token: str):
        self.app = Application.builder().token(token).build()

    def add_start_handler(self, handler: Callable[[Update, ContextTypes.DEFAULT_TYPE], None]) -> None:
        self.app.add_handler(CommandHandler("start", handler))

    def run(self) -> None:
        self.app.run_polling()
