"""Bot de Telegram para notificaciones y acciones rápidas."""
from __future__ import annotations

import asyncio
from typing import Iterable, List, Set

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

from mimosa.core.api import CoreAPI
from mimosa.core.blocking import BlockEntry
from mimosa.core.detection import Alert


class MimosaBot:
    """Wrapper de python-telegram-bot con comandos operativos."""

    def __init__(self, token: str, api: CoreAPI, *, max_blocks: int = 10):
        self.app = Application.builder().token(token).build()
        self.api = api
        self.max_blocks = max_blocks
        self._alert_subscribers: Set[int] = set()
        self._register_handlers()

    def _register_handlers(self) -> None:
        self.app.add_handler(CommandHandler("start", self._start))
        self.app.add_handler(CommandHandler(["bloqueos", "list"], self._list_blocks))
        self.app.add_handler(CommandHandler("bloquear", self._block_ip))
        self.app.add_handler(CommandHandler("desbloquear", self._unblock_ip))
        self.app.add_handler(CommandHandler("alertas", self._toggle_alerts))

    async def _start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id if update.effective_chat else None
        if chat_id:
            self._alert_subscribers.add(chat_id)
        message = (
            "🌿 Bienvenido a Mimosa\n\n"
            "Comandos disponibles:\n"
            "• /bloqueos – Ver las últimas IP bloqueadas\n"
            "• /bloquear <ip> [motivo] – Bloquear manualmente\n"
            "• /desbloquear <ip> – Quitar un bloqueo\n"
            "• /alertas on|off – Activar o desactivar alertas automáticas"
        )
        if update.message:
            await update.message.reply_text(message)

    async def _list_blocks(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        blocks: List[BlockEntry] = list(self.api.list_blocks())
        if not blocks:
            text = "No hay IPs bloqueadas actualmente."
        else:
            limited = blocks[: self.max_blocks]
            lines = ["Últimos bloqueos registrados:"]
            for entry in limited:
                reason = entry.reason or "Sin motivo"
                timestamp = entry.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                lines.append(f"• {entry.ip} – {reason} ({timestamp})")
            text = "\n".join(lines)
        if update.message:
            await update.message.reply_text(text)

    async def _block_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not context.args:
            await update.message.reply_text(
                "Uso: /bloquear <ip> [motivo opcional]",
            )
            return

        ip = context.args[0]
        reason = " ".join(context.args[1:]).strip() or "Bloqueo manual desde bot"
        self.api.block_ip(ip, reason)
        if update.message:
            await update.message.reply_text(f"✅ IP {ip} bloqueada. Motivo: {reason}")

    async def _unblock_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not context.args:
            await update.message.reply_text("Uso: /desbloquear <ip>")
            return

        ip = context.args[0]
        self.api.unblock_ip(ip)
        if update.message:
            await update.message.reply_text(f"🔓 IP {ip} desbloqueada.")

    async def _toggle_alerts(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id if update.effective_chat else None
        if chat_id is None:
            return

        if context.args:
            desired = context.args[0].lower()
            enable = desired in {"on", "1", "true", "si", "sí"}
        else:
            enable = chat_id not in self._alert_subscribers

        if enable:
            self._alert_subscribers.add(chat_id)
            text = "🔔 Alertas automáticas activadas."
        else:
            self._alert_subscribers.discard(chat_id)
            text = "🔕 Alertas automáticas desactivadas."

        if update.message:
            await update.message.reply_text(text)

    async def notify_alerts(self, alerts: Iterable[Alert]) -> None:
        """Envía una serie de alertas de seguridad a los suscriptores."""

        if not self._alert_subscribers:
            return

        messages = [self._format_alert(alert) for alert in alerts]
        payload = "\n\n".join(messages)
        await self._broadcast(payload)

    async def notify_block(self, ip: str, reason: str) -> None:
        """Envía una notificación de bloqueo manual/automático."""

        if not self._alert_subscribers:
            return
        message = f"🚫 Bloqueo aplicado a *{ip}*\nMotivo: {reason}"
        await self._broadcast(message, parse_mode=ParseMode.MARKDOWN)

    async def _broadcast(self, message: str, *, parse_mode: str | None = None) -> None:
        send_tasks = [
            self.app.bot.send_message(chat_id=chat_id, text=message, parse_mode=parse_mode)
            for chat_id in self._alert_subscribers
        ]
        await asyncio.gather(*send_tasks)

    @staticmethod
    def _format_alert(alert: Alert) -> str:
        return (
            "🚨 <b>Alerta de Mimosa</b>\n"
            f"IP origen: <code>{alert.source_ip}</code>\n"
            f"Severidad: <b>{alert.severity}</b>\n"
            f"Detalle: {alert.description}"
        )

    def run(self) -> None:
        self.app.run_polling()
