"""Bot de Telegram para gestión de Mimosa."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Callable, Any

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from mimosa.core.blocking import BlockManager
from mimosa.core.domain.telegram import TelegramUser, TelegramInteraction
from mimosa.core.offenses import OffenseStore
from mimosa.core.repositories.telegram_repository import (
    TelegramUserRepository,
    TelegramInteractionRepository,
)
from mimosa.core.rules import OffenseRuleStore
from mimosa.core.telegram_config import TelegramConfigStore

logger = logging.getLogger(__name__)


class TelegramBotService:
    """Servicio para el bot de Telegram de Mimosa."""

    def __init__(
        self,
        config_store: TelegramConfigStore,
        user_repo: TelegramUserRepository,
        interaction_repo: TelegramInteractionRepository,
        offense_store: OffenseStore,
        block_manager: BlockManager,
        rule_store: OffenseRuleStore,
    ):
        self.config_store = config_store
        self.user_repo = user_repo
        self.interaction_repo = interaction_repo
        self.offense_store = offense_store
        self.block_manager = block_manager
        self.rule_store = rule_store
        self.application: Optional[Application] = None
        self._running = False

    async def start(self) -> None:
        """Inicia el bot de Telegram."""
        config = self.config_store.get_config()

        if not config.enabled:
            logger.info("Bot de Telegram deshabilitado en la configuración")
            return

        if not config.bot_token:
            logger.error("No se ha configurado el token del bot de Telegram")
            return

        try:
            # Crear la aplicación del bot
            self.application = Application.builder().token(config.bot_token).build()

            # Registrar handlers
            self.application.add_handler(CommandHandler("start", self._start_command))
            self.application.add_handler(CommandHandler("help", self._help_command))
            self.application.add_handler(CommandHandler("stats", self._stats_command))
            self.application.add_handler(CommandHandler("menu", self._menu_command))
            self.application.add_handler(CommandHandler("blocks", self._blocks_command))
            self.application.add_handler(CommandHandler("rules", self._rules_command))
            self.application.add_handler(CommandHandler("block", self._block_ip_command))
            self.application.add_handler(CommandHandler("unblock", self._unblock_ip_command))

            # Handler para botones inline
            self.application.add_handler(CallbackQueryHandler(self._button_callback))

            # Handler para mensajes de texto (para capturar IPs)
            self.application.add_handler(
                MessageHandler(filters.TEXT & ~filters.COMMAND, self._handle_text)
            )

            # Iniciar el bot
            await self.application.initialize()
            await self.application.start()
            await self.application.updater.start_polling()
            self._running = True
            logger.info("Bot de Telegram iniciado correctamente")

        except Exception as e:
            logger.error(f"Error al iniciar el bot de Telegram: {e}")
            raise

    async def stop(self) -> None:
        """Detiene el bot de Telegram."""
        if self.application and self._running:
            try:
                await self.application.updater.stop()
                await self.application.stop()
                await self.application.shutdown()
                self._running = False
                logger.info("Bot de Telegram detenido")
            except Exception as e:
                logger.error(f"Error al detener el bot de Telegram: {e}")

    def is_running(self) -> bool:
        """Verifica si el bot está corriendo."""
        return self._running

    async def _start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Maneja el comando /start."""
        await self._log_interaction(update, "/start")

        if not update.effective_user:
            return

        user = await self._get_or_create_user(update.effective_user)

        if not user.authorized:
            config = self.config_store.get_config()
            await update.message.reply_text(config.unauthorized_message)
            return

        config = self.config_store.get_config()
        keyboard = [
            [
                InlineKeyboardButton("📊 Estadísticas", callback_data="stats"),
                InlineKeyboardButton("🚫 Bloqueos", callback_data="blocks"),
            ],
            [
                InlineKeyboardButton("⚙️ Reglas", callback_data="rules"),
                InlineKeyboardButton("❓ Ayuda", callback_data="help"),
            ],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            f"{config.welcome_message}\n\n"
            "Usa los botones para navegar o escribe /help para ver los comandos disponibles.",
            reply_markup=reply_markup,
        )

    async def _help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Muestra la ayuda con los comandos disponibles."""
        await self._log_interaction(update, "/help")

        if not await self._is_authorized(update):
            return

        help_text = """
🤖 *Comandos disponibles:*

/start - Inicia el bot y muestra el menú principal
/menu - Muestra el menú principal
/stats - Muestra estadísticas del sistema
/blocks - Lista los bloqueos activos
/rules - Lista las reglas de bloqueo configuradas
/block <IP> - Bloquea una dirección IP
/unblock <IP> - Desbloquea una dirección IP
/help - Muestra este mensaje de ayuda

También puedes usar los botones del menú para navegar.
        """
        await update.message.reply_text(help_text, parse_mode="Markdown")

    async def _menu_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Muestra el menú principal."""
        await self._log_interaction(update, "/menu")

        if not await self._is_authorized(update):
            return

        keyboard = [
            [
                InlineKeyboardButton("📊 Estadísticas", callback_data="stats"),
                InlineKeyboardButton("🚫 Bloqueos", callback_data="blocks"),
            ],
            [
                InlineKeyboardButton("⚙️ Reglas", callback_data="rules"),
                InlineKeyboardButton("❓ Ayuda", callback_data="help"),
            ],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            "Selecciona una opción:", reply_markup=reply_markup
        )

    async def _stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Muestra estadísticas del sistema."""
        await self._log_interaction(update, "/stats")

        if not await self._is_authorized(update):
            return

        # Obtener estadísticas
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)

        total_offenses = len(self.offense_store.list_all())
        offenses_last_hour = len(
            [o for o in self.offense_store.list_all() if o.created_at >= hour_ago]
        )
        offenses_last_day = len(
            [o for o in self.offense_store.list_all() if o.created_at >= day_ago]
        )

        active_blocks = len(self.block_manager.list_active())
        all_blocks = len(self.block_manager.list_all())

        total_rules = len(self.rule_store.list())

        stats_text = f"""
📊 *Estadísticas de Mimosa*

*Ofensas:*
• Total: {total_offenses}
• Última hora: {offenses_last_hour}
• Último día: {offenses_last_day}

*Bloqueos:*
• Activos: {active_blocks}
• Total histórico: {all_blocks}

*Reglas:*
• Configuradas: {total_rules}
        """

        await update.message.reply_text(stats_text, parse_mode="Markdown")

    async def _blocks_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Lista los bloqueos activos."""
        await self._log_interaction(update, "/blocks")

        if not await self._is_authorized(update):
            return

        blocks = self.block_manager.list_active()

        if not blocks:
            await update.message.reply_text("No hay bloqueos activos.")
            return

        # Mostrar solo los primeros 10 bloqueos
        blocks_to_show = blocks[:10]
        blocks_text = "🚫 *Bloqueos activos:*\n\n"

        for block in blocks_to_show:
            expires = (
                block.expires_at.strftime("%H:%M %d/%m")
                if block.expires_at
                else "Permanente"
            )
            blocks_text += f"• `{block.ip}` - {block.reason}\n  Expira: {expires}\n\n"

        if len(blocks) > 10:
            blocks_text += f"\n_Mostrando 10 de {len(blocks)} bloqueos_"

        keyboard = [
            [
                InlineKeyboardButton("🔄 Actualizar", callback_data="blocks"),
                InlineKeyboardButton("« Menú", callback_data="menu"),
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            blocks_text, parse_mode="Markdown", reply_markup=reply_markup
        )

    async def _rules_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Lista las reglas de bloqueo configuradas."""
        await self._log_interaction(update, "/rules")

        if not await self._is_authorized(update):
            return

        rules = self.rule_store.list()

        if not rules:
            await update.message.reply_text("No hay reglas configuradas.")
            return

        rules_text = "⚙️ *Reglas de bloqueo:*\n\n"

        # Construir botones para activar/desactivar cada regla
        keyboard = []
        for i, rule in enumerate(rules[:10], 1):
            status_icon = "✅" if rule.enabled else "❌"
            rules_text += f"{status_icon} *{i}. {rule.description}*\n"
            rules_text += f"Plugin: {rule.plugin}\n"
            rules_text += f"Severidad: {rule.severity}\n"
            if rule.min_last_hour:
                rules_text += f"Min. última hora: {rule.min_last_hour}\n"
            if rule.min_total:
                rules_text += f"Min. total: {rule.min_total}\n"
            if rule.block_minutes:
                rules_text += f"Duración: {rule.block_minutes} min\n"

            # Añadir botón para toggle
            btn_text = f"{'🔴 Desactivar' if rule.enabled else '🟢 Activar'} Regla {i}"
            keyboard.append([InlineKeyboardButton(btn_text, callback_data=f"toggle_rule_{rule.id}")])
            rules_text += "\n"

        if len(rules) > 10:
            rules_text += f"\n_Mostrando 10 de {len(rules)} reglas_"

        keyboard.append([
            InlineKeyboardButton("🔄 Actualizar", callback_data="rules"),
            InlineKeyboardButton("« Menú", callback_data="menu")
        ])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            rules_text, parse_mode="Markdown", reply_markup=reply_markup
        )

    async def _block_ip_command(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Bloquea una dirección IP."""
        await self._log_interaction(update, "/block")

        if not await self._is_authorized(update):
            return

        if not context.args:
            await update.message.reply_text(
                "Uso: /block <IP> [razón]\nEjemplo: /block 1.2.3.4 Ataque detectado"
            )
            return

        ip = context.args[0]
        reason = " ".join(context.args[1:]) if len(context.args) > 1 else "Bloqueado desde Telegram"

        try:
            # Bloquear la IP
            self.block_manager.add(
                ip=ip,
                reason=reason,
                source="telegram",
                duration_minutes=60,  # 1 hora por defecto
                sync_with_firewall=True,
            )
            await update.message.reply_text(f"✅ IP {ip} bloqueada correctamente.")
        except Exception as e:
            await update.message.reply_text(f"❌ Error al bloquear IP: {str(e)}")

    async def _unblock_ip_command(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Desbloquea una dirección IP."""
        await self._log_interaction(update, "/unblock")

        if not await self._is_authorized(update):
            return

        if not context.args:
            await update.message.reply_text("Uso: /unblock <IP>\nEjemplo: /unblock 1.2.3.4")
            return

        ip = context.args[0]

        try:
            # Desbloquear la IP
            self.block_manager.remove(ip)
            await update.message.reply_text(f"✅ IP {ip} desbloqueada correctamente.")
        except Exception as e:
            await update.message.reply_text(f"❌ Error al desbloquear IP: {str(e)}")

    async def _button_callback(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Maneja los callbacks de los botones inline."""
        query = update.callback_query
        await query.answer()

        if not await self._is_authorized(update):
            return

        data = query.data

        if data == "stats":
            await self._show_stats(update, context)
        elif data == "blocks":
            await self._show_blocks(update, context)
        elif data == "rules":
            await self._show_rules(update, context)
        elif data == "help":
            await self._show_help(update, context)
        elif data == "menu":
            await self._show_menu(update, context)
        elif data.startswith("toggle_rule_"):
            # Extraer ID de la regla del callback
            try:
                rule_id = int(data.replace("toggle_rule_", ""))
                new_state = self.rule_store.toggle(rule_id)
                status = "activada" if new_state else "desactivada"
                await query.answer(f"Regla {status}")
                # Actualizar el mensaje con el nuevo estado
                await self._show_rules(update, context)
            except (ValueError, Exception) as e:
                await query.answer(f"Error: {str(e)}")

    async def _show_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Muestra estadísticas (desde botón)."""
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)

        total_offenses = len(self.offense_store.list_all())
        offenses_last_hour = len(
            [o for o in self.offense_store.list_all() if o.created_at >= hour_ago]
        )
        offenses_last_day = len(
            [o for o in self.offense_store.list_all() if o.created_at >= day_ago]
        )

        active_blocks = len(self.block_manager.list_active())
        all_blocks = len(self.block_manager.list_all())
        total_rules = len(self.rule_store.list())

        stats_text = f"""
📊 *Estadísticas de Mimosa*

*Ofensas:*
• Total: {total_offenses}
• Última hora: {offenses_last_hour}
• Último día: {offenses_last_day}

*Bloqueos:*
• Activos: {active_blocks}
• Total histórico: {all_blocks}

*Reglas:*
• Configuradas: {total_rules}
        """

        keyboard = [[InlineKeyboardButton("« Menú", callback_data="menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.callback_query.edit_message_text(
            stats_text, parse_mode="Markdown", reply_markup=reply_markup
        )

    async def _show_blocks(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Muestra bloqueos activos (desde botón)."""
        blocks = self.block_manager.list_active()

        if not blocks:
            text = "No hay bloqueos activos."
        else:
            blocks_to_show = blocks[:10]
            text = "🚫 *Bloqueos activos:*\n\n"

            for block in blocks_to_show:
                expires = (
                    block.expires_at.strftime("%H:%M %d/%m")
                    if block.expires_at
                    else "Permanente"
                )
                text += f"• `{block.ip}` - {block.reason}\n  Expira: {expires}\n\n"

            if len(blocks) > 10:
                text += f"\n_Mostrando 10 de {len(blocks)} bloqueos_"

        keyboard = [
            [
                InlineKeyboardButton("🔄 Actualizar", callback_data="blocks"),
                InlineKeyboardButton("« Menú", callback_data="menu"),
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.callback_query.edit_message_text(
            text, parse_mode="Markdown", reply_markup=reply_markup
        )

    async def _show_rules(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Muestra reglas (desde botón)."""
        rules = self.rule_store.list()

        if not rules:
            text = "No hay reglas configuradas."
            keyboard = [[InlineKeyboardButton("« Menú", callback_data="menu")]]
        else:
            text = "⚙️ *Reglas de bloqueo:*\n\n"

            # Construir botones para activar/desactivar cada regla
            keyboard = []
            for i, rule in enumerate(rules[:10], 1):
                status_icon = "✅" if rule.enabled else "❌"
                text += f"{status_icon} *{i}. {rule.description}*\n"
                text += f"Plugin: {rule.plugin}\n"
                text += f"Severidad: {rule.severity}\n"
                if rule.min_last_hour:
                    text += f"Min. última hora: {rule.min_last_hour}\n"
                if rule.min_total:
                    text += f"Min. total: {rule.min_total}\n"
                if rule.block_minutes:
                    text += f"Duración: {rule.block_minutes} min\n"

                # Añadir botón para toggle
                btn_text = f"{'🔴 Desactivar' if rule.enabled else '🟢 Activar'} Regla {i}"
                keyboard.append([InlineKeyboardButton(btn_text, callback_data=f"toggle_rule_{rule.id}")])
                text += "\n"

            if len(rules) > 10:
                text += f"\n_Mostrando 10 de {len(rules)} reglas_"

            keyboard.append([
                InlineKeyboardButton("🔄 Actualizar", callback_data="rules"),
                InlineKeyboardButton("« Menú", callback_data="menu")
            ])

        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.callback_query.edit_message_text(
            text, parse_mode="Markdown", reply_markup=reply_markup
        )

    async def _show_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Muestra ayuda (desde botón)."""
        help_text = """
🤖 *Comandos disponibles:*

/start - Inicia el bot y muestra el menú principal
/menu - Muestra el menú principal
/stats - Muestra estadísticas del sistema
/blocks - Lista los bloqueos activos
/rules - Lista las reglas de bloqueo configuradas
/block <IP> - Bloquea una dirección IP
/unblock <IP> - Desbloquea una dirección IP
/help - Muestra este mensaje de ayuda

También puedes usar los botones del menú para navegar.
        """

        keyboard = [[InlineKeyboardButton("« Menú", callback_data="menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.callback_query.edit_message_text(
            help_text, parse_mode="Markdown", reply_markup=reply_markup
        )

    async def _show_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Muestra el menú principal (desde botón)."""
        keyboard = [
            [
                InlineKeyboardButton("📊 Estadísticas", callback_data="stats"),
                InlineKeyboardButton("🚫 Bloqueos", callback_data="blocks"),
            ],
            [
                InlineKeyboardButton("⚙️ Reglas", callback_data="rules"),
                InlineKeyboardButton("❓ Ayuda", callback_data="help"),
            ],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.callback_query.edit_message_text(
            "Selecciona una opción:", reply_markup=reply_markup
        )

    async def _handle_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Maneja mensajes de texto."""
        await self._log_interaction(update, None)

        if not await self._is_authorized(update):
            return

        # Por ahora, solo respondemos con el menú
        await update.message.reply_text(
            "Usa /help para ver los comandos disponibles o /menu para ver el menú."
        )

    async def _is_authorized(self, update: Update) -> bool:
        """Verifica si el usuario está autorizado."""
        if not update.effective_user:
            return False

        user = self.user_repo.find_by_telegram_id(update.effective_user.id)

        if not user or not user.authorized:
            config = self.config_store.get_config()
            if update.message:
                await update.message.reply_text(config.unauthorized_message)
            elif update.callback_query:
                await update.callback_query.answer(config.unauthorized_message)
            return False

        return True

    async def _get_or_create_user(self, telegram_user) -> TelegramUser:
        """Obtiene o crea un usuario en la base de datos."""
        user = self.user_repo.find_by_telegram_id(telegram_user.id)

        if user:
            # Actualizar last_seen
            self.user_repo.increment_interaction_count(
                telegram_user.id, datetime.now(timezone.utc)
            )
            return user

        # Crear nuevo usuario
        now = datetime.now(timezone.utc)
        new_user = TelegramUser(
            id=0,
            telegram_id=telegram_user.id,
            username=telegram_user.username,
            first_name=telegram_user.first_name,
            last_name=telegram_user.last_name,
            authorized=False,
            first_seen=now,
            last_seen=now,
            interaction_count=1,
        )

        return self.user_repo.save(new_user)

    async def _log_interaction(self, update: Update, command: Optional[str]) -> None:
        """Registra una interacción en la base de datos."""
        if not update.effective_user:
            return

        user = self.user_repo.find_by_telegram_id(update.effective_user.id)
        authorized = user.authorized if user else False

        message_text = None
        if update.message:
            message_text = update.message.text
        elif update.callback_query:
            message_text = f"callback: {update.callback_query.data}"

        interaction = TelegramInteraction(
            id=0,
            telegram_id=update.effective_user.id,
            username=update.effective_user.username,
            command=command,
            message=message_text,
            authorized=authorized,
            created_at=datetime.now(timezone.utc),
        )

        self.interaction_repo.save(interaction)


__all__ = ["TelegramBotService"]
