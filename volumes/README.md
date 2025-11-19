# Volúmenes locales para Mimosa

Cada servicio monta un directorio dedicado para conservar artefactos locales durante el desarrollo:

- `volumes/web/` para cualquier archivo generado por el dashboard.
- `volumes/worker/` para los registros o salidas de tareas.
- `volumes/bot/` para el estado local del bot de Telegram si fuera necesario.

Estos directorios pueden ser limpiados de forma segura en entornos de prueba.
