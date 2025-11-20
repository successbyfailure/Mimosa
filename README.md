# Mimosa

Mimosa es un sistema de defensa para homelabs y entusiastas creado con nocturnidad e IA. Este esqueleto inicial incluye los módulos principales y ejemplos mínimos de código para cada uno.

## ¿Por qué “Mimosa”?
La Mimosa pudica es la planta que repliega sus hojas al mínimo contacto: un movimiento rápido y eficiente para protegerse. Este proyecto aspira a reaccionar igual de ágil ante señales hostiles, combinando componentes ligeros (ingestión de logs, reputación, proxy-trap, bots y dashboard) que se contraen y coordinan en conjunto para reforzar un homelab.

## Estructura de módulos
- `core/`: API interna, detección, bloqueos e integración de firewall.
- `logs/`: recolección de logs vía SSH y parser base.
- `proxy_trap/`: endpoint que recibe tráfico desde un reverse proxy para inspección.
- `reputation/`: descarga y parsing de listas de reputación de IPs.
- `web/`: dashboard en FastAPI listo para integrar Tailwind.
- `bot/`: bot de Telegram usando `python-telegram-bot`.
- `tasks/`: programador mínimo para tareas periódicas.

## Instalación rápida

```bash
pip install -r requirements.txt
uvicorn mimosa.web.main:app --reload
```

## Contenedores

El repositorio incluye un `docker/Dockerfile` y `docker-compose.yml` mínimos para empaquetar el dashboard y los servicios auxiliares.
