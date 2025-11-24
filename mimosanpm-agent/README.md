# MimosaNPM agent

Agente ligero para desplegar junto a Nginx Proxy Manager (NPM). Lee los logs de acceso, detecta peticiones a dominios no registrados y envía alertas a Mimosa vía HTTPS.

## Preparación
1. Copia `.env` a partir de `env.example` y completa las variables obligatorias.
2. Asegúrate de montar el mismo volumen de logs que usa NPM en `/data/logs` (solo lectura).
3. Opcional: monta un volumen persistente en `/state` para recordar el desplazamiento de lectura entre reinicios.

## Variables de entorno
- `MIMOSA_API_URL` (**obligatoria**): endpoint completo de Mimosa, normalmente `https://mimosa.local/api/plugins/mimosanpm/ingest`.
- `MIMOSA_SHARED_SECRET` (**obligatoria**): secreto compartido configurado en Mimosa para el plugin MimosaNPM.
- `NPM_LOG_GLOB` (opcional): patrón de logs a vigilar. Por defecto `/data/logs/*_access.log`.
- `KNOWN_DOMAINS` (opcional): lista separada por comas de dominios válidos. Las peticiones a otros hosts generan alertas.
- `POLL_INTERVAL` (opcional): segundos entre exploraciones del log (defecto: 5).
- `BATCH_SIZE` (opcional): máximo de alertas a enviar por lote (defecto: 50).
- `STATE_PATH` (opcional): ruta para guardar el desplazamiento de lectura. El directorio debe ser escribible (defecto: `/state/mimosanpm-agent.json`).

## Despliegue con Docker Compose
Ejemplo minimal para ejecutarlo en la misma red/stack que NPM:

```yaml
services:
  mimosanpm-agent:
    image: ghcr.io/successbyfailure/mimosanpm-agent:latest
    build: .
    restart: unless-stopped
    env_file: .env
    volumes:
      - ./state:/state
      - /ruta/a/logs/npm:/data/logs:ro
    networks:
      - npm_stack

networks:
  npm_stack:
    external: true
```

Ajusta el volumen `/ruta/a/logs/npm` al directorio real de logs de NPM (p. ej. el volumen `data` del compose de NPM). Si el stack ya define una red compartida, reutilízala en `networks` para que el agente pueda resolver el host de Mimosa.

## Ejecución local

```bash
python -m mimosanpm_agent.main
```

El agente escribirá en stdout las detecciones enviadas y los lotes que Mimosa acepte.
