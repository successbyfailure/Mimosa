# AGENTS

Este archivo aplica a todo el repositorio Mimosa. Úsalo como referencia rápida para ejecutar, contribuir y mantener coherencia en los cambios.

## Propósito y alcance
Mimosa es un núcleo de defensa para homelabs que coordina bloqueos temporales contra OPNsense. Aquí se documentan normas y atajos para cualquiera que toque el código o la infraestructura de este repo.

## Ejecución rápida
- Requisitos: Python 3.11+ recomendado.
- Instala dependencias: `pip install -r requirements.txt`.
- Arranca el servidor FastAPI: `uvicorn mimosa.web.app:app --reload`.
- UI por defecto: `http://localhost:8000` (dashboard) y `http://localhost:8000/admin` (gestión). La configuración de firewalls se persiste en `data/firewalls.json`.

## Despliegue con Docker Compose
1. Crea `.env` a partir de `env.example`. El contenedor sincroniza claves nuevas sin perder valores existentes.
2. Lanza servicios: `docker compose up --build -d`.
3. Usa `network_mode: host`; asegúrate de que el puerto 8000 esté libre. Datos persistidos en `./data`.
4. Watchtower en `docker-compose.yml` actualiza la imagen periódicamente; limita sus credenciales a esta pila.

## Configuración inicial y variables de entorno
- Variables `INITIAL_FIREWALL_*` permiten crear un firewall inicial automáticamente (usadas por la UI).
- Las credenciales de OPNsense se leen del entorno (ver `env.example`).

## Documentación de APIs
- OPNsense: https://docs.opnsense.org/development/api.html
- Documento de referencia local para la API de OPNsense: consulta `reference_docs/api-opnsense.md`.

## Convenciones de contribución
- Sigue el estilo Python del proyecto (módulos `mimosa/`); evita capturar excepciones en torno a imports.
- Commits: mensajes en modo imperativo y conciso. Incluye pruebas ejecutadas en la descripción del PR.
- Orden sugerido antes de abrir PR: lint/format (si aplica), tests relevantes y verificación manual del dashboard si el cambio afecta UI.

## Versionado
- La versión fuente vive en `version.json` en la raíz del repo. Cualquier cambio que modifique funcionalidad, UI, esquemas o dependencias debe actualizar este archivo.
- Incrementa la versión automáticamente según la naturaleza del cambio:
  - **Mayor** (X.y.z): cambios incompatibles o migraciones obligatorias.
  - **Menor** (x.Y.z): nuevas funcionalidades, pantallas o endpoints.
  - **Patch** (x.y.Z): correcciones, pequeños ajustes de UI o documentación.
- Mantén sincronizado el valor de `version.json` con cualquier lugar donde se muestre la versión (p.ej. metadatos de FastAPI o la UI). No dupliques valores sueltos; lee siempre desde el JSON.

## Testing
- Tests disponibles en `tests/`; ejecútalos con `pytest` cuando modifiques lógica.
- Si añades endpoints o UI, indica cómo verificaste (comandos o capturas) en el PR.
- Para activar pruebas reales contra firewalls, el entorno de CI puede exponer algunas variables. Las pruebas se ejecutan solo si
  las variables de OPNsense correspondientes están presentes:
  - OPNsense: `TEST_FIREWALL_OPNSENSE_BASE_URL`, `TEST_FIREWALL_OPNSENSE_API_KEY`, `TEST_FIREWALL_OPNSENSE_API_SECRET`,
    `TEST_FIREWALL_OPNSENSE_ALIAS_NAME`, `TEST_FIREWALL_OPNSENSE_VERIFY_SSL`.
  - Ajustes comunes: `TEST_FIREWALL_APPLY_CHANGES` y `TEST_FIREWALL_TIMEOUT`.
