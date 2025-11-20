# Evaluación de cobertura de funcionalidades (Mimosa)

Este documento resume qué partes del repositorio actual cubren la funcionalidad solicitada para Mimosa y qué elementos faltan o están solo esbozados.

## Estado del dashboard y administración web
- **Dashboard**: `mimosa/web/main.py` ofrece FastAPI con rutas de ejemplo y datos de demo para incidentes y bloqueos, sin gráficos ni métricas reales (no hay agregaciones de ofensas en 7d/24h/1h, ni conteo de puertos vigilados, ni estadísticas persistentes).
- **Configuración admin**: hay un estado en memoria (`AdminState`) con bloqueo manual y reglas ficticias, pero no hay CRUD real para gestionar reglas de ofensas, listas blanca/negra ni conexión con el núcleo de bloqueos. Tampoco existe persistencia en disco o base de datos.
- **Interfaz de firewall**: el panel no expone formularios para añadir pfSense/OPNsense ni para sincronizar bloqueos con esos destinos.

## Gestor de ofensas y bloqueos
- **Detección**: el detector (`mimosa/core/detection.py`) solo inspecciona líneas en busca de "failed password" y devuelve alertas en memoria sin correlación temporal ni severidad configurable.
- **Bloqueos**: `mimosa/core/blocking.py` mantiene bloqueos en un diccionario en memoria sin expiración, histórico ni búsqueda. No hay mapeo a listas blanca/negra ni a puertos específicos.
- **Integración con pfSense/OPNsense**: `mimosa/core/pfsense.py` implementa un cliente HTTP básico, pero ningún servicio lo usa ni existe lógica para manejar alias múltiples, expiraciones coordinadas o reconciliación periódica con el firewall.
- **Workflow de ofensa→bloqueo**: el API núcleo (`mimosa/core/api.py`) registra bloqueos directamente y carece de reglas o umbrales para decidir cuándo una ofensa genera un bloqueo. Tampoco hay auditoría ni historial.

## Ingesta y módulos de generación de ofensas
- **Proxy HTTP**: `mimosa/proxy_trap/endpoint.py` expone un endpoint HTMX con intentos mínimos, pero no clasifica ofensas ni dispara bloqueos.
- **Rangos de puertos**: no existe un módulo que abra puertos y genere ofensas TCP/UDP; solo hay detectores de SSH fallido y collectors de logs como ejemplos.
- **Listas de reputación**: `mimosa/reputation` solo contiene skeletons de fetch y parse sin integración con el núcleo ni con listas blanca/negra.

## Persistencia y tareas programadas
- **Almacenamiento**: no hay base de datos ni modelo de datos para ofensas, bloqueos, listas blanca/negra o configuración de firewalls. Todo estado se pierde al reiniciar.
- **Tareas**: el scheduler (`mimosa/tasks`) es un esqueleto sin jobs que mantengan bloqueos temporales, recarguen reputación o limpien expiraciones en el firewall.

## Conclusión
El repositorio actual es un esqueleto: muestra endpoints de ejemplo y clientes básicos, pero faltan la mayoría de las funcionalidades descritas (dashboard con métricas reales, gestor completo de ofensas/bloqueos, integración efectiva con pfSense/OPNsense, módulos de generación de ofensas adicionales y persistencia). Priorizar la modelización de datos y la integración real entre módulos antes de extender la UI facilitará cubrir los huecos.
