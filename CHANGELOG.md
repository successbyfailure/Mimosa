# Changelog

## 1.3.30
- **OPNsense**: whitelist acepta FQDN resolviendo a IPs antes de sincronizar.

## 1.3.29
- **OPNsense**: normaliza entradas /32 en whitelist para evitar errores al añadir.

## 1.3.28
- **OPNsense**: fija la carga de alias de whitelist para evitar error en `/api/firewalls/{id}/aliases`.

## 1.3.27
- **UI**: banderas de país en inspector de IPs y ranking de bloqueos en mapa.

## 1.3.26
- **UI**: ordenación en el inspector de IPs por columna.

## 1.3.25
- **UI**: pestañas separadas por plugin en la sección Plugins.

## 1.3.24
- **Firewall**: bloqueo manual solo sincroniza alias, no activa reglas automáticamente.

## 1.3.23
- **Firewall**: al bloquear manualmente activa la regla temporal si estaba deshabilitada.

## 1.3.22
- **pfSense**: no fuerza el estado enabled al sincronizar reglas (respeta toggles).

## 1.3.21
- **pfSense**: aplica cambios al activar/desactivar o borrar reglas.

## 1.3.20
- **Firewall**: sincroniza whitelist eliminando entradas que no existan en Mimosa.

## 1.3.19
- **pfSense**: el alias de whitelist cambia a host o network según el tipo de entrada.

## 1.3.18
- **pfSense**: whitelist usa alias de host y permite FQDN/rangos sin resolver.

## 1.3.17
- **pfSense**: whitelist usa alias de red y resuelve hostnames antes de sincronizar.

## 1.3.16
- **Firewall**: sincroniza whitelist con los firewalls al añadir/eliminar entradas.

## 1.3.15
- **pfSense**: recrea port forwards cuando faltan reglas asociadas.

## 1.3.14
- **pfSense**: recrea reglas asociadas si faltan tras limpiar NAT.

## 1.3.13
- **pfSense**: fuerza actualización de NAT para recrear reglas asociadas.

## 1.3.12
- **pfSense**: regenera reglas asociadas a NAT cuando apuntan a alias antiguo.

## 1.3.11
- **Firewall**: alias `mimosa_host` sustituye a `mimosa_ip` para NAT.

## 1.3.10
- **pfSense**: NAT de Mimosa usa el alias `mimosa_host` como destino.

## 1.3.9
- **pfSense**: aplica cambios cuando se crean/actualizan reglas o NAT.

## 1.3.8
- **pfSense**: no sobrescribe `associated_rule_id` al actualizar port forwards.

## 1.3.7
- **pfSense**: preserva la regla asociada en NAT de Mimosa al actualizar.

## 1.3.6
- **pfSense**: NAT de Mimosa apunta al valor de `MIMOSA_IP` para evitar ambigüedad de alias.

## 1.3.5
- **pfSense**: NAT y regla asociada para publicar puertos Mimosa hacia `mimosa_host`.

## 1.3.4
- **pfSense**: creación automática de reglas Mimosa vía pfrest (whitelist/temporal/blacklist).

## 1.3.3
- **pfSense**: listado, detalle, toggle y borrado de reglas vía pfrest.

## 1.3.2
- **OPNsense**: reglas de bloqueo creadas por defecto en estado desactivado.
- **pfSense**: ajuste de PATCH en aliases para incluir `id` en payload (requisito pfrest).

## 1.3.1
- **Dashboard**: nueva pestaña de mapa de calor y refresco automático de secciones con datos.
- **API**: nuevo endpoint `/api/offenses/heatmap` para puntos agregados.
- **GeoIP**: soporte opcional para geolocalización de IPs via `MIMOSA_GEOIP_*`.
- **GeoIP**: se elimina el proxy local, se consulta `ip-api.com` directamente cuando se habilita.
- **Mapa**: base cartográfica con puntos de calor y valores numéricos.
- **pfSense**: soporte inicial con pfrest (alias y bloqueos básicos) con detección de ruta API.
- **Firewall**: alias `mimosa_host` opcional a partir de `MIMOSA_IP`.

## 1.1.6
- **Dashboard/Ofensas**: corrección de timestamps con zona horaria explícita y coloreado por reglas de escalado.
- **Reglas de escalado**: edición desde UI, comodines `*` y `?` para coincidencias.
- **OPNsense**: actualización de reglas preserva valores válidos y evita errores de validación.
- **Limpieza**: retirada de plugin dummy, scripts y documentación actualizados.

## 1.1.0
- **Gestión de Reglas de Firewall**: Nueva interfaz web para visualizar y controlar reglas de bloqueo en OPNsense
  - Pestaña Firewall ahora incluye sección "Reglas de Firewall" con tabla de reglas gestionadas por Mimosa
  - Toggles interactivos para activar/desactivar reglas sin acceder a OPNsense
  - API REST completa para gestión de reglas: listado, consulta individual, toggle y eliminación
  - Cuatro nuevos métodos en FirewallGateway: `list_firewall_rules()`, `get_firewall_rule()`, `toggle_firewall_rule()`, `delete_firewall_rule()`
  - Creación automática de 3 reglas en OPNsense con orden de evaluación correcto:
    1. **Whitelist** (sequence 1, action PASS) - permite IPs del alias `mimosa_whitelist` - evaluada primero
    2. **Temporal blocks** (action BLOCK) - bloquea IPs del alias `mimosa_temporal_list`
    3. **Permanent blacklist** (action BLOCK) - bloquea IPs del alias `mimosa_blacklist`
  - Visualización de estado, interfaz, acción, origen y tipo de cada regla
- **Scripts de Diagnóstico**:
  - `diagnose_opnsense.py` - Prueba completa de todas las funciones de OPNsense (7 pruebas)
  - `verify_firewall_rules.py` - Verificación de reglas de firewall creadas por Mimosa
  - Documentación completa en `scripts/README.md`
- **Mejoras de Seguridad**:
  - `.gitignore` y `.dockerignore` mejorados para proteger archivos sensibles
  - Exclusión de credenciales, claves y datos de producción
- **Correcciones**:
  - Alias de puertos ahora funciona correctamente usando `/api/firewall/alias/setItem` con formato de líneas
  - Listado de reglas usa `/api/firewall/filter/get` en lugar de `searchRule`
  - Toggle de reglas usa `/api/firewall/filter/toggleRule` para cambios de estado confiables

## 1.0.0
- Se elimina el soporte de firewalls distinto de OPNsense (pfSense, Dummy, SSH iptables).
- La UI y los tests se ajustan a la nueva única integración.

## 0.7.0
- Alias fijo `mimosa_temporal_list` para bloqueos temporales y `mimosa_blacklist` para bloqueos permanentes; se eliminan campos configurables de alias.
- UI de administración muestra y gestiona la blacklist desde la pestaña Whitelist; aliases de puertos permanecen visibles.
- Clientes pfSense/OPNsense crean ambos alias y soportan operaciones sobre blacklist; Dummy/SSH adaptados.
- Tests de firewall rehacen el flujo solicitado de alias y cobertura de endpoints locales; httpx fijado a <0.28 para estabilidad de tests.
