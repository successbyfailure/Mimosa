# Changelog

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
