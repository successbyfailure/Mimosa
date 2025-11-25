# Changelog
# Changelog

## 1.0.0
- Simplificación de integraciones de firewall: se elimina soporte para pfSense, SSH/iptables y el cliente dummy; OPNsense queda como única opción.
- Ajustes de UI y API para reflejar el tipo único de firewall y nuevos valores por defecto.
- Limpieza de pruebas y documentación para alinear el proyecto con OPNsense exclusivamente.

## 0.7.0
- Alias fijo `mimosa_temporal_list` para bloqueos temporales y `mimosa_blacklist` para bloqueos permanentes; se eliminan campos configurables de alias.
- UI de administración muestra y gestiona la blacklist desde la pestaña Whitelist; aliases de puertos permanecen visibles.
- Clientes pfSense/OPNsense crean ambos alias y soportan operaciones sobre blacklist; Dummy/SSH adaptados.
- Tests de firewall rehacen el flujo solicitado de alias y cobertura de endpoints locales; httpx fijado a <0.28 para estabilidad de tests.
