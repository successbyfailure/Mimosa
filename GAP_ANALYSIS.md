# Evaluación de cobertura de funcionalidades (Mimosa)

El repositorio se ha reducido a un esqueleto centrado en el núcleo de bloqueos. Solo se incluyen los componentes imprescindibles para probar integraciones básicas con el firewall y almacenar ofensas de manera local.

## Alcance actual
- **API núcleo**: coordina bloqueos y desbloqueos delegando en un `FirewallGateway`.
- **Gestor de bloqueos**: mantiene bloqueos en memoria con soporte de expiración opcional e historial simple.
- **Cliente pfSense/OPNsense**: implementa la integración mínima con el firewall mediante su API REST.
- **Almacén de ofensas**: registra ofensas en SQLite sin lógica de correlación o reglas.
- **Detección básica**: un detector de ejemplo que busca cadenas simples en logs.

## Huecos pendientes
- Dashboard y panel de control.
- Plugins de ingestión (proxy trap, rangos de puertos, reputación, etc.).
- Bots o canales de alerta.
- Reglas de correlación que automaticen bloqueos según severidad o volumen de ofensas.
- Persistencia avanzada y reconciliación con el firewall.

Estos elementos se incorporarán más adelante sobre el esqueleto actual.
