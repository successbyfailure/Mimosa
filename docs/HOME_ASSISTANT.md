# Home Assistant

Esta guia describe como exponer Mimosa en Home Assistant con sensores y switches
REST. La integracion usa el token configurado en Mimosa y endpoints dedicados.

## 1. Habilitar integracion en Mimosa

Tambien puedes hacerlo desde la UI: Settings -> Home Assistant.

Puedes habilitarla via API (requiere sesion admin):

```bash
curl -X PUT http://mimosa:8000/api/homeassistant/config \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "api_token": "cambia-este-token",
    "expose_stats": true,
    "expose_signals": true,
    "expose_heatmap": true,
    "heatmap_source": "offenses",
    "heatmap_window": "24h",
    "expose_rules": true,
    "expose_firewall_rules": false
  }'
```

Si prefieres generarlo automaticamente, puedes usar `rotate_token: true` y leer
el token en la respuesta.

## 2. Sensores REST en Home Assistant

Ejemplo de sensores para estadisticas y senales:

```yaml
rest:
  - resource: http://mimosa:8000/api/homeassistant/stats
    method: GET
    headers:
      Authorization: "Bearer cambia-este-token"
    scan_interval: 60
    sensor:
      - name: "Mimosa Offenses 24h"
        value_template: "{{ value_json.offenses.last_24h }}"
      - name: "Mimosa Blocks 24h"
        value_template: "{{ value_json.blocks.last_24h }}"

  - resource: http://mimosa:8000/api/homeassistant/signals?client_id=ha-main
    method: GET
    headers:
      Authorization: "Bearer cambia-este-token"
    scan_interval: 30
    sensor:
      - name: "Mimosa Offense Signal"
        value_template: "{{ value_json.offense.new }}"
      - name: "Mimosa Block Signal"
        value_template: "{{ value_json.block.new }}"
```

Notas:
- El primer `signals` guarda un baseline y devuelve `new: false`.
- Usa un `client_id` fijo por instalacion para evitar duplicados.

## 3. Heatmap

El endpoint de heatmap devuelve puntos agregados para tarjetas de mapa o
custom cards:

```
GET /api/homeassistant/heatmap?window=24h&limit=300&source=offenses
```

## 4. Switches para reglas

Puedes mapear reglas a switches REST con `state_resource` y `resource`.
Ejemplo para una regla local (id 3):

```yaml
switch:
  - platform: rest
    name: "Mimosa Rule 3"
    resource: http://mimosa:8000/api/homeassistant/rules/3/toggle?enabled=true
    state_resource: http://mimosa:8000/api/homeassistant/rules/3
    body_on: ""
    body_off: ""
    headers:
      Authorization: "Bearer cambia-este-token"
    is_on_template: "{{ value_json.enabled }}"
    turn_off:
      service: rest_command.mimosa_rule_3_off
    turn_on:
      service: rest_command.mimosa_rule_3_on

rest_command:
  mimosa_rule_3_on:
    url: http://mimosa:8000/api/homeassistant/rules/3/toggle?enabled=true
    method: POST
    headers:
      Authorization: "Bearer cambia-este-token"
  mimosa_rule_3_off:
    url: http://mimosa:8000/api/homeassistant/rules/3/toggle?enabled=false
    method: POST
    headers:
      Authorization: "Bearer cambia-este-token"
```

Para reglas de firewall (si estan habilitadas), usa:

```
GET /api/homeassistant/firewall/rules
POST /api/homeassistant/firewall/rules/{uuid}/toggle?enabled=true
```
