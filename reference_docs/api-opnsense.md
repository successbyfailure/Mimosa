# OPNsense API – Guía para agentes de programación
(api-opnsense.md)

Esta guía resume cómo usar la API de OPNsense desde código o desde un agente de programación (LLM, bot, automatización, etc.). Está pensada para:

- Entender cómo se construyen las URLs de la API.
- Autenticarse correctamente con clave/secret.
- Descubrir endpoints y parámetros a partir de la propia GUI.
- Trabajar con recursos típicos (firmware, firewall, interfaces, servicios…).
- Aplicar buenas prácticas para no romper el firewall en producción.

---

## 1. Estructura básica de la API

### 1.1. Forma general de las URLs

Todas las llamadas siguen este patrón:

```text
https://<host>/api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
```

Ejemplos típicos (no exhaustivos):

```text
https://fw.example.com/api/core/firmware/status
https://fw.example.com/api/firewall/alias/getAliasUUID/MiAlias
https://fw.example.com/api/interfaces/overview/interfaces_info
```

- **module**: bloque funcional (core, firewall, interfaces, openvpn, routes, unbound, wireguard, etc.).
- **controller**: parte concreta dentro del módulo (p.ej. firmware, alias, overview, service…).
- **command**: acción que se va a ejecutar (status, search, add_item, set_item, reconfigure…).

La lista completa de módulos/controladores/comandos está en la referencia oficial de la API dentro de la documentación de OPNsense (Development Manual → API Reference).

### 1.2. Verbo HTTP

La API usa únicamente dos verbos:

- `GET` → Consultar datos.
- `POST` → Crear, modificar o ejecutar acciones.

Regla mental simple:

- Si es un “listado” o una “consulta”, lo normal es `GET`.
- Si estás “cambiando algo” o “ejecutando una acción”, será `POST`.

### 1.3. Formato de datos

- Cuando se manda contenido en `POST`, el cuerpo es JSON (`application/json`).
- Las respuestas también devuelven JSON.

Ejemplo de respuesta típica de un grid (resumen):

```json
{
  "total": 10,
  "rowCount": 7,
  "current": 1,
  "rows": [
    {
      "id": "configd",
      "locked": 1,
      "running": 1,
      "description": "System Configuration Daemon",
      "name": "configd"
    }
  ]
}
```

Muchas vistas de tablas en la GUI devuelven estructuras muy similares a esta: contadores y un array `rows` con objetos.

---

## 2. Autenticación (key / secret)

La API de OPNsense no usa el usuario/contraseña normales directamente, sino **parejas de clave / secreto** asociadas a un usuario del sistema.

### 2.1. Creación de claves

1. Ir a **System → Access → Users**.
2. Editar el usuario que vaya a usar la API (crea uno nuevo si es para una aplicación/bot).
3. En la parte inferior aparecerá la sección de **API keys**.
4. Pulsar el botón de añadir (+).
5. Descargar el fichero que contiene algo parecido a:

   ```ini
   key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   secret=yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
   ```

   > El secret sólo se muestra una vez; si se pierde, hay que generar una clave nueva.

### 2.2. Cómo se envían las credenciales

Se usa **HTTP Basic Auth**, pero con `key` como usuario y `secret` como contraseña.

En cURL:

```bash
curl -k   -u "MI_KEY:MI_SECRET"   https://fw.example.com/api/core/firmware/status
```

En Python (requests):

```python
import requests

url = "https://fw.example.com/api/core/firmware/status"
api_key = "MI_KEY"
api_secret = "MI_SECRET"

r = requests.get(url, auth=(api_key, api_secret), verify=False)
```

### 2.3. Privilegios (ACL)

- La clave hereda los permisos del usuario.
- En la ficha del usuario, en “Effective Privileges”, se ve qué secciones puede usar.
- Cada privilegio se corresponde con uno o varios endpoints.
- Para un agente, lo ideal es un usuario dedicado con **mínimos privilegios necesarios**.

---

## 3. Descubrir endpoints y parámetros

La documentación de API lista todos los endpoints, pero no siempre todos los parámetros. La forma recomendada de “aprender” cómo se usan es:

### 3.1. Tronco de referencia de la API

En la documentación de OPNsense:

- **Development Manual → API Reference**:
  - Core API (auth, firewall, firmware, interfaces, routes, unbound, wireguard, etc.).
  - Plugins API (acmeclient, freeradius, haproxy, nginx, wazuhagent, zerotier, …).
  - Business Edition API (solo si tienes BE).

Cada sección lista, para cada controlador, una tabla con:

- Method (GET/POST)
- Module
- Controller
- Command
- Parámetros de ruta (por ejemplo `$uuid`, `$if`, `$identifier`, etc.)

Ejemplo visual (interfaces, simplificado):

| Method | Module    | Controller      | Command        | Params  |
| ------ | --------- | --------------- | -------------- | ------- |
| GET    | interfaces| overview        | interfaces_info| $details=false |
| POST   | interfaces| vlan_settings   | add_item       |         |
| GET    | interfaces| vlan_settings   | get_item       | $uuid   |

Esto se traduce a URLs como:

```text
GET  /api/interfaces/overview/interfaces_info
POST /api/interfaces/vlan_settings/add_item
GET  /api/interfaces/vlan_settings/get_item/<uuid>
```

### 3.2. Inspeccionar la GUI con el navegador

Casi todos los endpoints se usan internamente por la WebGUI. Para “copiarlos”:

1. Abre la página de la GUI que te interesa (por ejemplo, una tabla de servicios, alias de firewall, interfaces, etc.).
2. Abre las herramientas de desarrollador del navegador (pestaña **Network**).
3. Filtra las peticiones por la ruta `/api/`.
4. Ejecuta la acción en la GUI (pulsar “guardar”, “aplicar”, “añadir”, etc.).
5. Copia:
   - La URL completa.
   - El método (`GET`/`POST`).
   - El cuerpo JSON si es un `POST`.

Ejemplo típico de body que verás en un grid:

```json
{
  "current": 1,
  "rowCount": 7,
  "sort": {},
  "searchPhrase": ""
}
```

Con esa información, puedes reproducir la llamada en cURL, Python, n8n, etc.

---

## 4. Patrón de trabajo con recursos

Aunque cada módulo tiene sus particularidades, muchos comparten el mismo patrón de controladores y comandos, especialmente los que gestionan “listas de cosas” (vlan_settings, vip_settings, alias, rutas, etc.).

### 4.1. Operaciones CRUD típicas

Para muchos controladores de “lista” verás comandos como:

- `get` → Obtener vista general / estructura.
- `get_item` → Leer un ítem concreto (`$uuid`).
- `search_item` → Buscar / listar ítems con paginación.
- `add_item` → Crear un nuevo ítem.
- `set_item` → Modificar un ítem existente (`$uuid`).
- `del_item` → Borrar un ítem (`$uuid`).
- `reconfigure` → Aplicar los cambios a la configuración activa.

Ejemplo genérico sobre `interfaces/vlan_settings`:

```text
POST /api/interfaces/vlan_settings/add_item
POST /api/interfaces/vlan_settings/set_item/<uuid>
POST /api/interfaces/vlan_settings/del_item/<uuid>
POST /api/interfaces/vlan_settings/reconfigure
```

### 4.2. Ejemplo: estado del firmware

Consultar si hay actualizaciones:

```bash
curl -k   -u "MI_KEY:MI_SECRET"   https://fw.example.com/api/core/firmware/status
```

- La respuesta indicará si el sistema se puede actualizar, el tamaño de descarga, número de paquetes, etc.

Lanzar una actualización:

```bash
curl -k -X POST   -u "MI_KEY:MI_SECRET"   https://fw.example.com/api/core/firmware/update
```

### 4.3. Ejemplo: servicios del sistema

El grid de **System → Diagnostics → Services** hace un `POST` a algo como:

```text
/api/core/service/search
```

con un cuerpo parecido a:

```json
{
  "current": 1,
  "rowCount": 20,
  "sort": {},
  "searchPhrase": ""
}
```

La respuesta es un grid con `rows` que incluye cada servicio y su estado (`running`, `locked`, etc.). Eso es muy cómodo para que un agente liste servicios y decida qué hacer.

---

## 5. Buenas prácticas para un agente de programación

### 5.1. Configuración centralizada

- Define en variables de entorno o config:
  - `OPNSENSE_URL` (e.g. `https://fw.example.com`)
  - `OPNSENSE_API_KEY`
  - `OPNSENSE_API_SECRET`
  - Opciones de verificación TLS (certificado propio o `verify=False` sólo en laboratorio).

### 5.2. Uso de credenciales

- Crea un **usuario específico para la API**.
- Asigna sólo los **“Effective Privileges”** necesarios (por ejemplo, solo Firewall + Routes si eso es lo que va a tocar).
- Rotar claves periódicamente si es posible.

### 5.3. Descubrimiento automático

Un agente puede:

1. Consultar la documentación de API para conocer módulos/controladores.
2. Usar patrones “estándar” (`add_item`, `set_item`, `del_item`, `get`, `search_item`, `reconfigure`) cuando existen.
3. Usar el navegador (o logs de desarrollo) para aprender el cuerpo JSON exacto que espera cada endpoint.

### 5.4. Validación antes de aplicar cambios

- Siempre que sea posible, **leer primero** el estado actual (por ejemplo, `get` o `search_item`) antes de “machacar” datos.
- Para cambios agresivos:
  - Hacer copia de la configuración (backup de OPNsense).
  - Probar primero en un entorno de pruebas.
- Muchos controladores separan “guardar” (`add_item`/`set_item`) de “aplicar” (`reconfigure`). Aprovecha eso para:
  - Hacer todos los cambios necesarios.
  - Aplicarlos todos juntos al final.

### 5.5. Manejo de errores

- Comprueba siempre:
  - Código HTTP (200, 400, 403, 500…).
  - Campo `status` o similar en el JSON devuelto (según el endpoint).
  - Mensajes de error específicos (`status_msg`, etc. cuando los haya).
- Si el endpoint devuelve un grid:
  - Valida que `total`, `rowCount` y `rows` tengan sentido antes de actuar.

### 5.6. Consideraciones de seguridad

- Usa HTTPS siempre.
- No loguear la `secret` en claro.
- En herramientas tipo n8n, Ansible, etc., guardar la clave/secret en credenciales cifradas, no en texto plano.
- Si sospechas de fuga de credenciales, revoca la clave desde la GUI y genera una nueva.

---

## 6. Patrones útiles para automatización

Aquí van algunas ideas concretas que un agente puede implementar usando la API de OPNsense:

1. **Gestión de servicios**
   - Enumerar servicios y sus estados (`core/service/search`).
   - Reiniciar o parar servicios concretos a través de los endpoints apropiados.

2. **Gestión de reglas / aliases (firewall)**
   - Resolver el UUID de un alias por nombre.
   - Activar/desactivar rutas o aliases alterando su configuración y llamando a `reconfigure`.

3. **Gestión de interfaces lógicas**
   - Crear VLANs, VxLANs, bridges… usando los controladores `*_settings` del módulo `interfaces`.
   - Reaplicar la configuración de red con `reconfigure` cuando sea necesario.

4. **Automatizar upgrades**
   - Consultar el estado del firmware de uno o varios firewalls.
   - Programar ventanas de actualización nocturnas mediante `firmware/update`.

---

## 7. Resumen rápido para el agente

- Las rutas de la API siguen siempre:  
  `https://<host>/api/<module>/<controller>/<command>/…`
- Autenticación: Basic Auth con **key/secret** generados por usuario.
- Solo se usan `GET` (consultar) y `POST` (cambiar/ejecutar).
- El cuerpo en `POST` es JSON; las respuestas también.
- Los parámetros concretos se aprenden:
  - Mirando la **API Reference** en la documentación.
  - Inspeccionando la WebGUI con las herramientas del navegador.
- Muchos controladores siguen el patrón `get` / `search_item` / `add_item` / `set_item` / `del_item` / `reconfigure`.
- Siempre validar respuestas y aplicar principios de mínimo privilegio y pruebas antes de cambiar un firewall en producción.

Con esta guía, un agente de programación debería ser capaz de descubrir endpoints específicos, construir las peticiones correctas y operar de forma segura sobre un OPNsense utilizando su API oficial.
