# pfSense REST API (pfrest.org)

Guía completa para agentes de programación

## 1. Conceptos básicos

La API REST de pfSense (pfrest.org) expone endpoints completos para
gestionar reglas, interfaces, usuarios, rutas, gateways, servicios y
toda la configuración del firewall. Está basada en OpenAPI 3.0 y ofrece
acceso REST + GraphQL.

### Base URL típica

    https://<host>/api/v2/

### Documentación interactiva

    https://<host>/api-docs/

------------------------------------------------------------------------

## 2. Autenticación

Métodos soportados: - **Basic Auth** - **API Key** (`X-API-Key`) - **JWT
Bearer** (`Authorization: Bearer <token>`)

### API Key

Recomendado para agentes:

    X-API-Key: <key>

### JWT

Token obtenido vía:

    POST /api/v2/auth/jwt

------------------------------------------------------------------------

## 3. Endpoints singulares vs plurales

### Singulares

Operan sobre un solo objeto:

    /api/v2/firewall/rule
    /api/v2/user
    /api/v2/interface

### Plurales

Operan sobre colecciones:

    /api/v2/firewall/rules
    /api/v2/users
    /api/v2/interfaces

------------------------------------------------------------------------

## 4. IDs y parent_id

### ID

-   Es un **índice**, NO persistente.
-   Cambia si se borran o reordenan elementos.
-   No debe cachearse.

### parent_id

Usado en objetos anidados:

    id: 0
    aliases: [
      { parent_id: 0, id: 0 },
      { parent_id: 0, id: 1 }
    ]

------------------------------------------------------------------------

## 5. Content-Type y Accept

### Content-Type

-   `application/json` **(recomendado)**
-   `application/x-www-form-urlencoded`

### Accept

-   `application/json`

------------------------------------------------------------------------

## 6. Queries, filtros, ordenación, paginación

### Filtros

Formato:

    campo__filtro=valor

Filtros soportados: - `exact` - `startswith` - `endswith` - `contains` -
`lt`, `lte`, `gt`, `gte` - `regex` - `format` (ipv4, ipv6, subnet, fqdn,
url...)

Ejemplo:

    ?interface__exact=wan&action__exact=block

### Ordenación

    sort_by=name
    sort_order=asc
    sort_flags=

### Paginación

    limit=100
    offset=0

------------------------------------------------------------------------

## 7. HATEOAS

Al activarlo en los ajustes de la API, cada objeto incluye:

    _links.self
    _links.update
    _links.delete
    _links.next
    _links.prev
    _links["pfsense:field:<campo>"]

Permite navegación automática entre objetos.

------------------------------------------------------------------------

## 8. Parámetros de control

### append (PATCH)

Añadir en vez de reemplazar arrays:

    "append": true

### apply

Aplicar configuración tras la llamada:

    "apply": true

### async

    "async": true

### placement

Colocar en una posición concreta de la lista.

------------------------------------------------------------------------

## 9. Flujos típicos

### Listar reglas filtradas

    GET /api/v2/firewall/rules?interface__exact=wan&action__exact=block

### Crear una regla

    POST /api/v2/firewall/rule
    {
      "interface": "wan",
      "action": "block",
      "protocol": "tcp",
      "src": "any",
      "dst": "1.2.3.4",
      "dst_port": "22",
      "descr": "Regla creada",
      "apply": true
    }

### Actualizar reglas en lote

1.  GET reglas
2.  Modificar lista localmente
3.  PUT lista completa
4.  Aplicar:

```{=html}
<!-- -->
```
    POST /api/v2/firewall/apply

### Uso de HATEOAS

Ejemplo de `_links`:

    _links.self.href
    _links.update.href
    _links["pfsense:field:gateway"].href

------------------------------------------------------------------------

## 10. GraphQL

La API expone un endpoint GraphQL útil para consultas complejas e
introspección.

------------------------------------------------------------------------

## 11. Recomendaciones para agentes

1.  Usar API Key.
2.  No confiar en IDs → siempre re-resolver objetos por filtros.
3.  Activar HATEOAS si está disponible.
4.  Usar filtros + paginación.
5.  Separar editar y aplicar en cambios masivos.
6.  Respetar Content-Type.
7.  Manejar errores y timeouts.

------------------------------------------------------------------------

## 12. Resumen

-   REST + GraphQL completos.
-   Auth: API Key o JWT.
-   IDs no persistentes → siempre filtrar.
-   Soporta filtros avanzados, ordenación, paginación.
-   HATEOAS facilita navegación.
-   apply/async/append para controlar cambios.
-   Ideal para agentes que manipulan firewall dinámicamente.
