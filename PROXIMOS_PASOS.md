# Próximos Pasos - Mimosa

## 🎯 Roadmap de Mejoras Pendientes

### Fase 1: Seguridad y Autenticación (Alta Prioridad)

**Objetivo:** Proteger acceso a la aplicación

**Tareas:**
1. **Autenticación en Dashboard**
   - Implementar OAuth2 o JWT
   - Login page con credenciales configurables
   - Roles (admin, viewer)

2. **HTTPS Obligatorio**
   - Documentar setup de reverse proxy
   - Agregar middleware de redirección HTTP→HTTPS
   - Configurar HSTS headers

3. **Rate Limiting**
   - Limitar endpoints de API
   - Protección contra brute-force
   - IP-based throttling

**Estimación:** 2 semanas

---

### Fase 2: Observabilidad (Recomendado)

**Objetivo:** Visibilidad completa del sistema

**Tareas:**
1. **Métricas Prometheus**
   ```python
   # Métricas a exportar:
   - mimosa_blocks_total{source="plugin", firewall="fw1"}
   - mimosa_offenses_total{severity="high", plugin="proxytrap"}
   - mimosa_firewall_latency_seconds{operation="block_ip"}
   - mimosa_cache_hits_total / mimosa_cache_misses_total
   ```

2. **Structured Logging**
   - Migrar a `structlog`
   - JSON logs para ingestión
   - Correlación con trace IDs

3. **Health Checks**
   ```python
   GET /health
   {
     "status": "healthy",
     "firewall": "connected",
     "database": "ok",
     "plugins": {
       "proxytrap": "running",
       "portdetector": "running"
     }
   }
   ```

4. **Dashboard de Métricas**
   - Grafana dashboards pre-configurados
   - Alertas de Prometheus (firewall down, high offense rate)
5. **Integracion con homeassistant**
   - Estadisticas, alertas, activar/desactivar las reglas de firewall bloquear/desbloquear ips
6. **Bot de Telegram**
   Estadisticas, alertas, activar/desactivar las reglas de firewall, bloquear/desbloquear ips
**Estimación:** 2 semanas

---

### Fase 3: Performance y Escalabilidad (Opcional)

**Objetivo:** Soportar alta concurrencia

**Tareas:**
1. **Async/Await Migration**
   - Migrar a `aiosqlite`
   - Usar `httpx.AsyncClient` para firewall
   - FastAPI completamente async

   **Beneficios:**
   - 10x más requests/segundo
   - Menor uso de memoria (menos threads)

2. **Redis Cache**
   - Cache distribuido para `gateway_cache`
   - Sesiones de usuario compartidas
   - Pub/Sub para eventos entre instancias

3. **PostgreSQL Migration**
   - Mejor concurrencia de escritura
   - Índices avanzados
   - Full-text search en ofensas

4. **Horizontal Scaling**
   - Múltiples instancias detrás de load balancer
   - Sesiones compartidas en Redis
   - Leader election para tareas periódicas

**Prioridad:** Baja (solo si necesitas >1000 req/s)
**Estimación:** 4 semanas

---

### Fase 4: Features Avanzados (Futuro)

**Ideas a explorar:**

1. **Machine Learning**
   - Detección de anomalías basada en patrones
   - Clasificación automática de severidad
   - Predicción de ataques

2. **Integración con SIEM**
   - Exportar a Splunk, ELK, Wazuh
   - Formato CEF (Common Event Format)
   - Alertas bidireccionales

3. **Gestión Multi-Tenant**
   - Múltiples organizaciones en una instancia
   - Aislamiento de datos
   - Facturación por uso

4. **Plugin Marketplace**
   - Repositorio de plugins comunitarios
   - Instalación one-click
   - Versionado y compatibilidad

---

## 🔧 Mejoras Técnicas Específicas

### 1. Índices de Base de Datos

**Problema:** Queries lentas en tablas grandes

**Solución:**
```sql
-- En mimosa/core/storage.py, agregar a ensure_database():

CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip);
CREATE INDEX IF NOT EXISTS idx_blocks_active ON blocks(active, expires_at);
CREATE INDEX IF NOT EXISTS idx_offenses_ip_created ON offenses(source_ip, created_at);
CREATE INDEX IF NOT EXISTS idx_offenses_severity ON offenses(severity);
```

**Impacto:** 10-100x más rápido en queries de lookup

---

### 2. Configuración Externa

**Problema:** Configuración hardcodeada en código

**Solución:**
```yaml
# mimosa.yaml
server:
  host: 0.0.0.0
  port: 8000
  workers: 4

security:
  auth_enabled: true
  jwt_secret: ${JWT_SECRET}
  session_ttl: 3600

cache:
  gateway_ttl: 300
  type: redis  # o "memory"
  redis_url: redis://localhost:6379

database:
  path: data/mimosa.db
  pool_size: 10

firewall:
  sync_interval: 300
  default_block_duration: 60

plugins:
  proxytrap:
    enabled: true
    port: 8080
  portdetector:
    enabled: true
    ranges:
      tcp: 10000-20000
      udp: 10000-20000

monitoring:
  prometheus:
    enabled: true
    port: 9090
  logging:
    level: INFO
    format: json
```

---

### 3. Testing Exhaustivo

**Estructura recomendada:**

```
tests/
├── unit/
│   ├── test_blocking.py          # BlockManager tests
│   ├── test_rules.py              # RuleManager tests
│   ├── test_offenses.py           # OffenseStore tests
│   └── test_concurrency.py        # Thread-safety tests
├── integration/
│   ├── test_firewall_opnsense.py  # OPNsense integration
│   ├── test_firewall_pfsense.py   # pfSense integration
│   └── test_plugins.py            # Plugin integration
├── performance/
│   ├── test_load.py               # Locust load tests
│   └── test_benchmark.py          # Benchmark suite
└── e2e/
    └── test_full_workflow.py      # End-to-end scenarios
```

**Agregar test de concurrencia:**
```python
# tests/unit/test_concurrency.py

import threading
from concurrent.futures import ThreadPoolExecutor
from mimosa.core.blocking import BlockManager

def test_block_manager_concurrent_adds():
    """Verifica que múltiples threads pueden agregar bloques sin race conditions."""
    block_manager = BlockManager()

    def add_block(ip_suffix: int):
        for i in range(100):
            block_manager.add(f"192.168.1.{ip_suffix}", "test")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(add_block, i) for i in range(10)]
        for future in futures:
            future.result()

    # Verificar integridad
    blocks = block_manager.list()
    assert len(blocks) == 1000  # 10 IPs * 100 inserts cada una
    assert len(set(b.ip for b in blocks)) == 10
```

---

### 4. CI/CD Pipeline

**Recomendación:**

```yaml
# .github/workflows/ci.yml

name: CI/CD Pipeline

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov

      - name: Run tests
        run: pytest --cov=mimosa tests/

      - name: Upload coverage
        uses: codecov/codecov-action@v2

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2

      - name: Lint with ruff
        run: |
          pip install ruff
          ruff check mimosa/

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2

      - name: Security scan
        run: |
          pip install bandit safety
          bandit -r mimosa/
          safety check

  build:
    needs: [test, lint, security]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Build Docker image
        run: docker build -t mimosa:${{ github.sha }} .

      - name: Push to registry
        if: github.ref == 'refs/heads/main'
        run: |
          docker tag mimosa:${{ github.sha }} ghcr.io/user/mimosa:latest
          docker push ghcr.io/user/mimosa:latest
```

---

## 📚 Documentación Pendiente

### Crear estos documentos:

1. **DEPLOYMENT.md**
   - Guía de instalación en producción
   - Configuración de reverse proxy (nginx/Caddy)
   - Setup de HTTPS con Let's Encrypt
   - Backup y recovery procedures

2. **API.md**
   - Documentación completa de endpoints
   - Ejemplos de uso con curl
   - Rate limits y autenticación
   - Códigos de error

3. **PLUGINS.md**
   - Guía para desarrolladores de plugins
   - API de plugin interface
   - Ejemplos de plugins custom
   - Best practices

4. **ARCHITECTURE.md**
   - Diagramas de componentes
   - Flujo de datos
   - Decisiones de diseño
   - Patrones utilizados

---

## 🎨 Modernización de UI (Prioridad Media-Alta)

**Problema Actual:**
- 4,208 líneas de HTML total (3,238 solo en admin.html)
- CSS/JS inline dificulta mantenimiento
- Sin componentes reutilizables
- Dificultad para compartir UI con integraciones (Home Assistant)

**Estado actual:**
- Templates Jinja2 con CSS/JS inline
- Vanilla JavaScript para interactividad
- Chart.js + Leaflet (mantener)
- Design system dark mode funcional

---

### Opción 1: Svelte + SvelteKit ⭐ RECOMENDADA

**Por qué Svelte:**
- ✅ Bundle mínimo (~3KB vs 40KB React) - crítico para acceso móvil
- ✅ Sintaxis limpia sin JSX
- ✅ Reactivity nativa sin hooks
- ✅ TypeScript built-in
- ✅ Excelente para dashboards en tiempo real
- ✅ Componentes reutilizables para Home Assistant

**Arquitectura propuesta:**
```
mimosa-ui/                    # Nueva SPA separada
├── src/
│   ├── lib/
│   │   ├── components/
│   │   │   ├── ui/           # Design system
│   │   │   │   ├── Card.svelte
│   │   │   │   ├── Table.svelte
│   │   │   │   ├── Modal.svelte
│   │   │   │   ├── Toggle.svelte
│   │   │   │   └── Button.svelte
│   │   │   ├── charts/
│   │   │   │   ├── TimelineChart.svelte
│   │   │   │   ├── RatioChart.svelte
│   │   │   │   └── Heatmap.svelte
│   │   │   └── dashboard/
│   │   │       ├── StatsGrid.svelte
│   │   │       ├── LiveFeed.svelte
│   │   │       ├── TopIPs.svelte
│   │   │       └── PluginStats.svelte
│   │   ├── api/              # Cliente API tipado
│   │   │   ├── client.ts
│   │   │   ├── types.ts
│   │   │   └── websocket.ts  # WebSocket para live updates
│   │   └── stores/           # Estado global reactivo
│   │       ├── stats.ts
│   │       ├── firewalls.ts
│   │       └── auth.ts
│   └── routes/
│       ├── +layout.svelte    # Layout común
│       ├── +page.svelte      # Dashboard
│       ├── login/
│       │   └── +page.svelte
│       └── admin/
│           ├── +page.svelte
│           ├── blocks/
│           ├── offenses/
│           ├── firewall/
│           └── whitelist/
├── vite.config.ts
├── tsconfig.json
└── package.json
```

**Plan de implementación (6-7 semanas):**

**Semana 1-2: Setup + Design System**
- [ ] Inicializar proyecto SvelteKit con TypeScript
- [ ] Migrar tokens CSS a variables (`tokens.ts`)
- [ ] Crear componentes base:
  ```typescript
  // src/lib/components/ui/Card.svelte
  // src/lib/components/ui/Table.svelte
  // src/lib/components/ui/Button.svelte
  // src/lib/components/ui/Modal.svelte
  // src/lib/components/ui/Toggle.svelte
  ```
- [ ] Cliente API con tipos generados desde FastAPI
  ```typescript
  // src/lib/api/client.ts
  export const api = {
    stats: () => fetch('/api/stats').then(r => r.json()),
    blocks: {
      list: () => fetch('/api/blocks').then(r => r.json()),
      create: (data) => fetch('/api/blocks', { method: 'POST', body: JSON.stringify(data) })
    }
  }
  ```

**Semana 3-4: Dashboard**
- [ ] Stats grid con auto-refresh
  ```svelte
  <script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { statsStore } from '$lib/stores/stats';

    let interval: number;
    onMount(() => {
      statsStore.fetch();
      interval = setInterval(() => statsStore.fetch(), 60000);
    });
    onDestroy(() => clearInterval(interval));
  </script>

  <div class="stats-grid">
    {#each $statsStore.cards as stat}
      <StatsCard {stat} />
    {/each}
  </div>
  ```
- [ ] Charts con `svelte-chartjs`
- [ ] Mapa con `svelte-leaflet`
- [ ] Live feed con WebSocket (reemplazar polling actual)
  ```typescript
  // src/lib/api/websocket.ts
  export function connectLiveFeed() {
    const ws = new WebSocket('ws://localhost:8000/ws/live');
    return {
      subscribe: (callback) => {
        ws.onmessage = (e) => callback(JSON.parse(e.data));
      }
    }
  }
  ```

**Semana 5-6: Admin Panel**
- [ ] Tabs de configuración
- [ ] CRUD de firewalls con validación
- [ ] Inspector de IPs con búsqueda
- [ ] Gestión de reglas (drag & drop para prioridad)
- [ ] Whitelist manager

**Semana 7: Polish & Deploy**
- [ ] Dark/light mode toggle (mantener dark por defecto)
- [ ] Responsive mobile (breakpoints en 640px, 768px, 1024px)
- [ ] Loading states y skeletons
- [ ] Error boundaries con retry
- [ ] E2E tests con Playwright
- [ ] Build production y deploy junto a FastAPI:
  ```dockerfile
  # Dockerfile - multi-stage
  FROM node:18 AS frontend-builder
  WORKDIR /app/mimosa-ui
  COPY mimosa-ui/package*.json ./
  RUN npm ci
  COPY mimosa-ui/ ./
  RUN npm run build

  FROM python:3.11
  COPY --from=frontend-builder /app/mimosa-ui/build /app/static
  # ... resto del build Python
  ```

**Ventajas:**
- 50% reducción de código estimada
- Hot reload instantáneo en desarrollo
- TypeScript para API safety
- Componentes compartibles con Home Assistant
- SSR opcional (mejor SEO si se necesita público)

**Contras:**
- Requiere separar completamente backend/frontend
- Curva de aprendizaje (pequeña, ~2-3 días)
- Despliegue ligeramente más complejo

---

### Opción 2: HTMX + Alpine.js (Conservadora)

**Por qué HTMX:**
- ✅ Mantiene arquitectura Jinja2 actual
- ✅ Interactividad sin frameworks pesados
- ✅ SSR-first (buen SEO)
- ✅ Migración incremental posible

**Cambios mínimos:**
```html
<!-- Antes: JavaScript manual -->
<form onsubmit="blockIp(event)">...</form>

<!-- Después: HTMX -->
<form hx-post="/api/blocks"
      hx-target="#blocks-table"
      hx-swap="afterbegin"
      hx-indicator="#spinner">
  <input name="ip" required />
  <button type="submit">Bloquear</button>
</form>

<!-- Alpine.js para tabs -->
<div x-data="{ tab: 'config' }">
  <button @click="tab = 'config'" :class="{ active: tab === 'config' }">
    Configuración
  </button>
  <div x-show="tab === 'config'">...</div>
</div>
```

**Estructura:**
```
mimosa/web/
├── static/
│   ├── css/
│   │   ├── base.css         # Extraer del <style> inline
│   │   ├── components.css   # Cards, tables, forms
│   │   └── dashboard.css
│   └── js/
│       ├── alpine-setup.js
│       └── charts.js        # Mantener Chart.js
└── templates/
    ├── components/          # Partials reutilizables
    │   ├── stats_card.html
    │   ├── table.html
    │   └── modal.html
    └── pages/
```

**Ventajas:**
- ✅ Migración incremental (1-2 semanas)
- ✅ Mantiene arquitectura actual
- ✅ Menos complejidad de despliegue

**Contras:**
- ⚠️ No resuelve problema de 3,238 líneas en admin
- ⚠️ Limitado para apps complejas
- ⚠️ Sin componentes para Home Assistant

---

### Opción 3: Vue 3 + Vite (Híbrida)

**Migración progresiva:**
1. **Fase 1**: Admin panel → Vue SPA
2. **Fase 2**: Dashboard → Mantener o migrar
3. **Fase 3**: Componentes compartidos

**Por qué Vue:**
- ✅ Puede empezar con un solo tab
- ✅ Composition API (similar a React hooks)
- ✅ Gran ecosistema (Pinia, VueRouter)

**Ventajas:**
- ✅ Migración por partes (menos riesgo)
- ✅ Gran documentación

**Contras:**
- ⚠️ Más pesado que Svelte (~35KB gzipped)
- ⚠️ Sintaxis más verbose

---

### 🎯 Recomendación Final: Svelte + SvelteKit

**Razones específicas para Mimosa:**
1. Tamaño: 3,238 líneas en admin.html es insostenible a largo plazo
2. Home Assistant: Podrás compartir componentes Svelte directamente
3. Performance: Dashboards en tiempo real se benefician de reactivity nativa
4. Bundle size: Crítico para acceso desde móvil o redes lentas
5. DX: Hot reload + TypeScript = desarrollo 3x más rápido

**Dependencias a añadir:**
```json
{
  "dependencies": {
    "@sveltejs/kit": "^2.0.0",
    "svelte": "^4.2.0",
    "chart.js": "^4.4.0",
    "svelte-chartjs": "^3.1.0",
    "leaflet": "^1.9.4",
    "svelte-leaflet": "^0.8.0"
  },
  "devDependencies": {
    "@playwright/test": "^1.40.0",
    "@sveltejs/adapter-static": "^3.0.0",
    "@sveltejs/vite-plugin-svelte": "^3.0.0",
    "typescript": "^5.3.0",
    "vite": "^5.0.0"
  }
}
```

**Backend changes necesarios:**
```python
# mimosa/web/app.py - Servir SPA build

from fastapi.staticfiles import StaticFiles

# Montar build de Svelte
app.mount("/assets", StaticFiles(directory="static/assets"), name="assets")

# Catch-all para SPA routing
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """Sirve la SPA de Svelte para todas las rutas no-API."""
    if full_path.startswith("api/"):
        raise HTTPException(404)
    return FileResponse("static/index.html")
```

---

### 💡 Siguientes Pasos

**Antes de empezar:**
1. [ ] Crear branch `feature/ui-modernization`
2. [ ] Documentar API actual con OpenAPI para generar tipos
3. [ ] Decidir: ¿WebSocket para live updates? (recomendado)

**Primeras tareas:**
1. [ ] `npm create svelte@latest mimosa-ui`
2. [ ] Setup de tokens CSS como variables TS
3. [ ] Componente `<Card>` (aparece 9 veces, alto ROI)
4. [ ] Cliente API tipado
5. [ ] Página de login (necesaria para la Fase 1: Autenticación)

**Nota:** Esta modernización se alinea perfectamente con:
- Fase 1 (Autenticación): Login page moderno
- Fase 2 (Home Assistant): Componentes reutilizables
- Fase 2 (Telegram Bot): API consistente

---

### 🎨 Design System a Extraer

**Componentes prioritarios (por frecuencia de uso):**

1. **`<StatsCard>`** - Aparece 9 veces
   ```svelte
   <script lang="ts">
     export let title: string;
     export let value: number;
     export let subtitle: string;
     export let trend: 'up' | 'down' | 'neutral' = 'neutral';
   </script>
   ```

2. **`<DataTable>`** - Aparece 12+ veces
   - Props: columns, data, sortable, onRowClick
   - Features: sorting, pagination, search

3. **`<Modal>`** - Múltiples variantes
   - Confirm, Form, Info

4. **`<TabGroup>`** - Dashboard y admin
   - Reactivo, persiste en localStorage

5. **`<Toggle>`** - Switches de firewall
   - Estados: enabled/disabled/loading

**Tokens CSS a migrar:**
```typescript
// src/lib/tokens.ts
export const colors = {
  bg: '#0f172a',
  card: '#111827',
  text: '#e2e8f0',
  muted: '#94a3b8',
  accent: '#38bdf8',
  success: '#4ade80',
  warning: '#fbbf24',
  error: '#f87171',
} as const;

export const spacing = {
  xs: '4px',
  sm: '8px',
  md: '12px',
  lg: '16px',
  xl: '24px',
} as const;

export const borderRadius = {
  sm: '10px',
  md: '12px',
  lg: '16px',
  full: '999px',
} as const;
```

---

### 📊 Estimación Comparativa

| Opción | Tiempo | Complejidad | Mantenibilidad | Performance | Reutilización |
|--------|--------|-------------|----------------|-------------|---------------|
| **Svelte** | 6-7 sem | Media | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **HTMX** | 1-2 sem | Baja | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| **Vue** | 5-6 sem | Media | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

---

## 🔐 Hardening de Seguridad

### Checklist de producción:

- [ ] HTTPS obligatorio con certificado válido
- [ ] Autenticación en todos los endpoints sensibles
- [ ] Rate limiting configurado
- [ ] CSRF protection en forms
- [ ] Cabeceras de seguridad:
  ```python
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  X-XSS-Protection: 1; mode=block
  Strict-Transport-Security: max-age=31536000
  Content-Security-Policy: default-src 'self'
  ```
- [ ] Input validation en todos los endpoints
- [ ] SQL injection protection (parametrized queries ✅)
- [ ] Secrets en variables de entorno (no en código)
- [ ] Logging de accesos y cambios
- [ ] Backup automático de BD
- [ ] Firewall rules para restringir acceso

---

## 💡 Siguiente Acción Recomendada

**Prioridad Inmediata:** Implementar autenticación básica en el dashboard con JWT o API keys.

**Prioridad Media:** Agregar métricas de Prometheus para observabilidad.

**Largo Plazo:** Async migration si necesitas escalar.
