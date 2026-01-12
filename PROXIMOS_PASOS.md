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

## 🎨 Mejoras de UX en Dashboard

### Ideas para mejorar la interfaz:

1. **Dashboard Moderno**
   - Migrar a framework moderno (React, Vue, Svelte)
   - Gráficos interactivos con Chart.js o D3.js
   - Real-time updates con WebSockets
   - Dark mode

2. **Gestión Visual de Reglas**
   - Drag & drop para priorizar reglas
   - Preview de regla antes de guardar
   - Import/export de reglas (JSON/YAML)
   - Templates de reglas comunes

3. **Mapa de Ofensas**
   - Mapa mundial con GeoIP
   - Animaciones de ataques en tiempo real
   - Filtros por país/región
   - Heatmap de actividad

4. **Notificaciones**
   - Alertas push en navegador
   - Integración con Telegram/Slack/Discord
   - Email notifications
   - Webhooks configurables

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
