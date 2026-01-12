# Plan de Migración Arquitectónica - Mimosa

## Estado Actual

Se ha creado una **nueva arquitectura basada en Clean Architecture** que separa:
- **Domain** (modelos puros)
- **Repositories** (acceso a datos)
- **Services** (lógica de negocio)
- **Integrations** (firewalls, plugins)
- **API** (endpoints REST separados de UI)

## Nueva Estructura Creada

```
mimosa/
├── core/
│   ├── domain/                    # ✅ NUEVO
│   │   ├── __init__.py
│   │   ├── block.py              # BlockEntry
│   │   ├── offense.py            # OffenseRecord, IpProfile, WhitelistEntry
│   │   └── rule.py               # OffenseEvent, OffenseRule
│   │
│   ├── repositories/              # ✅ NUEVO
│   │   ├── __init__.py
│   │   ├── block_repository.py   # Persistencia de bloqueos
│   │   ├── offense_repository.py # (pendiente)
│   │   └── rule_repository.py    # (pendiente)
│   │
│   ├── services/                  # ✅ NUEVO
│   │   ├── __init__.py
│   │   ├── blocking_service.py   # (pendiente)
│   │   ├── offense_service.py    # (pendiente)
│   │   └── rule_service.py       # (pendiente)
│   │
│   ├── integrations/              # ✅ NUEVO
│   │   ├── firewall/             # (mover api.py, sense.py, pfrest.py)
│   │   └── plugins/              # (mover proxytrap, portdetector, mimosanpm)
│   │
│   └── [archivos legacy]          # ⚠️ MANTENER TEMPORALMENTE
│       ├── blocking.py
│       ├── offenses.py
│       ├── rules.py
│       └── ...
│
├── api/                           # ✅ NUEVO
│   └── v1/                       # API REST v1
│       ├── __init__.py
│       ├── blocks.py             # (pendiente)
│       ├── offenses.py           # (pendiente)
│       └── rules.py              # (pendiente)
│
└── web/                          # Existente - refactorizar
    ├── app.py                    # Separar endpoints de UI
    └── config.py
```

## Estrategia de Migración Incremental

Para **evitar romper la aplicación**, usaremos una migración por fases:

### Fase 1: Coexistencia (Actual) ✅

**Estado:** Los archivos legacy mantienen sus clases originales pero importan los modelos de `domain/`

**Implementación:**
```python
# mimosa/core/blocking.py (legacy)
from mimosa.core.domain import BlockEntry  # ✅ Re-export desde domain

# El resto del código sigue igual
class BlockManager:
    # ... código existente ...
```

**Ventajas:**
- ✅ No rompe imports existentes
- ✅ Permite testing gradual
- ✅ Backward compatible

### Fase 2: Migración de Repositories (Próximo)

**Objetivo:** Extraer lógica de persistencia de BlockManager, OffenseStore, OffenseRuleStore

**Implementación:**
```python
# mimosa/core/repositories/offense_repository.py (nuevo)
class OffenseRepository:
    def save(self, offense: OffenseRecord) -> OffenseRecord: ...
    def find_by_ip(self, ip: str) -> List[OffenseRecord]: ...
    # ... solo CRUD operations ...

# mimosa/core/offenses.py (legacy - usar repository internamente)
from mimosa.core.repositories import OffenseRepository

class OffenseStore:
    def __init__(self, ...):
        self._repository = OffenseRepository(db_path)

    def record(self, ...):
        # Lógica de enriquecimiento (GeoIP, etc.)
        record = OffenseRecord(...)
        self._repository.save(record)
```

**Ventajas:**
- ✅ Separación de concerns
- ✅ Testeable sin BD (mocks)
- ✅ Mantiene API pública existente

### Fase 3: Migración de Services

**Objetivo:** Extraer lógica de negocio pura

**Implementación:**
```python
# mimosa/core/services/blocking_service.py (nuevo)
class BlockingService:
    def __init__(self, repository: BlockRepository):
        self._repository = repository
        self._lock = threading.Lock()

    def add_block(self, ip: str, reason: str, ...) -> BlockEntry:
        # Validaciones
        # Lógica de negocio
        # Llama a repository

    def get_expired_blocks(self, now: datetime) -> List[BlockEntry]:
        blocks = self._repository.find_all_active()
        return [b for b in blocks if b.is_expired(now)]

# mimosa/core/blocking.py (legacy - wrapper)
from mimosa.core.services import BlockingService

class BlockManager:
    def __init__(self, ...):
        self._service = BlockingService(BlockRepository(db_path))

    def add(self, ip, reason, ...):
        return self._service.add_block(ip, reason, ...)
```

### Fase 4: Migración de API Endpoints

**Objetivo:** Separar endpoints REST de la UI

**Implementación:**
```python
# mimosa/api/v1/blocks.py (nuevo)
from fastapi import APIRouter
from mimosa.core.services import BlockingService

router = APIRouter(prefix="/api/v1/blocks")

@router.get("/")
def list_blocks(service: BlockingService = Depends(get_blocking_service)):
    return service.list_active_blocks()

# mimosa/web/app.py (refactorizar)
from mimosa.api.v1 import blocks, offenses, rules

app = FastAPI()
app.include_router(blocks.router)
app.include_router(offenses.router)
app.include_router(rules.router)
```

### Fase 5: Migración de Integraciones

**Objetivo:** Organizar integraciones en carpetas dedicadas

**Implementación:**
```bash
# Mover archivos
mv mimosa/core/api.py mimosa/core/integrations/firewall/base.py
mv mimosa/core/sense.py mimosa/core/integrations/firewall/opnsense.py
mv mimosa/core/pfrest.py mimosa/core/integrations/firewall/pfsense.py

mv mimosa/core/proxytrap.py mimosa/core/integrations/plugins/proxytrap.py
mv mimosa/core/portdetector.py mimosa/core/integrations/plugins/portdetector.py
mv mimosa/core/mimosanpm.py mimosa/core/integrations/plugins/mimosanpm.py
```

**Re-exports en archivos legacy:**
```python
# mimosa/core/api.py (mantener para backward compatibility)
from mimosa.core.integrations.firewall.base import *
```

### Fase 6: Eliminación de Legacy (Final)

Una vez que todos los imports estén actualizados:
- Eliminar archivos legacy en `mimosa/core/`
- Actualizar documentación
- Lanzar versión mayor (2.0.0)

## Checklist de Migración

### Fase 1: Coexistencia ✅
- [x] Crear estructura de directorios
- [x] Extraer modelos de dominio (Block, Offense, Rule)
- [x] Crear BlockRepository
- [ ] Actualizar blocking.py para importar desde domain
- [ ] Actualizar offenses.py para importar desde domain
- [ ] Actualizar rules.py para importar desde domain
- [ ] Tests de modelos de dominio

### Fase 2: Repositories
- [ ] Crear OffenseRepository
- [ ] Crear RuleRepository
- [ ] Crear WhitelistRepository
- [ ] Integrar repositories en stores existentes
- [ ] Tests de repositories

### Fase 3: Services
- [ ] Crear BlockingService
- [ ] Crear OffenseService
- [ ] Crear RuleService
- [ ] Integrar services en managers existentes
- [ ] Tests de services

### Fase 4: API v1
- [ ] Extraer endpoints de blocks
- [ ] Extraer endpoints de offenses
- [ ] Extraer endpoints de rules
- [ ] Extraer endpoints de firewalls
- [ ] Extraer endpoints de plugins
- [ ] Tests de API endpoints

### Fase 5: Integraciones
- [ ] Mover firewalls a integrations/firewall/
- [ ] Mover plugins a integrations/plugins/
- [ ] Crear re-exports para backward compatibility
- [ ] Actualizar imports

### Fase 6: Cleanup
- [ ] Eliminar archivos legacy
- [ ] Actualizar toda la documentación
- [ ] Actualizar CHANGELOG
- [ ] Release 2.0.0

## Ventajas de Esta Arquitectura

### 1. **Testabilidad**
```python
# Antes: difícil de testear (acoplado a SQLite)
def test_block_manager():
    manager = BlockManager(db_path="test.db")
    manager.add("1.2.3.4", "test")
    # Necesita BD real

# Después: fácil de testear (dependency injection)
def test_blocking_service():
    mock_repo = MagicMock(spec=BlockRepository)
    service = BlockingService(mock_repo)
    service.add_block("1.2.3.4", "test")
    mock_repo.save.assert_called_once()
```

### 2. **Separación de Concerns**
- **Domain:** Modelos puros, sin lógica de infraestructura
- **Repositories:** Solo CRUD, sin lógica de negocio
- **Services:** Lógica de negocio pura
- **API:** Capa de presentación

### 3. **Mantenibilidad**
- Cambios en BD no afectan lógica de negocio
- Cambios en lógica no afectan API
- Fácil agregar nuevas interfaces (CLI, gRPC)

### 4. **Escalabilidad**
- Services pueden ser stateless
- Repositories pueden usar cache distribuido
- Fácil horizontal scaling

## Orden de Ejecución Recomendado

1. **Hoy:** Completar Fase 1 (coexistencia)
2. **Esta semana:** Fase 2 (repositories)
3. **Próxima semana:** Fase 3 (services)
4. **Próximo mes:** Fases 4-5 (API + integraciones)
5. **Futuro:** Fase 6 (cleanup)

## Rollback Plan

Si algo falla durante la migración:

1. **Fase 1-3:** Los archivos legacy siguen funcionando, simplemente revertir imports
2. **Fase 4-5:** Mantener re-exports hasta validar completamente
3. **Git tags:** Crear tag antes de cada fase para rollback rápido

## Conclusión

Esta migración es **segura y gradual**. No romperá funcionalidad existente gracias a:
- Re-exports en archivos legacy
- Coexistencia temporal de ambas arquitecturas
- Backward compatibility en toda la migración

El resultado final será un código más **limpio, testeable y escalable**.

---

**Próxima Acción:** Actualizar imports en `blocking.py`, `offenses.py` y `rules.py` para usar modelos desde `domain/`.
