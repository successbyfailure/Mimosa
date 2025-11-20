# Mimosa
Mimosa es un sistema de defensa para homelabs y entusiastas. Este repositorio se ha reducido a un esqueleto mínimo centrado en el núcleo de bloqueos para poder construir la funcionalidad principal antes de añadir módulos extra (dashboard, bots o plugins de ingestión).

## ¿Por qué “Mimosa”?
La Mimosa pudica repliega sus hojas ante el mínimo contacto. La meta de este proyecto es reaccionar igual de rápido ante señales hostiles, coordinando bloqueos ligeros y temporales sobre el firewall del homelab.

## Qué incluye el esqueleto
- **Core API** (`mimosa/core/api.py`): orquesta las operaciones de bloqueo y ofrece un punto de entrada común.
- **Gestor de bloqueos en memoria** (`mimosa/core/blocking.py`): registra bloqueos temporales con historial básico.
- **Cliente pfSense/OPNsense** (`mimosa/core/pfsense.py`): integra el núcleo con el firewall mediante su API REST.
- **Almacén de ofensas** (`mimosa/core/offenses.py`): guarda eventos sospechosos en SQLite para futura correlación.
- **Detección mínima** (`mimosa/core/detection.py`): ejemplo trivial de detector que puede ampliarse más adelante.

## Uso rápido
1. Instala las dependencias: `pip install -r requirements.txt`.
2. Configura tus credenciales del firewall y la ruta de base de datos mediante variables de entorno (ver `env.example`).
3. Crea la API núcleo y el cliente pfSense:
   ```python
   from mimosa.core.api import CoreAPI
   from mimosa.core.blocking import BlockManager
   from mimosa.core.pfsense import PFSenseClient

   firewall = PFSenseClient(
       base_url="https://firewall.local",
       api_key="API_KEY",
       api_secret="API_SECRET",
       alias_name="mimosa_blocklist",
   )

   api = CoreAPI(firewall, block_manager=BlockManager())
   api.block_ip("203.0.113.10", reason="Prueba de bloqueo", duration_minutes=60)
   ```

## Próximos pasos
Se añadirán más adelante el dashboard web, los plugins de ingestión (proxy trap, rangos de puertos) y la integración con bots. Este esqueleto pretende ser la base estable sobre la que construir esas piezas.
