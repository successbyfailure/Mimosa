# Mimosa
Mimosa es un sistema de defensa para homelabs y entusiastas creado con nocturnidad e IA. Este repositorio se ha reducido a un esqueleto mínimo centrado en el núcleo de bloqueos para poder construir la funcionalidad principal antes de añadir módulos extra (dashboard, bots o plugins de ingestión).

## ¿Por qué “Mimosa”?
La Mimosa pudica repliega sus hojas ante el mínimo contacto. La meta de este proyecto es reaccionar igual de rápido ante señales hostiles, coordinando bloqueos ligeros y temporales sobre el firewall del homelab.

## ¿Cómo funciona?
Mimosa esta pensado para correr en una mv detras de un firewall pfSense o OpnSense, tiene plugins que detectan diferentes ofensas y se comunica via api con el firewall para bloquear temporalmente las ips que ofenden.

## Plugins planificados
 - Detector de conexiones tcp/udp:
   El firewall le envia por nat todos los puertos que no estan en uso a mimosa, cuando una ip intenta conectar a algunos de los puertos definidos en el rango se genera una ofensa.
 - Reverse proxy trap
   El proxy reverso de la red le envia a mimosa las conexiones a dominos no registrados como dominios de produccion. Cuando una ip intenta acceder a algun dominio tipo admin.midominio se genera una ofensa.

## Dasboard de estadisticas:
Mimosa tiene un servidor web para servir un dashboard con estadisticas de ofensas y bloqueos

## Backend de gestión
En la ruta /control hay un interfaz de gestion y configuracion que permite gestionar las reglar por las que las ofensas generan un bloqueo.

## Servidor web de dashboard y administración
Mimosa incluye una pequeña aplicación FastAPI para consultar métricas y gestionar firewalls.

1. Instala las dependencias actualizadas: `pip install -r requirements.txt`.
2. Lanza el servidor: `uvicorn mimosa.web.app:app --reload`.
3. Abre en el navegador `http://localhost:8000` para ver el dashboard y `http://localhost:8000/admin` para gestionar los firewalls configurados (persisten en `data/firewalls.json`).
4. La UI aplica automáticamente un *apply/reload* tras crear alias o modificar entradas en pfSense/OPNsense para que los cambios surtan efecto. Puedes desactivar el flag de "Recargar reglas tras cambios" en la pantalla de administración si necesitas hacer pruebas sin impactar el firewall.

## Despliegue con Docker Compose
1. Crea un fichero `.env` a partir de `env.example` con tus credenciales de firewall y la ruta de base de datos deseada. El contenedor sincronizará automáticamente las variables nuevas que aparezcan en `env.example` manteniendo los valores existentes de `.env`.
2. Levanta el servicio con Docker Compose: `docker compose up --build -d`.
3. El servicio usa `network_mode: host`, por lo que expone directamente el puerto 8000 de la máquina donde se ejecuta. Asegúrate de no tener otro servicio en ese puerto antes de levantar el contenedor.
4. El servicio quedará accesible en `http://localhost:8000` y persistirá los datos en el volumen local `./data`.
5. Watchtower se encarga de actualizar la imagen de Mimosa cada 60 segundos usando el mismo `docker-compose.yml`, limitando el alcance a los servicios de esta pila.

## Uso rápido
1. Instala las dependencias: `pip install -r requirements.txt`.
2. Configura tus credenciales del firewall y la ruta de base de datos mediante variables de entorno (ver `env.example`). Si defines `INITIAL_FIREWALL_NAME`, la UI creará automáticamente una configuración inicial de firewall en `data/firewalls.json` usando los valores `INITIAL_FIREWALL_*`.
3. Crea la API núcleo y el cliente pfSense:
   ```python
   from mimosa.core.api import CoreAPI
   from mimosa.core.blocking import BlockManager
   from mimosa.core.sense import OPNsenseClient, PFSenseClient

   # Para pfSense (pfRest)
   firewall = PFSenseClient(
       base_url="https://firewall.local",
       api_key="API_KEY",
       api_secret="API_SECRET",
       alias_name="mimosa_blocklist",
   )

   # O bien para OPNsense
   firewall = OPNsenseClient(
       base_url="https://firewall.local",
       api_key="API_KEY",
       api_secret="API_SECRET",
       alias_name="mimosa_blocklist",
   )

   api = CoreAPI(firewall, block_manager=BlockManager())
   api.block_ip("203.0.113.10", reason="Prueba de bloqueo", duration_minutes=60)
   ```

La comprobación de conectividad para pfSense se realiza contra el endpoint
documentado de estado de pfRest (`/api/v1/status/system`). Si este punto responde
con un 401/403, Mimosa devolverá un error claro indicando que las credenciales
no son válidas o carecen de permisos.
