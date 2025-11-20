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
