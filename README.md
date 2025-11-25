# Mimosa
Mimosa es un sistema de defensa para homelabs y entusiastas creado con nocturnidad e IA. Pensado para correr en una mv detras de un firewall OpnSense, tiene plugins que detectan diferentes ofensas y se comunica via api con el firewall para bloquear temporalmente las ips que ofenden.

## ¿Por qué “Mimosa”?
La Mimosa pudica repliega sus hojas ante el mínimo contacto. La meta de este proyecto es reaccionar igual de rápido ante señales hostiles, coordinando bloqueos ligeros y temporales sobre el firewall del homelab.

## Plugins planificados
 - Detector de conexiones tcp/udp:
   El firewall le envia por nat todos los puertos que no estan en uso a mimosa, cuando una ip intenta conectar a algunos de los puertos definidos en el rango se genera una ofensa.
 - Reverse proxy trap
   El proxy reverso de la red le envia a mimosa las conexiones a dominos no registrados como dominios de produccion. Cuando una ip intenta acceder a algun dominio tipo admin.midominio se genera una ofensa.

### MimosaNPM
Agente ligero pensado para correr junto a Nginx Proxy Manager, con acceso al volumen de logs y a la API. El agente analiza peticiones a dominios inexistentes y envía alertas a Mimosa vía HTTP/HTTPS:

- Configura el plugin y el secreto compartido desde `/admin` en la tarjeta MimosaNPM.
- Envía un `POST` a `/api/plugins/mimosanpm/ingest` con cabecera `X-Mimosa-Token` y un cuerpo JSON con `alerts` (ip origen, host solicitado, ruta, user-agent y estado opcional).
- Mimosa registra las ofensas y ejecuta las reglas configuradas para aplicar bloqueos temporales si procede.
- El agente remoto vive en `mimosanpm-agent/` con su propio `docker-compose.yml` y `env.example` para desplegarlo junto a NPM.

## Dasboard de estadisticas:
Mimosa tiene un servidor web para servir un dashboard con estadisticas de ofensas y bloqueos

## Despliegue con Docker Compose
1. Crea un fichero `.env` a partir de `env.example` con tus credenciales de firewall y la ruta de base de datos deseada. El contenedor sincronizará automáticamente las variables nuevas que aparezcan en `env.example` manteniendo los valores existentes de `.env`.
2. Levanta el servicio con Docker Compose: `docker compose up --build -d`.
3. El servicio usa `network_mode: host`, por lo que expone directamente el puerto 8000 de la máquina donde se ejecuta. Asegúrate de no tener otro servicio en ese puerto antes de levantar el contenedor.
4. El servicio quedará accesible en `http://localhost:8000` y persistirá los datos en el volumen local `./data`.
5. Watchtower se encarga de actualizar la imagen de Mimosa cada 60 segundos usando el mismo `docker-compose.yml`, limitando el alcance a los servicios de esta pila.
