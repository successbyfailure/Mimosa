# Mimosa
Mimosa es un sistema de defensa para homelabs y entusiastas creado con nocturnidad e IA.

## ¿Por qué “Mimosa”?
La Mimosa pudica es la planta que repliega sus hojas al mínimo contacto: un movimiento rápido y eficiente para protegerse. Este proyecto aspira a reaccionar igual de ágil ante señales hostiles, combinando componentes ligeros (ingestión de logs, reputación, proxy-trap, bots y dashboard) que se contraen y coordinan en conjunto para reforzar un homelab.

## ¿Cómo funciona?
Mimosa esta pensado para correr en una mv detras de un firewall pfSense o OpnSense, tiene plugins que detectan diferentes ofensas y se comunica via api con el firewall para bloquear temporalmente las ips que ofenden.

## Plugins
 - Detector de conexiones tcp/udp:
   El firewall le envia por nat todos los puertos que no estan en uso a mimosa, cuando una ip intenta conectar a algunos de los puertos definidos en el rango se genera una ofensa.
 - Reverse proxy trap
   El proxy reverso de la red le envia a mimosa las conexiones a dominos no registrados como dominios de produccion. Cuando una ip intenta acceder a algun dominio tipo admin.midominio se genera una ofensa.

## Dasboard de estadisticas:
Mimosa tiene un servidor web para servir un dashboard con estadisticas de ofensas y bloqueos

## Backend de gestión
En la ruta /control hay un interfaz de gestion y configuracion que permite gestionar las reglar por las que las ofensas generan un bloqueo.

## Contenedores
El repositorio incluye un `docker/Dockerfile` y `docker-compose.yml` mínimos para empaquetar el dashboard y los servicios auxiliares.
