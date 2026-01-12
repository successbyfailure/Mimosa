# Mimosa 🌿

<div align="center">

**Sistema de defensa inteligente para homelabs**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

Mimosa es un sistema de defensa automatizado para homelabs y entusiastas, diseñado para detectar y responder rápidamente ante actividad sospechosa. Se integra con firewalls OPNsense para aplicar bloqueos temporales coordinados.

## 🌸 ¿Por qué "Mimosa"?

La *Mimosa pudica* repliega sus hojas al mínimo contacto. Mimosa replica esta respuesta rápida y defensiva ante señales hostiles, aplicando bloqueos ligeros y temporales en tu firewall.

## ✨ Características

- 🔥 **Integración OPNsense/pfSense** - Control directo de alias y reglas de firewall
- 🎛️ **Gestión de Reglas** - Activar/desactivar reglas de bloqueo desde la UI sin acceder a OPNsense
- 🔍 **Detección de Puertos** - Identifica escaneos y conexiones sospechosas
- 🌐 **Proxy Trap** - Detecta acceso a dominios no autorizados
- 📊 **Dashboard Web** - Visualización en tiempo real de ofensas, bloqueos y estado de reglas
- ⚙️ **API REST** - Integración programática completa
- 🔒 **Bloqueos Temporales** - Configurables por tipo de ofensa
- 🤖 **MimosaNPM Agent** - Integración con Nginx Proxy Manager

## 🚀 Inicio Rápido

### Requisitos
- Docker y Docker Compose
- Firewall OPNsense con acceso API
- Puerto 8000 disponible

### Instalación

1. **Clonar el repositorio:**
```bash
git clone https://github.com/successbyfailure/mimosa.git
cd mimosa
```

2. **Configurar variables de entorno:**
```bash
cp env.example .env
# Editar .env con tus credenciales de OPNsense
```

3. **Levantar el servicio:**
```bash
docker compose up -d
```

4. **Acceder al dashboard:**
   - Dashboard: http://localhost:8000
   - Admin: http://localhost:8000/admin

### Desarrollo de UI (SvelteKit)

1. **Instalar dependencias del frontend:**
```bash
cd mimosa-ui
npm install
```

2. **Levantar el frontend en modo desarrollo:**
```bash
npm run dev
```

3. **Build del frontend para FastAPI:**
```bash
npm run build:backend
```

### Configuración

El archivo `.env` contiene las variables de configuración. Las más importantes:

```env
# Firewall inicial (opcional - también configurable desde UI)
INITIAL_FIREWALL_NAME=mi-firewall
INITIAL_FIREWALL_TYPE=opnsense # o pfsense (pfrest)
INITIAL_FIREWALL_BASE_URL=https://firewall.local
INITIAL_FIREWALL_API_KEY=tu_api_key
INITIAL_FIREWALL_API_SECRET=tu_api_secret

# Base de datos
MIMOSA_DB_PATH=data/mimosa.db

# GeoIP (opcional)
MIMOSA_GEOIP_ENABLED=false
MIMOSA_GEOIP_PROVIDER=ip-api
MIMOSA_GEOIP_ENDPOINT=http://ip-api.com/json

# IP del servidor Mimosa (opcional)
MIMOSA_IP=
```

Notas pfSense (pfrest):
- Usa una API key de pfrest (se envía como `X-API-Key`).
- `API_SECRET` puede dejarse vacío si solo usas API key.

Alias mimosa_host:
- Si defines `MIMOSA_IP`, Mimosa creará el alias `mimosa_host` en el firewall con esa IP.
- Úsalo como destino en tus reglas NAT/port forward de TCP/UDP.

### Actualización Automática

Watchtower actualiza la imagen automáticamente cada 60 segundos. Para deshabilitarlo, comenta el servicio `watchtower` en `docker-compose.yml`.

### GeoIP (ip-api)

Mimosa consulta `ip-api.com` directamente cuando `MIMOSA_GEOIP_ENABLED=true`. Para usarlo:
1. Activa `MIMOSA_GEOIP_ENABLED=true` en `.env`
2. Usa `MIMOSA_GEOIP_ENDPOINT=http://ip-api.com/json`
3. Reinicia la stack y refresca IPs desde el panel

## 🔌 Plugins

### Detector de Puertos TCP/UDP

El firewall envía por NAT todos los puertos no usados a Mimosa. Cuando una IP intenta conectar a puertos definidos en el rango, se genera una ofensa.

**Configuración:**
1. Crear alias de puertos en OPNsense
2. Configurar regla NAT para redirigir a Mimosa
3. Activar plugin desde el dashboard

### Reverse Proxy Trap (MimosaNPM)

Agente ligero para Nginx Proxy Manager que detecta acceso a dominios inexistentes.

**Características:**
- Monitoreo de logs en tiempo real
- Detección de dominios sospechosos (admin.*, test.*, staging.*)
- Envío de alertas vía API
- Configuración desde dashboard de Mimosa

**Despliegue:**
```bash
cd mimosanpm-agent
cp env.example .env
# Configurar URL de Mimosa y token
docker compose up -d
```

Ver [mimosanpm-agent/README.md](mimosanpm-agent/README.md) para más detalles.

## 📊 Dashboard Web

Mimosa incluye un servidor web FastAPI con:

- **Dashboard de estadísticas** - Visualización de ofensas y bloqueos en tiempo real
- **Panel de administración** - Gestión de firewalls, reglas y configuración
- **API REST** - Endpoints para integración con otros sistemas

### Endpoints Principales

- `GET /` - Dashboard principal
- `GET /admin` - Panel de administración
- `POST /api/plugins/mimosanpm/ingest` - Ingesta de alertas de MimosaNPM
- `GET /api/stats` - Estadísticas generales

Ver documentación completa de la API en `/docs` (Swagger UI).

## 🛠️ Desarrollo

### Configuración Local

```bash
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar en modo desarrollo
uvicorn mimosa.web.app:app --reload --port 8000
```

### Testing

```bash
# Ejecutar tests unitarios
pytest tests/

# Ejecutar tests de integración (requiere OPNsense accesible)
export TEST_FIREWALL_OPNSENSE_BASE_URL=https://firewall.local
export TEST_FIREWALL_OPNSENSE_API_KEY=your_key
export TEST_FIREWALL_OPNSENSE_API_SECRET=your_secret
pytest tests/test_opnsense_client.py
```

### Scripts de Utilidad

El directorio `scripts/` contiene herramientas de diagnóstico y mantenimiento:

- **diagnose_opnsense.py** - Diagnóstico completo de funciones OPNsense

```bash
# Diagnosticar OPNsense
docker exec mimosa python scripts/diagnose_opnsense.py
```

Ver [scripts/README.md](scripts/README.md) para más detalles.

## 🔒 Seguridad

### Mejores Prácticas

1. **Variables de entorno:**
   - Nunca commitear archivos `.env`
   - Usar `env.example` como plantilla
   - Rotar credenciales regularmente

2. **Firewall:**
   - Usar HTTPS con certificados válidos
   - Limitar acceso API a IPs específicas
   - Habilitar autenticación de 2 factores en OPNsense

Ver [SECURITY_REVIEW.md](SECURITY_REVIEW.md) para el informe completo de auditoría.

## 📚 Documentación

- [AGENTS.md](AGENTS.md) - Guía para contribuidores y mantenedores
- [CHANGELOG.md](CHANGELOG.md) - Historial de cambios
- [SECURITY_REVIEW.md](SECURITY_REVIEW.md) - Auditoría de seguridad
- [scripts/README.md](scripts/README.md) - Documentación de scripts
- [reference_docs/](reference_docs/) - Documentación de APIs externas
- [mimosanpm-agent/README.md](mimosanpm-agent/README.md) - Agente MimosaNPM

## 🤝 Contribuir

Las contribuciones son bienvenidas! Por favor:

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

Ver [AGENTS.md](AGENTS.md) para convenciones y guías de estilo.

## 📝 Versionado

El proyecto usa [Semantic Versioning](https://semver.org/). La versión actual está en `version.json`:

- **Mayor (X.y.z)** - Cambios incompatibles
- **Menor (x.Y.z)** - Nuevas funcionalidades
- **Patch (x.y.Z)** - Correcciones y mejoras

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## 🙏 Agradecimientos

- [OPNsense](https://opnsense.org/) - Firewall de código abierto
- [FastAPI](https://fastapi.tiangolo.com/) - Framework web moderno
- [Nginx Proxy Manager](https://nginxproxymanager.com/) - Proxy reverso simplificado

---

<div align="center">

**¿Te gusta Mimosa?** ⭐ ¡Dale una estrella al repositorio!

</div>
