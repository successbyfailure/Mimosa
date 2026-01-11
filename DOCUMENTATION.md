# Índice de Documentación de Mimosa

Esta es la guía completa de la documentación de Mimosa. Usa este índice para encontrar rápidamente la información que necesitas.

## 📚 Documentación Principal

### [README.md](README.md)
**Documentación principal del proyecto**

- Introducción a Mimosa
- Características principales
- Guía de inicio rápido
- Configuración y despliegue
- Descripción de plugins
- Dashboard web
- Desarrollo local
- Seguridad
- Licencia y contribuciones

**Ideal para:** Nuevos usuarios, referencia general

---

### [AGENTS.md](AGENTS.md)
**Guía para contribuidores y mantenedores**

- Propósito y alcance del proyecto
- Ejecución rápida en desarrollo
- Despliegue con Docker
- Variables de entorno
- Convenciones de contribución
- Versionado semántico
- Testing y CI
- Scripts de utilidad

**Ideal para:** Desarrolladores, contribuidores, mantenedores

---

### [CHANGELOG.md](CHANGELOG.md)
**Historial de cambios del proyecto**

- Registro cronológico de versiones
- Nuevas características
- Correcciones de bugs
- Cambios incompatibles

**Ideal para:** Seguir evolución del proyecto, ver qué cambió entre versiones

---

### [SECURITY_REVIEW.md](SECURITY_REVIEW.md)
**Auditoría de seguridad y mejores prácticas**

- Resumen de auditoría de seguridad
- Archivos sensibles protegidos
- Protecciones en Git y Docker
- Herramientas de verificación
- Resultados de auditoría
- Recomendaciones
- Referencias de seguridad

**Ideal para:** Revisión de seguridad, cumplimiento, mejores prácticas

---

## 🔧 Documentación de Scripts

### [scripts/README.md](scripts/README.md)
**Documentación de scripts de utilidad**

Scripts disponibles:
- **diagnose_opnsense.py** - Diagnóstico de funciones OPNsense
- **verify_firewall_rules.py** - Verificación de reglas de firewall de Mimosa

Incluye:
- Descripción de cada script
- Uso y ejemplos
- Requisitos
- Troubleshooting
- Guía de mantenimiento

**Ideal para:** Diagnóstico, mantenimiento, desarrollo

---

## 📖 Documentación de Referencias

### [reference_docs/api-opnsense.md](reference_docs/api-opnsense.md)
**Documentación de la API de OPNsense**

- Endpoints de firewall
- Autenticación
- Gestión de alias
- Formato de respuestas

**Ideal para:** Integración con OPNsense, desarrollo de features

### pfSense (pfrest)
**Documentación externa:** https://pfrest.org/

**Ideal para:** Integración con pfSense usando pfrest

---

## 🔌 Documentación de Plugins

### [mimosanpm-agent/README.md](mimosanpm-agent/README.md)
**Agente MimosaNPM para Nginx Proxy Manager**

- Instalación y configuración
- Integración con NPM
- Variables de entorno
- Uso y ejemplos
- Troubleshooting

**Ideal para:** Configurar plugin MimosaNPM

---

## 🗂️ Estructura del Proyecto

```
Mimosa/
├── README.md                    # Documentación principal
├── AGENTS.md                    # Guía para contribuidores
├── CHANGELOG.md                 # Historial de cambios
├── SECURITY_REVIEW.md           # Auditoría de seguridad
├── DOCUMENTATION.md             # Este archivo (índice maestro)
│
├── scripts/                     # Scripts de utilidad
│   ├── README.md               # Documentación de scripts
│   ├── diagnose_opnsense.py    # Diagnóstico OPNsense
│   └── verify_firewall_rules.py # Verificación de reglas
│
├── reference_docs/              # Documentación de referencia
│   └── api-opnsense.md         # API de OPNsense
│
├── mimosanpm-agent/            # Agente MimosaNPM
│   └── README.md               # Doc del agente
│
├── mimosa/                      # Código fuente
│   ├── core/                   # Lógica de negocio
│   ├── web/                    # API y dashboard
│   ├── bot/                    # Placeholder (sin implementación)
│   └── tasks/                  # Placeholder (sin implementación)
│
├── tests/                       # Tests unitarios e integración
├── data/                        # Datos de producción (ignorado)
├── volumes/                     # Volúmenes Docker (ignorado)
└── env.example                  # Plantilla de configuración
```

---

## 🎯 Rutas Rápidas

### Para Nuevos Usuarios
1. [README.md](README.md) - Introducción y guía de inicio
2. [env.example](env.example) - Configuración básica
3. [docker-compose.yml](docker-compose.yml) - Despliegue

### Para Desarrolladores
1. [AGENTS.md](AGENTS.md) - Convenciones y guías
2. [scripts/README.md](scripts/README.md) - Scripts de desarrollo
3. [tests/](tests/) - Tests del proyecto
4. [reference_docs/](reference_docs/) - APIs externas

### Para Mantenimiento
1. [scripts/diagnose_opnsense.py](scripts/diagnose_opnsense.py) - Diagnóstico OPNsense
2. [SECURITY_REVIEW.md](SECURITY_REVIEW.md) - Auditoría de seguridad

### Para Seguridad
1. [SECURITY_REVIEW.md](SECURITY_REVIEW.md) - Auditoría completa
2. [.gitignore](.gitignore) - Archivos protegidos
3. [.dockerignore](.dockerignore) - Exclusiones de imagen

---

## 📝 Convenciones de Documentación

Al añadir o actualizar documentación:

1. **Formato Markdown**
   - Usar Markdown estándar (GitHub-flavored)
   - Incluir tabla de contenidos para docs largos
   - Usar emojis con moderación para secciones principales

2. **Estructura**
   - Título claro con `#`
   - Secciones organizadas con `##` y `###`
   - Ejemplos de código con syntax highlighting

3. **Código de Ejemplo**
   ```bash
   # Usar bloques de código con lenguaje especificado
   docker compose up -d
   ```

4. **Enlaces**
   - Usar enlaces relativos dentro del repo
   - Enlaces absolutos para recursos externos
   - Verificar que los enlaces funcionan

5. **Actualización**
   - Mantener documentación sincronizada con código
   - Actualizar CHANGELOG.md con cada versión
   - Revisar documentación en cada PR

---

## 🔄 Mantenimiento de Documentación

### Checklist antes de Commit
- [ ] README.md actualizado si hay cambios importantes
- [ ] CHANGELOG.md actualizado con versión y cambios
- [ ] AGENTS.md actualizado si cambian convenciones
- [ ] Scripts documentados en scripts/README.md
- [ ] Enlaces verificados y funcionando
- [ ] Ejemplos de código probados

### Versionado de Documentación
- Documentación vive en el mismo repo que el código
- Versiones etiquetadas con git tags
- Cambios documentados en CHANGELOG.md

---

## 📬 Contacto y Soporte

- **Issues:** [GitHub Issues](https://github.com/successbyfailure/mimosa/issues)
- **Contribuciones:** Ver [AGENTS.md](AGENTS.md)
- **Seguridad:** Ver [SECURITY_REVIEW.md](SECURITY_REVIEW.md)

---

<div align="center">

**¿Falta algo en la documentación?** [Abre un issue](https://github.com/successbyfailure/mimosa/issues) o envía un PR.

</div>
