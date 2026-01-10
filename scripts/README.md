# Scripts de Utilidad de Mimosa

Este directorio contiene scripts de mantenimiento y diagnóstico para Mimosa.

## 📋 Índice de Scripts

### 🔍 diagnose_opnsense.py
**Diagnóstico de Funciones de OPNsense**

Script de diagnóstico completo que prueba todas las funciones del cliente OPNsense.

**Requisitos:**
- Configuración de firewall en `data/firewalls.json`
- Firewall OPNsense accesible

**Uso:**
```bash
# Desde el host (requiere dependencias)
python scripts/diagnose_opnsense.py

# Desde Docker (recomendado)
docker exec mimosa python scripts/diagnose_opnsense.py
```

**Pruebas Realizadas:**
1. **Conectividad** - Verifica conexión con OPNsense
2. **Estado del Firewall** - Obtiene status y alias
3. **Operaciones de Listado** - Lista bloques y blacklist
4. **Bloqueo/Desbloqueo IPs** - Prueba alias temporal
5. **Blacklist** - Prueba lista negra permanente
6. **Operaciones de Puertos** - Prueba alias de puertos
7. **Aplicación de Cambios** - Verifica reload

**Salida:**
```
🔥 Diagnóstico de funciones de OPNsense
======================================
✅ connection
✅ status
✅ list_operations
✅ block_unblock
✅ blacklist
✅ ports
✅ apply_changes

Resultado: 7/7 pruebas exitosas
```

**Notas:**
- Usa IP de prueba `198.51.100.99` (rango TEST-NET-2)
- Restaura el estado original después de las pruebas
- Aplica cambios en el firewall si está configurado

---

## 📂 Estructura de Directorios

```
Mimosa/
├── scripts/              # Scripts de utilidad (este directorio)
│   ├── README.md        # Esta documentación
│   └── diagnose_opnsense.py
├── data/                # Datos de producción (ignorado en git)
├── tests/               # Tests unitarios
└── reference_docs/      # Documentación de referencia
```

## 🔧 Mantenimiento

### Añadir un Nuevo Script

1. Crear el script en este directorio
2. Hacerlo ejecutable si es shell: `chmod +x scripts/script.sh`
3. Documentarlo en este README
4. Añadir comentarios descriptivos en el script
5. Verificar que funciona en Docker si es relevante

### Mejores Prácticas

- **Nombrado:** Usar nombres descriptivos con guiones bajos
- **Documentación:** Incluir comentarios al inicio del script
- **Salida:** Usar códigos de salida apropiados (0 = éxito)
- **Colores:** Usar códigos ANSI en scripts de shell para mejor legibilidad
- **Cleanup:** Restaurar estado original en scripts de diagnóstico

## 🐛 Troubleshooting

### Script no se ejecuta en Docker
```bash
# Verificar que el script existe en el contenedor
docker exec mimosa ls -la scripts/

# Copiar script al contenedor si es necesario
docker cp scripts/script.py mimosa:/app/scripts/

# Ejecutar con ruta absoluta
docker exec mimosa python /app/scripts/script.py
```

### Permisos denegados
```bash
chmod +x scripts/*.sh
```

### Dependencias faltantes
Los scripts Python requieren las dependencias de `requirements.txt`. Ejecutarlos dentro del contenedor Docker para evitar problemas.

## 📚 Ver También

- [SECURITY_REVIEW.md](../SECURITY_REVIEW.md) - Auditoría de seguridad
- [AGENTS.md](../AGENTS.md) - Guía para contribuidores
- [reference_docs/](../reference_docs/) - Documentación de APIs
