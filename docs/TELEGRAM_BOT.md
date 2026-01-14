# 🤖 Bot de Telegram para Mimosa

El bot de Telegram permite gestionar Mimosa de forma remota mediante comandos y menús interactivos, con un sistema completo de autenticación y control de acceso.

## 📋 Tabla de Contenidos

- [Configuración](#configuración)
- [Variables de Entorno](#variables-de-entorno)
- [Comandos Disponibles](#comandos-disponibles)
- [Gestión de Usuarios](#gestión-de-usuarios)
- [Seguridad](#seguridad)

## ⚙️ Configuración

### Opción 1: Desde la Interfaz Web (Recomendado)

1. Accede a la sección **"Telegram Bot"** en el menú de Mimosa
2. Crea un bot con [@BotFather](https://t.me/BotFather) en Telegram:
   - Envía `/newbot` a @BotFather
   - Sigue las instrucciones para elegir un nombre y username
   - Copia el token que te proporciona (formato: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)
3. Pega el token en el campo "Token del Bot"
4. Marca la casilla "Habilitar bot de Telegram"
5. Personaliza los mensajes de bienvenida y no autorizado (opcional)
6. Haz clic en "Guardar configuración"

### Opción 2: Usando Variables de Entorno

Para despliegues automatizados o contenedores, puedes configurar el bot mediante variables de entorno:

```bash
# .env
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_BOT_ENABLED=true
TELEGRAM_WELCOME_MESSAGE=Bienvenido al bot de Mimosa
TELEGRAM_UNAUTHORIZED_MESSAGE=No estás autorizado para usar este bot
```

**Nota:** La configuración desde variables de entorno solo se aplica si no existe una configuración previa en la base de datos. Una vez configurado, los cambios deben hacerse desde la interfaz web o modificando directamente la base de datos.

## 🔧 Variables de Entorno

| Variable | Descripción | Valor por defecto |
|----------|-------------|-------------------|
| `TELEGRAM_BOT_TOKEN` | Token del bot obtenido de @BotFather | _(vacío)_ |
| `TELEGRAM_BOT_ENABLED` | Habilitar el bot automáticamente | `false` |
| `TELEGRAM_WELCOME_MESSAGE` | Mensaje de bienvenida para usuarios autorizados | `Bienvenido al bot de Mimosa` |
| `TELEGRAM_UNAUTHORIZED_MESSAGE` | Mensaje para usuarios no autorizados | `No estás autorizado para usar este bot` |

## 🎮 Comandos Disponibles

Una vez autorizado, puedes usar los siguientes comandos:

### Comandos Básicos

- `/start` - Inicia el bot y muestra el menú principal con botones interactivos
- `/menu` - Muestra el menú principal
- `/help` - Muestra la ayuda con todos los comandos disponibles

### Información y Estadísticas

- `/stats` - Muestra estadísticas del sistema:
  - Total de ofensas (última hora, último día, total)
  - Bloqueos activos e histórico
  - Número de reglas configuradas

### Gestión de Bloqueos

- `/blocks` - Lista los bloqueos activos (máximo 10)
- `/block <IP> [razón]` - Bloquea una dirección IP manualmente
  - Ejemplo: `/block 1.2.3.4 Ataque detectado`
  - La duración por defecto es 60 minutos
- `/unblock <IP>` - Desbloquea una dirección IP
  - Ejemplo: `/unblock 1.2.3.4`

### Gestión de Reglas

- `/rules` - Lista las reglas de bloqueo automático configuradas (máximo 5)

## 👥 Gestión de Usuarios

### Proceso de Autorización

1. **Usuario interactúa con el bot**: Cualquier persona puede escribir al bot
2. **Aparece en pendientes**: El usuario aparece en la lista "Usuarios Pendientes" en la interfaz web
3. **Autorización manual**: Un administrador autoriza al usuario desde la web
4. **Acceso completo**: El usuario puede usar todos los comandos del bot

### Desde la Interfaz Web

La página "Telegram Bot" en Mimosa permite:

- ✅ **Autorizar usuarios**: Dar acceso a usuarios pendientes
- ❌ **Desautorizar usuarios**: Revocar acceso a usuarios autorizados
- 🗑️ **Eliminar usuarios**: Eliminar usuarios de la base de datos
- 📊 **Ver estadísticas**: Número de usuarios, interacciones, etc.
- 📜 **Historial**: Ver las últimas 50 interacciones con el bot

### Información de Usuarios

Para cada usuario se registra:

- Username de Telegram (@username)
- Nombre y apellido
- ID de Telegram (numérico único)
- Número de interacciones
- Primera y última actividad
- Quién lo autorizó y cuándo

## 🔒 Seguridad

### Sistema de Autenticación

- **Autorización explícita**: Solo los usuarios autorizados pueden ejecutar comandos
- **Registro de actividad**: Todas las interacciones quedan registradas (autorizadas y no autorizadas)
- **Control granular**: Los administradores pueden autorizar/desautorizar usuarios en cualquier momento
- **Token seguro**: El token del bot se oculta en la interfaz web por seguridad

### Buenas Prácticas

1. **Revisa regularmente** la lista de usuarios autorizados
2. **Elimina usuarios** que ya no necesiten acceso
3. **Monitorea el historial** de interacciones para detectar actividad sospechosa
4. **Cambia el token** si sospechas que ha sido comprometido
5. **Usa mensajes claros** para que los usuarios sepan qué pueden hacer

## 🎨 Menús Interactivos

El bot incluye menús con botones (InlineKeyboard) para facilitar la navegación:

```
┌─────────────────────────────┐
│     Menú Principal          │
├─────────────┬───────────────┤
│ 📊 Stats    │ 🚫 Blocks     │
├─────────────┼───────────────┤
│ ⚙️ Rules    │ ❓ Help       │
└─────────────┴───────────────┘
```

Los botones permiten navegar sin necesidad de escribir comandos, haciendo la experiencia más intuitiva.

## 📱 Ejemplo de Uso

```
Usuario: /start
Bot: Bienvenido al bot de Mimosa

     Usa los botones para navegar o escribe /help para ver los comandos disponibles.

     [📊 Estadísticas] [🚫 Bloqueos]
     [⚙️ Reglas]      [❓ Ayuda]

Usuario: /stats
Bot: 📊 Estadísticas de Mimosa

     Ofensas:
     • Total: 1,245
     • Última hora: 12
     • Último día: 156

     Bloqueos:
     • Activos: 23
     • Total histórico: 567

     Reglas:
     • Configuradas: 5

Usuario: /block 1.2.3.4 Escaneo de puertos detectado
Bot: ✅ IP 1.2.3.4 bloqueada correctamente.

Usuario: /blocks
Bot: 🚫 Bloqueos activos:

     • 1.2.3.4 - Escaneo de puertos detectado
       Expira: 15:30 14/01

     • 5.6.7.8 - Ataque de fuerza bruta
       Expira: 16:45 14/01

     [🔄 Actualizar] [« Menú]
```

## 🐛 Solución de Problemas

### El bot no responde

1. Verifica que el bot esté habilitado en la configuración
2. Comprueba que el token sea correcto
3. Revisa los logs de la aplicación para errores
4. Asegúrate de que el usuario esté autorizado

### El bot se reinicia constantemente

1. Verifica que el token sea válido
2. Comprueba la conectividad a los servidores de Telegram
3. Revisa los logs para mensajes de error específicos

### No puedo autorizar usuarios

1. Verifica que tienes rol de administrador en Mimosa
2. Comprueba que el usuario haya interactuado con el bot primero
3. Recarga la página de configuración del bot

## 📚 Recursos Adicionales

- [Documentación de python-telegram-bot](https://docs.python-telegram-bot.org/)
- [Crear un bot con @BotFather](https://core.telegram.org/bots#botfather)
- [API de Telegram Bot](https://core.telegram.org/bots/api)

---

¿Necesitas ayuda? Abre un issue en el [repositorio de Mimosa](https://github.com/successbyfailure/Mimosa/issues).
