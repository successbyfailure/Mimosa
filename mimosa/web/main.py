"""Dashboard de Mimosa basado en FastAPI y HTMX/Alpine.js."""
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, FastAPI, Form
from fastapi.responses import HTMLResponse

from mimosa.core.api import BlockRequest, CoreAPI
from mimosa.core.offenses import OffenseStore
from mimosa.core.firewall import DummyFirewall
from mimosa.proxy_trap.endpoint import forbidden_interface_attempts, router as proxy_router

app = FastAPI(title="Mimosa Dashboard")

dashboard_router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])


@dataclass
class AlertRule:
    """Describe una regla que generará alertas de seguridad."""

    rule_id: str
    condition: str
    target: str
    severity: str


@dataclass
class BlockingPolicy:
    """Configura cuándo una serie de alertas deriva en bloqueo."""

    threshold: int
    window_minutes: int
    block_minutes: int


class AdminState:
    """Mantiene la configuración editable desde el panel de administración."""

    def __init__(self) -> None:
        self.alert_rules: List[AlertRule] = [
            AlertRule(
                rule_id="ports-default",
                condition="Acceso a rango de puertos prohibido",
                target="0-1023",
                severity="alto",
            ),
            AlertRule(
                rule_id="domain-default",
                condition="Acceso a dominio restringido",
                target="intranet.corp",
                severity="medio",
            ),
        ]
        self.blocking_policy = BlockingPolicy(
            threshold=int(os.getenv("ALERT_BLOCK_THRESHOLD", "5")),
            window_minutes=int(os.getenv("ALERT_WINDOW_MINUTES", "15")),
            block_minutes=int(os.getenv("BLOCK_DURATION_MINUTES", "60")),
        )

    def add_alert_rule(self, condition: str, target: str, severity: str) -> None:
        rule_id = f"rule-{int(datetime.utcnow().timestamp() * 1000)}"
        self.alert_rules.append(
            AlertRule(rule_id=rule_id, condition=condition, target=target, severity=severity)
        )

    def remove_alert_rule(self, rule_id: str) -> None:
        self.alert_rules = [rule for rule in self.alert_rules if rule.rule_id != rule_id]

    def update_blocking_policy(self, threshold: int, window_minutes: int, block_minutes: int) -> None:
        self.blocking_policy = BlockingPolicy(
            threshold=threshold,
            window_minutes=window_minutes,
            block_minutes=block_minutes,
        )


admin_state = AdminState()
core_api = CoreAPI(DummyFirewall())
offense_store = OffenseStore()


def _demo_tasks() -> List[Dict[str, str]]:
    """Devuelve el estado actual de tareas a modo demo."""

    now = datetime.utcnow()
    return [
        {
            "name": "proxy-guardian",
            "status": "activo",
            "last_run": (now - timedelta(minutes=5)).isoformat(timespec="seconds"),
        },
        {
            "name": "reputation-refresh",
            "status": "en pausa",
            "last_run": (now - timedelta(hours=1, minutes=12)).isoformat(timespec="seconds"),
        },
        {
            "name": "audit-log-export",
            "status": "activo",
            "last_run": (now - timedelta(minutes=25)).isoformat(timespec="seconds"),
        },
    ]


def _blocked_ip_summary() -> List[Dict[str, str]]:
    """Agrega intentos del proxy para mostrar un gráfico ligero."""

    if forbidden_interface_attempts:
        counts = Counter(
            attempt.get("client", "desconocido") for attempt in forbidden_interface_attempts
        )
        return [
            {"ip": ip, "count": str(count)}
            for ip, count in counts.most_common(6)
        ]

    blocked = core_api.list_blocks()
    if blocked:
        return [
            {"ip": entry.ip, "count": "1"} for entry in blocked[:6]
        ]

    # Datos de ejemplo cuando no hay actividad real
    return [
        {"ip": "192.0.2.15", "count": "8"},
        {"ip": "198.51.100.7", "count": "6"},
        {"ip": "203.0.113.42", "count": "4"},
    ]


def _recent_incidents() -> List[Dict[str, str]]:
    """Construye una tabla de incidentes a partir de intentos o datos ficticios."""

    stored_offenses = offense_store.list_recent(limit=10)
    incidents: List[Dict[str, str]] = []
    for offense in stored_offenses:
        incidents.append(
            {
                "timestamp": offense.created_at.isoformat(timespec="seconds"),
                "host": offense.host or "desconocido",
                "client": offense.source_ip,
                "path": offense.path or "/",
                "user_agent": offense.user_agent or "",
            }
        )

    if incidents:
        return incidents

    base_time = datetime.utcnow()
    return [
        {
            "timestamp": (base_time - timedelta(minutes=12)).isoformat(timespec="seconds"),
            "host": "api.mimosa.local",
            "client": "203.0.113.42",
            "path": "/auth/login",
            "user_agent": "curl/8.6.0",
        },
        {
            "timestamp": (base_time - timedelta(minutes=34)).isoformat(timespec="seconds"),
            "host": "api.mimosa.local",
            "client": "198.51.100.7",
            "path": "/admin",
            "user_agent": "python-requests/2.31",
        },
        {
            "timestamp": (base_time - timedelta(hours=2, minutes=5)).isoformat(timespec="seconds"),
            "host": "api.mimosa.local",
            "client": "192.0.2.15",
            "path": "/api/trap",
            "user_agent": "Mozilla/5.0",
        },
    ]


def _render_blocklist_rows() -> str:
    """Pinta las filas de la tabla de bloqueos manuales."""

    blocks = core_api.list_blocks()
    if not blocks:
        return """
        <tr><td class=\"py-3 px-3 text-sm text-slate-500\" colspan=\"5\">No hay bloqueos activos.</td></tr>
        """

    def format_expiry(expires_at: Optional[datetime]) -> str:
        if not expires_at:
            return "Sin caducidad"
        return expires_at.isoformat(timespec="seconds")

    rows = []
    for entry in blocks:
        rows.append(
            f"""
            <tr class=\"border-b border-slate-100 last:border-none\">
                <td class=\"py-2 px-3 text-sm font-semibold\">{entry.ip}</td>
                <td class=\"py-2 px-3 text-sm text-slate-700\">{entry.reason}</td>
                <td class=\"py-2 px-3 text-xs text-slate-500\">{entry.created_at.isoformat(timespec='seconds')}</td>
                <td class=\"py-2 px-3 text-xs text-slate-500\">{format_expiry(entry.expires_at)}</td>
                <td class=\"py-2 px-3\">
                    <button
                        hx-post=\"/api/admin/blocklist/{entry.ip}/remove\"
                        hx-target=\"#blocklist\"
                        hx-swap=\"innerHTML\"
                        class=\"text-xs font-semibold text-rose-700 bg-rose-50 hover:bg-rose-100 rounded px-3 py-1 transition\"
                    >
                        Quitar
                    </button>
                </td>
            </tr>
            """
        )
    return "".join(rows)


def _render_alert_rules() -> str:
    """Devuelve la lista de reglas de alerta configuradas."""

    if not admin_state.alert_rules:
        return """
        <tr><td class=\"py-3 px-3 text-sm text-slate-500\" colspan=\"4\">Sin reglas configuradas.</td></tr>
        """

    rows = []
    for rule in admin_state.alert_rules:
        rows.append(
            f"""
            <tr class=\"border-b border-slate-100 last:border-none\">
                <td class=\"py-2 px-3 text-sm font-semibold\">{rule.condition}</td>
                <td class=\"py-2 px-3 text-sm text-slate-700\">{rule.target}</td>
                <td class=\"py-2 px-3 text-xs font-semibold\">
                    <span class=\"inline-flex items-center gap-2 rounded-full px-2 py-1 { 'bg-red-50 text-red-700' if rule.severity == 'alto' else 'bg-amber-50 text-amber-700' if rule.severity == 'medio' else 'bg-slate-100 text-slate-700' }\">{rule.severity.title()}</span>
                </td>
                <td class=\"py-2 px-3\">
                    <button
                        hx-post=\"/api/admin/alert-rules/{rule.rule_id}/remove\"
                        hx-target=\"#alert-rules\"
                        hx-swap=\"innerHTML\"
                        class=\"text-xs font-semibold text-rose-700 bg-rose-50 hover:bg-rose-100 rounded px-3 py-1 transition\"
                    >
                        Eliminar
                    </button>
                </td>
            </tr>
            """
        )
    return "".join(rows)


def _render_blocking_policy() -> str:
    """Renderiza la política actual de escalado de alertas a bloqueo."""

    policy = admin_state.blocking_policy
    return f"""
    <div id=\"blocking-policy\" class=\"glass rounded-2xl shadow-sm border border-slate-100 p-6 space-y-3\">
        <div class=\"flex items-center justify-between\">
            <div>
                <p class=\"text-xs font-semibold text-emerald-600\">Escalado automático</p>
                <h2 class=\"text-xl font-bold\">Condiciones de bloqueo</h2>
            </div>
            <button class=\"text-xs text-emerald-700\" hx-get=\"/api/admin/blocking-policy\" hx-target=\"#blocking-policy\" hx-swap=\"outerHTML\">Refrescar</button>
        </div>
        <form class=\"grid md:grid-cols-3 gap-4 text-sm\" hx-post=\"/api/admin/blocking-policy\" hx-target=\"#blocking-policy\" hx-swap=\"outerHTML\">
            <label class=\"space-y-2\">
                <span class=\"text-xs font-semibold text-slate-600\">Alertas totales por IP</span>
                <input name=\"threshold\" type=\"number\" min=\"1\" value=\"{policy.threshold}\" class=\"w-full border border-slate-200 rounded-lg px-3 py-2\" />
            </label>
            <label class=\"space-y-2\">
                <span class=\"text-xs font-semibold text-slate-600\">Ventana (minutos)</span>
                <input name=\"window_minutes\" type=\"number\" min=\"1\" value=\"{policy.window_minutes}\" class=\"w-full border border-slate-200 rounded-lg px-3 py-2\" />
            </label>
            <label class=\"space-y-2\">
                <span class=\"text-xs font-semibold text-slate-600\">Tiempo de bloqueo (minutos)</span>
                <input name=\"block_minutes\" type=\"number\" min=\"1\" value=\"{policy.block_minutes}\" class=\"w-full border border-slate-200 rounded-lg px-3 py-2\" />
            </label>
            <div class=\"md:col-span-3 flex justify-end\">
                <button type=\"submit\" class=\"text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded px-4 py-2 transition\">Guardar cambios</button>
            </div>
        </form>
        <p class=\"text-xs text-slate-500\">Se bloqueará una IP que supere el umbral de alertas en la ventana indicada por el tiempo configurado.</p>
    </div>
    """


@dashboard_router.get("/blocked-ips", response_class=HTMLResponse)
async def blocked_ips_partial() -> str:
    """Devuelve un gráfico de barras mínimo para HTMX."""

    data = _blocked_ip_summary()
    max_count = max(int(item["count"]) for item in data)
    bars = []
    for item in data:
        percentage = int(int(item["count"]) / max_count * 100) if max_count else 0
        bars.append(
            f"""
            <div class=\"flex items-center gap-3\">
                <div class=\"w-28 text-xs font-semibold text-slate-600\">{item['ip']}</div>
                <div class=\"flex-1 h-3 rounded-full bg-slate-200 overflow-hidden\">
                    <div class=\"h-full bg-emerald-500 transition-all duration-500\" style=\"width: {percentage}%\"></div>
                </div>
                <span class=\"text-sm font-bold text-slate-800\">{item['count']}</span>
            </div>
            """
        )

    return "".join(bars)


@dashboard_router.get("/incidents", response_class=HTMLResponse)
async def incidents_partial() -> str:
    """Renderiza la tabla de incidentes para HTMX."""

    rows = []
    for incident in _recent_incidents():
        rows.append(
            f"""
            <tr class=\"border-b border-slate-100 last:border-none\">
                <td class=\"py-2 px-3 text-xs text-slate-600\">{incident['timestamp']}</td>
                <td class=\"py-2 px-3 text-sm font-semibold\">{incident['host']}</td>
                <td class=\"py-2 px-3 text-sm text-rose-600\">{incident['client']}</td>
                <td class=\"py-2 px-3 text-sm text-slate-700\">{incident['path']}</td>
                <td class=\"py-2 px-3 text-xs text-slate-500\">{incident['user_agent']}</td>
            </tr>
            """
        )
    return "".join(rows)


@dashboard_router.get("/tasks", response_class=HTMLResponse)
async def tasks_partial() -> str:
    """Muestra el estado de tareas registradas en Mimosa."""

    rows = []
    for task in _demo_tasks():
        rows.append(
            f"""
            <tr class=\"border-b border-slate-100 last:border-none\">
                <td class=\"py-2 px-3 text-sm font-semibold\">{task['name']}</td>
                <td class=\"py-2 px-3 text-sm\">
                    <span class=\"inline-flex items-center gap-2 rounded-full px-2 py-1 text-xs font-semibold { 'bg-emerald-50 text-emerald-700' if task['status'] == 'activo' else 'bg-amber-50 text-amber-700' }\">
                        <span class=\"h-2 w-2 rounded-full { 'bg-emerald-500' if task['status'] == 'activo' else 'bg-amber-400' }\"></span>
                        {task['status']}
                    </span>
                </td>
                <td class=\"py-2 px-3 text-xs text-slate-500\">{task['last_run']}</td>
                <td class=\"py-2 px-3\">
                    <button
                        hx-post=\"/api/dashboard/tasks/{task['name']}/toggle\"
                        hx-target=\"closest tr\"
                        hx-swap=\"outerHTML\"
                        class=\"text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded px-3 py-1 transition\"
                    >
                        Alternar
                    </button>
                </td>
            </tr>
            """
        )
    return "".join(rows)


@dashboard_router.post("/tasks/{task_name}/toggle", response_class=HTMLResponse)
async def toggle_task(task_name: str) -> str:
    """Alterna el estado de una tarea demo y devuelve la fila renderizada."""

    tasks = _demo_tasks()
    task = next((item for item in tasks if item["name"] == task_name), None)
    if task:
        task["status"] = "activo" if task["status"] == "en pausa" else "en pausa"
    else:
        task = {"name": task_name, "status": "activo", "last_run": datetime.utcnow().isoformat(timespec="seconds")}
        tasks.append(task)

    status_class = "bg-emerald-50 text-emerald-700" if task["status"] == "activo" else "bg-amber-50 text-amber-700"
    dot_class = "bg-emerald-500" if task["status"] == "activo" else "bg-amber-400"

    return f"""
    <tr class=\"border-b border-slate-100 last:border-none\">
        <td class=\"py-2 px-3 text-sm font-semibold\">{task['name']}</td>
        <td class=\"py-2 px-3 text-sm\">
            <span class=\"inline-flex items-center gap-2 rounded-full px-2 py-1 text-xs font-semibold {status_class}\">
                <span class=\"h-2 w-2 rounded-full {dot_class}\"></span>
                {task['status']}
            </span>
        </td>
        <td class=\"py-2 px-3 text-xs text-slate-500\">{task['last_run']}</td>
        <td class=\"py-2 px-3\">
            <button
                hx-post=\"/api/dashboard/tasks/{task['name']}/toggle\"
                hx-target=\"closest tr\"
                hx-swap=\"outerHTML\"
                class=\"text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded px-3 py-1 transition\"
            >
                Alternar
            </button>
        </td>
    </tr>
    """


@admin_router.get("/blocklist", response_class=HTMLResponse)
async def blocklist_partial() -> str:
    """Devuelve el listado de bloqueos en formato HTML para HTMX."""

    return _render_blocklist_rows()


@admin_router.post("/blocklist", response_class=HTMLResponse)
async def add_block(ip: str = Form(...), reason: str = Form("Bloqueo manual")) -> str:
    """Registra un bloqueo manual desde el panel."""

    payload = BlockRequest(
        source_ip=ip.strip(),
        reason=reason.strip() or "Bloqueo manual",
        duration_minutes=admin_state.blocking_policy.block_minutes,
    )
    core_api.register_block(payload)
    return _render_blocklist_rows()


@admin_router.post("/blocklist/{ip}/remove", response_class=HTMLResponse)
async def remove_block(ip: str) -> str:
    """Elimina una IP bloqueada manualmente."""

    core_api.unblock_ip(ip)
    return _render_blocklist_rows()


@admin_router.get("/alert-rules", response_class=HTMLResponse)
async def alert_rules_partial() -> str:
    """Lista las reglas que generan alertas."""

    return _render_alert_rules()


@admin_router.post("/alert-rules", response_class=HTMLResponse)
async def add_alert_rule(
    condition: str = Form(...),
    target: str = Form(...),
    severity: str = Form("medio"),
) -> str:
    """Añade una nueva condición de alerta configurable."""

    admin_state.add_alert_rule(condition.strip(), target.strip(), severity.strip() or "medio")
    return _render_alert_rules()


@admin_router.post("/alert-rules/{rule_id}/remove", response_class=HTMLResponse)
async def remove_alert_rule(rule_id: str) -> str:
    """Elimina una regla de alerta."""

    admin_state.remove_alert_rule(rule_id)
    return _render_alert_rules()


@admin_router.get("/blocking-policy", response_class=HTMLResponse)
async def blocking_policy_partial() -> str:
    """Muestra la política de escalado de alertas a bloqueo."""

    return _render_blocking_policy()


@admin_router.post("/blocking-policy", response_class=HTMLResponse)
async def update_blocking_policy(
    threshold: int = Form(...),
    window_minutes: int = Form(...),
    block_minutes: int = Form(...),
) -> str:
    """Actualiza los parámetros que convierten alertas en bloqueos."""

    admin_state.update_blocking_policy(threshold, window_minutes, block_minutes)
    return _render_blocking_policy()


app.include_router(dashboard_router)
app.include_router(admin_router, prefix="/api")
app.include_router(proxy_router, prefix="/api")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """
    <!doctype html>
    <html lang="es">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <title>Mimosa Dashboard</title>
            <link
                rel="stylesheet"
                href="https://cdn.jsdelivr.net/npm/tailwindcss@3.4.11/dist/tailwind.min.css"
                integrity="sha256-UZKknobrJUKd3vnHwR5K4cBHPtnRdG52D3Q+y6cANUk="
                crossorigin="anonymous"
            />
            <script src="https://unpkg.com/htmx.org@1.9.12" integrity="sha384-GLFEyep8smq56UMV7Evd9YndtxyQHJLmSxP5cGSNTWiLxTMoY4xAMGIPR3mS6O4S" crossorigin="anonymous"></script>
            <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
            <style>
                body { background: radial-gradient(circle at 10% 20%, #f0f9ff 0, #f7f7ff 25%, #ffffff 60%); }
                .glass { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); }
            </style>
        </head>
        <body class="min-h-screen text-slate-900">
            <header class="border-b border-slate-100 bg-white/70 backdrop-blur sticky top-0 z-10">
                <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
                    <div>
                        <p class="text-xs font-semibold text-emerald-600">Mimosa · API</p>
                        <h1 class="text-2xl font-bold">Panel de Control</h1>
                    </div>
                    <div class="flex items-center gap-3 text-sm text-slate-600">
                        <span class="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
                        API en línea
                    </div>
                </div>
            </header>
            <main class="max-w-6xl mx-auto px-6 py-8 space-y-6">
                <section class="grid md:grid-cols-2 gap-6">
                    <div class="glass rounded-2xl shadow-sm border border-slate-100 p-6 space-y-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-xs font-semibold text-emerald-600">Bloqueos</p>
                                <h2 class="text-xl font-bold">IPs bloqueadas</h2>
                            </div>
                            <button class="text-xs text-emerald-700" hx-get="/api/dashboard/blocked-ips" hx-target="#blocked-ips" hx-swap="innerHTML">Actualizar</button>
                        </div>
                        <div id="blocked-ips" class="space-y-3" hx-get="/api/dashboard/blocked-ips" hx-trigger="load, every 10s" hx-swap="innerHTML">
                            <div class="text-sm text-slate-500">Cargando...</div>
                        </div>
                    </div>
                    <div class="glass rounded-2xl shadow-sm border border-slate-100 p-6 space-y-4" x-data="{ filter: '' }">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-xs font-semibold text-emerald-600">Eventos</p>
                                <h2 class="text-xl font-bold">Incidentes recientes</h2>
                            </div>
                            <input x-model="filter" type="text" placeholder="Filtrar por IP" class="text-sm border border-slate-200 rounded-lg px-3 py-2" />
                        </div>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left">
                                <thead>
                                    <tr class="text-xs uppercase text-slate-500">
                                        <th class="py-2 px-3">Fecha</th>
                                        <th class="py-2 px-3">Host</th>
                                        <th class="py-2 px-3">IP</th>
                                        <th class="py-2 px-3">Ruta</th>
                                        <th class="py-2 px-3">Agente</th>
                                    </tr>
                                </thead>
                                <tbody id="incidents" hx-get="/api/dashboard/incidents" hx-trigger="load, every 12s" hx-swap="innerHTML" x-html="document.querySelector('#incidents')?.innerHTML" x-effect="
                                    document.querySelectorAll('#incidents tr').forEach(row => {
                                        const ipCell = row.querySelector('td:nth-child(3)');
                                        row.style.display = !filter || ipCell?.textContent.includes(filter) ? '' : 'none';
                                    });
                                ">
                                    <tr><td class="py-3 px-3 text-sm text-slate-500" colspan="5">Cargando incidentes...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>
                <section class="grid md:grid-cols-2 gap-6">
                    <div class="glass rounded-2xl shadow-sm border border-slate-100 p-6 space-y-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-xs font-semibold text-emerald-600">Administración</p>
                                <h2 class="text-xl font-bold">Lista de bloqueo manual</h2>
                            </div>
                            <button class="text-xs text-emerald-700" hx-get="/api/admin/blocklist" hx-target="#blocklist" hx-swap="innerHTML">Refrescar</button>
                        </div>
                        <form class="grid md:grid-cols-3 gap-3 text-sm" hx-post="/api/admin/blocklist" hx-target="#blocklist" hx-swap="innerHTML">
                            <input name="ip" type="text" required placeholder="IP a bloquear" class="md:col-span-1 border border-slate-200 rounded-lg px-3 py-2" />
                            <input name="reason" type="text" placeholder="Motivo" class="md:col-span-1 border border-slate-200 rounded-lg px-3 py-2" />
                            <button type="submit" class="md:col-span-1 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded px-4 py-2 transition">Añadir bloqueo</button>
                        </form>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left">
                                <thead>
                                    <tr class="text-xs uppercase text-slate-500">
                                        <th class="py-2 px-3">IP</th>
                                        <th class="py-2 px-3">Motivo</th>
                                        <th class="py-2 px-3">Creado</th>
                                        <th class="py-2 px-3">Expira</th>
                                        <th class="py-2 px-3">Acciones</th>
                                    </tr>
                                </thead>
                                <tbody id="blocklist" hx-get="/api/admin/blocklist" hx-trigger="load" hx-swap="innerHTML">
                                    <tr><td class="py-3 px-3 text-sm text-slate-500" colspan="5">Cargando bloqueos...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="glass rounded-2xl shadow-sm border border-slate-100 p-6 space-y-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-xs font-semibold text-emerald-600">Alertas</p>
                                <h2 class="text-xl font-bold">Condiciones configurables</h2>
                            </div>
                            <button class="text-xs text-emerald-700" hx-get="/api/admin/alert-rules" hx-target="#alert-rules" hx-swap="innerHTML">Refrescar</button>
                        </div>
                        <form class="grid md:grid-cols-3 gap-3 text-sm" hx-post="/api/admin/alert-rules" hx-target="#alert-rules" hx-swap="innerHTML">
                            <input name="condition" type="text" required placeholder="Condición (p.ej. Puerto prohibido)" class="md:col-span-1 border border-slate-200 rounded-lg px-3 py-2" />
                            <input name="target" type="text" required placeholder="Destino o rango (p.ej. 0-1023)" class="md:col-span-1 border border-slate-200 rounded-lg px-3 py-2" />
                            <select name="severity" class="md:col-span-1 border border-slate-200 rounded-lg px-3 py-2">
                                <option value="alto">Severidad alta</option>
                                <option value="medio" selected>Severidad media</option>
                                <option value="bajo">Severidad baja</option>
                            </select>
                            <div class="md:col-span-3 flex justify-end">
                                <button type="submit" class="text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded px-4 py-2 transition">Guardar regla</button>
                            </div>
                        </form>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left">
                                <thead>
                                    <tr class="text-xs uppercase text-slate-500">
                                        <th class="py-2 px-3">Condición</th>
                                        <th class="py-2 px-3">Objetivo</th>
                                        <th class="py-2 px-3">Severidad</th>
                                        <th class="py-2 px-3">Acciones</th>
                                    </tr>
                                </thead>
                                <tbody id="alert-rules" hx-get="/api/admin/alert-rules" hx-trigger="load" hx-swap="innerHTML">
                                    <tr><td class="py-3 px-3 text-sm text-slate-500" colspan="4">Cargando reglas...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>
                <section hx-get="/api/admin/blocking-policy" hx-trigger="load" hx-target="#blocking-policy" hx-swap="outerHTML">
                    <div id="blocking-policy">
                        <div class="glass rounded-2xl shadow-sm border border-slate-100 p-6 space-y-4">
                            <p class="text-sm text-slate-500">Cargando política de bloqueo...</p>
                        </div>
                    </div>
                </section>
                <section class="glass rounded-2xl shadow-sm border border-slate-100 p-6 space-y-4">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-xs font-semibold text-emerald-600">Automatización</p>
                            <h2 class="text-xl font-bold">Control de tareas</h2>
                        </div>
                        <button class="text-xs text-emerald-700" hx-get="/api/dashboard/tasks" hx-target="#tasks" hx-swap="innerHTML">Sincronizar</button>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left">
                            <thead>
                                <tr class="text-xs uppercase text-slate-500">
                                    <th class="py-2 px-3">Tarea</th>
                                    <th class="py-2 px-3">Estado</th>
                                    <th class="py-2 px-3">Última ejecución</th>
                                    <th class="py-2 px-3">Acciones</th>
                                </tr>
                            </thead>
                            <tbody id="tasks" hx-get="/api/dashboard/tasks" hx-trigger="load, every 15s" hx-swap="innerHTML">
                                <tr><td class="py-3 px-3 text-sm text-slate-500" colspan="4">Cargando tareas...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </section>
            </main>
        </body>
    </html>
    """
