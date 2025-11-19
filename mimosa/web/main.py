"""Dashboard de Mimosa basado en FastAPI y HTMX/Alpine.js."""
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List

from fastapi import APIRouter, FastAPI
from fastapi.responses import HTMLResponse

from mimosa.proxy_trap.endpoint import forbidden_interface_attempts, router as proxy_router

app = FastAPI(title="Mimosa Dashboard")

dashboard_router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


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
        counts = Counter(attempt.get("client", "desconocido") for attempt in forbidden_interface_attempts)
        return [
            {"ip": ip, "count": str(count)}
            for ip, count in counts.most_common(6)
        ]

    # Datos de ejemplo cuando no hay actividad real
    return [
        {"ip": "192.0.2.15", "count": "8"},
        {"ip": "198.51.100.7", "count": "6"},
        {"ip": "203.0.113.42", "count": "4"},
    ]


def _recent_incidents() -> List[Dict[str, str]]:
    """Construye una tabla de incidentes a partir de intentos o datos ficticios."""

    incidents: List[Dict[str, str]] = []
    if forbidden_interface_attempts:
        for attempt in forbidden_interface_attempts[-10:]:
            incidents.append(
                {
                    "timestamp": attempt.get("timestamp", datetime.utcnow().isoformat(timespec="seconds")),
                    "host": attempt.get("host", "desconocido"),
                    "client": attempt.get("client", "desconocido"),
                    "path": attempt.get("path", "/"),
                    "user_agent": attempt.get("user_agent", ""),
                }
            )
    else:
        base_time = datetime.utcnow()
        incidents = [
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

    return incidents


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


app.include_router(dashboard_router)
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
