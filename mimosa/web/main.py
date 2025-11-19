"""Dashboard de Mimosa basado en FastAPI.

Incluye la base para montar Tailwind CSS a través de compilación externa.
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from mimosa.proxy_trap.endpoint import router as proxy_router

app = FastAPI(title="Mimosa Dashboard")
app.include_router(proxy_router, prefix="/api")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """
    <html>
        <head>
            <title>Mimosa</title>
            <link rel="stylesheet" href="/static/styles.css" />
        </head>
        <body class="bg-gray-50 text-slate-900">
            <main class="container mx-auto py-10">
                <h1 class="text-3xl font-bold">Mimosa Dashboard</h1>
                <p class="mt-4">Punto de partida para integrar métricas, alertas y bloqueos.</p>
            </main>
        </body>
    </html>
    """
