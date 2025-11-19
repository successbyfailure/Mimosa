"""Definición de tareas periódicas de Mimosa."""
from datetime import datetime
from typing import Callable, Dict


class TaskScheduler:
    """Programador mínimo para tareas periódicas.

    Se puede reemplazar por Celery, APScheduler u otro componente más robusto.
    """

    def __init__(self):
        self.tasks: Dict[str, Callable[[], None]] = {}

    def register(self, name: str, func: Callable[[], None]) -> None:
        self.tasks[name] = func

    def run_all(self) -> None:
        for name, func in self.tasks.items():
            print(f"[TASKS] Ejecutando {name} @ {datetime.utcnow().isoformat()}")
            func()
