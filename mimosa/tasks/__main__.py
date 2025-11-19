"""Punto de entrada para ejecutar tareas periódicas en modo demo."""
from mimosa.tasks.scheduler import TaskScheduler


def example_task() -> None:
    print("[TASKS] Ejecutando tarea de ejemplo")


def main() -> None:
    scheduler = TaskScheduler()
    scheduler.register("demo", example_task)
    scheduler.run_all()


if __name__ == "__main__":
    main()
