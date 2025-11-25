from pathlib import Path

from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.web.app import create_app


def _get_endpoint(app, path: str, method: str = "GET"):
    for route in app.router.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", {"GET"}):
            return route.endpoint
    raise AssertionError(f"No se encontró el endpoint {path}")


def test_stats_reset_clears_data(tmp_path: Path) -> None:
    db_path = tmp_path / "mimosa.db"
    offense_store = OffenseStore(db_path=db_path)
    block_manager = BlockManager(
        db_path=db_path, whitelist_checker=offense_store.is_whitelisted
    )
    app = create_app(
        offense_store=offense_store,
        block_manager=block_manager,
        proxytrap_stats_path=tmp_path / "proxytrap.json",
    )
    stats_endpoint = _get_endpoint(app, "/api/stats")
    reset_endpoint = _get_endpoint(app, "/api/stats/reset", "POST")

    offense_store.record(source_ip="1.2.3.4", description="test")
    block_manager.add("1.2.3.4", "reason")

    before = stats_endpoint()
    assert before["offenses"]["total"] == 1
    assert before["blocks"]["total"] == 1

    reset = reset_endpoint()
    assert reset["offenses"]["total"] == 0

    after = stats_endpoint()
    assert after["offenses"]["total"] == 0
    assert after["blocks"]["total"] == 0
    assert after["offenses"]["timeline"]["7d"] == []
    assert after["blocks"]["timeline"]["7d"] == []
