from pathlib import Path

from fastapi.testclient import TestClient

from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.web.app import create_app
from tests.firewall_stubs import InMemoryFirewall


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
        gateway_builder=lambda cfg: InMemoryFirewall(),
    )
    client = TestClient(app)

    offense_store.record(source_ip="1.2.3.4", description="test")
    block_manager.add("1.2.3.4", "reason")

    before = client.get("/api/stats").json()
    assert before["offenses"]["total"] == 1
    assert before["blocks"]["total"] == 1

    reset = client.post("/api/stats/reset")
    assert reset.status_code == 200

    after = client.get("/api/stats").json()
    assert after["offenses"]["total"] == 0
    assert after["blocks"]["total"] == 0
    assert after["offenses"]["timeline"]["7d"] == []
    assert after["blocks"]["timeline"]["7d"] == []
