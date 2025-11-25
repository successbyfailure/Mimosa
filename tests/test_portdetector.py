import socket
import time
from tempfile import TemporaryDirectory

from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.core.plugins import PortDetectorConfig, PortDetectorRule
from mimosa.core.portdetector import PortDetectorService
from mimosa.core.rules import OffenseRuleStore
from tests.helpers import MemoryFirewall


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_portdetector_records_tcp_offense() -> None:
    with TemporaryDirectory() as tmp:
        offense_store = OffenseStore(db_path=f"{tmp}/mimosa.db")
        block_manager = BlockManager(db_path=offense_store.db_path)
        rule_store = OffenseRuleStore(db_path=offense_store.db_path)
        service = PortDetectorService(
            offense_store,
            block_manager,
            rule_store,
            gateway_factory=lambda: MemoryFirewall(),
        )

        port = _free_port()
        config = PortDetectorConfig(
            enabled=True,
            default_severity="alto",
            rules=[PortDetectorRule(protocol="tcp", port=port, severity="alto")],
        )
        service.apply_config(config)

        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
        time.sleep(0.2)

        offenses = offense_store.list_recent(5)
        assert any(off.description == f"portdetector TCP:{port}" for off in offenses)
        service.stop()


def test_portdetector_records_udp_offense() -> None:
    with TemporaryDirectory() as tmp:
        offense_store = OffenseStore(db_path=f"{tmp}/mimosa.db")
        block_manager = BlockManager(db_path=offense_store.db_path)
        rule_store = OffenseRuleStore(db_path=offense_store.db_path)
        service = PortDetectorService(
            offense_store,
            block_manager,
            rule_store,
            gateway_factory=lambda: MemoryFirewall(),
        )

        port = _free_port()
        config = PortDetectorConfig(
            enabled=True,
            default_severity="medio",
            rules=[PortDetectorRule(protocol="udp", port=port, severity="bajo")],
        )
        service.apply_config(config)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(b"ping", ("127.0.0.1", port))
        time.sleep(0.2)

        offenses = offense_store.list_recent(5)
        assert any(off.description == f"portdetector UDP:{port}" for off in offenses)
        service.stop()
