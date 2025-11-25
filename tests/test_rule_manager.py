from datetime import timedelta
from pathlib import Path

from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.core.rules import OffenseEvent, OffenseRule, RuleManager
from tests.firewall_stubs import InMemoryFirewall


def _setup(tmp_path: Path):
    store = OffenseStore(db_path=tmp_path / "rules.db")
    block_manager = BlockManager(
        db_path=store.db_path,
        default_duration_minutes=45,
        whitelist_checker=store.is_whitelisted,
    )
    firewall = InMemoryFirewall()
    return store, block_manager, firewall


def test_catch_all_rule_blocks_first_offense(tmp_path):
    store, block_manager, firewall = _setup(tmp_path)
    manager = RuleManager(store, block_manager, firewall)

    event = OffenseEvent(
        source_ip="203.0.113.10",
        plugin="any",
        event_id="generic",
        severity="alto",
        description="prueba de bloqueo",
    )
    store.record(source_ip=event.source_ip, description=event.description, severity=event.severity)

    entry = manager.process_offense(event)

    assert entry is not None
    assert entry.ip == event.source_ip
    assert firewall.list_blocks() == [event.source_ip]


def test_rule_thresholds_consider_counts(tmp_path):
    store, block_manager, firewall = _setup(tmp_path)
    rule = OffenseRule(
        plugin="auth",
        event_id="login_failed",
        severity="alto",
        description="Fallo de login",
        min_last_hour=1,
        min_total=2,
        block_minutes=120,
    )
    manager = RuleManager(store, block_manager, firewall, rules=[rule])

    event = OffenseEvent(
        source_ip="198.51.100.5",
        plugin="auth",
        event_id="login_failed",
        severity="alto",
        description="Fallo de login",
    )

    for _ in range(2):
        store.record(source_ip=event.source_ip, description=event.description, severity=event.severity)
        assert manager.process_offense(event) is None

    store.record(source_ip=event.source_ip, description=event.description, severity=event.severity)
    entry = manager.process_offense(event)

    assert entry is not None
    assert entry.expires_at is not None
    remaining = entry.expires_at - entry.created_at
    assert remaining >= timedelta(minutes=119)
    assert firewall.list_blocks() == [event.source_ip]


def test_whitelisted_ips_are_not_sent_to_firewall(tmp_path):
    store, block_manager, firewall = _setup(tmp_path)
    store.add_whitelist("203.0.113.0/24")
    manager = RuleManager(store, block_manager, firewall)

    event = OffenseEvent(
        source_ip="203.0.113.10",
        plugin="any",
        event_id="generic",
        severity="alto",
        description="en whitelist",
    )
    store.record(source_ip=event.source_ip, description=event.description, severity=event.severity)

    entry = manager.process_offense(event)

    assert entry is not None
    assert firewall.list_blocks() == []
    assert any(b.ip == event.source_ip for b in block_manager.list())


def test_unblock_removes_from_firewall(tmp_path):
    store, block_manager, firewall = _setup(tmp_path)
    manager = RuleManager(store, block_manager, firewall)

    event = OffenseEvent(
        source_ip="192.0.2.33",
        plugin="any",
        event_id="generic",
        severity="medio",
        description="ruido",
    )
    store.record(source_ip=event.source_ip, description=event.description, severity=event.severity)
    manager.process_offense(event)
    assert firewall.list_blocks() == [event.source_ip]

    manager.unblock_ip(event.source_ip)

    assert block_manager.list() == []
    assert firewall.list_blocks() == []


def test_empty_filters_behave_as_wildcards(tmp_path):
    store, block_manager, firewall = _setup(tmp_path)
    rule = OffenseRule(
        plugin="",
        event_id="",
        severity="",
        description="",
    )
    manager = RuleManager(store, block_manager, firewall, rules=[rule])

    event = OffenseEvent(
        source_ip="203.0.113.50",
        plugin="any",
        event_id="any_event",
        severity="medio",
        description="Prueba de wildcard",
    )
    store.record(source_ip=event.source_ip, description=event.description, severity=event.severity)

    entry = manager.process_offense(event)

    assert entry is not None
    assert firewall.list_blocks() == [event.source_ip]
