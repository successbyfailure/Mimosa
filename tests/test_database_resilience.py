import sqlite3
import threading

from mimosa.core.blocking import _should_rebuild_sqlite as blocking_should_rebuild
from mimosa.core.offenses import OffenseStore
from mimosa.core.offenses import _should_rebuild_sqlite as offenses_should_rebuild
from mimosa.core.plugins import PluginConfigStore


def test_offense_store_record_handles_ip_profile_race(tmp_path) -> None:
    db_path = tmp_path / "mimosa.db"
    store = OffenseStore(db_path=db_path)
    store._enrich_ip = lambda _ip: {}  # evita llamadas de red en test

    total = 2
    barrier = threading.Barrier(total)
    errors: list[Exception] = []

    def worker(index: int) -> None:
        try:
            barrier.wait(timeout=5)
            store.record(source_ip="203.0.113.10", description=f"race-{index}")
        except Exception as exc:  # pragma: no cover - solo para recolectar fallos de hilo
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(total)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    with store._connection() as conn:
        profile = conn.execute(
            "SELECT offenses_count FROM ip_profiles WHERE ip = ?;",
            ("203.0.113.10",),
        ).fetchone()
        offense_count = conn.execute(
            "SELECT COUNT(*) FROM offenses WHERE source_ip = ?;",
            ("203.0.113.10",),
        ).fetchone()
    assert profile is not None
    assert int(profile[0]) == total
    assert int(offense_count[0]) == total


def test_get_mimosanpm_does_not_save_when_config_is_already_normalized(tmp_path, monkeypatch) -> None:
    store = PluginConfigStore(
        db_path=tmp_path / "mimosa.db",
        legacy_path=tmp_path / "plugins.json",
    )
    calls = {"count": 0}
    original_save = store._save

    def tracked_save() -> None:
        calls["count"] += 1
        original_save()

    monkeypatch.setattr(store, "_save", tracked_save)

    store.get_mimosanpm()
    store.get_mimosanpm()

    assert calls["count"] == 0


def test_rebuild_guard_ignores_transient_errors() -> None:
    locked = sqlite3.OperationalError("database is locked")
    readonly = sqlite3.OperationalError("attempt to write a readonly database")
    assert not offenses_should_rebuild(locked)
    assert not offenses_should_rebuild(readonly)
    assert not blocking_should_rebuild(locked)
    assert not blocking_should_rebuild(readonly)


def test_rebuild_guard_accepts_corruption_signatures() -> None:
    malformed = sqlite3.DatabaseError("database disk image is malformed")
    bad_file = sqlite3.DatabaseError("file is not a database")
    assert offenses_should_rebuild(malformed)
    assert offenses_should_rebuild(bad_file)
    assert blocking_should_rebuild(malformed)
    assert blocking_should_rebuild(bad_file)
