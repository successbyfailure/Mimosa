from pathlib import Path

from mimosa.core.rules import OffenseRule, OffenseRuleStore


def test_rule_store_reorder_persists_priority(tmp_path: Path):
    store = OffenseRuleStore(db_path=tmp_path / "rules_store.db")
    first = store.add(OffenseRule(name="first"))
    second = store.add(OffenseRule(name="second"))
    third = store.add(OffenseRule(name="third"))

    ordered = store.list()
    assert [rule.id for rule in ordered] == [first.id, second.id, third.id]

    assert first.id is not None and second.id is not None and third.id is not None
    reordered = store.reorder([third.id, first.id, second.id])
    assert [rule.id for rule in reordered] == [third.id, first.id, second.id]
    assert [rule.priority for rule in reordered] == [1, 2, 3]

    persisted = store.list()
    assert [rule.id for rule in persisted] == [third.id, first.id, second.id]
