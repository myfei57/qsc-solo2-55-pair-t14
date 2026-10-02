"""跨段校验链、封段、补段与同轴回放的测试。"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cspplant.app import build_plant
from cspplant.audit.replay import SHARED_AXIS, replay_shared_axis, working_condition_at
from cspplant.clock import ManualClock
from cspplant.config import default_config
from cspplant.store.chain import (
    ChainedJournal,
    LENIENT,
    STRICT,
    SegmentIntegrityError,
    export_segment_bundle,
    load_segment_bundle,
)
from cspplant.telemetry import Sample


# ---- 链式流水：封段 / 重开 / 检测 -----------------------------------


def test_chain_seals_segments_and_links(tmp_path):
    journal = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(5):
        journal.append({"ts": 100.0 + index, "action": f"a{index}"})
    assert journal.active_segment() == 2
    assert journal.sealed_indices() == [0, 1]
    reads = journal.verify(STRICT)
    # 两个已封段 + 一个活动段。
    assert [(r.index, r.ok, r.sealed) for r in reads] == [
        (0, True, True),
        (1, True, True),
        (2, True, False),
    ]


def test_chain_reopens_and_continues(tmp_path):
    first = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(4):
        first.append({"ts": float(index), "action": f"a{index}"})
    second = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    assert second.count() == 4
    assert second.active_segment() == 2
    second.append({"ts": 4.0, "action": "a4"})
    second.append({"ts": 5.0, "action": "a5"})  # 填满段 2 触发自动封段
    assert second.sealed_indices() == [0, 1, 2]
    assert all(r.ok for r in second.verify(STRICT))


def test_tampered_record_is_pinpointed(tmp_path):
    journal = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(6):
        journal.append({"ts": float(index), "action": f"a{index}"})
    target = Path(journal._sealed_path(1))
    lines = target.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["body"]["action"] = "forged"
    target.write_text(json.dumps(row, ensure_ascii=False) + "\n" + "\n".join(lines[1:]) + "\n",
                      encoding="utf-8")

    reopened = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    with pytest.raises(SegmentIntegrityError) as exc:
        reopened.verify(STRICT)
    assert exc.value.segment == 1
    assert exc.value.kind == "corrupt"

    reads = reopened.verify(LENIENT)
    by_index = {r.index: r for r in reads}
    assert by_index[1].ok is False
    assert "入口哈希" in by_index[1].errors[0]
    # 坏段整段不采信，好段仍按段号读出。
    assert by_index[1].entries == []
    assert [e["action"] for e in by_index[0].entries] == ["a0", "a1"]


def test_extra_inserted_record_breaks_segment(tmp_path):
    journal = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(4):
        journal.append({"ts": float(index), "action": f"a{index}"})
    target = journal._sealed_path(0)
    extra = {"seq": 99, "prev_hash": "x", "entry_hash": "y", "body": {"ts": 0.1, "action": "extra"}}
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(extra) + "\n")
    reopened = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    with pytest.raises(SegmentIntegrityError):
        reopened.verify(STRICT)
    assert reopened.verify(LENIENT)[0].ok is False


def test_deleted_segment_is_detected_and_named(tmp_path):
    journal = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(6):
        journal.append({"ts": float(index), "action": f"a{index}"})
    os.remove(journal._sealed_path(1))
    os.remove(journal._meta_path(1))

    reopened = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    assert reopened.missing_indices() == [1]
    with pytest.raises(SegmentIntegrityError) as exc:
        reopened.verify(STRICT)
    assert exc.value.segment == 1 and exc.value.kind == "missing"

    reads = reopened.verify(LENIENT)
    by_index = {r.index: r for r in reads}
    assert by_index[1].missing is True and by_index[1].ok is False
    # 宽松读：跳过缺段，段 0、段 2 的记录仍按段号升序，时间不乱。
    entries, _ = reopened.read_all(LENIENT)
    assert [e["action"] for e in entries] == ["a0", "a1", "a4", "a5"]


def test_strict_vs_lenient_read_policies(tmp_path):
    journal = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(4):
        journal.append({"ts": float(index), "action": f"a{index}"})
    os.remove(journal._sealed_path(0))
    os.remove(journal._meta_path(0))
    reopened = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    with pytest.raises(SegmentIntegrityError):
        reopened.read_all(STRICT)
    entries, reads = reopened.read_all(LENIENT)
    assert any(not r.ok for r in reads)
    assert isinstance(entries, list)  # 宽松模式不抛错，能返回好段数据


def test_hmac_rejects_forged_manifest(tmp_path):
    # 攻击场景：攻击者改了段数据，并伪造一份"自洽"清单（按改后数据重算
    # root/chain），但他没有密钥、算不出合法 HMAC。无密钥的链会被这份自洽清单
    # 骗过，带密钥的链必须在验签这一步拦下。
    forged = ChainedJournal(str(tmp_path / "forged"), "audit", segment_limit=2)
    for index in range(4):
        forged.append({"ts": float(index), "action": "forged_data"})
    signed = ChainedJournal(str(tmp_path / "signed"), "audit", segment_limit=2, secret="s3cr3t")
    for index in range(4):
        signed.append({"ts": float(index), "action": f"a{index}"})

    meta = Path(signed._meta_path(0))
    manifest = json.loads(meta.read_text(encoding="utf-8").strip())
    forged_manifest = forged.manifest_of(0)
    manifest["root"] = forged_manifest.root
    manifest["chain"] = forged_manifest.chain  # 改后自洽，但 mac 仍是旧的
    meta.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    reopened = ChainedJournal(str(tmp_path / "signed"), "audit", segment_limit=2, secret="s3cr3t")
    with pytest.raises(SegmentIntegrityError) as exc:
        reopened.verify(STRICT)
    assert exc.value.kind == "corrupt"
    read = reopened.verify(LENIENT)[0]
    assert any("签名" in err for err in read.errors)


# ---- 补段：守时序 / 幂等 / 落审计 -----------------------------------


def test_fill_missing_segment_from_bundle(tmp_path):
    # 源侧产生多段并导出段 1。
    source_root = tmp_path / "src"
    src = ChainedJournal(str(source_root), "audit", segment_limit=2)
    for index in range(6):
        src.append({"ts": float(index), "action": f"a{index}"})
    bundle = tmp_path / "bundles" / "segment-00001"
    export_segment_bundle(src, 1, str(bundle))
    envelopes, manifest = load_segment_bundle(str(bundle))

    dst = ChainedJournal(str(tmp_path / "dst"), "audit", segment_limit=2)
    for index in range(6):  # 同链重放，再删段 1
        dst.append({"ts": float(index), "action": f"a{index}"})
    os.remove(dst._sealed_path(1))
    os.remove(dst._meta_path(1))
    dst._recover_state()
    assert dst.missing_indices() == [1]

    returned = dst.import_segment(1, envelopes, manifest)
    assert returned.chain == manifest.chain
    assert dst.missing_indices() == []
    assert all(r.ok for r in dst.verify(STRICT))


def test_fill_is_idempotent(tmp_path):
    journal = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(6):
        journal.append({"ts": float(index), "action": f"a{index}"})
    bundle = tmp_path / "seg"
    export_segment_bundle(journal, 1, str(bundle))
    envelopes, manifest = load_segment_bundle(str(bundle))
    # 段已存在且链值一致：重复补不报错、不覆盖。
    again = journal.import_segment(1, envelopes, manifest)
    assert again.chain == manifest.chain
    assert journal.sealed_indices() == [0, 1, 2]


def test_fill_rejects_tampered_and_wrong_chain(tmp_path):
    good = ChainedJournal(str(tmp_path / "good"), "audit", segment_limit=2)
    for index in range(6):
        good.append({"ts": float(index), "action": f"a{index}"})
    bundle = tmp_path / "b"
    export_segment_bundle(good, 1, str(bundle))
    envelopes, manifest = load_segment_bundle(str(bundle))

    dst = ChainedJournal(str(tmp_path / "dst"), "audit", segment_limit=2)
    for index in range(6):
        dst.append({"ts": float(index), "action": "DIFFERENT"})
    os.remove(dst._sealed_path(1))
    os.remove(dst._meta_path(1))
    dst._recover_state()
    # 来源段属于另一条链（prev_chain 对不上 / root 自洽但接不上）。
    with pytest.raises(SegmentIntegrityError) as exc:
        dst.import_segment(1, envelopes, manifest)
    assert exc.value.kind in ("chain", "corrupt")


def test_fill_must_follow_segment_order(tmp_path):
    journal = ChainedJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(8):
        journal.append({"ts": float(index), "action": f"a{index}"})
    for seg in (1, 2):
        os.remove(journal._sealed_path(seg))
        os.remove(journal._meta_path(seg))
    journal._recover_state()
    assert journal.missing_indices() == [1, 2]
    bundle2 = tmp_path / "b2"
    export_segment_bundle(
        ChainedJournal(str(tmp_path / "fresh"), "audit", segment_limit=2), 0, str(bundle2)
    ) if False else None
    # 即便拿到段 2 的真包，前驱段 1 缺失时也不许跳着补段 2。
    real = ChainedJournal(str(tmp_path / "real"), "audit", segment_limit=2)
    for index in range(8):
        real.append({"ts": float(index), "action": f"a{index}"})
    b2 = tmp_path / "real2"
    export_segment_bundle(real, 2, str(b2))
    envelopes, manifest = load_segment_bundle(str(b2))
    with pytest.raises(SegmentIntegrityError) as exc:
        journal.import_segment(2, envelopes, manifest)
    assert exc.value.kind == "chain"


# ---- 审计层：校验/补段落审计 + 回放策略 -----------------------------


def _plant(tmp_path, clock=None):
    clock = clock or ManualClock()
    return build_plant(default_config(), clock=clock, storage_root=str(tmp_path / "state")), clock


def test_audit_fill_missing_logs_everything_and_is_idempotent(tmp_path):
    from cspplant.audit.log import AuditLog
    from cspplant.eventbus import EventBus

    # 用很小的审计段，制造多个已封段后删中间段，形成真正的"中段缺口"。
    clock = ManualClock()
    bus = EventBus()
    journal = ChainedJournal(str(tmp_path / "state"), "audit", segment_limit=3)
    audit = AuditLog(clock, bus, journal)
    from cspplant.audit.record import AuditRecord

    for index in range(9):
        audit.record(AuditRecord.create(100.0 + index, "m021", "field", f"act{index}"))
    audit.seal()  # 封好最后一段 → 共 3 个已封段
    assert audit.journal.sealed_indices() == [0, 1, 2]

    victim = 1
    bundle_root = tmp_path / "bundles"
    export_segment_bundle(audit.journal, victim, str(bundle_root / f"segment-{victim:05d}"))
    os.remove(audit.journal._sealed_path(victim))
    os.remove(audit.journal._meta_path(victim))
    audit.journal._recover_state()
    assert audit.journal.missing_indices() == [victim]

    before_fill = audit.count("audit_segment_filled")
    report = audit.fill_missing(str(bundle_root))
    assert [item["segment"] for item in report["filled"]] == [victim]
    assert report["chain_closed"] is True
    # 补段记录里必须写明依据哪段清单的校验值。
    fill_entry = [e for e in audit.entries(50) if e["action"] == "audit_segment_filled"][0]
    assert fill_entry["payload"]["basis_chain"]
    assert fill_entry["payload"]["segment"] == victim
    assert audit.count("audit_segment_filled") == before_fill + 1
    assert all(r.ok for r in audit.verify(STRICT))

    # 再触发一次：无缺口，幂等，不多落补段审计。
    again = audit.fill_missing(str(bundle_root))
    assert again["idempotent"] is True and again["filled"] == []
    assert audit.count("audit_segment_filled") == before_fill + 1


def test_audit_verify_lifecycle_is_recorded(tmp_path):
    plant, _ = _plant(tmp_path)
    plant.start()
    plant.track(800.0, 720.0)
    plant.audit.verify(LENIENT)
    assert plant.audit.count("audit_verify") >= 1


def test_restore_skips_untrusted_journal(tmp_path):
    plant, clock = _plant(tmp_path)
    plant.start()
    plant.track(800.0, 720.0)
    plant.trip("overtemperature")
    plant.seal_archives()
    # 篡改一个已封段，使 STRICT 取证回放失败。
    indices = plant.audit.journal.sealed_indices()
    target_meta = Path(plant.audit.journal._meta_path(indices[0]))
    m = json.loads(target_meta.read_text(encoding="utf-8").strip())
    m["root"] = "f" * 64
    target_meta.write_text(json.dumps(m) + "\n", encoding="utf-8")

    restarted = build_plant(default_config(), clock=ManualClock(start=clock.now()),
                            storage_root=plant.store.root)
    # 链不可信 → 不据回放置位联锁。
    assert restarted.latch.latched() is False
    assert restarted.audit.count("audit_restore_skipped") == 1


# ---- 同轴回放 --------------------------------------------------------


def test_replay_is_shared_axis_and_sorted(tmp_path):
    plant, clock = _plant(tmp_path)
    plant.start()
    plant.track(800.0, 720.0)
    plant.circulate()
    plant.dispatch(100.0, "t")
    for _ in range(3):
        plant.cycle(dt=5.0)
        clock.advance(5.0)
    result = plant.replay()
    assert result["axis"] == SHARED_AXIS
    ts = [event["ts"] for event in result["events"]]
    assert ts == sorted(ts)
    kinds = {event["kind"] for event in result["events"]}
    assert kinds == {"trend", "audit"}
    assert result["trustworthy"] is True


def test_replay_tiebreak_trend_before_audit():
    a = [_rec(10.0, "track")]
    t = {"x": [Sample(10.0, 1.5)]}
    window = replay_shared_axis(a, t)
    assert window.events[0]["kind"] == "trend"
    assert window.events[1]["kind"] == "audit"


def test_replay_rejects_independent_axis():
    with pytest.raises(ValueError):
        replay_shared_axis([], {}, axis="independent")


def test_working_condition_reconstructs_moment(tmp_path):
    plant, clock = _plant(tmp_path)
    plant.start()
    plant.cycle(dt=5.0)
    clock.advance(5.0)
    plant.trip("overtemperature")
    moment = clock.now()
    plant.cycle(dt=5.0)
    clock.advance(5.0)
    condition = plant.working_condition(moment)
    assert condition["axis"] == SHARED_AXIS
    assert "receiver_temperature" in condition["signals"]
    actions = [e["action"] for e in condition["audit"]]
    assert "receiver_trip_complete" in actions


def test_replay_survives_restart_on_shared_axis(tmp_path):
    plant, clock = _plant(tmp_path)
    plant.start()
    plant.circulate()
    for _ in range(2):
        plant.cycle(dt=5.0)
        clock.advance(5.0)
    plant.stop()
    restarted = build_plant(default_config(), clock=ManualClock(start=clock.now()),
                            storage_root=plant.store.root)
    result = restarted.replay()
    assert result["trustworthy"] is True
    assert {e["kind"] for e in result["events"]} == {"trend", "audit"}
    # 趋势从链式流水读回内存。
    assert len(restarted.trend.series("receiver_temperature")) == 2


def _rec(ts: float, action: str):
    from cspplant.audit.record import AuditRecord

    return AuditRecord.create(ts, "m021", "field", action, "notice", "")
