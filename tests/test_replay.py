"""审计与趋势的同轴回放、缺段补齐与归档封段（平台级）。"""

from __future__ import annotations

import json
import os

import pytest

from cspplant.audit.replay import CO_AXIS
from cspplant.store.journal import JsonlJournal


def test_trend_samples_are_persisted_and_replayed_co_axis(online):
    for _ in range(4):
        online.cycle(dt=5.0)
    online.seal_archives()

    result = online.replay_plant(policy="strict")
    assert result["alignment"] == CO_AXIS
    assert result["complete"] is True
    timeline = result["timeline"]
    # 同轴：同一条时间轴上既有 audit 又有 trend 两类事件。
    kinds = {event["kind"] for event in timeline}
    assert {"audit", "trend"} <= kinds
    # 时间严格有序；同一时刻审计排在趋势前面。
    keys = [(event["ts"], 0 if event["kind"] == "audit" else 1) for event in timeline]
    assert keys == sorted(keys)
    # 帧把同一时刻的处置与采样合到一起。
    assert result["counts"]["frames"] >= 1
    assert any(frame["trend"] for frame in result["frames"])
    # 回放动作本身落审计。
    assert online.audit.count("audit_replay") >= 1


def test_replay_restores_working_condition_at_alarm_moment(online, clock):
    online.trip("overtemperature")
    online.seal_archives()
    result = online.replay_plant(policy="strict")
    trip_events = [
        event
        for event in result["timeline"]
        if event["kind"] == "audit" and event["action"] == "receiver_trip_complete"
    ]
    assert trip_events
    trip_ts = trip_events[0]["ts"]
    # 同一帧里能看到跳闸时刻的处置；附近帧带有趋势采样，工况可还原。
    frame = next(frame for frame in result["frames"] if frame["ts"] == trip_ts)
    assert any(item["action"] == "receiver_trip_complete" for item in frame["audit"])


def test_trend_survives_restart(online, clock):
    for _ in range(3):
        online.cycle(dt=5.0)
    before = online.trend.series("receiver_temperature", limit=10)
    from cspplant.app import build_plant
    from cspplant.config import default_config

    reopened = build_plant(default_config(), clock=clock, storage_root=online.store.root)
    after = reopened.trend.series("receiver_temperature", limit=10)
    assert len(after) == len(before)
    assert [sample.ts for sample in after] == pytest.approx([sample.ts for sample in before])


def test_fill_missing_segment_is_audited_and_idempotent(online, clock):
    online.start()
    online.track(820.0, 720.0)
    online.seal_archives()

    root = online.store.root
    journal = online.audit.journal
    anchor = journal.verify_chain()["anchor"]
    # 删掉最后一个封档段（anchor 指向它，重开后被识别为缺段）。
    target = anchor["tail_seq"]
    os.remove(os.path.join(root, f"audit-{target:05d}.jsonl"))

    first = online.fill_audit_gaps(note="test")
    assert first["filled"] and first["filled"][0]["seq"] == target
    # 补段动作落了审计，且带依据的左右邻校验值。
    fill_records = [
        item for item in online.audit.entries(limit=50)
        if item["action"] == "audit_segment_filled"
    ]
    assert fill_records
    payload = fill_records[0]["payload"]
    assert payload["segment_seq"] == target
    assert payload["gap_digest"]
    assert "left_digest" in payload

    # 幂等：再触发不产生补段、不再多落审计。
    audit_count_before = online.audit.count("audit_segment_filled")
    second = online.fill_audit_gaps(note="test")
    assert second["filled"] == []
    assert online.audit.count("audit_segment_filled") == audit_count_before

    # 补齐属于部分失败：marked 回放显式标注缺口、不伪造内容。
    replay = online.replay_plant(policy="marked")
    assert replay["alignment"] == CO_AXIS
    assert any(seg["status"] == "gap" for seg in replay["integrity"]["audit_skipped"])


def test_verify_reports_healthy_chain(online):
    online.start()
    online.track(820.0, 720.0)
    online.seal_archives()
    report = online.verify_archives()
    assert report["audit"]["healthy"] is True
    assert report["trend"]["healthy"] is True


def test_stop_seals_archives(online):
    online.stop()
    chain = online.audit.verify_chain()
    assert all(seg["status"] in ("ok",) for seg in chain["segments"])
