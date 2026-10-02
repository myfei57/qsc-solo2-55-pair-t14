"""跨段哈希链：篡改/缺段定位、按策略读、补段幂等、时间顺序守护。"""

from __future__ import annotations

import json
import os

import pytest

from cspplant.errors import StorageError
from cspplant.store.chain import (
    READ_LENIENT,
    READ_MARKED,
    READ_STRICT,
    SEGMENT_ALTERED,
    SEGMENT_BROKEN_LINK,
    SEGMENT_GAP,
    SEGMENT_MISSING,
    SEGMENT_OK,
    SEGMENT_UNSEALED,
)
from cspplant.store.journal import JsonlJournal


def _write(tmp_path, limit=2, n=5, topic="audit"):
    journal = JsonlJournal(str(tmp_path), topic, segment_limit=limit)
    for index in range(n):
        journal.append({"ts": 100.0 + index, "index": index})
    return journal


def test_chain_healthy_after_seal_and_reopen(tmp_path):
    journal = _write(tmp_path)
    report = journal.verify_chain()
    assert report["healthy"] is True
    statuses = [(seg["seq"], seg["status"]) for seg in report["segments"]]
    assert statuses == [(0, SEGMENT_OK), (1, SEGMENT_OK), (2, SEGMENT_UNSEALED)]
    # 每个封档段都带跨段摘要，且首段锚定 GENESIS。
    assert report["segments"][0]["prev_digest"] == "0" * 64
    assert report["segments"][1]["prev_digest"] == report["segments"][0]["digest"]

    reopened = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    assert reopened.count() == 5
    assert [item["index"] for item in reopened.read_verified(READ_STRICT)["records"]] == [0, 1, 2, 3, 4]


def test_extra_record_in_sealed_segment_is_detected(tmp_path):
    journal = _write(tmp_path)
    journal.seal_active()
    path = str(tmp_path / "audit-00001.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    # 在数据行和 manifest 之间多塞一条。
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(lines[0] + "\n")
        handle.write(json.dumps({"ts": 150, "index": 99}) + "\n")
        handle.write("\n".join(lines[1:]) + "\n")

    report = JsonlJournal(str(tmp_path), "audit", segment_limit=2).verify_chain()
    assert report["healthy"] is False
    assert report["altered"] == [1]
    seg1 = report["segments"][1]
    assert seg1["status"] == SEGMENT_ALTERED
    assert "摘要" in seg1["detail"]


def test_modified_record_is_detected(tmp_path):
    _write(tmp_path)
    path = str(tmp_path / "audit-00000.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    lines[0] = json.dumps({"ts": 100.0, "index": 7})  # 改了一条正文
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    report = JsonlJournal(str(tmp_path), "audit", segment_limit=2).verify_chain()
    assert report["altered"] == [0]


def test_deleted_segment_breaks_chain_and_names_the_segment(tmp_path):
    journal = _write(tmp_path)
    journal.seal_active()
    os.remove(str(tmp_path / "audit-00001.jsonl"))

    report = JsonlJournal(str(tmp_path), "audit", segment_limit=2).verify_chain()
    assert report["missing"] == [1]
    by_seq = {seg["seq"]: seg["status"] for seg in report["segments"]}
    assert by_seq[1] == SEGMENT_MISSING
    # 右邻的 prev 对不上被删段之后的实际左邻，也要点名。
    assert by_seq[2] == SEGMENT_BROKEN_LINK


def test_strict_policy_rejects_entire_read_on_bad_segment(tmp_path):
    _write(tmp_path)
    path = str(tmp_path / "audit-00000.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    lines[0] = json.dumps({"ts": 100.0, "index": 7})
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    with pytest.raises(StorageError) as exc:
        journal.read_verified(READ_STRICT)
    assert "段 0" in exc.value.message


def test_marked_policy_partial_read_and_flags_segments(tmp_path):
    _write(tmp_path)
    path = str(tmp_path / "audit-00000.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    lines[0] = json.dumps({"ts": 100.0, "index": 7})
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    result = JsonlJournal(str(tmp_path), "audit", segment_limit=2).read_verified(READ_MARKED)
    # 段0 整条标记并跳过，段1/尾段照常读。
    assert [item["index"] for item in result["records"]] == [2, 3, 4]
    assert result["complete"] is False
    assert [seg["seq"] for seg in result["skipped"]] == [0]


def test_sealed_segments_read_back_in_time_order(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(6):
        journal.append({"ts": 100.0 + index, "index": index})
    journal.seal_active()
    records = journal.read_verified(READ_STRICT)["records"]
    timestamps = [item["ts"] for item in records]
    assert timestamps == sorted(timestamps)


def test_time_disorder_across_segments_is_detected(tmp_path):
    # 手工构造两个时间倒挂的封档段（利用合法 append + 调换文件正文）。
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(4):
        journal.append({"ts": 100.0 + index, "index": index})
    seg0 = (tmp_path / "audit-00000.jsonl").read_text(encoding="utf-8")
    seg1 = (tmp_path / "audit-00001.jsonl").read_text(encoding="utf-8")
    # 交换两段的数据行但保留各自 manifest，使跨段时间倒挂。
    seg0_lines = seg0.splitlines()
    seg1_lines = seg1.splitlines()
    (tmp_path / "audit-00000.jsonl").write_text(
        "\n".join(seg1_lines[:-1] + [seg0_lines[-1]]) + "\n", encoding="utf-8"
    )
    report = JsonlJournal(str(tmp_path), "audit", segment_limit=2).verify_chain()
    assert any(seg["status"] == SEGMENT_ALTERED for seg in report["segments"])


def test_fill_missing_writes_identifiable_gap_and_is_idempotent(tmp_path):
    journal = _write(tmp_path)
    journal.seal_active()
    os.remove(str(tmp_path / "audit-00001.jsonl"))

    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    filled = journal.fill_missing(now_ts=500.0, note="ops-fill")
    assert [item["seq"] for item in filled] == [1]
    assert filled[0]["status"] == "filled"
    assert filled[0]["kind"] == SEGMENT_GAP
    # 占位段里钉死了左右邻的校验值。
    assert filled[0]["left_digest"]
    assert filled[0]["right_expected_prev"]

    report = journal.verify_chain()
    by_seq = {seg["seq"]: seg["status"] for seg in report["segments"]}
    assert by_seq[1] == SEGMENT_GAP

    # 重复触发幂等：不再产生新补段。
    assert journal.fill_missing(now_ts=501.0) == []
    # marked 读承认这是部分失败（缺口内容没有被伪装成数据）。
    result = journal.read_verified(READ_MARKED)
    assert result["complete"] is False
    assert any(seg["status"] == SEGMENT_GAP for seg in result["skipped"])
    # strict 用途下占位段同样拒读。
    with pytest.raises(StorageError):
        journal.read_verified(READ_STRICT)


def test_fill_does_not_overwrite_altered_segment(tmp_path):
    _write(tmp_path)
    path = str(tmp_path / "audit-00000.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    lines[0] = json.dumps({"ts": 100.0, "index": 7})
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    assert journal.fill_missing(now_ts=1.0) == []
    # 被篡改段原样保留为证据。
    assert JsonlJournal(str(tmp_path), "audit", segment_limit=2).verify_chain()["altered"] == [0]



def test_legacy_chain_without_anchor_or_manifest_is_readable(tmp_path):
    # 升级前的旧链：只有裸 JSONL，没有可信根、没有 manifest。
    (tmp_path / "audit-00000.jsonl").write_text(
        json.dumps({"ts": 0.0, "index": 0}) + "\n"
        + json.dumps({"ts": 1.0, "index": 1}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "audit-00001.jsonl").write_text(
        json.dumps({"ts": 2.0, "index": 2}) + "\n", encoding="utf-8"
    )
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=8)
    report = journal.verify_chain()
    # 没有可信根时，最后的裸段是 unsealed 尾段，其余是 legacy 旧段。
    assert [seg["status"] for seg in report["segments"]] == ["legacy", "unsealed"]
    # marked：旧中段不带，只给尾段。
    assert [item["index"] for item in journal.read_verified(READ_MARKED)["records"]] == [2]
    # lenient：旧段也尽力读。
    assert [item["index"] for item in journal.read_verified(READ_LENIENT)["records"]] == [0, 1, 2]
    # 在旧链上继续追加后封档，链从当前段重新建立可信根。
    journal.append({"ts": 3.0, "index": 3})
    journal.seal_active()
    assert journal.verify_chain()["anchor"]["tail_seq"] == 1
