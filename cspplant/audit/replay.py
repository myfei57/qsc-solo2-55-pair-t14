"""审计 × 趋势同轴回放。

趋势平时只在内存里（另有一份链式落盘），审计是分段落盘，两条流要回答同一个
问题："某一刻现场是什么工况"。回放必须把两者对齐到**同一条时间轴**。

对齐方式在本模块定死为 :data:`SHARED_AXIS`（同轴对齐），不提供"各轴独立"模式：
审计记录与趋势样本都来自平台的同一个 :class:`~cspplant.clock.Clock`，时间戳是
同一把尺，合并时只按 ``ts`` 排序。同一时刻两类事件并列时，顺序用固定的确定性
规则排（先趋势采样、后审计事件；同类内再按稳定的次级键），保证任何时候回放
结果都一致、可复算，不依赖读取顺序。

输出是一条按时间升序的统一事件流，每个事件带：

* ``ts``：同轴时间戳；
* ``kind``：``trend``（采样）或 ``audit``（审计事件）；
* ``signal`` / ``action`` 等字段：当时的工况；
* 随流附带一份逐段校验结果，让调用方知道哪些时刻因为坏/缺段而不可信。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..store.chain import LENIENT, STRICT, SegmentRead
from ..telemetry import Sample
from .record import AuditRecord

# 对齐模式：唯一允许值——审计与趋势共用一条挂钟时间轴。
SHARED_AXIS = "shared_axis"

# 同刻并列的固定次序：先采样（工况），后事件（对工况做的动作/判出的告警）。
KIND_ORDER = {"trend": 0, "audit": 1}


@dataclass
class ReplayWindow:
    """一次同轴回放的结果。"""

    axis: str
    start_ts: float | None
    end_ts: float | None
    events: list[dict] = field(default_factory=list)
    segment_checks: list[dict] = field(default_factory=list)
    bad_segments: list[int] = field(default_factory=list)
    missing_segments: list[int] = field(default_factory=list)
    policy: str = LENIENT

    @property
    def trustworthy(self) -> bool:
        """链是否完整可信（无坏段、无缺段）。"""

        return not self.bad_segments and not self.missing_segments

    def as_dict(self) -> dict:
        return {
            "axis": self.axis,
            "policy": self.policy,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "count": len(self.events),
            "trustworthy": self.trustworthy,
            "bad_segments": list(self.bad_segments),
            "missing_segments": list(self.missing_segments),
            "segment_checks": list(self.segment_checks),
            "events": self.events,
        }


def _audit_event(record: AuditRecord) -> dict:
    raw = record.as_dict()
    return {
        "ts": round(float(record.ts), 3),
        "kind": "audit",
        "component": record.component,
        "action": record.action,
        "severity": record.severity,
        "asset": record.asset,
        "message": record.message,
        "payload": raw.get("payload", {}),
    }


def _trend_event(signal: str, sample: Sample) -> dict:
    return {
        "ts": round(float(sample.ts), 3),
        "kind": "trend",
        "signal": signal,
        "value": round(float(sample.value), 4),
    }


def _sort_key(event: dict) -> tuple:
    # 同轴：主时间戳；同刻按"先采样后事件"；再按稳定次级键，保证可复算。
    if event["kind"] == "trend":
        secondary = event.get("signal", "")
    else:
        secondary = (event.get("component", ""), event.get("action", ""), event.get("asset", ""))
    return (event["ts"], KIND_ORDER[event["kind"]], str(secondary))


def replay_shared_axis(
    audit_records: list[AuditRecord],
    trend_samples: dict[str, list[Sample]],
    segment_reads: list[SegmentRead] | None = None,
    *,
    policy: str = LENIENT,
    start_ts: float | None = None,
    end_ts: float | None = None,
    signals: list[str] | None = None,
    axis: str = SHARED_AXIS,
) -> ReplayWindow:
    """把审计记录与趋势样本合并到同一条时间轴上回放。

    ``segment_reads`` 是两条落盘流各自的逐段校验结果，合并进窗口，让调用方在
    看回放的同时知道哪些段不可信。``policy`` 决定读盘口径（STRICT 一般在调用
    方读盘阶段就已抛错，这里仅透传进结果做标注）。
    """

    if axis != SHARED_AXIS:
        # 模式定死：不接受各轴独立对齐，避免同一时刻在两条尺上对歪了还原错工况。
        raise ValueError(f"回放只支持同轴对齐 {SHARED_AXIS!r}，收到 {axis!r}")

    wanted = set(signals) if signals else None
    events: list[dict] = []
    for record in audit_records:
        events.append(_audit_event(record))
    for signal, samples in trend_samples.items():
        if wanted is not None and signal not in wanted:
            continue
        events.extend(_trend_event(signal, sample) for sample in samples)

    if start_ts is not None:
        events = [event for event in events if event["ts"] >= start_ts]
    if end_ts is not None:
        events = [event for event in events if event["ts"] <= end_ts]

    events.sort(key=_sort_key)

    checks = [read.as_dict() for read in (segment_reads or [])]
    bad = [read.index for read in (segment_reads or []) if not read.ok and not read.missing]
    missing = [read.index for read in (segment_reads or []) if read.missing]
    timestamps = [event["ts"] for event in events]
    return ReplayWindow(
        axis=SHARED_AXIS,
        start_ts=min(timestamps) if timestamps else None,
        end_ts=max(timestamps) if timestamps else None,
        events=events,
        segment_checks=checks,
        bad_segments=sorted(set(bad)),
        missing_segments=sorted(set(missing)),
        policy=policy,
    )


def working_condition_at(window: ReplayWindow, ts: float) -> dict:
    """在回放轴上取某一时刻的工况还原：该时刻最近的一组采样 + 已发生的审计事件。

    同轴对齐的直接用途——"当时工况"：采样取 ``<= ts`` 的每信号最近值，事件取
    ``<= ts`` 的全部已发生事件（动作/告警按发生顺序）。
    """

    signals: dict[str, dict] = {}
    events: list[dict] = []
    for event in window.events:
        if event["ts"] > ts:
            break
        if event["kind"] == "trend":
            signals[event["signal"]] = {"ts": event["ts"], "value": event["value"]}
        else:
            events.append(event)
    return {
        "axis": window.axis,
        "ts": round(ts, 3),
        "signals": signals,
        "audit": events,
        "trustworthy": window.trustworthy,
        "bad_segments": list(window.bad_segments),
        "missing_segments": list(window.missing_segments),
    }
