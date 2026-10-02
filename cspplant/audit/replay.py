"""审计与趋势的同轴回放。

回放口径在这里**定死**：``CO_AXIS``（同轴对齐）。审计事件与趋势采样都带
Unix 秒时间戳，回放时把两股流合并到**同一条时间轴**上按 ``ts`` 升序交错，
同一时刻先审计后趋势（工况以该时刻的处置事件为准，再看采样值）。不存在
"各轴各放各的"模式——两条轴独立回放无法回答"告警那一刻温度到底是多少"，
也就还原不出当时工况。

读取策略仍按用途选择（见 :mod:`cspplant.store.chain`）：恢复/再执行用
strict，一段不可信就整次拒读；控制台展示用 marked，问题段跳过并点名。
"""

from __future__ import annotations

from ..store.chain import SEGMENT_OK, SEGMENT_UNSEALED

#: 同轴对齐（唯一支持的回放口径）。
CO_AXIS = "co_axis"

#: 同一时间戳下的先后：先看处置事件，再看采样值。
KIND_AUDIT = "audit"
KIND_TREND = "trend"
_KIND_ORDER = {KIND_AUDIT: 0, KIND_TREND: 1}


def _audit_ts(item: dict) -> float:
    try:
        return float(item.get("ts", 0.0))
    except (TypeError, ValueError):
        return 0.0


def _trend_ts(item: dict) -> float:
    try:
        return float(item.get("ts", 0.0))
    except (TypeError, ValueError):
        return 0.0


def co_axis_replay(
    audit_read: dict,
    trend_read: dict,
    *,
    asset: str | None = None,
    signals: list[str] | None = None,
    start_ts: float | None = None,
    end_ts: float | None = None,
) -> dict:
    """把已按策略读出的审计记录与趋势样本合并到同一时间轴。

    参数是两份 :meth:`JsonlJournal.read_verified` 风格的结果（含 ``records``
    与逐段状态），本函数不再做文件读取，因此读策略由调用方按用途定死。
    """

    wanted = set(signals) if signals else None
    events: list[dict] = []
    for item in audit_read.get("records", []):
        if asset is not None and item.get("asset") != asset:
            continue
        ts = _audit_ts(item)
        if not _within(ts, start_ts, end_ts):
            continue
        events.append(
            {
                "ts": round(ts, 3),
                "kind": KIND_AUDIT,
                "component": item.get("component", ""),
                "action": item.get("action", ""),
                "severity": item.get("severity", "notice"),
                "asset": item.get("asset", ""),
                "message": item.get("message", ""),
                "payload": item.get("payload", {}),
            }
        )

    aligned_samples: dict[str, list[tuple[float, float]]] = {}
    for item in trend_read.get("records", []):
        signal = str(item.get("signal", ""))
        if wanted is not None and signal not in wanted:
            continue
        ts = _trend_ts(item)
        if not _within(ts, start_ts, end_ts):
            continue
        try:
            value = float(item.get("value", 0.0))
        except (TypeError, ValueError):
            continue
        aligned_samples.setdefault(signal, []).append((ts, value))
        events.append(
            {
                "ts": round(ts, 3),
                "kind": KIND_TREND,
                "signal": signal,
                "value": round(value, 4),
            }
        )

    events.sort(key=lambda event: (event["ts"], _KIND_ORDER[event["kind"]]))

    # 帧视图：按时间戳聚合成工况帧，同一时刻的处置与采样落在一帧里。
    frames = _build_frames(events)

    series_report: dict[str, dict] = {}
    for signal, points in sorted(aligned_samples.items()):
        values = [{"ts": round(ts, 3), "value": round(value, 4)} for ts, value in points]
        series_report[signal] = {"samples": len(values), "first": values[0] if values else None,
                                 "last": values[-1] if values else None}

    audit_ok = _healthy_segments(audit_read)
    trend_ok = _healthy_segments(trend_read)
    return {
        "alignment": CO_AXIS,
        "complete": bool(audit_read.get("complete", False) and trend_read.get("complete", False)),
        "policy": {"audit": audit_read.get("policy"), "trend": trend_read.get("policy")},
        "window": {"start_ts": start_ts, "end_ts": end_ts},
        "counts": {"audit": sum(1 for e in events if e["kind"] == KIND_AUDIT),
                   "trend": sum(1 for e in events if e["kind"] == KIND_TREND),
                   "frames": len(frames)},
        "integrity": {
            "audit_complete": bool(audit_read.get("complete", False)),
            "trend_complete": bool(trend_read.get("complete", False)),
            "audit_segments_healthy": audit_ok,
            "trend_segments_healthy": trend_ok,
            "audit_skipped": audit_read.get("skipped", []),
            "trend_skipped": trend_read.get("skipped", []),
        },
        "timeline": events,
        "frames": frames,
        "series": series_report,
    }


def _healthy_segments(read: dict) -> bool:
    return all(
        segment.get("status") in (SEGMENT_OK, SEGMENT_UNSEALED)
        for segment in read.get("segments", [])
    )


def _within(ts: float, start_ts: float | None, end_ts: float | None) -> bool:
    if start_ts is not None and ts < start_ts:
        return False
    if end_ts is not None and ts > end_ts:
        return False
    return True


def _build_frames(events: list[dict]) -> list[dict]:
    """把同轴事件按时间戳聚合成工况帧。"""

    frames: list[dict] = []
    current_ts: float | None = None
    frame: dict | None = None
    for event in events:
        if current_ts != event["ts"]:
            if frame is not None:
                frames.append(frame)
            current_ts = event["ts"]
            frame = {"ts": event["ts"], "audit": [], "trend": {}}
        if event["kind"] == KIND_AUDIT:
            frame["audit"].append(
                {
                    "component": event["component"],
                    "action": event["action"],
                    "severity": event["severity"],
                    "asset": event["asset"],
                    "message": event["message"],
                }
            )
        else:
            frame["trend"][event["signal"]] = event["value"]
    if frame is not None:
        frames.append(frame)
    return frames
