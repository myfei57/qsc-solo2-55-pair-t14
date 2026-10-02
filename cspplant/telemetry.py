"""趋势缓冲、补点与落盘。

现场采样可能因为机械动作被抢占而丢点，控制台要展示的是按固定周期对齐的
趋势而不是原始采样流。:class:`TrendBuffer` 按信号名收集样本（内存，给状态
页读最新值），并可通过 sink 回调把每个样本同步落盘：平台装配时挂的是一份
和审计流水同构的链式 :class:`~cspplant.store.journal.JsonlJournal`，于是趋势
跨重启也能按同一条时间轴回放，而不是只活在内存里。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

#: 样本落盘记录的字段。
SINK_FIELDS = ("ts", "signal", "value")

TrendSink = Callable[[str, float, float], None]


@dataclass(frozen=True)
class Sample:
    """一个带时间戳的采样点。"""

    ts: float
    value: float

    def as_dict(self) -> dict:
        return {"ts": round(self.ts, 3), "value": round(self.value, 4)}


class TrendBuffer:
    """按信号名保存有限长度的趋势样本，并可同步落盘。"""

    def __init__(self, limit: int = 2048, period_s: float = 5.0) -> None:
        self._series: dict[str, list[Sample]] = {}
        self._limit = max(1, limit)
        self._period_s = max(0.001, period_s)
        self._sinks: list[TrendSink] = []
        self._lock = threading.RLock()

    @property
    def period_s(self) -> float:
        return self._period_s

    @property
    def limit(self) -> int:
        return self._limit

    def add_sink(self, sink: TrendSink) -> None:
        """挂一个落盘回调，``append`` 时在同一把锁内调用。"""

        with self._lock:
            self._sinks.append(sink)

    def append(self, signal: str, ts: float, value: float) -> None:
        """追加一个采样点，超出上限时丢弃最旧的样本，并同步给落盘回调。"""

        with self._lock:
            series = self._series.setdefault(signal, [])
            series.append(Sample(ts, float(value)))
            if len(series) > self._limit:
                del series[: len(series) - self._limit]
            for sink in list(self._sinks):
                sink(signal, ts, float(value))

    def load(self, signal: str, samples: list[tuple[float, float]]) -> int:
        """批量灌入历史样本（跨重启从趋势流水恢复内存视图），不落盘。"""

        with self._lock:
            series = self._series.setdefault(signal, [])
            series.extend(Sample(ts, float(value)) for ts, value in samples)
            if len(series) > self._limit:
                del series[: len(series) - self._limit]
            return len(series)

    def latest(self, signal: str) -> Sample | None:
        """返回某信号的最后一个样本。"""

        with self._lock:
            series = self._series.get(signal)
            return series[-1] if series else None

    def series(self, signal: str, limit: int = 120) -> list[Sample]:
        """返回某信号最近的若干样本。"""

        with self._lock:
            series = list(self._series.get(signal, ()))
        return series[-limit:]

    def signals(self) -> list[str]:
        """返回当前登记的全部信号名。"""

        with self._lock:
            return sorted(self._series)

    def fill_gaps(self, signal: str, samples: list[Sample]) -> list[Sample]:
        """对丢点周期做线性补点，保持趋势按固定周期对齐。"""

        if len(samples) < 2:
            return samples
        filled: list[Sample] = [samples[0]]
        for previous, current in zip(samples, samples[1:]):
            steps = int(round((current.ts - previous.ts) / self._period_s))
            if steps <= 1:
                filled.append(current)
                continue
            for index in range(1, steps):
                ratio = index / steps
                ts = previous.ts + (current.ts - previous.ts) * ratio
                value = previous.value + (current.value - previous.value) * ratio
                filled.append(Sample(ts, value))
            filled.append(current)
        return filled

    def snapshot(self, limit: int = 8) -> dict:
        """汇总各信号的最新样本，供状态快照读取。"""

        with self._lock:
            signals = sorted(self._series)
        report: dict[str, object] = {}
        for signal in signals:
            latest = self.latest(signal)
            report[signal] = {
                "latest": latest.as_dict() if latest else None,
                "recent": [sample.as_dict() for sample in self.series(signal, limit)],
            }
        return report
