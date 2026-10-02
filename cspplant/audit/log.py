"""审计日志。

``AuditLog`` 是事件总线的全量订阅者：组件只发布事件，日志把它们落成流水并
保留内存副本。控制台读内存副本，跨重启回放读落盘流水；两份数据都来自同一个
:class:`AuditRecord` 结构，字段口径一致。
"""

from __future__ import annotations

import threading

from ..clock import Clock
from ..eventbus import Event, EventBus
from ..store.chain import READ_LENIENT, READ_MARKED, READ_STRICT
from ..store.journal import JsonlJournal
from .record import AuditRecord
from .replay import CO_AXIS, co_axis_replay
from .report import summarize


class AuditLog:
    """审计流水：内存副本 + 分段落盘。"""

    def __init__(
        self,
        clock: Clock,
        bus: EventBus,
        journal: JsonlJournal,
        memory_limit: int = 4096,
    ) -> None:
        self._clock = clock
        self._journal = journal
        self._entries: list[AuditRecord] = []
        self._memory_limit = max(1, memory_limit)
        self._lock = threading.RLock()
        bus.subscribe("*", self._on_event)

    @property
    def journal(self) -> JsonlJournal:
        return self._journal

    def _on_event(self, event: Event) -> None:
        severity = "notice"
        payload = dict(event.payload)
        if "severity" in payload:
            severity = str(payload.pop("severity"))
        asset = str(payload.pop("asset", ""))
        message = str(payload.pop("message", ""))
        # 事件载荷里可能出现与记录字段同名的键（例如辐照采样自带的 ts），
        # 这些键只用于审计正文，不能覆盖记录本身的字段。
        for reserved in ("ts", "component", "action", "type"):
            payload.pop(reserved, None)
        self.record(
            AuditRecord.create(
                self._clock.now(), asset, event.component, event.action, severity, message, **payload
            )
        )

    def record(self, record: AuditRecord) -> dict:
        """记一条审计流水（内存 + 落盘），返回其字典形式。"""

        with self._lock:
            self._entries.append(record)
            if len(self._entries) > self._memory_limit:
                del self._entries[: len(self._entries) - self._memory_limit]
            self._journal.append(record.as_dict())
        return record.as_dict()

    def entries(self, limit: int = 100) -> list[dict]:
        """返回最近的记录（最新的在前）。"""

        with self._lock:
            selected = list(self._entries)[-limit:]
        return [entry.as_dict() for entry in reversed(selected)]

    def tail(self, limit: int = 20) -> list[dict]:
        """返回最近的记录（按时间升序）。"""

        with self._lock:
            selected = list(self._entries)[-limit:]
        return [entry.as_dict() for entry in selected]

    def alarms(self) -> list[dict]:
        """返回全部告警档记录。"""

        with self._lock:
            selected = [entry for entry in self._entries if entry.is_alarm()]
        return [entry.as_dict() for entry in selected]

    def records(self, limit: int = 200) -> list[AuditRecord]:
        """返回最近的记录对象（按时间升序），供时间线构造使用。"""

        with self._lock:
            return list(self._entries)[-limit:]

    def count(self, action: str) -> int:
        """统计某个动作累计出现过多少次。"""

        with self._lock:
            return len([entry for entry in self._entries if entry.action == action])

    def summary(self) -> dict:
        """返回审计汇总计数。"""

        with self._lock:
            entries = list(self._entries)
        report = summarize(entries)
        report["journal_count"] = self._journal.count()
        report["active_segment"] = self._journal.active_segment()
        return report

    def replay_from_journal(self, limit: int = 100_000, policy: str = READ_STRICT) -> list[dict]:
        """从落盘流水回放记录，供跨重启恢复使用。

        恢复用途默认 ``strict``：任何一段校验不过就整段（整次）拒读，避免拿
        被改过的流水重放现场。控制台展示用 :meth:`read_for_console`。
        """

        records = self._journal.read_verified(policy=policy)["records"]
        return records[-limit:]

    def replay_segment(self, index: int) -> list[dict]:
        """按段号回放一段流水。"""

        return self._journal.read_segment(index)

    # ---- 跨段校验、补段与同轴回放 -------------------------------------

    def verify_chain(self) -> dict:
        """返回审计流水的跨段哈希链校验报告。"""

        return self._journal.verify_chain()

    def read_for_console(self, policy: str = READ_MARKED, **window: object) -> dict:
        """按策略读取流水供展示；默认 marked：标记后部分读。"""

        return self._journal.read_verified(
            policy=policy,
            start_ts=window.get("start_ts"),
            end_ts=window.get("end_ts"),
        )

    def seal_segment(self) -> dict | None:
        """立即封档当前正在写的审计段（归档前显式封存）。"""

        return self._journal.seal_active()

    def fill_missing_segments(
        self,
        seq: int | None = None,
        *,
        note: str = "",
        policy: str = READ_MARKED,
    ) -> dict:
        """补齐缺失的审计段（部分失败操作），并把补段动作落审计。

        只补文件缺失的段，篡改段不覆盖；重复触发幂等。每补一段落一条
        warning 审计，写清补了哪段、占位摘要、依据的左右两段校验值。补齐
        属于部分失败：返回里保留补后仍未通过校验的段清单。
        """

        with self._lock:
            before = {
                report["seq"]
                for report in self._journal.verify_chain()["segments"]
                if report["status"] == "gap"
            }
            filled = self._journal.fill_missing(seq, now_ts=self._clock.now(), note=note)
            for item in filled:
                if item.get("status") != "filled":
                    continue
                self.record(
                    AuditRecord.create(
                        self._clock.now(),
                        "",
                        "audit",
                        "audit_segment_filled",
                        severity="warning",
                        message=f"审计段 {item['seq']} 缺失，已按左右邻校验值补占位段",
                        segment_seq=item["seq"],
                        gap_digest=item["digest"],
                        left_digest=item["left_digest"],
                        right_expected_prev=item["right_expected_prev"],
                        right_present=item["right_present"],
                        note=note or "manual_fill",
                    )
                )
            verification = self._journal.verify_chain()
            still_bad = [
                report["seq"]
                for report in verification["segments"]
                if report["status"] not in ("ok", "unsealed", "gap")
            ]
            return {
                "ok": not still_bad,
                "partial_failure": bool(still_bad),
                "filled": filled,
                "already_gap_segments": sorted(before),
                "remaining_bad_segments": still_bad,
                "verification": verification,
            }

    def replay_co_axis(
        self,
        trend_journal: JsonlJournal,
        *,
        policy: str = READ_MARKED,
        asset: str | None = None,
        signals: list[str] | None = None,
        start_ts: float | None = None,
        end_ts: float | None = None,
        audit: bool = True,
    ) -> dict:
        """审计与趋势按**同轴对齐**（唯一回放口径）合并到一条时间轴。

        回放结果同时供控制台展示并落审计：``audit=False`` 时只返回不落审计，
        用于内部预览；默认落一条 ``audit_replay`` notice，记录窗口、策略、
        条目数与完整度。
        """

        if policy not in (READ_STRICT, READ_MARKED, READ_LENIENT):
            raise ValueError(f"未知读策略: {policy}")
        audit_read = self._journal.read_verified(
            policy=policy, start_ts=start_ts, end_ts=end_ts
        )
        trend_read = trend_journal.read_verified(
            policy=policy, start_ts=start_ts, end_ts=end_ts
        )
        result = co_axis_replay(
            audit_read,
            trend_read,
            asset=asset,
            signals=signals,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        if audit:
            self.record(
                AuditRecord.create(
                    self._clock.now(),
                    "",
                    "audit",
                    "audit_replay",
                    severity="notice" if result["complete"] else "warning",
                    message=(
                        "同轴回放完成"
                        if result["complete"]
                        else "同轴回放完成（存在缺口或不可信段，结果不完整）"
                    ),
                    alignment=CO_AXIS,
                    policy=policy,
                    complete=result["complete"],
                    audit_events=result["counts"]["audit"],
                    trend_samples=result["counts"]["trend"],
                    frames=result["counts"]["frames"],
                    filter_asset=asset or "",
                )
            )
        return result

    def to_records(self, raw: list[dict]) -> list[AuditRecord]:
        """把落盘字段还原成记录对象。"""

        return [AuditRecord.from_dict(item) for item in raw]
