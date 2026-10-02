"""审计流水。

``AuditLog`` 是事件总线的全量订阅者：组件只发布事件，日志把它们落成流水并
保留内存副本。控制台读内存副本，跨重启回放读落盘流水；两份数据都来自同一个
:class:`AuditRecord` 结构，字段口径一致。

落盘走的是 :class:`~cspplant.store.chain.ChainedJournal`：每段封好时写清单，
段与段用哈希链相扣，删掉一段、改掉一条、多塞一条都会在 :meth:`verify` 里被
逐段指出（具体哪一段、什么错）。读取分两种用途：

* 取证/联锁恢复用 :data:`~cspplant.store.chain.STRICT` —— 第一段坏或缺就整段
  拒读、抛 :class:`~cspplant.store.chain.SegmentIntegrityError`；
* 控制台展示用 :data:`~cspplant.store.chain.LENIENT` —— 坏段标记后跳过，好段
  按段号升序照常读出，时间顺序不乱。

补齐缺失段（:meth:`fill_missing`）属于部分失败下的修复，只准按段号顺序往缺口
上补，补了什么、依据哪段清单的校验值都另落审计，且重复触发幂等。
"""

from __future__ import annotations

import threading

from ..clock import Clock
from ..eventbus import Event, EventBus
from ..store.chain import (
    ChainedJournal,
    LENIENT,
    STRICT,
    SegmentIntegrityError,
    SegmentManifest,
    SegmentRead,
    load_segment_bundle,
)
from .record import AuditRecord
from .report import summarize

POLICIES = (STRICT, LENIENT)


class AuditLog:
    """审计流水：内存副本 + 带跨段校验链的分段落盘。"""

    def __init__(
        self,
        clock: Clock,
        bus: EventBus,
        journal: ChainedJournal,
        memory_limit: int = 4096,
    ) -> None:
        self._clock = clock
        self._bus = bus
        self._journal = journal
        self._entries: list[AuditRecord] = []
        self._memory_limit = max(1, memory_limit)
        self._lock = threading.RLock()
        # 最近一次链校验结果，供状态页直接展示（不必每次重扫磁盘）。
        self._last_verify: list[SegmentRead] = []
        bus.subscribe("*", self._on_event)

    @property
    def journal(self) -> ChainedJournal:
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
        """记一条审计流水（内存 + 链式落盘），返回其字典形式。"""

        with self._lock:
            self._entries.append(record)
            if len(self._entries) > self._memory_limit:
                del self._entries[: len(self._entries) - self._memory_limit]
            self._journal.append(record.as_dict())
        return record.as_dict()

    def _write_meta(self, action: str, severity: str, message: str, **fields: object) -> AuditRecord:
        """把审计子系统自身的动作（校验/补段/回放）落一条流水。

        这些"关于流水的流水"直接进内存与链式日志，和业务记录同一套校验，
        防止补段/校验动作本身被无痕做掉。
        """

        record = AuditRecord.create(
            self._clock.now(), "", "audit", action, severity, message, **fields
        )
        with self._lock:
            self._entries.append(record)
            if len(self._entries) > self._memory_limit:
                del self._entries[: len(self._entries) - self._memory_limit]
            self._journal.append(record.as_dict())
        return record

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
        """返回审计汇总计数，含链校验与缺口状态。"""

        with self._lock:
            entries = list(self._entries)
        report = summarize(entries)
        report["journal_count"] = self._journal.count()
        report["active_segment"] = self._journal.active_segment()
        report["missing_segments"] = self._journal.missing_indices()
        heads = self._journal.chain_heads()
        report["chain_tail"] = heads["last_chain"]
        report["next_seq"] = heads["next_seq"]
        if self._last_verify:
            bad = [item.as_dict() for item in self._last_verify if not item.ok]
            report["chain_ok"] = not bad
            report["chain_bad_segments"] = bad
        else:
            report["chain_ok"] = None
        return report

    # ---- 封段 ---------------------------------------------------------

    def seal(self) -> dict | None:
        """显式封好当前活动段（归档前调用），返回清单摘要。"""

        manifest = self._journal.seal()
        return manifest.as_dict() if manifest else None

    # ---- 校验 ---------------------------------------------------------

    def verify(self, policy: str = LENIENT, *, annotate: bool = True) -> list[SegmentRead]:
        """逐段验链。STRICT 在第一个缺/坏段抛错；LENIENT 返回全部段结果。

        校验本身落一条审计（链是否完整、发现几个坏/缺段），让"什么时候验过、
        结论是什么"本身可追溯。
        """

        if policy not in POLICIES:
            raise ValueError(f"未知的读取策略: {policy}")
        try:
            reads = self._journal.verify(policy)
        except SegmentIntegrityError as error:
            if annotate:
                self._write_meta(
                    "audit_verify",
                    "alarm",
                    f"审计链校验未通过（{policy}）：段 {error.segment} {error.kind}",
                    policy=policy,
                    failed_segment=error.segment,
                    reason=error.kind,
                )
            raise
        bad = [item for item in reads if not item.ok]
        if annotate:
            self._write_meta(
                "audit_verify",
                "notice" if not bad else "warning",
                "审计链校验通过" if not bad else f"审计链发现 {len(bad)} 个坏/缺段",
                policy=policy,
                segments_checked=len(reads),
                bad_segments=[item.index for item in bad],
                missing_segments=[item.index for item in bad if item.missing],
            )
        with self._lock:
            self._last_verify = reads
        return reads

    def verification(self) -> list[dict]:
        """返回最近一次校验结果（未校验过则现场 LENIENT 扫一遍，不落审计）。"""

        with self._lock:
            cached = list(self._last_verify)
        if not cached:
            cached = self._journal.verify(LENIENT)
            with self._lock:
                self._last_verify = cached
        return [item.as_dict() for item in cached]

    # ---- 回放 ---------------------------------------------------------

    def replay_from_journal(self, limit: int = 100_000, policy: str = LENIENT) -> list[dict]:
        """从落盘流水回放记录，供跨重启恢复使用。

        默认 LENIENT：坏段跳过、好段照读，返回的仍是按段号/时间升序的记录。
        取证恢复可传 STRICT：链有任何缺/坏就整段拒读并抛错。
        """

        if policy not in POLICIES:
            raise ValueError(f"未知的读取策略: {policy}")
        records, _reads = self._journal.read_all(policy)
        return records[-limit:]

    def replay_verified(self, limit: int = 100_000) -> list[dict]:
        """取证口径回放：链不完整就拒读（STRICT）。"""

        return self.replay_from_journal(limit=limit, policy=STRICT)

    def replay_segment(self, index: int, policy: str = LENIENT) -> list[dict]:
        """按段号回放一段流水（按用途选严格/宽松）。"""

        if policy not in POLICIES:
            raise ValueError(f"未知的读取策略: {policy}")
        return self._journal.read_segment(index, policy).entries

    def to_records(self, raw: list[dict]) -> list[AuditRecord]:
        """把落盘字段还原成记录对象。"""

        return [AuditRecord.from_dict(item) for item in raw]

    # ---- 补段 ---------------------------------------------------------

    def fill_missing(self, source_dir: str, *, limit: int = 4096) -> dict:
        """从补段包目录补齐链上缺失的段。

        补段是部分失败下的修复：只补链上确实缺失的段号，按段号升序逐个补，
        每补一段都硬校验（数据/清单自洽、前驱链接得上、配密钥时签名对），验
        不过就整段拒收并继续尝试后续可补的段，但时序始终守住（前驱缺失的段不
        会被跳过硬补）。每个动作都落审计：补了哪段、依据清单里哪个 chain 值、
        来源是哪个包。重复触发幂等：无缺口时不落新审计、直接回报。
        """

        missing = self._journal.missing_indices()
        if not missing:
            return {"filled": [], "rejected": [], "missing_before": [], "idempotent": True}
        filled: list[dict] = []
        rejected: list[dict] = []
        for index in missing:
            if len(filled) >= limit:
                break
            bundle_path = f"{source_dir.rstrip('/')}/segment-{index:05d}"
            try:
                envelopes, manifest = load_segment_bundle(bundle_path)
            except OSError as error:
                rejected.append({"segment": index, "reason": "bundle_missing", "detail": str(error)})
                self._write_meta(
                    "audit_segment_fill_rejected",
                    "warning",
                    f"段 {index} 补段包缺失，未补入",
                    segment=index,
                    source=bundle_path,
                    reason="bundle_missing",
                )
                continue
            # 先只凭数据/清单自洽性筛一道（不依赖本地链），明显伪造的包不必进链校验。
            if not ChainedJournal.verify_segment_payload(envelopes, manifest):
                rejected.append({"segment": index, "reason": "malformed",
                                 "detail": "补段包数据与清单不自洽"})
                self._write_meta(
                    "audit_segment_fill_rejected",
                    "alarm",
                    f"段 {index} 补段包自校验不通过，未补入",
                    segment=index,
                    source=bundle_path,
                    reason="malformed",
                )
                continue
            try:
                self._journal.import_segment(index, envelopes, manifest)
            except SegmentIntegrityError as error:
                rejected.append({"segment": index, "reason": error.kind, "detail": error.message})
                self._write_meta(
                    "audit_segment_fill_rejected",
                    "alarm",
                    f"段 {index} 补段被拒：{error.kind}",
                    segment=index,
                    source=bundle_path,
                    reason=error.kind,
                    claimed_chain=manifest.chain,
                )
                continue
            filled.append({"segment": index, "chain": manifest.chain, "source": bundle_path})
            self._write_meta(
                "audit_segment_filled",
                "warning",
                f"缺失段 {index} 已依据来源清单补入",
                segment=index,
                source=bundle_path,
                basis_chain=manifest.chain,
                basis_prev_chain=manifest.prev_chain,
                basis_root=manifest.root,
                first_seq=manifest.first_seq,
                last_seq=manifest.last_seq,
                count=manifest.count,
            )
        # 补完复检一次，确认链重新闭合（结果落审计）。
        remaining = self._journal.missing_indices()
        self.verify(LENIENT)
        return {
            "filled": filled,
            "rejected": rejected,
            "missing_before": missing,
            "missing_after": remaining,
            "chain_closed": not remaining,
            "idempotent": False,
        }
