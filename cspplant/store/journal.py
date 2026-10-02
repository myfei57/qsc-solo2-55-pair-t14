"""带跨段哈希链的分段 JSONL 流水。

流水只追加不重写，按 ``segment_limit`` 条一段滚动成 ``<topic>-00000.jsonl``、
``<topic>-00001.jsonl``…。一段写满、滚到下一段时，上一段会被"封档"：在其
文件末尾追加一行 manifest（见 :mod:`cspplant.store.chain`），记录本段全部
记录的摘要、前一段 manifest 摘要、段号、条数与时间范围。于是：

* 删掉一段           —— 后一段的 ``prev`` 对不上，报 ``broken_link`` /
                        ``missing``，并指出段号；
* 在段里多写/改一条  —— 本段 ``records`` 摘要对不上，报 ``altered``；
* 封好档的段读回来   —— 按段号链顺序拼接，并用 ``first_ts/last_ts`` 做跨段
                        时间单调校验，顺序被打乱时报 ``time_disorder``。

链的可信根是同目录的 ``<topic>.chain``：记录最后封档段的段号与摘要，原子写。
打开日志时按链扫描全部段并校验，结果由 :meth:`verify_chain` 返回；读取时再
按用途选策略（strict / marked / lenient，见 :mod:`cspplant.store.chain`）。

缺段可以补：:meth:`fill_missing` 只为"文件缺失"的段写占位段（``kind=gap``），
占位锚定缺口左右两段的摘要，幂等；被篡改的段不覆盖、原样留证。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any

from ..errors import StorageError
from .chain import (
    GENESIS,
    READ_LENIENT,
    READ_MARKED,
    READ_POLICIES,
    READ_STRICT,
    SEGMENT_ALTERED,
    SEGMENT_BROKEN_LINK,
    SEGMENT_DISORDER,
    SEGMENT_GAP,
    SEGMENT_LEGACY,
    SEGMENT_MISSING,
    SEGMENT_OK,
    SEGMENT_UNSEALED,
    SegmentManifest,
    digest_manifest,
    extract_ts,
)

#: 扫描时最多识别多少段，防止目录里塞进异常文件后扫描无界。
MAX_SCAN_SEGMENTS = 100_000


@dataclass
class SegmentReport:
    """一段流水的校验结果。"""

    seq: int
    path: str
    status: str
    count: int
    digest: str = ""
    prev_digest: str = GENESIS
    first_ts: float | None = None
    last_ts: float | None = None
    records: list[dict] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "seq": self.seq,
            "path": self.path,
            "status": self.status,
            "count": self.count,
            "digest": self.digest,
            "prev_digest": self.prev_digest,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "detail": self.detail,
        }


class JsonlJournal:
    """按段落盘、段间用哈希链相扣的流水。"""

    def __init__(self, root: str, topic: str, segment_limit: int = 512) -> None:
        self._root = os.path.abspath(root)
        self._topic = topic
        self._segment_limit = max(1, segment_limit)
        self._lock = threading.RLock()
        os.makedirs(self._root, exist_ok=True)
        # _anchor_seq/_anchor_digest：最后封档段；_anchor_total：截至该段累计条数。
        self._anchor_seq: int | None = None
        self._anchor_digest: str = GENESIS
        self._anchor_total: int = 0
        self._load_anchor()
        scan = self._scan_locked()
        self._reports: list[SegmentReport] = scan
        self._tail_seq = scan[-1].seq if scan else 0
        tail = scan[-1] if scan else None
        if tail is not None and tail.status in (SEGMENT_UNSEALED, SEGMENT_LEGACY):
            # 可信根之后还有正在写的尾段（或升级前没有可信根的旧链）：在尾段
            # 之后接着追加，条数按现存段重数。
            self._segment = tail.seq
            self._count = sum(item.count for item in scan if item.status not in (SEGMENT_MISSING, SEGMENT_GAP))
        else:
            self._segment = (self._anchor_seq + 1) if self._anchor_seq is not None else 0
            self._count = self._anchor_total

    # ---- 路径与可信根 -------------------------------------------------

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def segment_limit(self) -> int:
        return self._segment_limit

    def _segment_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.jsonl")

    def _anchor_path(self) -> str:
        return os.path.join(self._root, f"{self._topic}.chain")

    def _load_anchor(self) -> None:
        path = self._anchor_path()
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
            self._anchor_seq = int(raw["tail_seq"])
            self._anchor_digest = str(raw["tail_digest"])
            self._anchor_total = int(raw.get("total_records", 0))
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise StorageError(f"流水可信根损坏: {path}: {error}", component="store") from error

    def _write_anchor(self, seq: int, tail_digest: str, total: int) -> None:
        payload = {
            "topic": self._topic,
            "tail_seq": seq,
            "tail_digest": tail_digest,
            "total_records": total,
        }
        path = self._anchor_path()
        fd, tmp = tempfile.mkstemp(prefix=f".{self._topic}.chain-", dir=self._root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except OSError as error:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise StorageError(f"更新流水可信根失败: {error}", component="store") from error

    # ---- 扫描与校验 ---------------------------------------------------

    def _read_segment_file(self, path: str) -> tuple[list[str], list[dict], SegmentManifest | None, str]:
        """返回 (记录行原文, 记录对象, manifest 或 None, 解析异常说明)。"""

        lines: list[str] = []
        records: list[dict] = []
        manifest: SegmentManifest | None = None
        error = ""
        with open(path, "r", encoding="utf-8") as handle:
            raw_lines = [line.rstrip("\n") for line in handle if line.strip()]
        for line in raw_lines:
            parsed = SegmentManifest.from_line(line)
            if parsed is not None:
                manifest = parsed
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as bad:
                error = f"第 {len(lines) + 1} 行不是合法 JSON: {bad}"
                continue
            if isinstance(item, dict):
                lines.append(line)
                records.append(item)
        return lines, records, manifest, error

    def _scan_locked(self) -> list[SegmentReport]:
        """按链扫描段文件并逐段校验。"""

        reports: list[SegmentReport] = []
        seq = 0
        while seq < MAX_SCAN_SEGMENTS:
            path = self._segment_path(seq)
            if not os.path.isfile(path):
                # 有可信根且还没扫到根记录的尾段：中间缺文件。
                if self._anchor_seq is not None and seq <= self._anchor_seq:
                    reports.append(
                        SegmentReport(
                            seq=seq,
                            path=path,
                            status=SEGMENT_MISSING,
                            count=0,
                            prev_digest=reports[-1].digest if reports else GENESIS,
                            detail="段文件缺失",
                        )
                    )
                    seq += 1
                    continue
                break
            report = self._inspect_locked(seq, path, reports[-1] if reports else None)
            reports.append(report)
            seq += 1
        return reports

    def _inspect_locked(
        self,
        seq: int,
        path: str,
        previous: SegmentReport | None,
    ) -> SegmentReport:
        try:
            lines, records, manifest, parse_error = self._read_segment_file(path)
        except OSError as error:
            return SegmentReport(
                seq=seq, path=path, status=SEGMENT_MISSING, count=0,
                detail=f"段文件无法读取: {error}",
            )

        prev_digest = previous.digest if previous is not None and previous.digest else GENESIS
        prev_last_ts = previous.last_ts if previous is not None else None

        if manifest is None:
            # 无 manifest 的裸段：可信根之后的是"正在写的尾段"，其余是升级前
            # 旧段（legacy）。没有可信根时，只有现存编号最大的裸段算尾段。
            has_next = os.path.isfile(self._segment_path(seq + 1))
            if self._anchor_seq is not None:
                status = SEGMENT_UNSEALED if seq > self._anchor_seq else SEGMENT_LEGACY
            else:
                status = SEGMENT_LEGACY if has_next else SEGMENT_UNSEALED
            return SegmentReport(
                seq=seq,
                path=path,
                status=status,
                count=len(records),
                records=records,
                detail=parse_error,
            )

        if manifest.seq != seq:
            return SegmentReport(
                seq=seq, path=path, status=SEGMENT_BROKEN_LINK, count=len(records),
                digest=manifest.digest, prev_digest=manifest.prev_digest,
                first_ts=manifest.first_ts, last_ts=manifest.last_ts,
                records=records, detail=f"manifest 段号 {manifest.seq} 与文件段号不一致",
            )
        if manifest.digest != digest_manifest(_manifest_body(manifest)):
            # manifest 自身被改过（digest 字段对不上）。
            return SegmentReport(
                seq=seq, path=path, status=SEGMENT_ALTERED, count=len(records),
                digest=manifest.digest, prev_digest=manifest.prev_digest,
                first_ts=manifest.first_ts, last_ts=manifest.last_ts,
                detail="封档凭证自身摘要不匹配",
            )

        status = SEGMENT_OK
        detail = parse_error
        if not manifest.self_verifies(lines, len(records)):
            status = SEGMENT_ALTERED
            detail = detail or "段内记录摘要或条目数与封档凭证不一致（内容被增/删/改）"
        elif not self._link_matches(manifest, previous):
            status = SEGMENT_BROKEN_LINK
            if previous is not None and previous.status == SEGMENT_GAP:
                detail = detail or (
                    "本段封档时锚定的前一段摘要与占位补段不一致：缺段内容无法找回，"
                    "缺口位置已由占位段标出，链在该处不连续"
                )
            else:
                expected = (
                    manifest.gap_prev_digest if manifest.kind == SEGMENT_GAP else manifest.prev_digest
                )
                actual = prev_digest
                detail = detail or (
                    f"跨段链接断开：期望前一段摘要 {expected[:12]}…，实际左邻为 {actual[:12]}…"
                )

        if status == SEGMENT_OK and manifest.kind == SEGMENT_GAP:
            status = SEGMENT_GAP
        if (
            status == SEGMENT_OK
            and prev_last_ts is not None
            and manifest.first_ts is not None
            and manifest.first_ts < prev_last_ts
        ):
            status = SEGMENT_DISORDER
            detail = f"跨段时间倒挂：本段首 {manifest.first_ts} 早于前段尾 {prev_last_ts}"

        return SegmentReport(
            seq=seq,
            path=path,
            status=status,
            count=len(records),
            digest=manifest.digest,
            prev_digest=manifest.prev_digest,
            first_ts=manifest.first_ts,
            last_ts=manifest.last_ts,
            records=records,
            detail=detail,
        )

    @staticmethod
    def _link_matches(manifest: SegmentManifest, previous: SegmentReport | None) -> bool:
        """校验本段 manifest 与链上左邻是否相扣。

        普通段：``prev`` 必须等于左邻 manifest 摘要（左邻是 gap 占位段时同样
        按摘要穿链，占位段带没带原始内容不影响链的连续性）。
        gap 占位段：``gap_prev`` 必须等于缺口左邻摘要；右邻的期望钉在
        ``gap_next_prev`` 里，由右邻自身的 prev 校验兑现。
        """

        left_digest = previous.digest if previous is not None and previous.digest else GENESIS
        if manifest.kind == SEGMENT_GAP:
            return manifest.gap_prev_digest == left_digest
        return manifest.prev_digest == left_digest

    def verify_chain(self) -> dict:
        """重新扫描并返回全链校验报告（只读，不改文件）。"""

        with self._lock:
            self._reports = self._scan_locked()
            reports = list(self._reports)
        statuses: dict[str, int] = {}
        for report in reports:
            statuses[report.status] = statuses.get(report.status, 0) + 1
        healthy = all(report.status in (SEGMENT_OK, SEGMENT_UNSEALED) for report in reports)
        return {
            "topic": self._topic,
            "healthy": healthy,
            "segments": [report.as_dict() for report in reports],
            "status_counts": statuses,
            "missing": [report.seq for report in reports if report.status == SEGMENT_MISSING],
            "altered": [report.seq for report in reports if report.status in (SEGMENT_ALTERED, SEGMENT_BROKEN_LINK, SEGMENT_DISORDER)],
            "gaps": [report.seq for report in reports if report.status == SEGMENT_GAP],
            "anchor": None
            if self._anchor_seq is None
            else {
                "tail_seq": self._anchor_seq,
                "tail_digest": self._anchor_digest,
                "total_records": self._anchor_total,
            },
            "policies": list(READ_POLICIES),
        }

    # ---- 写入与封档 ---------------------------------------------------

    def append(self, record: Any) -> str:
        """追加一条记录，写满一段时自动封档上一段，返回写入的段路径。"""

        with self._lock:
            line = json.dumps(record, ensure_ascii=False)
            index = self._segment
            path = self._segment_path(index)
            already = self._tail_record_count(index)
            try:
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                raise StorageError(f"追加流水失败: {error}", component="store") from error
            self._count += 1

            if already + 1 >= self._segment_limit:
                self._seal_locked(index, path)
                self._segment = index + 1
            return path

    def _tail_record_count(self, index: int) -> int:
        """数某段当前已落盘的记录行数（不含 manifest）。"""

        path = self._segment_path(index)
        if not os.path.isfile(path):
            return 0
        try:
            _, records, manifest, _ = self._read_segment_file(path)
        except OSError:
            return 0
        if manifest is not None:
            return manifest.count
        return len(records)

    def seal_active(self) -> dict | None:
        """把当前正在写的尾段立即封档归档，返回封档段报告（空段不封）。"""

        with self._lock:
            index = self._segment
            path = self._segment_path(index)
            if not os.path.isfile(path) or self._tail_record_count(index) == 0:
                return None
            self._seal_locked(index, path)
            self._segment = index + 1
            self._reports = self._scan_locked()
            report = next((item for item in self._reports if item.seq == index), None)
            return report.as_dict() if report else None

    def _seal_locked(self, index: int, path: str) -> None:
        """封档：在段文件末尾追加 manifest，并把可信根推进到本段。"""

        lines, records, existing, _ = self._read_segment_file(path)
        if existing is not None:
            return  # 已封档（崩溃恢复后重复触发也安全）
        manifest = SegmentManifest.sealed(index, lines, records, self._prev_digest_for(index))
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(manifest.to_line() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise StorageError(f"封档失败: {path}: {error}", component="store") from error
        digest = digest_manifest(_manifest_body(manifest))
        self._anchor_seq = index
        self._anchor_digest = digest
        self._anchor_total = self._count
        self._write_anchor(index, digest, self._count)

    def _prev_digest_for(self, index: int) -> str:
        """封档 index 段时链上"前一段 manifest 摘要"。

        顺序封档（index 正好是可信根的下一段）直接用内存可信根，避免为封档
        重扫全链；只有异常编号（旧链/缺口后追加）才回落到扫描结果。
        """

        if index == 0:
            return GENESIS
        if self._anchor_seq == index - 1:
            return self._anchor_digest
        for report in reversed(self._reports):
            if report.seq == index - 1:
                return report.digest or GENESIS
        return GENESIS

    # ---- 缺段补齐 -----------------------------------------------------

    def fill_missing(
        self,
        seq: int | None = None,
        *,
        now_ts: float | None = None,
        note: str = "",
    ) -> list[dict]:
        """补齐缺失段：为每个文件缺失的段写 gap 占位段。

        * 只补 ``missing``；``altered``/``broken_link`` 段不覆盖，原样留证；
        * 占位段锚定缺口左右两段摘要，缺了什么、依据哪段校验值都在凭证里；
        * 重复触发幂等：已是 ``gap`` 或文件存在的段直接跳过；
        * 返回每个被补段的报告（调用方负责把它落审计）。
        """

        with self._lock:
            self._reports = self._scan_locked()
            missing = [
                report.seq
                for report in self._reports
                if report.status == SEGMENT_MISSING and (seq is None or report.seq == seq)
            ]
            filled: list[dict] = []
            for target in missing:
                filled.append(self._fill_one_locked(target, now_ts=now_ts, note=note))
            return filled

    def _fill_one_locked(self, target: int, *, now_ts: float | None, note: str) -> dict:
        path = self._segment_path(target)
        if os.path.isfile(path):  # 并发/重复触发：幂等
            return {"seq": target, "status": "skipped", "detail": "段文件已存在", "digest": ""}

        # 左邻：链上 target-1 段（gap 段也有摘要）。
        left = next((item for item in self._reports if item.seq == target - 1), None)
        left_digest = left.digest if left is not None and left.digest else GENESIS
        # 右邻：target+1 段 manifest 里记录的 prev，即"它本来期望链上的前一段摘要"。
        right = next((item for item in self._reports if item.seq == target + 1), None)
        right_expected_prev = right.prev_digest if right is not None else ""
        # 缺口前链头：target 之前最后一个真实封档摘要，作为占位段的链上 prev。
        prev_digest = left_digest
        manifest = SegmentManifest.gap(
            target,
            prev_digest,
            left_digest,
            right_expected_prev,
            filled_ts=float(now_ts) if now_ts is not None else None,
        )
        line = manifest.to_line()
        try:
            fd, tmp = tempfile.mkstemp(prefix=f".{self._topic}-gap-", dir=self._root)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except OSError as error:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise StorageError(f"补齐缺段失败: {path}: {error}", component="store") from error

        digest = digest_manifest(_manifest_body(manifest))
        # 缺口在链尾（右邻不存在）：把可信根推进到占位段并标注证据有限。
        tail_evidence = right is not None
        if not tail_evidence:
            self._anchor_seq = target
            self._anchor_digest = digest
            self._write_anchor(target, digest, self._anchor_total)

        self._reports = self._scan_locked()
        return {
            "seq": target,
            "status": "filled",
            "digest": digest,
            "kind": SEGMENT_GAP,
            "left_digest": left_digest,
            "right_expected_prev": right_expected_prev,
            "right_present": tail_evidence,
            "note": note,
            "path": path,
        }

    # ---- 读取 ---------------------------------------------------------

    def segments(self) -> list[str]:
        """返回已存在的段文件路径（按段号升序，缺失/占位不计入）。"""

        with self._lock:
            return [
                self._segment_path(report.seq)
                for report in self._scan_locked()
                if report.status != SEGMENT_MISSING
            ]

    def read_segment(self, index: int) -> list[dict]:
        """原样读取指定段（不过滤问题段，manifest 行不返回）。"""

        path = self._segment_path(index)
        if not os.path.isfile(path):
            return []
        _lines, records, _manifest, _error = self._read_file_raw(path)
        return records

    def _read_file_raw(self, path: str) -> tuple[list[str], list[dict], SegmentManifest | None, str]:
        try:
            return self._read_segment_file(path)
        except OSError as error:
            raise StorageError(f"读取流水 {path} 失败: {error}", component="store") from error

    def read_verified(
        self,
        policy: str = READ_STRICT,
        *,
        start_ts: float | None = None,
        end_ts: float | None = None,
    ) -> dict:
        """按策略读全链，返回记录与逐段校验结果。

        返回：``records``（时间有序）、``segments``（逐段状态）、``skipped``
        （被跳过的问题段）、``policy``、``complete``（是否覆盖了全链无缺口）。
        """

        if policy not in READ_POLICIES:
            raise ValueError(f"未知读策略: {policy}（可选 {READ_POLICIES}）")
        with self._lock:
            reports = self._scan_locked()
            self._reports = reports
            records: list[dict] = []
            skipped: list[dict] = []
            complete = True
            for report in reports:
                if report.status == SEGMENT_OK or report.status == SEGMENT_UNSEALED:
                    chosen = [
                        item
                        for item in report.records
                        if _in_window(extract_ts(item), start_ts, end_ts)
                    ]
                    records.extend(chosen)
                    continue
                if report.status == SEGMENT_LEGACY and policy == READ_LENIENT:
                    records.extend(
                        item
                        for item in report.records
                        if _in_window(extract_ts(item), start_ts, end_ts)
                    )
                    skipped.append({**report.as_dict(), "read_anyway": True})
                    continue
                if report.status == SEGMENT_GAP:
                    complete = False
                    skipped.append({**report.as_dict(), "read_anyway": False})
                    if policy == READ_STRICT:
                        raise StorageError(
                            f"段 {report.seq} 是缺段补齐占位，strict 策略拒读",
                            component="store",
                        )
                    continue
                # altered / broken_link / time_disorder / missing
                complete = False
                skipped.append({**report.as_dict(), "read_anyway": False})
                if policy == READ_STRICT:
                    raise StorageError(
                        f"段 {report.seq} 校验不过（{report.status}）：{report.detail}",
                        component="store",
                    )
            # marked/lenient 也守住段内与段间的时间顺序（只对读进来的记录）。
            ordered = sorted(records, key=lambda item: extract_ts(item) or 0.0)
            return {
                "topic": self._topic,
                "policy": policy,
                "complete": complete,
                "records": ordered,
                "segments": [report.as_dict() for report in reports],
                "skipped": skipped,
            }

    def count(self) -> int:
        """返回累计写入条数（以可信根 + 当前尾段为准）。"""

        with self._lock:
            return self._count

    def active_segment(self) -> int:
        """返回当前正在写入的段号。"""

        with self._lock:
            return self._segment


def _in_window(ts: float | None, start_ts: float | None, end_ts: float | None) -> bool:
    if ts is None:
        return start_ts is None and end_ts is None
    if start_ts is not None and ts < start_ts:
        return False
    if end_ts is not None and ts > end_ts:
        return False
    return True


def _manifest_body(manifest: SegmentManifest) -> dict:
    """重算 manifest 摘要时使用的规范字段（与 :meth:`SegmentManifest.to_line` 对齐）。"""

    return {
        "__manifest__": True,
        "v": 1,
        "seq": manifest.seq,
        "count": manifest.count,
        "records": manifest.records_digest,
        "prev": manifest.prev_digest,
        "first_ts": manifest.first_ts,
        "last_ts": manifest.last_ts,
        "kind": manifest.kind,
        "gap_prev": manifest.gap_prev_digest,
        "gap_next_prev": manifest.gap_next_prev,
        "filled_ts": manifest.filled_ts,
    }
