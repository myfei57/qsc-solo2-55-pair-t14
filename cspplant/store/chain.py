"""分段流水的跨段哈希链。

每段流水在"封档"（滚到下一段）时追加一行 manifest：

* ``records``    —— 段内全部记录行按字节拼接后的 SHA-256，任何一条被增删改
                    都会让它对不上；
* ``prev``       —— 前一段 manifest 的摘要。首段取固定常量 :data:`GENESIS`，
                    于是段与段首尾相扣：删掉一段、多塞一段、调换两段顺序，
                    校验链都会在对应段号断开；
* ``seq``、``count``、``first_ts``、``last_ts`` —— 段号、条目数与时间范围，
                    读回来时按它们守住时间顺序。

缺段被补齐时写成 ``kind="gap"`` 的占位段：它锚定缺失当时左右两段的摘要，
占位内容不是原始记录、永不伪装成正常段。链在占位段处是"可识别的断点"而不是
"悄悄愈合"。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

#: 首段的"前一段摘要"，全链固定起点。
GENESIS = "0" * 64

#: 段内 manifest 行的类型标记，普通数据行不含 ``__manifest__`` 键。
MANIFEST_KEY = "__manifest__"

#: 段状态：
#: OK       —— 封档且自校验、跨段链接全部通过；
#: UNSEALED —— 当前正在追加的尾段，尚无 manifest，内容按已写入行自校验；
#: ALTERED  —— 有 manifest，但内容摘要或条目数对不上（被改过/多写了一条）；
#: BROKEN_LINK —— 本段自校验通过，但前一段摘要与链上前一段不吻合（删段/调序）；
#: MISSING  —— 段号位置应有段但文件不存在（被删掉了）；
#: GAP      —— 缺段补写后的占位段，内容为缺口标记而非原始记录；
#: LEGACY   —— 升级前写出的旧段，没有 manifest，可读但不具备跨段校验；
#: DISORDER —— 段内容本身可信，但与前一段的时间范围倒挂（归档顺序被打乱）。
SEGMENT_OK = "ok"
SEGMENT_UNSEALED = "unsealed"
SEGMENT_ALTERED = "altered"
SEGMENT_BROKEN_LINK = "broken_link"
SEGMENT_MISSING = "missing"
SEGMENT_GAP = "gap"
SEGMENT_LEGACY = "legacy"
SEGMENT_DISORDER = "time_disorder"

#: 健康读不会放行的问题段。
BAD_STATUSES = (
    SEGMENT_ALTERED,
    SEGMENT_BROKEN_LINK,
    SEGMENT_MISSING,
    SEGMENT_DISORDER,
)

#: 读策略（按用途定）：
#: STRICT  —— 整段拒读：任何一段不过校验就抛错。恢复/再执行等只能基于
#:            完整可信流水的用途用它；
#: MARKED  —— 标记后部分读：可信段照常读，问题段跳过其正文并在报告里点名，
#:            控制台展示、巡检这类"能看多少看多少但要知道哪段不可信"的用途；
#: LENIENT —— 尽力读：连同无 manifest 的旧段一起读，只报告不拦截。
READ_STRICT = "strict"
READ_MARKED = "marked"
READ_LENIENT = "lenient"
READ_POLICIES = (READ_STRICT, READ_MARKED, READ_LENIENT)


def digest_records(lines: list[str]) -> str:
    """计算段内记录行（不含 manifest 行）的摘要。"""

    hasher = hashlib.sha256()
    for line in lines:
        hasher.update(line.encode("utf-8"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def digest_manifest(manifest: dict) -> str:
    """计算一段 manifest 的摘要，作为下一段的 ``prev``。"""

    body = {key: value for key, value in manifest.items() if key != "digest"}
    encoded = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def extract_ts(record: dict) -> float | None:
    """从一条记录里取时间戳；没有时间轴的主题返回 ``None``。"""

    ts = record.get("ts")
    try:
        return float(ts) if ts is not None else None
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class SegmentManifest:
    """一段流水的封档凭证。"""

    seq: int
    count: int
    records_digest: str
    prev_digest: str
    first_ts: float | None
    last_ts: float | None
    kind: str = "data"
    digest: str = ""
    #: gap 占位段专用：缺失当时左右两段的摘要，把缺口钉死在链上。
    gap_prev_digest: str = ""
    gap_next_prev: str = ""
    filled_ts: float | None = None

    def to_line(self) -> str:
        """序列化成追加到段文件末尾的一行 JSON。"""

        body = {
            MANIFEST_KEY: True,
            "v": 1,
            "seq": self.seq,
            "count": self.count,
            "records": self.records_digest,
            "prev": self.prev_digest,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "kind": self.kind,
            "gap_prev": self.gap_prev_digest,
            "gap_next_prev": self.gap_next_prev,
            "filled_ts": self.filled_ts,
        }
        body["digest"] = digest_manifest(body)
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def sealed(
        cls,
        seq: int,
        lines: list[str],
        records: list[dict],
        prev_digest: str,
    ) -> "SegmentManifest":
        """对一个装满记录的数据段封档。"""

        timestamps = [value for value in (extract_ts(item) for item in records) if value is not None]
        return cls(
            seq=seq,
            count=len(records),
            records_digest=digest_records(lines),
            prev_digest=prev_digest,
            first_ts=min(timestamps) if timestamps else None,
            last_ts=max(timestamps) if timestamps else None,
        )

    @classmethod
    def gap(
        cls,
        seq: int,
        prev_digest: str,
        left_digest: str,
        right_expected_prev: str,
        filled_ts: float,
    ) -> "SegmentManifest":
        """构造一个缺段占位凭证（段内没有任何原始记录行）。"""

        manifest = cls(
            seq=seq,
            count=0,
            records_digest=digest_records([]),
            prev_digest=prev_digest,
            first_ts=None,
            last_ts=None,
            kind=SEGMENT_GAP,
            gap_prev_digest=left_digest,
            gap_next_prev=right_expected_prev,
            filled_ts=filled_ts,
        )
        return manifest

    @classmethod
    def from_line(cls, line: str) -> "SegmentManifest | None":
        """解析一行；不是 manifest 行时返回 ``None``。"""

        try:
            raw = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(raw, dict) or not raw.get(MANIFEST_KEY):
            return None
        return cls(
            seq=int(raw.get("seq", -1)),
            count=int(raw.get("count", 0)),
            records_digest=str(raw.get("records", "")),
            prev_digest=str(raw.get("prev", "")),
            first_ts=raw.get("first_ts"),
            last_ts=raw.get("last_ts"),
            kind=str(raw.get("kind", "data")),
            digest=str(raw.get("digest", "")),
            gap_prev_digest=str(raw.get("gap_prev", "")),
            gap_next_prev=str(raw.get("gap_next_prev", "")),
            filled_ts=raw.get("filled_ts"),
        )

    def self_verifies(self, lines: list[str], count: int) -> bool:
        """段内记录行摘要与条目数是否与凭证一致。"""

        if self.kind == SEGMENT_GAP:
            return count == 0 and self.records_digest == digest_records([])
        return self.count == count and self.records_digest == digest_records(lines)
