"""带跨段校验链的分段 JSONL 流水。

普通 :class:`~cspplant.store.journal.JsonlJournal` 只按条数滚动段落，删掉一个段
文件、往段里多塞一条都不会被发现。:class:`ChainedJournal` 在每条记录上套
``seq`` 序号与入口哈希，在每个段封装（seal）时写一份段清单（manifest），把
段与段串成一条只能追加、无法无痕篡改的链。

段内：记录按落盘顺序做哈希链（``entry_hash = H(anchor | seq | body)``），再折成
Merkle 根 ``root``。任何一条被改、被删、多插，``root`` 立刻对不上。
段间：清单里 ``chain = H(prev_chain | root | first_seq | last_seq | index)``，
``prev_chain`` 指向前一段的 ``chain``（第 0 段用固定起源值）。删掉中间任何一段，
链值就接不上；多写一段也会因段号/序号区间对不齐而暴露。

清单额外带 HMAC（配置密钥时），防止有人连段带清单一起伪造。清单写在
``<topic>-NNNNN.meta`` 侧车文件里，数据本体仍是每行一条 JSON，可直接肉眼审计。

段一旦封好（段满滚动，或显式 :meth:`seal`）就冻结：文件移进 ``sealed/`` 并附带
清单，之后只读不改；读回来永远按段号升序、段内按落盘顺序，时间顺序不会乱。

本类只负责"怎么存、怎么验"，不决定"验不过怎么办"（整段拒读还是标记续读），
由读取方按用途在 :data:`STRICT` / :data:`LENIENT` 两种策略间选。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import threading
from dataclasses import dataclass, field

from ..errors import StorageError

GENESIS = "0" * 64
SEALED_DIR = "sealed"

# 读取策略：
STRICT = "strict"  # 验不过 / 缺段：整段拒读，抛 SegmentIntegrityError
LENIENT = "lenient"  # 验不过：标记该段为不可信并跳过，继续读好段

_META_VERSION = 1


class SegmentIntegrityError(StorageError):
    """段链校验失败：清单对不上、链断裂或记录被改动。"""

    def __init__(self, message: str, *, segment: int = -1, kind: str = "integrity") -> None:
        super().__init__(message, component="store")
        self.segment = segment
        self.kind = kind  # missing | corrupt | chain | exists | malformed


def _digest(parts: list[str]) -> str:
    """把若干字符串串起来求一次 SHA-256。"""

    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(part.encode("utf-8"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def _anchor(index: int) -> str:
    """段内入口哈希链的锚点：段号绑定，防止整段挪到别的位置。"""

    return _digest(["segment-anchor", str(index)])


def entry_hash(index: int, seq: int, raw: dict, prev_hash: str) -> str:
    """一条记录的段内链哈希：H(prev_hash | index | seq | canonical_json)。"""

    body = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return _digest([prev_hash, str(index), str(seq), body])


@dataclass(frozen=True)
class SegmentManifest:
    """一段封好的流水的校验清单。"""

    index: int
    first_seq: int
    last_seq: int
    count: int
    first_ts: float | None
    last_ts: float | None
    prev_chain: str
    root: str
    chain: str
    mac: str = ""
    version: int = _META_VERSION

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "index": self.index,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "count": self.count,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "prev_chain": self.prev_chain,
            "root": self.root,
            "chain": self.chain,
            "mac": self.mac,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "SegmentManifest":
        return cls(
            version=int(raw.get("version", _META_VERSION)),
            index=int(raw["index"]),
            first_seq=int(raw["first_seq"]),
            last_seq=int(raw["last_seq"]),
            count=int(raw["count"]),
            first_ts=raw.get("first_ts"),
            last_ts=raw.get("last_ts"),
            prev_chain=str(raw["prev_chain"]),
            root=str(raw["root"]),
            chain=str(raw["chain"]),
            mac=str(raw.get("mac", "")),
        )

    def unsigned(self) -> dict:
        data = self.as_dict()
        data["mac"] = ""
        return data


@dataclass
class SegmentRead:
    """一次段读取的结果（含校验状态）。"""

    index: int
    entries: list[dict] = field(default_factory=list)
    manifest: SegmentManifest | None = None
    ok: bool = True
    sealed: bool = False
    missing: bool = False
    errors: list[str] = field(default_factory=list)
    skipped_seq: list[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "ok": self.ok,
            "sealed": self.sealed,
            "missing": self.missing,
            "count": len(self.entries),
            "errors": list(self.errors),
            "skipped_seq": list(self.skipped_seq),
            "manifest": self.manifest.as_dict() if self.manifest else None,
        }


class ChainedJournal:
    """按段落盘、段间用哈希链校验的只追加流水。"""

    def __init__(
        self,
        root: str,
        topic: str,
        segment_limit: int = 512,
        secret: str | bytes | None = None,
        ts_key: str = "ts",
    ) -> None:
        self._root = os.path.abspath(root)
        self._sealed_root = os.path.join(self._root, SEALED_DIR, topic)
        self._topic = topic
        self._segment_limit = max(1, segment_limit)
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._ts_key = ts_key
        self._lock = threading.RLock()
        os.makedirs(self._sealed_root, exist_ok=True)
        self._seq = 0
        self._segment = 0
        self._buffer: list[dict] = []
        self._last_chain = GENESIS
        self._recover_state()

    # ---- 路径 ---------------------------------------------------------

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def segment_limit(self) -> int:
        return self._segment_limit

    def _active_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.jsonl")

    def _sealed_path(self, index: int) -> str:
        return os.path.join(self._sealed_root, f"{self._topic}-{index:05d}.jsonl")

    def _meta_path(self, index: int) -> str:
        return os.path.join(self._sealed_root, f"{self._topic}-{index:05d}.meta")

    # ---- 启动恢复 -----------------------------------------------------

    def _recover_state(self) -> None:
        """从已封段与活动段恢复序号、段号与链尾。

        已封段按段号升序取最后一段的 chain / last_seq 作为续写起点（清单可信与否
        在 verify 时才判定，恢复本身不因历史坏段而拒绝启动）。活动段逐行重放进
        内存，并按段内入口链自检；对不上的行截掉，避免把坏行继续往后写。
        """

        sealed = self.sealed_indices()
        chain = GENESIS
        active_index = 0
        next_seq = 0
        if sealed:
            last_manifest = self.manifest_of(sealed[-1])
            if last_manifest is not None:
                chain = last_manifest.chain
                active_index = sealed[-1] + 1
                next_seq = last_manifest.last_seq + 1
        active_path = self._active_path(active_index)
        entries: list[dict] = []
        if os.path.isfile(active_path):
            prev = _anchor(active_index)
            for raw in self._read_jsonl(active_path):
                seq = raw.get("seq")
                body = raw.get("body")
                if not isinstance(seq, int) or not isinstance(body, dict) or seq != next_seq:
                    break
                if entry_hash(active_index, seq, body, prev) != raw.get("entry_hash"):
                    break
                entries.append(raw)
                prev = raw["entry_hash"]
                next_seq = seq + 1
        self._buffer = entries
        self._segment = active_index
        self._seq = next_seq
        self._last_chain = chain

    # ---- 写入 ---------------------------------------------------------

    def append(self, record: dict) -> str:
        """追加一条业务记录（自动套 seq/哈希，段满自动封段），返回写入路径。"""

        with self._lock:
            return self._append_locked(record)

    def _append_locked(self, record: dict) -> str:
        seq = self._seq
        index = self._segment
        prev_hash = self._buffer[-1]["entry_hash"] if self._buffer else _anchor(index)
        body = dict(record)
        eh = entry_hash(index, seq, body, prev_hash)
        envelope = {"seq": seq, "prev_hash": prev_hash, "entry_hash": eh, "body": body}
        path = self._active_path(index)
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(envelope, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise StorageError(f"追加流水失败: {error}", component="store") from error
        self._buffer.append(envelope)
        self._seq += 1
        if len(self._buffer) >= self._segment_limit:
            self._seal_locked()
        return path

    def seal(self) -> SegmentManifest | None:
        """把当前活动段封好（空段返回 None）。"""

        with self._lock:
            return self._seal_locked()

    def _seal_locked(self) -> SegmentManifest | None:
        if not self._buffer:
            return None
        index = self._segment
        rows = list(self._buffer)
        first_seq = int(rows[0]["seq"])
        last_seq = int(rows[-1]["seq"])
        root = self._merkle(rows)
        timestamps = [self._ts_of(row.get("body", {})) for row in rows]
        timestamps = [ts for ts in timestamps if ts is not None]
        manifest = SegmentManifest(
            index=index,
            first_seq=first_seq,
            last_seq=last_seq,
            count=len(rows),
            first_ts=min(timestamps) if timestamps else None,
            last_ts=max(timestamps) if timestamps else None,
            prev_chain=self._last_chain,
            root=root,
            chain="",
        )
        chain = self._chain_value(manifest.prev_chain, root, first_seq, last_seq, index)
        manifest = SegmentManifest(**{**manifest.as_dict(), "chain": chain})
        if self._secret is not None:
            mac = hmac.new(self._secret, self._signing_bytes(manifest), hashlib.sha256).hexdigest()
            manifest = SegmentManifest(**{**manifest.as_dict(), "mac": mac})
        active = self._active_path(index)
        try:
            with open(self._meta_path(index), "w", encoding="utf-8") as handle:
                handle.write(json.dumps(manifest.as_dict(), ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            shutil.move(active, self._sealed_path(index))
        except OSError as error:
            raise StorageError(f"封段失败: {error}", component="store") from error
        self._last_chain = manifest.chain
        self._segment += 1
        self._buffer = []
        return manifest

    @staticmethod
    def _chain_value(prev_chain: str, root: str, first_seq: int, last_seq: int, index: int) -> str:
        return _digest([prev_chain, root, str(first_seq), str(last_seq), str(index)])

    @staticmethod
    def _merkle(rows: list[dict]) -> str:
        """对一段记录求 Merkle 根：叶子是每条记录的入口哈希。"""

        level = [row["entry_hash"] for row in rows]
        while len(level) > 1:
            nxt: list[str] = []
            for left, right in zip(level[0::2], level[1::2]):
                nxt.append(_digest(["node", left, right]))
            if len(level) % 2:
                nxt.append(_digest(["node", level[-1], level[-1]]))
            level = nxt
        return level[0] if level else GENESIS

    def _signing_bytes(self, manifest: SegmentManifest) -> bytes:
        return json.dumps(manifest.unsigned(), ensure_ascii=False, sort_keys=True).encode("utf-8")

    def _ts_of(self, body: dict) -> float | None:
        value = body.get(self._ts_key) if isinstance(body, dict) else None
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    # ---- 段索引 -------------------------------------------------------

    def sealed_indices(self) -> list[int]:
        """返回磁盘上已封段（数据与清单都在）的段号升序。"""

        if not os.path.isdir(self._sealed_root):
            return []
        indices: list[int] = []
        for name in os.listdir(self._sealed_root):
            if name.startswith(f"{self._topic}-") and name.endswith(".jsonl"):
                index_part = name[len(self._topic) + 1 : -len(".jsonl")]
                try:
                    index = int(index_part)
                except ValueError:
                    continue
                if os.path.isfile(self._meta_path(index)):
                    indices.append(index)
        return sorted(indices)

    def active_segment(self) -> int:
        with self._lock:
            return self._segment

    def count(self) -> int:
        with self._lock:
            return self._seq

    def segments(self) -> list[str]:
        """已封段 + 活动段的路径，按段号升序。"""

        with self._lock:
            paths = [self._sealed_path(i) for i in self.sealed_indices()]
            if self._buffer or os.path.isfile(self._active_path(self._segment)):
                paths.append(self._active_path(self._segment))
            return paths

    # ---- 校验 ---------------------------------------------------------

    def verify(self, policy: str = STRICT) -> list[SegmentRead]:
        """从第 0 段起逐段验链。

        STRICT 遇到第一个缺段/坏段抛 :class:`SegmentIntegrityError`；
        LENIENT 全扫，坏段整段标记且不采信其记录，好段照常读出。
        """

        with self._lock:
            return self._verify_locked(policy)

    def _verify_locked(self, policy: str) -> list[SegmentRead]:
        reads: list[SegmentRead] = []
        indices = self.sealed_indices()
        expected = 0
        prev_chain: str | None = GENESIS
        for index in indices:
            while expected < index:
                gap = SegmentRead(index=expected, ok=False, sealed=False, missing=True,
                                  errors=[f"段 {expected} 缺失：链在第 {expected} 段断开"])
                reads.append(gap)
                if policy == STRICT:
                    raise SegmentIntegrityError(gap.errors[0], segment=expected, kind="missing")
                prev_chain = None
                expected += 1
            read = self._read_sealed(index, expected_prev=prev_chain, policy=policy)
            if not read.ok and policy == STRICT:
                raise SegmentIntegrityError(
                    read.errors[0] if read.errors else f"段 {index} 校验失败",
                    segment=index, kind="corrupt",
                )
            reads.append(read)
            if read.ok and read.manifest is not None:
                prev_chain = read.manifest.chain if prev_chain is not None else None
            else:
                prev_chain = None
            expected = index + 1
        active = self._read_active_segment()
        if active is not None and (active.entries or active.errors):
            reads.append(active)
        return reads

    def _read_sealed(self, index: int, expected_prev: str | None, policy: str) -> SegmentRead:
        read = SegmentRead(index=index, sealed=True)
        data_path = self._sealed_path(index)
        meta_path = self._meta_path(index)
        if not os.path.isfile(data_path) or not os.path.isfile(meta_path):
            read.ok = False
            read.missing = True
            read.errors.append(f"段 {index} 数据或清单缺失")
            return read
        try:
            manifest = SegmentManifest.from_dict(self._read_jsonl(meta_path)[0])
        except (OSError, IndexError, KeyError, ValueError, json.JSONDecodeError) as error:
            read.ok = False
            read.errors.append(f"段 {index} 清单无法解析：{error}")
            return read
        read.manifest = manifest
        if self._secret is not None:
            expect = hmac.new(self._secret, self._signing_bytes(manifest), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expect, manifest.mac):
                read.ok = False
                read.errors.append(f"段 {index} 清单签名不匹配（可能被伪造）")
        try:
            rows = self._read_jsonl(data_path)
        except (OSError, json.JSONDecodeError) as error:
            read.ok = False
            read.errors.append(f"段 {index} 数据无法解析：{error}")
            return read
        bodies = self._validate_rows(index, rows, manifest, read)
        if read.ok and self._merkle(rows) != manifest.root:
            read.ok = False
            read.errors.append(
                f"段 {index} 记录根不匹配（有记录被改/增/删）："
                f"期望 {manifest.root[:12]} 实得 {self._merkle(rows)[:12]}"
            )
        if read.ok and expected_prev is not None and manifest.prev_chain != expected_prev:
            read.ok = False
            read.errors.append(
                f"段 {index} 链接断裂：前驱 {manifest.prev_chain[:12]} ≠ {expected_prev[:12]}"
            )
        if read.ok:
            chain = self._chain_value(
                manifest.prev_chain, manifest.root, manifest.first_seq, manifest.last_seq, manifest.index
            )
            if chain != manifest.chain:
                read.ok = False
                read.errors.append(f"段 {index} 链值不自洽")
        # 段级不可信时整段不采信，绝不把半真半假的记录交出去。
        read.entries = bodies if read.ok else []
        return read

    def _validate_rows(
        self, index: int, rows: list[dict], manifest: SegmentManifest, read: SegmentRead
    ) -> list[dict]:
        bodies: list[dict] = []
        if len(rows) != manifest.count:
            read.ok = False
            read.errors.append(f"段 {index} 条数 {len(rows)} ≠ 清单 {manifest.count}")
        prev = _anchor(index)
        expect_seq = manifest.first_seq
        for pos, row in enumerate(rows):
            body = row.get("body")
            seq = row.get("seq")
            if not isinstance(body, dict) or not isinstance(seq, int):
                read.ok = False
                read.errors.append(f"段 {index} 第 {pos} 行结构损坏")
                read.skipped_seq.append(seq if isinstance(seq, int) else -1)
                continue
            if seq != expect_seq:
                read.ok = False
                read.errors.append(f"段 {index} 序号错位：第 {pos} 行 seq={seq}，期望 {expect_seq}")
                read.skipped_seq.append(seq)
            if row.get("prev_hash") != prev or entry_hash(index, seq, body, prev) != row.get("entry_hash"):
                read.ok = False
                read.errors.append(f"段 {index} 第 {pos} 行入口哈希不匹配（记录被改动）")
            bodies.append(body)
            prev = row.get("entry_hash", prev)
            expect_seq += 1
        if rows:
            last_seq = rows[-1].get("seq")
            if last_seq != manifest.last_seq:
                read.ok = False
                read.errors.append(f"段 {index} 末序号 {last_seq} ≠ 清单 {manifest.last_seq}")
        return bodies

    def _read_active_segment(self) -> SegmentRead | None:
        if not self._buffer and not os.path.isfile(self._active_path(self._segment)):
            return None
        read = SegmentRead(index=self._segment, sealed=False)
        prev = _anchor(self._segment)
        expect_seq = self._buffer[0]["seq"] if self._buffer else 0
        for pos, row in enumerate(self._buffer):
            seq = int(row["seq"])
            body = row.get("body", {})
            if seq != expect_seq or row.get("prev_hash") != prev \
                    or entry_hash(self._segment, seq, body, prev) != row.get("entry_hash"):
                read.ok = False
                read.errors.append(f"活动段第 {pos} 行（seq={seq}）校验失败")
                continue
            read.entries.append(body)
            prev = row["entry_hash"]
            expect_seq += 1
        return read

    # ---- 读取 ---------------------------------------------------------

    def read_segment(self, index: int, policy: str = LENIENT) -> SegmentRead:
        """读单段。已封段按清单校验；活动段按入口链校验。"""

        with self._lock:
            active_index = self._segment
            meta_exists = os.path.isfile(self._meta_path(index))
            if index == active_index and not meta_exists:
                return self._read_active_segment()
            if not os.path.isfile(self._sealed_path(index)):
                if policy == STRICT:
                    raise SegmentIntegrityError(f"段 {index} 不存在", segment=index, kind="missing")
                return SegmentRead(index=index, ok=False, missing=True, errors=[f"段 {index} 不存在"])
            return self._read_sealed(index, expected_prev=self._prev_chain_for(index), policy=policy)

    def _prev_chain_for(self, index: int) -> str | None:
        if index == 0:
            return GENESIS
        prior = self.manifest_of(index - 1)
        return prior.chain if prior else None

    def read_all(self, policy: str = LENIENT) -> tuple[list[dict], list[SegmentRead]]:
        """按段号升序读全部，返回 (记录, 各段校验结果)。

        STRICT：第一个缺段/坏段就抛错（整段拒读，用于取证/联锁恢复）。
        LENIENT：坏段整段跳过并在第二段结果里标记，好段按段号升序照常读出
        （时间顺序仍守住，用于控制台展示这类可容忍缺口的用途）。
        """

        with self._lock:
            reads = self._verify_locked(policy)
            entries: list[dict] = []
            for read in reads:
                entries.extend(read.entries)
            return entries, reads

    def manifest_of(self, index: int) -> SegmentManifest | None:
        path = self._meta_path(index)
        if not os.path.isfile(path):
            return None
        try:
            return SegmentManifest.from_dict(self._read_jsonl(path)[0])
        except (OSError, IndexError, KeyError, ValueError, json.JSONDecodeError):
            return None

    def chain_heads(self) -> dict:
        """暴露链头/链尾，供补段后接链与外部对账。"""

        with self._lock:
            return {
                "genesis": GENESIS,
                "last_chain": self._last_chain,
                "active_segment": self._segment,
                "next_seq": self._seq,
                "sealed": self.sealed_indices(),
            }

    # ---- 补段 ---------------------------------------------------------

    def missing_indices(self) -> list[int]:
        """返回链上缺失（被删）的段号：从 0 到活动段前，凡无已封段的都算。"""

        with self._lock:
            present = set(self.sealed_indices())
            return [index for index in range(self._segment) if index not in present]

    def import_segment(self, index: int, envelopes: list[dict], manifest: SegmentManifest) -> SegmentManifest:
        """把一个已封好的缺失段（数据 + 清单）接进链里补齐。

        补段属部分失败下的修复，时序必须守住，因此硬校验：段号必须正落在链的
        缺口上（且只能补活动段之前的洞，不许在尾后插队打乱顺序）、序号区间连续、
        root 与 chain 自洽、前驱链值必须接上、配了密钥时签名必须对上。任何一项
        不过就整段拒收，绝不污染链。段已存在时幂等返回既有清单。
        """

        with self._lock:
            if index in self.sealed_indices():
                existing = self.manifest_of(index)
                if existing is not None and existing.chain == manifest.chain:
                    return existing
                raise SegmentIntegrityError(
                    f"段 {index} 已存在且链值不同，拒绝覆盖", segment=index, kind="exists"
                )
            if index >= self._segment:
                raise SegmentIntegrityError(
                    f"段 {index} 不在缺口上（活动段为 {self._segment}），补段不能插队到尾后",
                    segment=index, kind="chain",
                )
            self._validate_import(index, envelopes, manifest)
            self._write_import(index, envelopes, manifest)
            return manifest

    def _validate_import(self, index: int, envelopes: list[dict], manifest: SegmentManifest) -> None:
        if not envelopes:
            raise SegmentIntegrityError(f"段 {index} 内容为空，拒绝补入", segment=index)
        if len(envelopes) != manifest.count:
            raise SegmentIntegrityError(f"段 {index} 条数与清单不符", segment=index, kind="corrupt")
        if manifest.index != index:
            raise SegmentIntegrityError(f"段 {index} 清单段号 {manifest.index} 不一致", segment=index, kind="corrupt")
        if self._secret is not None and manifest.mac:
            expect = hmac.new(self._secret, self._signing_bytes(manifest), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expect, manifest.mac):
                raise SegmentIntegrityError(f"段 {index} 来源清单签名不匹配", segment=index, kind="chain")
        # 段内入口链 + 序号连续性。
        prev = _anchor(index)
        expect_seq = manifest.first_seq
        for pos, row in enumerate(envelopes):
            body = row.get("body")
            seq = row.get("seq")
            if not isinstance(body, dict) or not isinstance(seq, int) or seq != expect_seq:
                raise SegmentIntegrityError(f"段 {index} 第 {pos} 行序号/结构不对", segment=index, kind="corrupt")
            if row.get("prev_hash") != prev or entry_hash(index, seq, body, prev) != row.get("entry_hash"):
                raise SegmentIntegrityError(f"段 {index} 第 {pos} 行入口哈希不匹配", segment=index, kind="corrupt")
            prev = row["entry_hash"]
            expect_seq += 1
        if self._merkle(envelopes) != manifest.root:
            raise SegmentIntegrityError(f"段 {index} 根不匹配，来源数据与清单不符", segment=index, kind="corrupt")
        expected_prev = GENESIS if index == 0 else self._chain_value_of(index - 1)
        if expected_prev is None:
            raise SegmentIntegrityError(
                f"段 {index} 的前驱段 {index - 1} 尚缺，必须按段号顺序补", segment=index, kind="chain"
            )
        if manifest.prev_chain != expected_prev:
            raise SegmentIntegrityError(
                f"段 {index} 前驱链接不上，来源段不属于本条链", segment=index, kind="chain"
            )
        chain = self._chain_value(
            manifest.prev_chain, manifest.root, manifest.first_seq, manifest.last_seq, index
        )
        if chain != manifest.chain:
            raise SegmentIntegrityError(f"段 {index} 链值不自洽", segment=index, kind="chain")
        # 与后继段的前驱也要咬合（后继段已在盘上）。
        successor = self.manifest_of(index + 1)
        if successor is not None and successor.prev_chain != manifest.chain:
            raise SegmentIntegrityError(
                f"段 {index} 补入后与后继段 {index + 1} 的前驱对不上", segment=index, kind="chain"
            )

    def _chain_value_of(self, index: int) -> str | None:
        if index < 0:
            return GENESIS
        manifest = self.manifest_of(index)
        return manifest.chain if manifest else None

    def _write_import(self, index: int, envelopes: list[dict], manifest: SegmentManifest) -> None:
        os.makedirs(self._sealed_root, exist_ok=True)
        data_path = self._sealed_path(index)
        meta_path = self._meta_path(index)
        tmp_data = data_path + ".tmp"
        tmp_meta = meta_path + ".tmp"
        try:
            with open(tmp_data, "w", encoding="utf-8") as handle:
                for row in envelopes:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            with open(tmp_meta, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(manifest.as_dict(), ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_data, data_path)
            os.replace(tmp_meta, meta_path)
        except OSError as error:
            for tmp in (tmp_data, tmp_meta):
                if os.path.isfile(tmp):
                    os.remove(tmp)
            raise StorageError(f"补段落盘失败: {error}", component="store") from error
        self._recover_state()

    @staticmethod
    def verify_segment_payload(envelopes: list[dict], manifest: SegmentManifest) -> bool:
        """只依据数据与清单自洽性判断一个待补段本身是否可信（不依赖本地链）。"""

        if not envelopes or len(envelopes) != manifest.count or manifest.index < 0:
            return False
        prev = _anchor(manifest.index)
        expect_seq = manifest.first_seq
        for row in envelopes:
            seq = row.get("seq")
            body = row.get("body")
            if not isinstance(body, dict) or not isinstance(seq, int) or seq != expect_seq:
                return False
            if row.get("prev_hash") != prev or entry_hash(manifest.index, seq, body, prev) != row.get("entry_hash"):
                return False
            prev = row["entry_hash"]
            expect_seq += 1
        if ChainedJournal._merkle(envelopes) != manifest.root:
            return False
        chain = ChainedJournal._chain_value(
            manifest.prev_chain, manifest.root, manifest.first_seq, manifest.last_seq, manifest.index
        )
        return chain == manifest.chain

    # ---- IO 辅助 ------------------------------------------------------

    @staticmethod
    def _read_jsonl(path: str) -> list[dict]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return [json.loads(line) for line in handle if line.strip()]
        except (OSError, json.JSONDecodeError) as error:
            raise StorageError(f"读取流水 {path} 失败: {error}", component="store") from error


def load_segment_bundle(path: str) -> tuple[list[dict], SegmentManifest]:
    """从一个补段包目录读取 ``data.jsonl`` 与 ``manifest.json``。"""

    envelopes = ChainedJournal._read_jsonl(os.path.join(path, "data.jsonl"))
    with open(os.path.join(path, "manifest.json"), "r", encoding="utf-8") as handle:
        manifest = SegmentManifest.from_dict(json.load(handle))
    return envelopes, manifest


def export_segment_bundle(journal: ChainedJournal, index: int, dest: str) -> str:
    """把本地一个已封段导出成可带往别处补段的包（数据 + 清单）。"""

    manifest = journal.manifest_of(index)
    if manifest is None:
        raise SegmentIntegrityError(f"段 {index} 无清单，无法导出", segment=index, kind="missing")
    envelopes = journal._read_jsonl(journal._sealed_path(index))
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, "data.jsonl"), "w", encoding="utf-8") as handle:
        for row in envelopes:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest.as_dict(), handle, ensure_ascii=False, indent=2)
    return dest
