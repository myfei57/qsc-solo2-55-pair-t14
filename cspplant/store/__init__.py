"""文件型持久化。

``JsonStore`` 保存"当前态"文档（每个文档一个 JSON 文件，写时先落临时文件
再原子替换）；``JsonlJournal`` 保存普通分段流水；``ChainedJournal`` 在分段流水
之上加了跨段哈希链与封段清单，删段/改条/多写都能被逐段指出；``StoreMetrics``
给出目录用量，供控制台判断快照是否已经滚动。它们都落在平台配置的
``storage_root`` 下。
"""

from __future__ import annotations

from .chain import (
    ChainedJournal,
    SegmentIntegrityError,
    SegmentManifest,
    SegmentRead,
    export_segment_bundle,
    load_segment_bundle,
)
from .jsonfile import JsonStore
from .journal import JsonlJournal
from .metrics import StoreMetrics

__all__ = [
    "JsonStore",
    "JsonlJournal",
    "ChainedJournal",
    "SegmentManifest",
    "SegmentRead",
    "SegmentIntegrityError",
    "StoreMetrics",
    "export_segment_bundle",
    "load_segment_bundle",
]
