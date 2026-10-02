"""运行审计。

审计是控制链的最后一环：每条联锁拒绝、每次追日、每次未通过的对焦都写一条
记录，内存保留最近若干条供控制台读取，同时按带跨段哈希链的段落 JSONL 供跨
重启可信回放。段封好即冻结，删段/改条/多写都能被逐段指出；缺段可按链顺序
补齐，补段与校验、回放动作本身同样落审计。
"""

from __future__ import annotations

from .log import AuditLog
from .record import AuditRecord
from .replay import (
    SHARED_AXIS,
    ReplayWindow,
    replay_shared_axis,
    working_condition_at,
)
from .report import summarize
from .timeline import build_timeline

__all__ = [
    "AuditLog",
    "AuditRecord",
    "summarize",
    "build_timeline",
    "SHARED_AXIS",
    "ReplayWindow",
    "replay_shared_axis",
    "working_condition_at",
]
