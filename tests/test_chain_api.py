"""校验/补段/同轴回放的控制台接口。"""

from __future__ import annotations

import os

from cspplant.console.api import Api


def test_journal_endpoint_reports_chain(platform):
    api = Api(platform)
    platform.start()
    platform.track(820.0, 720.0)
    status, payload = api.handle("GET", "/api/journal", {}, {})
    assert status == 200
    assert payload["chain"]["healthy"] is True


def test_verify_endpoint(platform):
    api = Api(platform)
    platform.start()
    platform.seal_archives()
    status, payload = api.handle("GET", "/api/journal/verify", {}, {})
    assert status == 200
    assert payload["audit"]["healthy"] is True
    assert payload["trend"]["healthy"] is True


def test_seal_endpoint(platform):
    api = Api(platform)
    platform.start()
    status, payload = api.handle("POST", "/api/journal/seal", {}, {})
    assert status == 200
    assert "audit" in payload and "trend" in payload


def test_fill_endpoint_is_idempotent(platform):
    api = Api(platform)
    platform.start()
    platform.track(820.0, 720.0)
    platform.seal_archives()
    target = platform.audit.verify_chain()["anchor"]["tail_seq"]
    os.remove(os.path.join(platform.store.root, f"audit-{target:05d}.jsonl"))

    status, first = api.handle("POST", "/api/journal/fill", {}, {"note": "api"})
    assert status == 200
    assert [item["seq"] for item in first["filled"]] == [target]
    status, second = api.handle("POST", "/api/journal/fill", {}, {"note": "api"})
    assert status == 200
    assert second["filled"] == []


def test_replay_endpoint_is_co_axis_and_marked(online):
    api = Api(online)
    for _ in range(3):
        online.cycle(dt=5.0)
    online.seal_archives()
    status, payload = api.handle("GET", "/api/replay", {}, {})
    assert status == 200
    assert payload["alignment"] == "co_axis"
    assert payload["complete"] is True
    kinds = {event["kind"] for event in payload["timeline"]}
    assert {"audit", "trend"} <= kinds
    # 默认 marked 策略。
    assert payload["policy"] == {"audit": "marked", "trend": "marked"}
