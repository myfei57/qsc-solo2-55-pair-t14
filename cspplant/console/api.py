"""控制台接口处理器。

每个接口都是对平台公开方法的一次调用；动作类接口把请求体里的参数透传给平台，
缺少必填字段或取值非法时返回 ``400``，平台联锁异常统一转成 ``409`` 并在响应
里带上组件名与原因。页面不走这里，见 :mod:`cspplant.console.pages`。
"""

from __future__ import annotations

from ..app import Platform
from ..audit.timeline import build_timeline
from ..errors import PlantError
from .router import Router


def _as_float(body: dict, key: str, default: float) -> float:
    value = body.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError) as error:
        raise PlantError(f"参数 {key!r} 必须是数值", component="console") from error


class Api:
    """把 HTTP 请求翻译成平台调用。"""

    def __init__(self, platform: Platform) -> None:
        self._platform = platform
        self._router = Router()
        self._register()

    @property
    def platform(self) -> Platform:
        return self._platform

    def _register(self) -> None:
        add = self._router.add
        add("GET", "/api/status", lambda params, body: self._platform.status())
        add("GET", "/api/snapshot", lambda params, body: self._platform.snapshot())
        add("GET", "/api/topology", self._topology)
        add("GET", "/api/namespaces", self._namespaces)
        add("GET", "/api/zones", lambda params, body: self._platform.zones.describe())
        add("GET", "/api/heliostats", lambda params, body: self._platform.heliostats.describe())
        add("GET", "/api/mirrors", self._mirrors)
        add("GET", "/api/mirror/{name}", self._mirror)
        add("GET", "/api/rules", lambda params, body: {"rules": self._platform.rules.describe()})
        add("GET", "/api/levels", lambda params, body: {"levels": self._platform.alert_levels()})
        add("GET", "/api/latch", self._latch)
        add("GET", "/api/forecast", self._forecast)
        add("GET", "/api/trend", self._trend)
        add("GET", "/api/events", self._events)
        add("GET", "/api/audit", self._audit)
        add("GET", "/api/alarms", self._alarms)
        add("GET", "/api/timeline", self._timeline)
        add("GET", "/api/journal", self._journal)
        add("GET", "/api/verify", self._verify)
        add("GET", "/api/audit/chain", self._audit_chain)
        add("GET", "/api/replay", self._replay)
        add("GET", "/api/condition", self._condition)
        add("POST", "/api/segments/fill", self._fill_segments)
        add("POST", "/api/segments/export", self._export_segment)
        add("POST", "/api/archive/seal", lambda params, body: self._platform.seal_archives())
        add("GET", "/api/store", self._store)
        add("GET", "/api/readiness", self._readiness)
        add("GET", "/api/window", lambda params, body: {"mirrors": self._platform.mirrors_in_window()})
        add("POST", "/api/track", self._track)
        add("POST", "/api/circulate", self._circulate)
        add("POST", "/api/cycle", self._cycle)
        add("POST", "/api/dispatch", self._dispatch)
        add("POST", "/api/changeover", lambda params, body: self._platform.changeover())
        add("POST", "/api/pump", self._pump)
        add("POST", "/api/calibrate", self._calibrate)
        add("POST", "/api/manual", self._manual)
        add("POST", "/api/manual/release", self._manual_release)
        add("POST", "/api/manual/expire", lambda params, body: self._platform.expire_manual())
        add("POST", "/api/wash", self._wash)
        add("POST", "/api/trip", self._trip)
        add("POST", "/api/reset", self._reset)
        add("POST", "/api/concurrency", self._concurrency)
        add("POST", "/api/disturb", self._disturb)
        add("POST", "/api/plant/reset-state", lambda params, body: {"removed": self._platform.reset_state()})

    def routes(self) -> list[dict]:
        """返回接口清单，供自检与文档核对。"""

        return [route.as_dict() for route in self._router.routes()]

    def handle(self, method: str, path: str, query: dict, body: dict) -> tuple[int, dict]:
        """处理一次请求，返回状态码与响应体。"""

        matched = self._router.match(method, path)
        if matched is None:
            return 404, {"error": "not_found", "path": path}
        handler, params = matched
        merged = {**query, **params}
        try:
            payload = handler(merged, body)
        except PlantError as error:
            self._platform.note_error(error)
            return 409, {"error": type(error).__name__, **error.as_record()}
        except (TypeError, ValueError) as error:
            return 400, {"error": "bad_request", "message": str(error)}
        return 200, payload

    # ---- 查询 ---------------------------------------------------------

    def _mirrors(self, params: dict, body: dict) -> dict:
        group = params.get("group")
        mirrors = self._platform.heliostats
        selected = mirrors.in_group(group) if group else mirrors.all()
        drives = {drive.name: drive.snapshot().as_dict() for drive in self._platform.field.drives()}
        return {
            "count": len(selected),
            "mirrors": [{**mirror.as_dict(), "drive": drives[mirror.name]} for mirror in selected],
        }

    def _mirror(self, params: dict, body: dict) -> dict:
        name = params.get("name", "")
        drive = self._platform.field.drive(name)
        return {
            "mirror": self._platform.heliostats.get(name).as_dict(),
            "drive": drive.snapshot().as_dict(),
            "aim": drive.aim_snapshot().as_dict(),
            "target_angles": drive.target_angles().as_dict(),
            "stow_angles": self._platform.field.stow_angles_for(name).as_dict(),
            "rate_limited_steps": drive.rate_limited_steps(),
        }

    def _topology(self, params: dict, body: dict) -> dict:
        topology = self._platform.topology
        payload = topology.summary()
        payload["downstream"] = {stage: topology.downstream(stage) for stage in topology.order()}
        payload["verify"] = topology.verify(set())
        return payload

    def _namespaces(self, params: dict, body: dict) -> dict:
        registry = self._platform.namespaces
        payload = registry.describe()
        payload["by_kind"] = {
            kind: [device.address for device in registry.by_kind(kind)] for kind in registry.kinds()
        }
        return payload

    def _latch(self, params: dict, body: dict) -> dict:
        return self._platform.latch.state().as_dict()

    def _forecast(self, params: dict, body: dict) -> dict:
        horizon = float(params.get("horizon_min", 60.0))
        minute = params.get("minute_of_day")
        return self._platform.forecast(None if minute is None else float(minute), horizon)

    def _trend(self, params: dict, body: dict) -> dict:
        signal = params.get("signal", "receiver_temperature")
        samples = self._platform.trend.series(signal, limit=int(params.get("limit", 60)))
        filled = self._platform.trend.fill_gaps(signal, samples)
        return {
            "signal": signal,
            "period_s": self._platform.trend.period_s,
            "signals": self._platform.trend.signals(),
            "samples": [sample.as_dict() for sample in filled],
        }

    def _events(self, params: dict, body: dict) -> dict:
        topic = params.get("topic")
        return {"events": [event.as_dict() for event in self._platform.bus.history(topic)]}

    def _audit(self, params: dict, body: dict) -> dict:
        limit = int(params.get("limit", 100))
        return {"entries": self._platform.audit.entries(limit=limit)}

    def _alarms(self, params: dict, body: dict) -> dict:
        limit = int(params.get("limit", 20))
        return {
            "recent": self._platform.history.recent(limit),
            "by_rule": self._platform.history.by_rule(),
            "latched": self._platform.latch.state().as_dict(),
        }

    def _timeline(self, params: dict, body: dict) -> dict:
        asset = params.get("asset")
        records = self._platform.audit.records(limit=int(params.get("limit", 200)))
        return {"timeline": build_timeline(records, asset=asset)}

    def _journal(self, params: dict, body: dict) -> dict:
        journal = self._platform.audit.journal
        # 控制台读单段用宽松口径：坏段标记后跳过，好段照常展示。
        policy = str(params.get("policy", "lenient"))
        payload: dict = {
            "topic": journal.topic,
            "count": journal.count(),
            "active_segment": journal.active_segment(),
            "segments": journal.segments(),
            "missing_segments": journal.missing_indices(),
        }
        segment = params.get("segment")
        if segment is not None:
            seg_index = int(segment)
            read = journal.read_segment(seg_index, policy)
            payload["segment_read"] = read.as_dict()
            # 与审计层 replay_segment 同一出口，保证单段回放口径一致。
            payload["records"] = self._platform.audit.replay_segment(seg_index, policy)
        return payload

    def _verify(self, params: dict, body: dict) -> dict:
        # 控制台默认宽松（全段体检并标记）；?policy=strict 走取证口径，坏段即 409。
        policy = str(params.get("policy", "lenient"))
        return self._platform.verify_chain(policy)

    def _audit_chain(self, params: dict, body: dict) -> dict:
        # 轻量链状态：用最近一次校验结果（无则现场宽松扫一遍，不写审计）。
        journal = self._platform.audit.journal
        return {
            "checks": self._platform.audit.verification(),
            "heads": journal.chain_heads(),
            "missing_segments": journal.missing_indices(),
        }

    def _replay(self, params: dict, body: dict) -> dict:
        policy = str(params.get("policy", "lenient"))
        start = params.get("start_ts")
        end = params.get("end_ts")
        signals_param = params.get("signals")
        signals = None
        if signals_param:
            signals = [item.strip() for item in str(signals_param).split(",") if item.strip()]
        return self._platform.replay(
            policy=policy,
            start_ts=None if start is None else float(start),
            end_ts=None if end is None else float(end),
            signals=signals,
        )

    def _condition(self, params: dict, body: dict) -> dict:
        ts = float(params.get("ts", self._platform.clock.now()))
        return self._platform.working_condition(ts, policy=str(params.get("policy", "lenient")))

    def _fill_segments(self, params: dict, body: dict) -> dict:
        source = str(body.get("source_dir", "")).strip()
        if not source:
            raise PlantError("补段需要 source_dir（补段包目录）", component="console")
        return self._platform.fill_audit_segments(source)

    def _export_segment(self, params: dict, body: dict) -> dict:
        segment = int(body.get("segment", -1))
        dest = str(body.get("dest", "")).strip()
        if not dest:
            raise PlantError("导出补段包需要 dest（目标目录）", component="console")
        path = self._platform.export_audit_segment(segment, dest)
        return {"segment": segment, "bundle": path}

    def _store(self, params: dict, body: dict) -> dict:
        return {
            "root": self._platform.store.root,
            "documents": self._platform.store.list_ids(),
            "metrics": self._platform.metrics.summary(),
            "platform_state": self._platform.store.read("platform_state"),
        }

    def _readiness(self, params: dict, body: dict) -> dict:
        platform = self._platform
        checks = {
            "irradiance_durable": platform.field.durable_ready(platform.clock.now()),
            "flow_confirmed": platform.receiver.flow_confirmed(),
            "header_admitted": platform.receiver.header.state() == "admitted",
            "latch_clear": not platform.latch.latched(),
        }
        info = {
            "receiver_state": platform.receiver.state(),
            "temperature_c": round(platform.receiver.output_temperature_c(), 2),
            "net_flow_kg_s": round(platform.salt.flow_kg_s(), 3),
            "last_audit_ts": platform.audit.tail(1)[-1]["ts"] if platform.audit.tail(1) else None,
        }
        return {"ready": all(checks.values()), "checks": checks, "info": info}

    # ---- 动作 ---------------------------------------------------------

    def _track(self, params: dict, body: dict) -> dict:
        dni = _as_float(body, "dni_w_m2", self._platform.field.meter.current())
        minute = body.get("minute_of_day")
        return self._platform.track(dni, None if minute is None else float(minute))

    def _circulate(self, params: dict, body: dict) -> dict:
        target = body.get("target_flow_kg_s")
        return self._platform.circulate(None if target is None else float(target))

    def _cycle(self, params: dict, body: dict) -> dict:
        return self._platform.cycle(_as_float(body, "dt", 1.0))

    def _dispatch(self, params: dict, body: dict) -> dict:
        return self._platform.dispatch(_as_float(body, "pct", 0.0), str(body.get("writer", "console")))

    def _calibrate(self, params: dict, body: dict) -> dict:
        measured = _as_float(body, "measured_kg_s", self._platform.salt.limits.flow_baseline_kg_s)
        return self._platform.calibrate_flow(measured, str(body.get("operator", "console")))

    def _manual(self, params: dict, body: dict) -> dict:
        return self._platform.manual_aim(
            str(body.get("mirror", "m021")),
            _as_float(body, "azimuth_deg", 180.0),
            _as_float(body, "elevation_deg", 35.0),
            str(body.get("operator", "console")),
            None if body.get("hold_s") is None else float(body["hold_s"]),
        )

    def _manual_release(self, params: dict, body: dict) -> dict:
        return self._platform.release_manual(str(body.get("mirror", "m021")))

    def _wash(self, params: dict, body: dict) -> dict:
        mirrors = body.get("mirrors")
        batch = None if not mirrors else [str(item) for item in mirrors]
        return self._platform.wash(batch, str(body.get("zone", "maint-north")))

    def _trip(self, params: dict, body: dict) -> dict:
        return self._platform.trip(str(body.get("reason", "overtemperature")))

    def _reset(self, params: dict, body: dict) -> dict:
        return self._platform.reset_trip(str(body.get("operator", "shift-lead")))

    def _concurrency(self, params: dict, body: dict) -> dict:
        return self._platform.concurrency_probe(rounds=int(body.get("rounds", 24)))

    def _pump(self, params: dict, body: dict) -> dict:
        action = str(body.get("action", "cold_start"))
        salt = self._platform.salt
        if action == "cold_start":
            return {"action": action, "target_flow_kg_s": salt.start_cold()}
        if action == "cold_stop":
            return {"action": action, "target_flow_kg_s": salt.stop_cold()}
        if action == "hot_start":
            return {"action": action, "target_flow_kg_s": salt.start_hot()}
        if action == "hot_stop":
            return {"action": action, "target_flow_kg_s": salt.stop_hot()}
        raise PlantError(f"未知的泵操作: {action}", component="console")

    def _disturb(self, params: dict, body: dict) -> dict:
        kind = str(body.get("kind", "steam"))
        if kind == "salt":
            return self._platform.disturb_salt(_as_float(body, "value", 0.2))
        return self._platform.disturb_steam(_as_float(body, "value", 0.0))
