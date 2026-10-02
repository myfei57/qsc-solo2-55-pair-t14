"""控制台页面。

四个页面各自只读一份状态：镜场页看辐照与对焦、吸热器页看温度带与降额、熔盐页
看罐位与联锁门限、告警页看闩锁与升级等级。页面不做任何写操作，动作一律走
``/api/...`` 接口，避免浏览器刷新就把现场设备带动一次。
"""

from __future__ import annotations

from html import escape

from ..app import Platform

PAGE_PATHS: tuple[str, ...] = ("/", "/receiver", "/salt", "/alarms", "/audit")

_STYLE = """
body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: #0f1720; color: #e6edf3; }
header { padding: 14px 20px; background: #16202b; border-bottom: 1px solid #223041; }
nav a { color: #8ecdf7; margin-right: 14px; text-decoration: none; }
main { padding: 18px 20px 40px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 18px; }
th, td { border: 1px solid #223041; padding: 6px 10px; text-align: left; font-size: 14px; }
th { background: #17222e; }
.alarm { color: #ff8080; font-weight: 600; }
.ok { color: #7ee787; }
.warn { color: #f0c674; }
"""


def _table(title: str, rows: list[tuple[object, ...]]) -> str:
    """渲染一张表（首格作表头列，其余作数据列；支持任意列数）。"""

    body = "".join(
        "<tr>"
        + "".join(
            f"<th>{escape(str(cell))}</th>" if index == 0 else f"<td>{escape(str(cell))}</td>"
            for index, cell in enumerate(row)
        )
        + "</tr>"
        for row in rows
    )
    return f"<h2>{escape(title)}</h2><table>{body}</table>"


def _shell(title: str, body: str) -> str:
    """套上页头与导航。"""

    nav = "".join(
        f'<a href="{path}">{label}</a>'
        for path, label in (
            ("/", "镜场"),
            ("/receiver", "吸热器"),
            ("/salt", "熔盐"),
            ("/alarms", "告警"),
            ("/audit", "审计归档"),
        )
    )
    return (
        "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">"
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><header><strong>{escape(title)}</strong><nav style=\"margin-top:8px\">{nav}</nav>"
        f"</header><main>{body}</main></body></html>"
    )


def _mirror_page(platform: Platform) -> str:
    """镜场页：辐照、策略、对焦与调度。"""

    status = platform.status()["field"]
    rows = [
        ("运行模式", status["mode"]),
        ("判定依据", status["reason"]),
        ("当前辐照 (W/m²)", status["dni_w_m2"]),
        ("已落盘辐照 (W/m²)", status["durable_dni_w_m2"]),
        ("采样 / 拒绝 / 落盘次数", f"{status['samples']} / {status['rejected']} / {status['persists']}"),
        ("对焦镜数", f"{status['focusing']} / {status['mirrors']['count']}"),
        ("避让镜数", status["excluded"]),
        ("手动接管镜数", status["manual"]),
        ("执行负荷 (%)", status["dispatch_pct"]),
        ("调度目标 (%)", status["dispatch_target_pct"]),
        ("避让区挡下次数", status["zone_vetoes"]),
        ("清洗窗口数", status["windows"]),
        ("热功率 (kW)", round(platform.field.thermal_power_kw(), 1)),
    ]
    return _shell("镜场控制台", _table("镜场状态", rows))


def _receiver_page(platform: Platform) -> str:
    """吸热器页：温度带、流量门控与降额。"""

    snapshot = platform.status()["receiver"]
    report = platform.temperature_report()
    rows = [
        ("状态", snapshot["state"]),
        ("出口温度 (℃)", snapshot["temperature_c"]),
        ("峰值 (℃)", snapshot["peak_c"]),
        ("目标 / 降额 / 上限 (℃)", f"{report['target_c']} / {report['derate_c']} / {report['max_c']}"),
        ("距降额余量 (℃)", report["margin_to_derate_c"]),
        ("距上限余量 (℃)", report["margin_to_max_c"]),
        ("是否降额", "是" if snapshot["derated"] else "否"),
        ("出力上限 (%)", snapshot["ceiling_pct"]),
        ("进口阀开度 (%)", snapshot["valve_pct"]),
        ("流量 (kg/s)", snapshot["flow_kg_s"]),
        ("流量确认", "已确认" if snapshot["flow_confirmed"] else "未确认"),
        ("确认累计 (s)", snapshot["hold_s"]),
        ("跳闸原因", snapshot["trip_reason"] or "-"),
    ]
    return _shell("吸热器控制台", _table("吸热器状态", rows))


def _salt_page(platform: Platform) -> str:
    """熔盐页：罐位、泵与联锁门限。"""

    salt = platform.status()["salt"]
    rows = [
        ("冷盐罐液位 (%)", f"{salt['cold_tank']['level_pct']} ({salt['cold_tank']['level_kg']} kg)"),
        ("热盐罐液位 (%)", f"{salt['hot_tank']['level_pct']} ({salt['hot_tank']['level_kg']} kg)"),
        ("冷泵流量 (kg/s)", salt["cold_pump"]["flow_kg_s"]),
        ("热泵流量 (kg/s)", salt["hot_pump"]["flow_kg_s"]),
        ("母管净流量 (kg/s)", salt["net_flow_kg_s"]),
        ("母管压力 (MPa)", salt["header"]["pressure_mpa"]),
        ("在运泵数", salt["cold_pump"]["running"] + salt["hot_pump"]["running"]),
        ("两泵对顶步数", salt["opposed_steps"]),
        ("流量基线 (kg/s)", salt["baseline_kg_s"]),
        ("联锁门限 (kg/s)", salt["threshold_kg_s"]),
        ("标定代际", salt["epoch"]),
        ("成功切换次数", salt["changeovers"]),
    ]
    return _shell("熔盐控制台", _table("熔盐回路", rows))


def _alarm_page(platform: Platform) -> str:
    """告警页：闩锁、历史与升级等级。"""

    status = platform.status()
    alarm = status["alarm"]
    rows = [
        ("闩锁状态", "已置位" if alarm["latched"] else "已复位"),
        ("跳闸来源", alarm["source"] or "-"),
        ("跳闸原因", alarm["reason"] or "-"),
        ("累计置位", alarm["trips"]),
        ("告警条数", alarm["history"]),
        ("按规则计数", alarm["by_rule"] or "-"),
    ]
    body = _table("闩锁与统计", rows)
    level_rows = [(item["rule"], f"{item['name']}（{item['occurrences']} 次）") for item in status["levels"]]
    body += _table("升级等级", level_rows)
    recent = platform.history.recent(12)
    recent_rows = [
        (f"{entry['ts']}", f"{entry['rule']} {entry['message']} = {entry['value']}") for entry in recent
    ] or [("暂无", "-")]
    body += _table("最近告警", recent_rows)
    body += _table("规则表", [(item["name"], f"{item['signal']} {'≥' if item['above'] else '≤'} {item['threshold']}") for item in platform.rules.describe()])
    return _shell("告警控制台", body)


_STATUS_LABEL = {
    "ok": "完好",
    "unsealed": "写入中",
    "altered": "被篡改",
    "broken_link": "链接断开",
    "time_disorder": "时序错乱",
    "missing": "缺失",
    "gap": "缺段占位",
    "legacy": "旧段",
}


def _audit_page(platform: Platform) -> str:
    """审计归档页：跨段哈希链状态与同轴回放工况帧。"""

    verification = platform.verify_archives()
    chain = verification["audit"]
    rows = [
        ("审计链是否完好", "是" if chain["healthy"] else "否（见下段明细）"),
        ("缺段", chain["missing"] or "-"),
        ("被改/断链/乱序段", chain["altered"] or "-"),
        ("缺段占位段", chain["gaps"] or "-"),
        (
            "可信根",
            "-"
            if chain["anchor"] is None
            else f"尾段 {chain['anchor']['tail_seq']}（{chain['anchor']['tail_digest'][:12]}…）",
        ),
    ]
    body = _table("审计跨段校验", rows)

    seg_rows = [
        (
            seg["seq"],
            _STATUS_LABEL.get(seg["status"], seg["status"]),
            seg["count"],
            seg["detail"] or "-",
        )
        for seg in chain["segments"]
    ] or [("-", "暂无段", 0, "-")]
    body += _table("分段明细（段号 / 状态 / 条数 / 说明）", seg_rows)

    # 同轴回放（marked：问题段标记后部分读），还原最近工况帧；页面轮询不落审计。
    replay = platform.replay_plant(policy="marked", audit=False)
    head_rows = [
        ("回放口径", "同轴对齐（审计与趋势同一时间轴）"),
        ("是否完整", "是" if replay["complete"] else "否（存在缺口或不可信段）"),
        ("审计事件 / 趋势采样 / 工况帧", f"{replay['counts']['audit']} / {replay['counts']['trend']} / {replay['counts']['frames']}"),
        ("跳过的审计段", [seg["seq"] for seg in replay["integrity"]["audit_skipped"]] or "-"),
    ]
    body += _table("同轴回放（marked 部分读）", head_rows)

    frame_rows: list[tuple[str, object]] = []
    for frame in replay["frames"][-12:]:
        actions = "；".join(
            f"{item['component']}.{item['action']}" for item in frame["audit"]
        ) or "-"
        trend = "，".join(f"{key}={value}" for key, value in sorted(frame["trend"].items())) or "-"
        frame_rows.append((frame["ts"], actions, trend))
    if not frame_rows:
        frame_rows = [("-", "暂无可回放内容", "-")]
    body += _table("最近工况帧（时间 / 处置 / 当时趋势）", frame_rows)
    return _shell("审计归档与回放", body)


_RENDERERS = {
    "/": _mirror_page,
    "/receiver": _receiver_page,
    "/salt": _salt_page,
    "/alarms": _alarm_page,
    "/audit": _audit_page,
}


def render_page(path: str, platform: Platform) -> str | None:
    """渲染一个页面；路径不是页面时返回 ``None``。"""

    renderer = _RENDERERS.get(path)
    if renderer is None:
        return None
    return renderer(platform)
