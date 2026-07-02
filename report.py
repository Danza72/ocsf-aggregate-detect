#!/usr/bin/env python3
"""
report.py
Generates a styled HTML report from risk_scores.json, baselines.json,
and incident_profiles.json.
Open the output HTML in a browser and print to PDF (Ctrl+P → Save as PDF).
"""

import json
import html
from pathlib import Path
from datetime import datetime, timezone

SCORES_FILE   = Path("risk_scores.json")
BASELINE_FILE = Path("baselines.json")
PROFILES_FILE = Path("incident_profiles.json")
OUTPUT        = Path("risk_report.html")

INCIDENT_DATE      = "2018-08-20"
ACCOUNT_ID         = "622676721278"
DATE_RANGE_START   = None   # set by runner when analysing a date range
DATE_RANGE_END     = None   # set by runner when analysing a date range
RANGE_DATES        = []     # ordered list of all dates in the range
OUT_DIR            = None   # output directory path for loading daily files
EXFIL_FILE         = None   # path to exfil_alerts.csv produced by detect_low_slow_exfil
SESSION_FILE       = None   # path to top_risky_sessions.csv produced by session detection

CT_DIMS  = ["new_operation", "new_resource", "new_region",
            "volume_zscore", "new_ip_known_region", "low_frequency_hour"]
S3_DIMS  = ["new_operation", "new_bucket", "new_src_ip",
            "error_rate", "bytes_zscore", "event_zscore"]
VPC_DIMS = ["new_dst_ip", "new_dst_port", "reject_ratio",
            "bytes_zscore", "flow_zscore", "new_protocol"]


# ── Helpers ────────────────────────────────────────────────────────────────

def _score_color(score: float) -> str:
    if score >= 0.7: return "#c0392b"
    if score >= 0.4: return "#e67e22"
    if score >= 0.2: return "#f1c40f"
    return "#27ae60"


def _score_badge(score: float | None) -> str:
    if score is None:
        return '<span class="badge badge-na">—</span>'
    color = _score_color(score)
    return f'<span class="badge" style="background:{color}">{score:.4f}</span>'


def _dim_bar(val: float) -> str:
    color = _score_color(val)
    pct   = int(val * 100)
    return (
        f'<div class="bar-wrap">'
        f'<div class="bar" style="width:{pct}%;background:{color}"></div>'
        f'<span class="bar-label">{val:.2f}</span>'
        f'</div>'
    )


def _dim_table(dims: dict, dim_names: list) -> str:
    if not dims:
        return "<p class='na'>No data</p>"
    rows = ""
    for d in dim_names:
        val  = dims.get(d, 0.0)
        rows += f"<tr><td class='dim-name'>{d}</td><td>{_dim_bar(val)}</td></tr>"
    return f'<table class="dim-table"><tbody>{rows}</tbody></table>'


def _has_any_baseline(r: dict) -> bool:
    if r.get("cloudtrail"):
        return True
    if r.get("s3")  and r["s3"].get("has_baseline"):
        return True
    if r.get("vpc") and r["vpc"].get("has_baseline"):
        return True
    return False


def _actor_tag(name: str, r: dict) -> str:
    if r.get("is_system_actor"):
        return '<span class="tag tag-system">SYSTEM</span>'
    if name.startswith("eni-"):
        return '<span class="tag tag-eni">ENI</span>'
    if not _has_any_baseline(r):
        return '<span class="tag tag-new">NEW</span>'
    return '<span class="tag tag-human">HUMAN</span>'


def _pill_list(items: list, highlight: set = None) -> str:
    if not items:
        return "<span class='na'>none</span>"
    pills = ""
    for item in items:
        cls = "pill pill-new" if highlight and item in highlight else "pill"
        pills += f'<span class="{cls}">{item}</span>'
    return f'<div class="pill-wrap">{pills}</div>'


def _kv(label: str, value) -> str:
    return f'<div class="kv"><span class="kv-label">{label}</span><span class="kv-value">{value}</span></div>'


def _hour_grid(bl_hours: dict, inc_hours) -> str:
    """24-cell activity grid showing baseline vs incident hour overlap."""
    # Normalise keys to int regardless of whether stored as str or int
    bl  = {int(k): v for k, v in (bl_hours or {}).items()}
    if isinstance(inc_hours, dict):
        inc = {int(k) for k in inc_hours}
    else:
        inc = {int(h) for h in (inc_hours or [])}

    max_count = max(bl.values(), default=1)

    cells = ""
    for h in range(24):
        in_bl  = h in bl
        in_inc = h in inc

        if in_bl and in_inc:
            color  = "#27ae60"
            title  = f"{h:02d}:00 — baseline + incident (normal)"
        elif in_inc:
            color  = "#c0392b"
            title  = f"{h:02d}:00 — incident only (not in baseline)"
        elif in_bl:
            # Shade grey by relative frequency
            shade  = int(180 + 60 * (1 - bl[h] / max_count))
            color  = f"rgb({shade},{shade},{shade})"
            title  = f"{h:02d}:00 — baseline only ({bl[h]} events)"
        else:
            color  = "#f0f4f8"
            title  = f"{h:02d}:00 — inactive"

        # Label every 6 hours (0, 6, 12, 18)
        lbl = f'<span class="hlbl">{h}</span>' if h % 6 == 0 else ""
        cells += f'<div class="hcell" style="background:{color}" title="{title}">{lbl}</div>'

    legend = (
        '<div class="hour-legend">'
        '<span class="hl"><span class="hlbox" style="background:#bdc3c7"></span>Baseline only</span>'
        '<span class="hl"><span class="hlbox" style="background:#27ae60"></span>Both (normal)</span>'
        '<span class="hl"><span class="hlbox" style="background:#c0392b"></span>Incident only</span>'
        '</div>'
    )
    return f'<div class="hour-grid">{cells}</div>{legend}'


def _vol_cmp(label: str, bl_mean: float, bl_std: float,
             incident_val: int | float, unit: str = "") -> str:
    """Single row showing baseline mean vs incident value with a multiplier."""
    if bl_mean > 0:
        mult   = incident_val / bl_mean
        z      = (incident_val - bl_mean) / bl_std if bl_std > 0 else 0.0
        color  = "#c0392b" if mult >= 3 or z >= 2 else \
                 "#e67e22" if mult >= 1.5 or z >= 1 else "#27ae60"
        mult_s = f'<span style="color:{color};font-weight:600">{mult:.1f}× baseline</span>'
    else:
        mult_s = '<span style="color:#aaa">—</span>'

    bl_s  = f'{bl_mean:,.0f}{unit} ± {bl_std:,.0f}{unit}/day'
    inc_s = f'{incident_val:,.0f}{unit} on incident day'
    return (
        f'<div class="kv vol-cmp">'
        f'<span class="kv-label">{label}</span>'
        f'<span class="kv-value">'
        f'<span class="vol-bl">baseline avg: {bl_s}</span>'
        f'<span class="vol-sep"> → </span>'
        f'<span class="vol-inc">{inc_s}</span> '
        f'{mult_s}'
        f'</span></div>'
    )


# ── Evidence sections ──────────────────────────────────────────────────────

def _ct_evidence(bl_ct: dict | None, inc_ct: dict | None) -> str:
    if not bl_ct and not inc_ct:
        return ""

    bl_ops  = set(bl_ct.get("known_operations", {}).keys()) if bl_ct else set()
    bl_ips  = set(bl_ct.get("known_ips", []))               if bl_ct else set()
    bl_regs = set(bl_ct.get("known_regions", []))           if bl_ct else set()
    bl_res  = set(bl_ct.get("known_resources", []))         if bl_ct else set()

    inc_ops  = set(inc_ct.get("known_operations", []))              if inc_ct else set()
    inc_ips  = {e["ip"] for e in inc_ct.get("known_ips", [])}      if inc_ct else set()
    inc_regs = set(inc_ct.get("known_regions", []))                 if inc_ct else set()
    inc_res  = set(inc_ct.get("known_resources", []))               if inc_ct else set()

    new_ops  = inc_ops  - bl_ops
    new_ips  = inc_ips  - bl_ips
    new_regs = inc_regs - bl_regs
    new_res  = inc_res  - bl_res

    html = ""

    # Volume comparison row (spans full width before the two-column split)
    if bl_ct and inc_ct:
        de         = bl_ct.get("daily_events", {})
        inc_events = inc_ct.get("event_count", 0)
        html += _vol_cmp("Events / day",
                         de.get("mean", 0), de.get("std", 0),
                         inc_events)

    # Hour-of-day activity grid
    if bl_ct or inc_ct:
        bl_hours  = bl_ct.get("known_hours", {})  if bl_ct  else {}
        inc_hours = inc_ct.get("known_hours", [])  if inc_ct else []
        html += '<div class="kv"><span class="kv-label">Activity hours</span>'
        html += f'<span class="kv-value">{_hour_grid(bl_hours, inc_hours)}</span></div>'

    html += '<div class="evidence-grid">'

    # Baseline column
    html += '<div class="ev-col">'
    html += '<h5>Baseline (normal behaviour)</h5>'
    if bl_ct:
        html += _kv("Known IPs",        _pill_list(sorted(bl_ips)))
        html += _kv("Known regions",    _pill_list(sorted(bl_regs)))
        html += _kv("Known operations", _pill_list(sorted(bl_ops)))
        html += _kv("Known resources",  _pill_list(sorted(bl_res)))
    else:
        html += "<p class='na'>No CT baseline</p>"
    html += '</div>'

    # Incident column
    html += '<div class="ev-col">'
    html += f'<h5>Incident day ({INCIDENT_DATE})</h5>'
    if inc_ct:
        html += _kv("Source IPs",  _pill_list(sorted(inc_ips),  new_ips))
        html += _kv("Regions",     _pill_list(sorted(inc_regs), new_regs))
        html += _kv("Operations",  _pill_list(sorted(inc_ops),  new_ops))
        html += _kv("Resources",   _pill_list(sorted(inc_res),  new_res))
        if new_ops or new_ips or new_regs or new_res:
            html += '<p class="new-note">🔴 Red pills = new (not in baseline)</p>'
    else:
        html += "<p class='na'>No CT incident data</p>"
    html += '</div>'

    html += '</div>'
    return html


def _s3_evidence(bl_s3: dict | None, inc_s3: dict | None) -> str:
    if not bl_s3 and not inc_s3:
        return ""

    bl_ops  = set(bl_s3.get("known_operations", [])) if bl_s3 else set()
    bl_bkts = set(bl_s3.get("known_buckets",    [])) if bl_s3 else set()
    bl_ips  = set(bl_s3.get("known_ips",        [])) if bl_s3 else set()

    inc_ops  = set(inc_s3.get("known_operations", [])) if inc_s3 else set()
    inc_bkts = set(inc_s3.get("known_buckets",    [])) if inc_s3 else set()
    inc_ips  = {e["ip"] for e in inc_s3.get("known_ips", [])} if inc_s3 else set()

    new_ops  = inc_ops  - bl_ops
    new_bkts = inc_bkts - bl_bkts
    new_ips  = inc_ips  - bl_ips

    html = ""

    # Volume comparison rows (full width)
    if bl_s3 and inc_s3:
        de = bl_s3.get("daily_events", {})
        db = bl_s3.get("daily_bytes",  {})
        html += _vol_cmp("Events / day",
                         de.get("mean", 0), de.get("std", 0),
                         inc_s3.get("event_count", 0))
        html += _vol_cmp("Bytes / day",
                         db.get("mean", 0), db.get("std", 0),
                         inc_s3.get("bytes_total", 0))

    html += '<div class="evidence-grid">'

    html += '<div class="ev-col">'
    html += '<h5>Baseline (normal behaviour)</h5>'
    if bl_s3:
        html += _kv("Known operations", _pill_list(sorted(bl_ops)))
        html += _kv("Known buckets",    _pill_list(sorted(bl_bkts)))
        html += _kv("Known IPs",        _pill_list(sorted(bl_ips)))
    else:
        html += "<p class='na'>No S3 baseline</p>"
    html += '</div>'

    html += '<div class="ev-col">'
    html += f'<h5>Incident day ({INCIDENT_DATE})</h5>'
    if inc_s3:
        bmax = inc_s3.get("bytes_max_single", {})
        html += _kv("Largest request",  f'{bmax.get("bytes", 0):,} bytes at {bmax.get("time", "—")}')
        html += _kv("Response codes",   str(inc_s3.get("response_codes", {})))
        html += _kv("Operations", _pill_list(sorted(inc_ops),  new_ops))
        html += _kv("Buckets",    _pill_list(sorted(inc_bkts), new_bkts))
        html += _kv("Source IPs", _pill_list(sorted(inc_ips),  new_ips))
        if new_ops or new_bkts or new_ips:
            html += '<p class="new-note">🔴 Red pills = new (not in baseline)</p>'
    else:
        html += "<p class='na'>No S3 incident data</p>"
    html += '</div>'

    html += '</div>'
    return html


def _vpc_evidence(bl_vpc: dict | None, inc_vpc: dict | None) -> str:
    if not bl_vpc and not inc_vpc:
        return ""

    bl_conns = set(bl_vpc.get("known_dst_conns", [])) if bl_vpc else set()
    bl_proto = set(bl_vpc.get("known_protocols", [])) if bl_vpc else set()

    inc_conns = set((inc_vpc.get("dst_conns") or {}).keys()) if inc_vpc else set()
    inc_proto = set(inc_vpc.get("protocols", []))             if inc_vpc else set()

    new_conns = inc_conns - bl_conns
    new_proto = inc_proto - bl_proto

    html = ""

    # Volume comparison rows (full width)
    if bl_vpc and inc_vpc:
        df = bl_vpc.get("daily_flows", {})
        db = bl_vpc.get("daily_bytes", {})
        html += _vol_cmp("Flows / day",
                         df.get("mean", 0), df.get("std", 0),
                         inc_vpc.get("event_count", 0))
        html += _vol_cmp("Bytes / day",
                         db.get("mean", 0), db.get("std", 0),
                         inc_vpc.get("bytes_total", 0))

    html += '<div class="evidence-grid">'

    html += '<div class="ev-col">'
    html += '<h5>Baseline (normal behaviour)</h5>'
    if bl_vpc:
        html += _kv("Known connections", _pill_list(sorted(bl_conns)))
        html += _kv("Known protocols",   _pill_list([str(p) for p in sorted(bl_proto)]))
    else:
        html += "<p class='na'>No VPC baseline</p>"
    html += '</div>'

    html += '<div class="ev-col">'
    html += f'<h5>Incident day ({INCIDENT_DATE})</h5>'
    if inc_vpc:
        bmax = inc_vpc.get("bytes_max_single", {})
        html += _kv("Largest flow", f'{bmax.get("bytes", 0):,} bytes at {bmax.get("time", "—")}')
        html += _kv("Actions",      str(inc_vpc.get("actions", {})))
        html += _kv("Active",       f'{inc_vpc.get("first_seen", "—")} → {inc_vpc.get("last_seen", "—")}')
        html += _kv("Connections", _pill_list(sorted(inc_conns), new_conns))
        html += _kv("Protocols",   _pill_list([str(p) for p in sorted(inc_proto)],
                                              {str(p) for p in new_proto}))
        if new_conns or new_proto:
            html += '<p class="new-note">🔴 Red pills = new (not in baseline)</p>'
    else:
        html += "<p class='na'>No VPC incident data</p>"
    html += '</div>'

    html += '</div>'
    return html


# ── Actor card ─────────────────────────────────────────────────────────────

def _actor_section(name: str, r: dict,
                   baselines: dict, profiles: dict) -> str:
    ct  = r.get("cloudtrail")
    s3  = r.get("s3")
    vpc = r.get("vpc")

    tag   = _actor_tag(name, r)
    final = _score_badge(r["final_score"])
    srcs  = "+".join(r.get("sources_used", []))

    ct_badge  = _score_badge(ct["score"]  if ct  else None)
    s3_badge  = _score_badge(s3["score"]  if s3  else None)
    vpc_badge = _score_badge(vpc["score"] if vpc else None)

    # Dimension bars
    dim_cols = ""
    if ct:
        dim_cols += f'<div class="src-col"><h4>CloudTrail dimensions</h4>{_dim_table(ct.get("dimensions",{}), CT_DIMS)}</div>'
    if s3:
        bl_lbl = "✓ baseline" if s3.get("has_baseline") else "✗ no baseline"
        dim_cols += f'<div class="src-col"><h4>S3 dimensions <small>{bl_lbl}</small></h4>{_dim_table(s3.get("dimensions",{}), S3_DIMS)}</div>'
    if vpc:
        bl_lbl = "✓ baseline" if vpc.get("has_baseline") else "✗ no baseline"
        dim_cols += f'<div class="src-col"><h4>VPC dimensions <small>{bl_lbl}</small></h4>{_dim_table(vpc.get("dimensions",{}), VPC_DIMS)}</div>'

    # Evidence from baselines.json + incident_profiles.json
    bl_ct  = baselines.get("cloudtrail", {}).get(name)
    bl_s3  = baselines.get("s3",         {}).get(name)
    bl_vpc = baselines.get("vpc",        {}).get(name)

    prof     = profiles.get(name, {})
    inc_ct   = prof.get("cloudtrail")
    inc_s3   = prof.get("s3")
    inc_vpc  = prof.get("vpc")

    ct_ev  = _ct_evidence(bl_ct,  inc_ct)
    s3_ev  = _s3_evidence(bl_s3,  inc_s3)
    vpc_ev = _vpc_evidence(bl_vpc, inc_vpc)

    evidence = ""
    if ct_ev:
        evidence += f'<div class="ev-section"><h4>CloudTrail — Baseline vs Incident</h4>{ct_ev}</div>'
    if s3_ev:
        evidence += f'<div class="ev-section"><h4>S3 — Baseline vs Incident</h4>{s3_ev}</div>'
    if vpc_ev:
        evidence += f'<div class="ev-section"><h4>VPC — Baseline vs Incident</h4>{vpc_ev}</div>'

    has_baseline = _has_any_baseline(r)
    if has_baseline:
        score_area = f"""
          <span class="src-label">CT</span>{ct_badge}
          <span class="src-label">S3</span>{s3_badge}
          <span class="src-label">VPC</span>{vpc_badge}
          <span class="src-label final-label">FINAL</span>{final}
          <span class="sources">{srcs}</span>"""
    else:
        score_area = f"""
          <span class="badge" style="background:#7f8c8d">NO BASELINE — INVESTIGATE</span>
          <span class="sources">{srcs}</span>"""

    return f"""
    <div class="actor-card">
      <div class="actor-header">
        <div class="actor-name">{tag} <span class="name">{name}</span></div>
        <div class="actor-scores">{score_area}</div>
      </div>
      <div class="src-grid">{dim_cols}</div>
      {evidence}
    </div>
    """


# ── Shared CSS ─────────────────────────────────────────────────────────────

def _html_css() -> str:
    return """
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          font-size: 13px; color: #2c3e50; background: #f5f6fa; padding: 32px; }
  h1   { font-size: 22px; margin-bottom: 4px; }
  h2   { font-size: 16px; margin: 32px 0 12px; border-bottom: 2px solid #dde; padding-bottom: 6px; }
  h4   { font-size: 12px; margin: 10px 0 6px; color: #444; font-weight: 600; }
  h5   { font-size: 11px; margin-bottom: 8px; color: #666; font-weight: 600;
           text-transform: uppercase; letter-spacing: 0.5px; }
  small { font-weight: normal; color: #888; }
  .meta { color: #777; font-size: 12px; margin-bottom: 12px; }
  .threshold-legend { display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
                       margin-bottom: 24px; font-size: 11px; }
  .legend-label { color: #555; font-weight: 600; margin-right: 4px; }
  .legend-item { padding: 3px 10px; border-radius: 4px; color: #fff;
                  font-weight: 600; letter-spacing: 0.3px; }
  .na { color: #aaa; font-size: 11px; font-style: italic; }
  .summary-table { width: 100%; border-collapse: collapse; margin-bottom: 8px; }
  .summary-table th { background: #2c3e50; color: #fff; padding: 8px 10px;
                       text-align: left; font-size: 12px; }
  .summary-table td { padding: 7px 10px; border-bottom: 1px solid #eee; }
  .summary-table tr:hover td { background: #f0f4ff; }
  .score-cell { text-align: center; }
  .subtitle { font-size: 12px; color: #888; margin-bottom: 10px; }
  .actor-card { background: #fff; border-radius: 8px; margin-bottom: 20px;
                 box-shadow: 0 1px 4px rgba(0,0,0,0.08); overflow: hidden; }
  .actor-header { display: flex; justify-content: space-between; align-items: center;
                   padding: 12px 16px; background: #2c3e50; color: #fff;
                   flex-wrap: wrap; gap: 8px; }
  .actor-name { font-size: 14px; font-weight: 600; }
  .name { margin-left: 6px; }
  .actor-scores { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .src-label { font-size: 11px; color: #aaa; }
  .final-label { color: #fff; font-weight: 600; }
  .sources { font-size: 11px; color: #7f8c8d; margin-left: 8px; }
  .src-grid { display: flex; border-bottom: 1px solid #eee; }
  .src-col  { flex: 1; padding: 12px 16px; border-right: 1px solid #eee; }
  .src-col:last-child { border-right: none; }
  .dim-table { width: 100%; border-collapse: collapse; }
  .dim-table td { padding: 3px 4px; font-size: 11px; vertical-align: middle; }
  .dim-name { width: 160px; color: #555; white-space: nowrap; }
  .bar-wrap  { display: flex; align-items: center; gap: 6px; }
  .bar       { height: 10px; border-radius: 3px; min-width: 2px; }
  .bar-label { font-size: 11px; color: #555; min-width: 32px; }
  .vol-cmp { background: #f8f9fa; border-radius: 4px; margin-bottom: 6px; padding: 4px 6px; }
  .vol-bl  { color: #888; }
  .vol-sep { color: #bbb; margin: 0 2px; }
  .vol-inc { color: #2c3e50; font-weight: 500; }
  .hour-grid  { display: flex; gap: 2px; margin: 6px 0 4px; }
  .hcell      { width: 22px; height: 26px; border-radius: 2px; display: flex;
                 align-items: flex-end; justify-content: center; cursor: default; }
  .hlbl       { font-size: 8px; color: rgba(0,0,0,0.45); padding-bottom: 2px; }
  .hour-legend { display: flex; gap: 12px; margin-top: 3px; }
  .hl   { display: flex; align-items: center; gap: 4px; font-size: 10px; color: #666; }
  .hlbox { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
  .ev-section { padding: 12px 16px; border-bottom: 1px solid #f0f0f0; }
  .ev-section:last-child { border-bottom: none; }
  .evidence-grid { display: flex; gap: 16px; margin-top: 8px; }
  .ev-col { flex: 1; }
  .kv { display: flex; gap: 8px; margin-bottom: 5px; align-items: flex-start; }
  .kv-label { font-size: 11px; color: #888; min-width: 170px; flex-shrink: 0; }
  .kv-value { font-size: 11px; color: #2c3e50; }
  .pill-wrap { display: flex; flex-wrap: wrap; gap: 3px; }
  .pill { display: inline-block; padding: 1px 6px; border-radius: 3px;
           font-size: 10px; background: #e8f4fd; color: #2980b9; }
  .pill-new { background: #fde8e8; color: #c0392b; font-weight: 600; }
  .new-note { font-size: 10px; color: #c0392b; margin-top: 6px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
            color: #fff; font-size: 12px; font-weight: 600;
            min-width: 60px; text-align: center; }
  .badge-na { background: #bdc3c7; }
  .tag { display: inline-block; padding: 1px 6px; border-radius: 3px;
          font-size: 10px; font-weight: 700; letter-spacing: 0.5px; }
  .tag-human  { background: #3498db; color: #fff; }
  .tag-system { background: #8e44ad; color: #fff; }
  .tag-eni    { background: #e67e22; color: #fff; }
  .tag-new    { background: #c0392b; color: #fff; }
  section { margin-bottom: 24px; }
  /* Tabs */
  .tabs { display: flex; gap: 4px; margin: 20px 0 0; flex-wrap: wrap;
          border-bottom: 2px solid #dde; }
  .tab-btn { padding: 8px 16px; border: none; background: #e8ecf0; cursor: pointer;
              border-radius: 6px 6px 0 0; font-size: 12px; color: #555;
              font-weight: 500; border-bottom: 2px solid transparent;
              margin-bottom: -2px; }
  .tab-btn:hover { background: #d0d8e4; }
  .tab-btn.active { background: #2c3e50; color: #fff; border-bottom-color: #2c3e50; }
  .tab-label { padding: 8px 10px 8px 14px; font-size: 11px; font-weight: 700;
               color: #95a5a6; text-transform: uppercase; letter-spacing: 0.6px;
               align-self: flex-end; border-left: 2px solid #dde; margin-left: 6px; }
  .tab-pane { display: none; padding-top: 8px; }
  .tab-pane.active { display: block; }
  @media print {
    body { background: #fff; padding: 16px; }
    .actor-card { break-inside: avoid; box-shadow: none; border: 1px solid #ddd; }
    h2 { break-before: auto; }
  }
"""


def _legend_html() -> str:
    return """<div class="threshold-legend">
  <span class="legend-label">Score thresholds:</span>
  <span class="legend-item" style="background:#27ae60">&#9632; Green &lt; 0.20 — Normal</span>
  <span class="legend-item" style="background:#f1c40f;color:#333">&#9632; Yellow 0.20–0.39 — Low concern, monitor</span>
  <span class="legend-item" style="background:#e67e22">&#9632; Orange 0.40–0.69 — Suspicious, investigate</span>
  <span class="legend-item" style="background:#c0392b">&#9632; Red &#x2265; 0.70 — High risk, escalate</span>
</div>"""


# ── Range: tabbed report helpers ───────────────────────────────────────────

def _score_trend_html(range_dates: list, all_scores: dict) -> str:
    available = [d for d in range_dates if d in all_scores]
    if not available:
        return ""

    all_actors: set = set()
    for s in all_scores.values():
        all_actors.update(s.keys())

    peak = {a: max((all_scores[d][a]["final_score"]
                    for d in available if a in all_scores.get(d, {})),
                   default=0.0)
            for a in all_actors}

    sorted_actors = sorted(all_actors, key=lambda a: -peak[a])
    short = [d[5:] for d in available]
    date_headers = "".join(f'<th style="text-align:center">{s}</th>' for s in short)

    rows = ""
    for actor in sorted_actors:
        cells = ""
        for d in available:
            r = all_scores.get(d, {}).get(actor)
            badge = (_score_badge(r["final_score"]) if r
                     else '<span class="badge badge-na">—</span>')
            cells += f"<td class='score-cell'>{badge}</td>"
        rows += (f"<tr><td>{actor}</td>{cells}"
                 f"<td class='score-cell'>{_score_badge(peak[actor])}</td></tr>")

    return f"""
    <section>
      <h2>Score Trend</h2>
      <p class="subtitle">Daily scores for each actor — ranked by peak score.</p>
      <div style="overflow-x:auto">
      <table class="summary-table">
        <thead><tr><th>Actor</th>{date_headers}<th style="text-align:center">Peak</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      </div>
    </section>
    """


def _peak_day_signals_html(range_dates: list, all_scores: dict) -> str:
    available = [d for d in range_dates if d in all_scores]
    if not available:
        return ""

    all_actors: set = set()
    for s in all_scores.values():
        all_actors.update(s.keys())

    # Find each actor's peak day
    actor_peak: dict = {}
    for actor in all_actors:
        best = max(
            ((d, all_scores[d][actor]) for d in available if actor in all_scores.get(d, {})),
            key=lambda x: x[1]["final_score"],
            default=None,
        )
        if best:
            actor_peak[actor] = {"day": best[0], "score": best[1]["final_score"], "data": best[1]}

    if not actor_peak:
        return ""

    def _dim_pill(name: str, value: float) -> str:
        return (f'<span class="pill" style="background:#eaecee;color:#2c3e50;font-weight:500">'
                f'{name}<small style="font-size:9px;color:#888"> {value:.0%}</small></span>')

    def _src_pills(src: dict) -> str:
        if not src:
            return '<span style="color:#bbb">—</span>'
        fired = {k: v for k, v in (src.get("dimensions") or {}).items() if v > 0}
        if not fired:
            return '<span style="color:#bbb">—</span>'
        return '<div class="pill-wrap">' + "".join(
            _dim_pill(k, v) for k, v in sorted(fired.items(), key=lambda x: -x[1])
        ) + '</div>'

    _SEP   = "border-right:3px solid #c8d0da"
    _SRC   = "background:#34495e;text-align:center;font-weight:600;letter-spacing:0.5px"
    _SRC_B = f"background:#34495e;text-align:center;font-weight:600;letter-spacing:0.5px;border-right:3px solid #c8d0da"

    sorted_actors = sorted(actor_peak.keys(), key=lambda a: -actor_peak[a]["score"])
    rows = ""
    for actor in sorted_actors:
        info  = actor_peak[actor]
        d     = info["data"]
        short = info["day"][5:]
        rows += (f'<tr>'
                 f'<td style="{_SEP}"><strong>{actor}</strong></td>'
                 f'<td class="score-cell" style="{_SEP};vertical-align:middle">'
                 f'{_score_badge(info["score"])}'
                 f'<br><small style="color:#aaa;font-size:10px">({short})</small></td>'
                 f'<td style="{_SEP}">{_src_pills(d.get("cloudtrail"))}</td>'
                 f'<td style="{_SEP}">{_src_pills(d.get("s3"))}</td>'
                 f'<td>{_src_pills(d.get("vpc"))}</td>'
                 f'</tr>')

    return f"""
    <section>
      <h2>Peak Day Signals</h2>
      <p class="subtitle">Dimensions that fired on each actor's highest-scoring day.</p>
      <div style="overflow-x:auto">
      <table class="summary-table">
        <thead>
          <tr>
            <th rowspan="2" style="vertical-align:bottom;{_SEP}">Actor</th>
            <th rowspan="2" style="vertical-align:bottom;text-align:center;{_SEP}">Peak Score</th>
            <th style="{_SRC_B}">CloudTrail</th>
            <th style="{_SRC_B}">S3</th>
            <th style="{_SRC}">VPC</th>
          </tr>
          <tr>
            <th style="{_SEP};text-align:center">Dimensions</th>
            <th style="{_SEP};text-align:center">Dimensions</th>
            <th style="text-align:center">Dimensions</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      </div>
    </section>
    """


def _notable_anomalies_html(range_dates: list, all_profiles: dict,
                             all_scores: dict, baselines: dict) -> str:
    actor_data: dict = {}

    for d in range_dates:
        if d not in all_profiles:
            continue
        short = d[5:]
        for actor, p in all_profiles[d].items():
            if actor not in actor_data:
                actor_data[actor] = {"op": {}, "res": {}, "bkt": {}, "conn": {}}
            ad = actor_data[actor]

            ct = p.get("cloudtrail") or {}
            for op  in ct.get("known_operations", []):
                if op  not in ad["op"]:  ad["op"][op]   = short
            for res in ct.get("known_resources",  []):
                if res not in ad["res"]: ad["res"][res]  = short

            s3 = p.get("s3") or {}
            for b in s3.get("known_buckets", []):
                if b not in ad["bkt"]: ad["bkt"][b] = short

            vpc = p.get("vpc") or {}
            for conn in (vpc.get("dst_conns") or {}).keys():
                if conn not in ad["conn"]: ad["conn"][conn] = short

    if not actor_data:
        return ""

    peak = {a: max((all_scores[d][a]["final_score"]
                    for d in range_dates
                    if d in all_scores and a in all_scores.get(d, {})),
                   default=0.0)
            for a in actor_data}
    sorted_actors = sorted(actor_data.keys(), key=lambda a: -peak.get(a, 0))

    def _baseline_set(actor: str, source: str, key: str) -> set:
        bl = (baselines.get(source) or {}).get(actor) or {}
        items = bl.get(key, [])
        if isinstance(items, dict):
            return {str(k) for k in items.keys()}
        if items and isinstance(items[0], dict):
            return {e.get("ip", "") for e in items}
        return set(items)

    _DASH = '<span style="color:#bbb">—</span>'
    _SEP  = "border-right:3px solid #c8d0da"
    _CTH  = f"text-align:center;{_SEP}"
    _S3H  = f"text-align:center;{_SEP}"
    _VPCH = "text-align:center"

    def _pill(label: str, date: str) -> str:
        truncated = label if len(label) <= 32 else label[:30] + "…"
        return (f'<span class="pill pill-new" title="{label}" '
                f'style="display:inline-flex;flex-direction:column;line-height:1.5;'
                f'max-width:220px;padding:3px 7px;margin:2px 2px">'
                f'<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{truncated}</span>'
                f'<small style="font-size:9px;opacity:0.7;margin-top:1px">{date}</small></span>')

    def _new_pills(d: dict, bl_set: set, prefix: str = "") -> str:
        new_items = {k: v for k, v in d.items() if k not in bl_set}
        if not new_items:
            return ""
        return "".join(
            _pill(f"{prefix}{k}", v)
            for k, v in sorted(new_items.items(), key=lambda x: x[1])
        )


    rows = ""
    for actor in sorted_actors:
        ad       = actor_data[actor]
        bl_ops   = _baseline_set(actor, "cloudtrail", "known_operations")
        bl_res   = _baseline_set(actor, "cloudtrail", "known_resources")
        bl_bkt   = _baseline_set(actor, "s3",         "known_buckets")
        bl_conn  = _baseline_set(actor, "vpc", "known_dst_conns")

        op_pills  = _new_pills(ad["op"],   bl_ops)
        res_pills = _new_pills(ad["res"],  bl_res)
        bkt_pills = _new_pills(ad["bkt"],  bl_bkt)
        conn_pills = _new_pills(ad["conn"], bl_conn)
        vpc_c     = f'<div class="pill-wrap">{conn_pills}</div>' if conn_pills else _DASH

        op_cell  = f'<div class="pill-wrap">{op_pills}</div>'  if op_pills  else _DASH
        res_cell = f'<div class="pill-wrap">{res_pills}</div>' if res_pills else _DASH
        bkt_cell = f'<div class="pill-wrap">{bkt_pills}</div>' if bkt_pills else _DASH

        if all(c == _DASH for c in [op_cell, res_cell, bkt_cell, vpc_c]):
            continue

        _VA = "vertical-align:top;padding:10px"
        rows += (f'<tr>'
                 f'<td style="{_VA};font-weight:600;white-space:nowrap;{_SEP}">{actor}</td>'
                 f'<td style="{_VA};{_SEP}">{op_cell}</td>'
                 f'<td style="{_VA};{_SEP}">{res_cell}</td>'
                 f'<td style="{_VA};{_SEP}">{bkt_cell}</td>'
                 f'<td style="{_VA}">{vpc_c}</td>'
                 f'</tr>')

    if not rows:
        return ""

    _SRC   = "background:#34495e;text-align:center;font-weight:600;letter-spacing:0.5px"
    _SRC_B = f"{_SRC};border-right:3px solid #c8d0da"

    return f"""
    <section>
      <h2>Anomalies Across Period</h2>
      <p class="subtitle">Items NOT seen in baseline — red pills, date on second line. Actors with no anomalies are hidden.</p>
      <div style="overflow-x:auto">
      <table class="summary-table">
        <thead>
          <tr>
            <th rowspan="2" style="vertical-align:middle;text-align:center;{_SEP}">Actor</th>
            <th colspan="2" style="{_SRC_B}">CloudTrail</th>
            <th colspan="1" style="{_SRC_B}">S3</th>
            <th colspan="1" style="{_SRC}">VPC</th>
          </tr>
          <tr>
            <th style="text-align:center;{_SEP}">New Operations</th>
            <th style="text-align:center;{_SEP}">New Resources</th>
            <th style="text-align:center;{_SEP}">New Buckets</th>
            <th style="text-align:center">New Dst IP:Port</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      </div>
    </section>
    """


def _day_tab_html(date_str: str, scores: dict,
                  baselines: dict, profiles: dict) -> str:
    known   = {n: r for n, r in scores.items() if     _has_any_baseline(r)}
    unknown = {n: r for n, r in scores.items() if not _has_any_baseline(r)}

    known_summary   = _summary_table(known, "Behavioral Anomaly Scores",
                                     "Actors with at least one baseline — ranked by final score.")
    unknown_summary = (_summary_table(unknown, "First-Seen Entities",
                                      "No baseline exists — investigate separately.",
                                      show_scores=False)
                       if unknown else "")

    known_detail = "\n".join(
        _actor_section(n, r, baselines, profiles)
        for n, r in sorted(known.items(), key=lambda x: -x[1]["final_score"])
    )
    unknown_detail = ""
    if unknown:
        unknown_detail = "<h2>First-Seen Entity Detail</h2>\n" + "\n".join(
            _actor_section(n, r, baselines, profiles)
            for n, r in sorted(unknown.items(), key=lambda x: x[0])
        )

    return f"""
{known_summary}
{unknown_summary}
<h2>Behavioral Anomaly Detail</h2>
{known_detail}
{unknown_detail}
"""


def _exfil_badge(score: float) -> str:
    if score <= 0:
        return '<span class="badge badge-na">—</span>'
    if score >= 70:
        bg = "#c0392b"
    elif score >= 40:
        bg = "#e67e22"
    else:
        bg = "#7f8c8d"
    return f'<span class="badge" style="background:{bg}">{score:.0f}</span>'


def _build_eni_map() -> dict:
    eni_to_actor: dict[str, str] = {}
    if not OUT_DIR:
        return eni_to_actor
    for vf in sorted(Path(OUT_DIR).glob("vpc_entities_*.json")):
        try:
            for eni, data in json.loads(vf.read_text()).items():
                name = data.get("actor_name")
                if name:
                    eni_to_actor[eni] = name
        except Exception:
            pass
    return eni_to_actor


def _resolve_exfil_actor(row, eni_to_actor: dict) -> str:
    p = str(row.get("principal", "") or "")
    if p and p not in ("nan", "", "unknown_principal"):
        return p
    ek = str(row.get("entity_key", "") or "")
    eni = ek.split(":")[-1]
    return eni_to_actor.get(eni, eni or "unknown")


def _fv(row, col: str, fmt: str = "", default: str = "—") -> str:
    v = row.get(col)
    if v is None or str(v).strip() in ("nan", "", "None"):
        return default
    try:
        if fmt == "int":    return f"{int(float(v)):,}"
        if fmt == "float1": return f"{float(v):.1f}"
        if fmt == "float2": return f"{float(v):.2f}"
        if fmt == "pct":    return f"{float(v)*100:.0f}%"
        if fmt == "x":      return f"{float(v):.2f}x"
        if fmt == "bytes":
            b = float(v)
            if b >= 1e9: return f"{b/1e9:.2f} GB"
            if b >= 1e6: return f"{b/1e6:.1f} MB"
            if b >= 1e3: return f"{b/1e3:.1f} KB"
            return f"{b:.0f} B"
    except Exception:
        pass
    return str(v)


def _load_exfil_df():
    if not EXFIL_FILE or not Path(EXFIL_FILE).exists():
        return None
    try:
        import pandas as pd
        return pd.read_csv(EXFIL_FILE)
    except Exception:
        return None


def _load_session_df():
    if not SESSION_FILE or not Path(SESSION_FILE).exists():
        return None
    try:
        import pandas as pd
        return pd.read_csv(SESSION_FILE)
    except Exception:
        return None


def _session_badge(score: float) -> str:
    if score <= 0:
        return '<span class="badge badge-na">—</span>'
    if score >= 70:
        color = "#c0392b"
    elif score >= 35:
        color = "#e67e22"
    else:
        color = "#27ae60"
    return f'<span class="badge" style="background:{color}">{score:.0f}</span>'


def _parse_json_list(value) -> list:
    if value is None or str(value).strip() in ("", "nan", "None"):
        return []
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _day_flag_pills(flags) -> str:
    if not isinstance(flags, list):
        return ""
    colors = {
        "elevated": "#e67e22",
        "spike": "#c0392b",
        "rare_resources": "#8e44ad",
    }
    labels = {
        "elevated": "Elevated",
        "spike": "Spike",
        "rare_resources": "Rare Resources",
    }
    return "".join(
        f'<span style="background:{colors.get(flag, "#95a5a6")};color:#fff;'
        f'border-radius:4px;padding:1px 6px;font-size:10px;margin-right:3px">'
        f'{html.escape(labels.get(flag, str(flag)))}</span>'
        for flag in flags
    )


def _time_day_evidence_html(row) -> str:
    days = _parse_json_list(row.get("contributing_day_evidence_json"))
    if not days:
        days = _parse_json_list(row.get("daily_evidence_json"))[:8]
    if not days:
        contributing = str(row.get("contributing_days", "") or "").replace("|", ", ")
        if not contributing:
            return ""
        return (
            '<div style="margin-top:10px;padding:10px;background:#f8f9fa;border-radius:4px;'
            'font-size:12px;line-height:1.6">'
            '<strong style="color:#2c3e50">Contributing days:</strong> '
            f'{html.escape(contributing)}</div>'
        )

    rows = ""
    for day in days[:10]:
        flags = _day_flag_pills(day.get("flags", []))
        rows += f"""
<tr style="border-bottom:1px solid #eee">
  <td style="padding:6px 8px;font-weight:600;white-space:nowrap">{html.escape(str(day.get("date", "—")))}</td>
  <td style="padding:6px 8px;text-align:right">{float(day.get("activity_ratio", 0) or 0):.2f}x</td>
  <td style="padding:6px 8px;text-align:right">{_fv(day, "bytes", "bytes")}</td>
  <td style="padding:6px 8px;text-align:right">{_fv(day, "events", "int")}</td>
  <td style="padding:6px 8px;text-align:right">{_fv(day, "distinct_resources", "int")}</td>
  <td style="padding:6px 8px;text-align:left">{flags}</td>
</tr>"""

    th = 'style="background:#ecf0f1;padding:6px 8px;text-align:center;font-size:11px;white-space:nowrap;border-bottom:2px solid #bdc3c7"'
    return f"""
<div style="margin-top:12px">
  <div style="color:#7f8c8d;font-weight:600;margin-bottom:4px;font-size:11px;text-transform:uppercase">
    Contributing Days
  </div>
  <div style="overflow-x:auto">
    <table style="border-collapse:collapse;width:100%;font-size:12px;border:1px solid #dee2e6">
      <thead><tr>
        <th {th} style="text-align:left">Date</th>
        <th {th}>Activity Ratio</th>
        <th {th}>Bytes</th>
        <th {th}>Events</th>
        <th {th}>Resources</th>
        <th {th} style="text-align:left">Why It Matters</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"""


def _findings_tab_html(all_scores: dict) -> str:
    peak_ueba: dict[str, float] = {}
    peak_ueba_date: dict[str, str] = {}
    for date, scores in all_scores.items():
        for actor, r in scores.items():
            s = r.get("final_score", 0)
            if s > peak_ueba.get(actor, 0):
                peak_ueba[actor] = s
                peak_ueba_date[actor] = date

    exfil_by_actor: dict[str, dict] = {}
    exfil_loaded = False
    df = _load_exfil_df()
    if df is not None:
        eni_map = _build_eni_map()
        exfil_loaded = True
        for _, row in df.iterrows():
            actor = _resolve_exfil_actor(row, eni_map)
            if not actor or actor == "unknown":
                continue
            net  = float(row.get("network_risk_score",   0) or 0)
            time = float(row.get("time_based_risk_score", 0) or 0)
            if actor not in exfil_by_actor:
                exfil_by_actor[actor] = {"net": 0.0, "time": 0.0}
            exfil_by_actor[actor]["net"]  = max(exfil_by_actor[actor]["net"],  net)
            exfil_by_actor[actor]["time"] = max(exfil_by_actor[actor]["time"], time)

    session_by_actor: dict[str, float] = {}
    session_loaded = False
    sdf = _load_session_df()
    if sdf is not None:
        session_loaded = True
        for _, row in sdf.iterrows():
            actor = str(row.get("identity_id", "") or "")
            if not actor or actor in ("nan", "unknown"):
                continue
            score = float(row.get("session_risk_score", 0) or 0)
            session_by_actor[actor] = max(session_by_actor.get(actor, 0), score)

    all_actors = sorted(set(peak_ueba) | set(exfil_by_actor) | set(session_by_actor))

    def _sort_key(a):
        u = peak_ueba.get(a, 0)
        n = exfil_by_actor.get(a, {}).get("net",  0)
        t = exfil_by_actor.get(a, {}).get("time", 0)
        k = session_by_actor.get(a, 0)
        flags = (1 if u >= 0.4 else 0) + (1 if n >= 40 else 0) + (1 if t >= 40 else 0) + (1 if k >= 35 else 0)
        return (-flags, -max(u, n / 100, t / 100, k / 100))

    all_actors.sort(key=_sort_key)

    exfil_note = (
        '<p style="font-size:12px;color:#7f8c8d;margin:4px 0 4px">'
        'Exfil scores 0–100 &nbsp;|&nbsp; Red ≥ 70 &nbsp;|&nbsp; Amber ≥ 40 &nbsp;—&nbsp; '
        'see <strong>Exfil Detection</strong> tab for full detail</p>'
        if exfil_loaded else
        '<p style="font-size:12px;color:#e67e22;margin:4px 0 4px">'
        '⚠ Exfil alerts not available — run pipeline to generate exfil_alerts.csv</p>'
    )
    session_note = (
        '<p style="font-size:12px;color:#7f8c8d;margin:4px 0 12px">'
        'Session score 0–100 &nbsp;|&nbsp; Red ≥ 70 &nbsp;|&nbsp; Amber ≥ 35 &nbsp;—&nbsp; '
        'see <strong>Session Detection</strong> tab for kill-chain detail</p>'
        if session_loaded else
        '<p style="font-size:12px;color:#e67e22;margin:4px 0 12px">'
        '⚠ Session data not available — run pipeline to generate top_risky_sessions.csv</p>'
    )

    _SB = "border-right:2px solid #bdc3c7;"
    rows = ""
    for actor in all_actors:
        u     = peak_ueba.get(actor, 0)
        u_day = peak_ueba_date.get(actor, "")
        ex    = exfil_by_actor.get(actor, {})
        net   = ex.get("net",  0.0)
        time  = ex.get("time", 0.0)
        sess  = session_by_actor.get(actor, 0.0)

        flags = (1 if u >= 0.4 else 0) + (1 if net >= 40 else 0) + (1 if time >= 40 else 0) + (1 if sess >= 35 else 0)
        total = 4 if session_loaded else 3
        if flags == total:
            fp = f'<span style="background:#c0392b;color:#fff;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700">ALL {total}</span>'
        elif flags >= 2:
            fp = f'<span style="background:#e67e22;color:#fff;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700">{flags} / {total}</span>'
        elif flags == 1:
            fp = f'<span style="background:#7f8c8d;color:#fff;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700">1 / {total}</span>'
        else:
            fp = f'<span style="background:#ecf0f1;color:#95a5a6;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700">0 / {total}</span>'

        ueba_cell = (f'{_score_badge(u)}<br><small style="color:#95a5a6;font-size:10px">{u_day[5:]}</small>'
                     if u > 0 else '<span class="badge badge-na">—</span>')
        sess_cell = _session_badge(sess) if session_loaded else ''

        sess_col = f'<td style="text-align:center;padding:8px 12px;{_SB}">{sess_cell}</td>' if session_loaded else ''

        rows += (f'<tr>'
                 f'<td style="font-weight:600;white-space:nowrap;padding:8px 12px;{_SB}">{actor}</td>'
                 f'<td style="text-align:center;padding:8px 12px;{_SB}">{ueba_cell}</td>'
                 f'<td style="text-align:center;padding:8px 12px;{_SB}">{_exfil_badge(net)}</td>'
                 f'<td style="text-align:center;padding:8px 12px;{_SB}">{_exfil_badge(time)}</td>'
                 f'{sess_col}'
                 f'<td style="text-align:center;padding:8px 12px">{fp}</td>'
                 f'</tr>\n')

    th = 'style="background:#2c3e50;color:#fff;padding:8px 12px;text-align:center;white-space:nowrap"'
    sess_th = f'<th {th} style="border-right:2px solid #bdc3c7">Session Risk</th>' if session_loaded else ''
    return f"""
<section>
  <h2>Findings — {DATE_RANGE_START} → {DATE_RANGE_END}</h2>
  <p style="font-size:12px;color:#7f8c8d;margin:4px 0 2px">
    UEBA: behavioural deviation (0–1) &nbsp;|&nbsp; Red ≥ 0.7 &nbsp;|&nbsp; Amber ≥ 0.4
  </p>
  {exfil_note}
  {session_note}
  <table style="border-collapse:collapse;width:100%;font-size:13px;border:1px solid #dee2e6">
    <thead>
      <tr>
        <th {th} style="border-right:2px solid #bdc3c7">Actor</th>
        <th {th} style="border-right:2px solid #bdc3c7">UEBA Peak</th>
        <th {th} style="border-right:2px solid #bdc3c7">Network Exfil</th>
        <th {th} style="border-right:2px solid #bdc3c7">Time-based Exfil</th>
        {sess_th}
        <th {th}>Signals</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


def _exfil_tab_html() -> str:
    df = _load_exfil_df()
    if df is None:
        return ('<section><h2>Exfil Detection</h2>'
                '<p style="color:#e67e22">⚠ exfil_alerts.csv not found — run the pipeline first.</p>'
                '</section>')
    if df.empty:
        return ('<section><h2>Exfil Detection</h2>'
                '<p style="color:#27ae60">No alerts generated.</p></section>')

    eni_map = _build_eni_map()
    df = df.copy()
    df["_actor"] = df.apply(lambda r: _resolve_exfil_actor(r, eni_map), axis=1)
    df["_is_time"] = df["alert_type"].str.contains("time_based", na=False)
    df = df.sort_values("combined_risk_score", ascending=False)

    # Group per actor
    actors_order = []
    actor_rows: dict[str, dict] = {}
    for _, row in df.iterrows():
        a = row["_actor"]
        if a not in actor_rows:
            actor_rows[a] = {"net": [], "time": []}
            actors_order.append(a)
        if row["_is_time"]:
            actor_rows[a]["time"].append(row)
        else:
            actor_rows[a]["net"].append(row)

    _DET_LABELS = {
        "sustained_elevation": ("#e67e22", "Sustained Elevation"),
        "ramp_up":             ("#8e44ad", "Ramp Up"),
        "periodic_spikes":     ("#c0392b", "Periodic Spikes"),
    }

    def _krow(label, val):
        return (f'<tr><td style="color:#666;padding:2px 0;padding-right:16px">{label}</td>'
                f'<td style="font-weight:600;text-align:right">{val}</td></tr>')

    cards_html = ""
    for actor in actors_order:
        g = actor_rows[actor]
        max_net  = max((float(r.get("network_risk_score",   0) or 0) for r in g["net"]),  default=0)
        max_time = max((float(r.get("time_based_risk_score", 0) or 0) for r in g["time"]), default=0)
        max_comb = max(max_net, max_time)

        sections = ""

        # ── Time-based section ──────────────────────────────────────────────
        if g["time"]:
            tr = max(g["time"], key=lambda r: float(r.get("time_based_risk_score", 0) or 0))
            det_raw = str(tr.get("time_detection_types") or "")
            type_pills = "".join(
                f'<span style="background:{c};color:#fff;border-radius:4px;'
                f'padding:2px 8px;font-size:11px;margin-right:4px">{lbl}</span>'
                for key in det_raw.split("|")
                for c, lbl in [_DET_LABELS.get(key.strip(), ("#95a5a6", key.strip()))]
                if key.strip()
            )
            reasons = str(tr.get("alert_reasons", "") or "—")
            evidence_summary = str(tr.get("time_evidence_summary", "") or "")
            day_evidence = _time_day_evidence_html(tr)
            evidence_block = (
                f'<div style="padding:10px;background:#fff8e8;border-left:4px solid #e67e22;'
                f'border-radius:4px;font-size:12px;line-height:1.7;margin:10px 0">'
                f'<strong style="color:#2c3e50">Contributing-day summary:</strong><br>'
                f'<span style="color:#555">{html.escape(evidence_summary)}</span></div>'
                if evidence_summary else ""
            )
            sections += f"""
<div style="margin-bottom:16px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <span style="background:#8e44ad;color:#fff;border-radius:4px;padding:3px 9px;font-size:11px;font-weight:700">TIME-BASED S3</span>
    {_exfil_badge(float(tr.get('time_based_risk_score', 0) or 0))}
    <span style="margin-left:8px">{type_pills}</span>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px 32px;font-size:12px;margin:10px 0">
    <div>
      <div style="color:#7f8c8d;font-weight:600;margin-bottom:4px;font-size:11px;text-transform:uppercase">Analysis Window</div>
      <table style="width:100%;border-collapse:collapse">
        {_krow("Baseline days", _fv(tr,"baseline_days","int"))}
        {_krow("Current period days", _fv(tr,"current_days","int"))}
        {_krow("Elevated days (≥2.5x)", f'{_fv(tr,"elevated_days","int")} / {_fv(tr,"current_days","int")}')}
        {_krow("Spike days (≥4x)", _fv(tr,"spike_days","int"))}
      </table>
    </div>
    <div>
      <div style="color:#7f8c8d;font-weight:600;margin-bottom:4px;font-size:11px;text-transform:uppercase">Activity vs Baseline</div>
      <table style="width:100%;border-collapse:collapse">
        {_krow("Avg activity ratio", _fv(tr,"avg_activity_ratio","x"))}
        {_krow("Max activity ratio", _fv(tr,"max_activity_ratio","x"))}
        {_krow("Trend slope", f'+{_fv(tr,"trend_slope_ratio_per_day","float2")}x/day')}
        {_krow("Baseline avg daily events", _fv(tr,"baseline_avg_daily_events","float1"))}
        {_krow("Total current events", _fv(tr,"total_current_events","int"))}
      </table>
    </div>
  </div>
  {evidence_block}
  {day_evidence}
  <div style="padding:10px;background:#f8f9fa;border-radius:4px;font-size:12px;line-height:1.7">
    <strong style="color:#2c3e50">Alert reasons:</strong><br>
    <span style="color:#555">{html.escape(reasons)}</span>
  </div>
</div>"""

        # ── Network section ─────────────────────────────────────────────────
        if g["net"]:
            dest_rows = ""
            for nr in sorted(g["net"], key=lambda r: float(r.get("network_risk_score", 0) or 0), reverse=True):
                dest     = str(nr.get("destination", "") or "—")
                score    = float(nr.get("network_risk_score", 0) or 0)
                b_out    = _fv(nr, "total_bytes_out",  "bytes")
                ev_cnt   = _fv(nr, "event_count",      "int")
                dur      = _fv(nr, "duration_hours",   "float1")
                s_ratio  = _fv(nr, "small_transfer_ratio", "pct")
                iv_cv    = _fv(nr, "interval_cv",      "float2")
                rsn      = str(nr.get("alert_reasons", "") or "—")
                dest_rows += f"""
<tr style="border-bottom:1px solid #eee">
  <td style="padding:8px 10px;font-weight:600;white-space:nowrap">{dest}</td>
  <td style="padding:8px 10px;text-align:center">{_exfil_badge(score)}</td>
  <td style="padding:8px 10px;text-align:right">{b_out}</td>
  <td style="padding:8px 10px;text-align:right">{ev_cnt}</td>
  <td style="padding:8px 10px;text-align:right">{dur} hrs</td>
  <td style="padding:8px 10px;text-align:right">{s_ratio}</td>
  <td style="padding:8px 10px;text-align:right">{iv_cv}</td>
  <td style="padding:8px 10px;font-size:11px;color:#555;max-width:300px">{rsn}</td>
</tr>"""
            th_s = 'style="background:#ecf0f1;padding:6px 10px;text-align:center;font-size:11px;white-space:nowrap;border-bottom:2px solid #bdc3c7"'
            sections += f"""
<div style="margin-bottom:16px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <span style="background:#2980b9;color:#fff;border-radius:4px;padding:3px 9px;font-size:11px;font-weight:700">NETWORK</span>
    {_exfil_badge(max_net)}
    <span style="font-size:12px;color:#7f8c8d">{len(g["net"])} destination(s)</span>
  </div>
  <div style="overflow-x:auto">
    <table style="border-collapse:collapse;width:100%;font-size:12px;border:1px solid #dee2e6">
      <thead><tr>
        <th {th_s} style="text-align:left">Destination</th>
        <th {th_s}>Score</th>
        <th {th_s}>Bytes Out</th>
        <th {th_s}>Events</th>
        <th {th_s}>Duration</th>
        <th {th_s}>Small Xfer %</th>
        <th {th_s}>Interval CV</th>
        <th {th_s} style="text-align:left">Alert Reasons</th>
      </tr></thead>
      <tbody>{dest_rows}</tbody>
    </table>
  </div>
</div>"""

        if sections:
            cards_html += f"""
<div style="border:1px solid #dee2e6;border-radius:6px;padding:16px 20px;margin-bottom:16px;background:#fff">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid #eee">
    <strong style="font-size:16px">{actor}</strong>
    <span style="margin-left:auto;font-size:12px;color:#7f8c8d">Combined score:</span>
    {_exfil_badge(max_comb)}
  </div>
  {sections}
</div>"""

    return f"""
<section>
  <h2>Exfil Detection — {DATE_RANGE_START} → {DATE_RANGE_END}</h2>
  <p style="font-size:12px;color:#7f8c8d;margin:4px 0 16px">
    Low-and-slow exfiltration detection across the full analysis period.
    <strong>Network layer</strong>: trickle transfers to rare destinations. &nbsp;
    <strong>Time-based layer</strong>: sustained S3 read elevation vs 30-day baseline.
  </p>
  {cards_html}
</section>"""


def _session_tab_html() -> str:
    df = _load_session_df()
    if df is None:
        return ('<section><h2>Session Detection</h2>'
                '<p style="color:#e67e22">⚠ top_risky_sessions.csv not found — run the pipeline first.</p>'
                '</section>')
    if df.empty:
        return ('<section><h2>Session Detection</h2>'
                '<p style="color:#27ae60">No risky sessions detected.</p></section>')

    _TH = 'style="background:#2c3e50;color:#fff;padding:8px 10px;text-align:center;white-space:nowrap;font-size:12px"'
    rows_html = ""
    for _, row in df.iterrows():
        actor   = str(row.get("identity_id", ""))
        start   = str(row.get("session_start", ""))[:16].replace("T", " ")
        end     = str(row.get("session_end",   ""))[:16].replace("T", " ")
        nevents = int(row.get("num_events", 0) or 0)
        dur     = float(row.get("duration_minutes", 0) or 0)
        risk    = float(row.get("session_risk_score",        0) or 0)
        rarity  = float(row.get("sequence_rarity_score",     0) or 0)
        chain   = float(row.get("suspicious_chain_score",    0) or 0)
        timing  = float(row.get("timing_burst_score",        0) or 0)
        deviat  = float(row.get("feature_deviation_score",   0) or 0)
        sensit  = float(row.get("sensitive_action_score",    0) or 0)
        expl    = html.escape(str(row.get("risk_explanation", "") or ""))

        def _mini_bar(val, max_val):
            pct = int(min(val / max_val * 100, 100))
            color = "#c0392b" if pct >= 70 else ("#e67e22" if pct >= 40 else "#27ae60")
            return (f'<div style="background:#ecf0f1;border-radius:3px;height:6px;width:60px;display:inline-block;vertical-align:middle">'
                    f'<div style="background:{color};height:100%;width:{pct}%;border-radius:3px"></div></div>'
                    f'<span style="font-size:11px;margin-left:4px">{val:.0f}</span>')

        risk_color = "#c0392b" if risk >= 70 else ("#e67e22" if risk >= 35 else "#27ae60")
        rows_html += f"""
<tr style="border-bottom:1px solid #eee">
  <td style="padding:8px 10px;font-weight:600;white-space:nowrap">{actor}</td>
  <td style="padding:8px 10px;font-size:11px;white-space:nowrap;color:#555">{start}<br>{end}</td>
  <td style="padding:8px 10px;text-align:center">{nevents}</td>
  <td style="padding:8px 10px;text-align:center">{dur:.1f} min</td>
  <td style="padding:8px 10px;text-align:center">
    <span style="background:{risk_color};color:#fff;border-radius:4px;padding:2px 8px;font-weight:700">{risk:.0f}</span>
  </td>
  <td style="padding:8px 10px">{_mini_bar(rarity, 25)}</td>
  <td style="padding:8px 10px">{_mini_bar(chain, 30)}</td>
  <td style="padding:8px 10px">{_mini_bar(timing, 20)}</td>
  <td style="padding:8px 10px">{_mini_bar(deviat, 15)}</td>
  <td style="padding:8px 10px">{_mini_bar(sensit, 10)}</td>
  <td style="padding:8px 10px;font-size:11px;color:#555;max-width:300px">{expl}</td>
</tr>"""

    return f"""
<section>
  <h2>Session Detection — {DATE_RANGE_START} → {DATE_RANGE_END}</h2>
  <p style="font-size:12px;color:#7f8c8d;margin:4px 0 8px">
    Kill-chain sequence analysis. Sessions scored globally against the 30-day baseline.
    Score 0–100 &nbsp;|&nbsp; Red ≥ 70 (high) &nbsp;|&nbsp; Amber ≥ 35 (medium).
    Sub-scores: <strong>Rarity</strong>/25 &nbsp;|&nbsp; <strong>Chain</strong>/30 &nbsp;|&nbsp;
    <strong>Timing</strong>/20 &nbsp;|&nbsp; <strong>Deviation</strong>/15 &nbsp;|&nbsp; <strong>Sensitive</strong>/10
  </p>
  <div style="overflow-x:auto">
  <table style="border-collapse:collapse;width:100%;font-size:13px;border:1px solid #dee2e6">
    <thead>
      <tr>
        <th {_TH}>Identity</th>
        <th {_TH}>Session Window</th>
        <th {_TH}>Events</th>
        <th {_TH}>Duration</th>
        <th {_TH}>Session Risk</th>
        <th {_TH}>Rarity /25</th>
        <th {_TH}>Chain /30</th>
        <th {_TH}>Timing /20</th>
        <th {_TH}>Deviation /15</th>
        <th {_TH}>Sensitive /10</th>
        <th {_TH}>Explanation</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>
  </div>
</section>"""


def _tabbed_report(baselines: dict, generated_at: str,
                   period_label: str, period_value: str, title_date: str) -> str:
    all_scores:   dict = {}
    all_profiles: dict = {}
    for d in RANGE_DATES:
        sp = Path(OUT_DIR) / f"risk_scores_{d}.json"
        pp = Path(OUT_DIR) / f"incident_profiles_{d}.json"
        if sp.exists():
            try:    all_scores[d]   = json.loads(sp.read_text())
            except Exception: pass
        if pp.exists():
            try:    all_profiles[d] = json.loads(pp.read_text())
            except Exception: pass

    available = [d for d in RANGE_DATES if d in all_scores]

    findings_html = _findings_tab_html(all_scores)

    period_html = (_score_trend_html(RANGE_DATES, all_scores) +
                   _peak_day_signals_html(RANGE_DATES, all_scores) +
                   _notable_anomalies_html(RANGE_DATES, all_profiles, all_scores, baselines))

    exfil_html   = _exfil_tab_html()
    session_html = _session_tab_html()

    tab_buttons = [
        '<button class="tab-btn active" data-tab="findings">Findings</button>',
        '<button class="tab-btn" data-tab="exfil">Exfil Detection</button>',
        '<button class="tab-btn" data-tab="session">Session Detection</button>',
        '<span class="tab-label">UEBA</span>',
        '<button class="tab-btn" data-tab="period">Period Overview</button>',
    ]
    day_panes   = []
    for d in available:
        content = _day_tab_html(d, all_scores.get(d, {}),
                                baselines, all_profiles.get(d, {}))
        tab_buttons.append(
            f'<button class="tab-btn" data-tab="{d}">{d[5:]}</button>')
        day_panes.append(
            f'<div class="tab-pane" id="tab-{d}">{content}</div>')

    css          = _html_css()
    legend       = _legend_html()
    tabs_html    = "\n".join(tab_buttons)
    panes_html   = "\n".join(day_panes)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS Threat Detection Report — {title_date}</title>
<style>{css}</style>
</head>
<body>
<h1>AWS Threat Detection Report</h1>
<p class="meta">
  {period_label}: <strong>{period_value}</strong> &nbsp;|&nbsp;
  AWS account: <strong>{ACCOUNT_ID}</strong> &nbsp;|&nbsp;
  Generated: {generated_at}
</p>
{legend}
<div class="tabs">{tabs_html}</div>
<div class="tab-pane active" id="tab-findings">{findings_html}</div>
<div class="tab-pane" id="tab-exfil">{exfil_html}</div>
<div class="tab-pane" id="tab-session">{session_html}</div>
<div class="tab-pane" id="tab-period">{period_html}</div>
{panes_html}
<script>
document.querySelectorAll('.tab-btn').forEach(function(btn) {{
  btn.addEventListener('click', function() {{
    document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
    document.querySelectorAll('.tab-pane').forEach(function(p) {{ p.classList.remove('active'); }});
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  }});
}});
</script>
</body>
</html>"""


# ── Summary table ──────────────────────────────────────────────────────────

def _na_cell() -> str:
    return '<span class="badge badge-na">N/A</span>'


def _summary_table(actors: dict, title: str, subtitle: str = "",
                   show_scores: bool = True) -> str:
    rows = ""
    for name, r in sorted(actors.items(), key=lambda x: -x[1]["final_score"]):
        ct  = r.get("cloudtrail")
        s3  = r.get("s3")
        vpc = r.get("vpc")
        tag = _actor_tag(name, r)
        if show_scores:
            ct_cell    = _score_badge(ct["score"]  if ct  else None)
            s3_cell    = _score_badge(s3["score"]  if s3  else None)
            vpc_cell   = _score_badge(vpc["score"] if vpc else None)
            final_cell = _score_badge(r["final_score"])
        else:
            ct_cell = s3_cell = vpc_cell = final_cell = _na_cell()
        rows += f"""
        <tr>
          <td>{tag} {name}</td>
          <td>{"+".join(r.get("sources_used", []))}</td>
          <td class="score-cell">{ct_cell}</td>
          <td class="score-cell">{s3_cell}</td>
          <td class="score-cell">{vpc_cell}</td>
          <td class="score-cell">{final_cell}</td>
        </tr>"""

    sub = f'<p class="subtitle">{subtitle}</p>' if subtitle else ""
    return f"""
    <section>
      <h2>{title}</h2>
      {sub}
      <table class="summary-table">
        <thead>
          <tr><th>Actor</th><th>Sources</th><th>CT</th><th>S3</th><th>VPC</th><th>Final</th></tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    """


# ── HTML generation ────────────────────────────────────────────────────────

def generate(results: dict, baselines: dict, profiles: dict) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    is_range = (DATE_RANGE_START and DATE_RANGE_END
                and DATE_RANGE_START != DATE_RANGE_END)
    if is_range:
        period_label = "Analysis period"
        period_value = f"{DATE_RANGE_START} → {DATE_RANGE_END}"
        title_date   = f"{DATE_RANGE_START} to {DATE_RANGE_END}"
    else:
        period_label = "Incident date"
        period_value = INCIDENT_DATE
        title_date   = INCIDENT_DATE

    if is_range and RANGE_DATES and OUT_DIR:
        return _tabbed_report(baselines, generated_at,
                              period_label, period_value, title_date)

    # ── Single-day mode ──────────────────────────────────────────────────────
    known   = {n: r for n, r in results.items() if     _has_any_baseline(r)}
    unknown = {n: r for n, r in results.items() if not _has_any_baseline(r)}

    known_summary   = _summary_table(known, "Behavioral Anomaly Scores",
                                     "Actors with at least one baseline — ranked by final score.")
    unknown_summary = (_summary_table(unknown, "First-Seen Entities",
                                      "No baseline exists — investigate separately.",
                                      show_scores=False)
                       if unknown else "")

    known_detail = "\n".join(
        _actor_section(n, r, baselines, profiles)
        for n, r in sorted(known.items(), key=lambda x: -x[1]["final_score"])
    )
    unknown_detail = ""
    if unknown:
        unknown_detail = "<h2>First-Seen Entity Detail</h2>" + "\n".join(
            _actor_section(n, r, baselines, profiles)
            for n, r in sorted(unknown.items(), key=lambda x: -x[1]["final_score"])
        )

    css    = _html_css()
    legend = _legend_html()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS Threat Detection Report — {title_date}</title>
<style>{css}</style>
</head>
<body>
<h1>AWS Threat Detection Report</h1>
<p class="meta">
  {period_label}: <strong>{period_value}</strong> &nbsp;|&nbsp;
  AWS account: <strong>{ACCOUNT_ID}</strong> &nbsp;|&nbsp;
  Generated: {generated_at}
</p>
{legend}
{known_summary}
{unknown_summary}
<h2>Behavioral Anomaly Detail</h2>
{known_detail}
{unknown_detail}
</body>
</html>"""


def main() -> None:
    for f in [SCORES_FILE, BASELINE_FILE, PROFILES_FILE]:
        if not f.exists():
            print(f"[report] {f} not found — run the pipeline first.")
            return

    results   = json.loads(SCORES_FILE.read_text())
    baselines = json.loads(BASELINE_FILE.read_text())
    profiles  = json.loads(PROFILES_FILE.read_text())

    html = generate(results, baselines, profiles)
    OUTPUT.write_text(html, encoding="utf-8")
    print(f"Report saved -> {OUTPUT}")
    print("Open in a browser and Ctrl+P -> Save as PDF.")


if __name__ == "__main__":
    main()
