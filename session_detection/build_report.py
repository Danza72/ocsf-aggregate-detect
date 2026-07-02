"""Builds a PDF summary of the global session-risk MVP run: methodology,
baseline stats, score distribution, and the top risky sessions with
explanations.

Source: ../output/{baseline_sessions,scored_new_sessions}.parquet,
        ../output/global_session_baseline_model.json
Output: ../session_risk_report.pdf

Usage:
    python3 build_report.py
"""
import json
import os

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "output")
OUTPUT_PDF = os.path.join(ROOT, "session_risk_report.pdf")

baseline_sessions = pd.read_parquet(os.path.join(OUT_DIR, "baseline_sessions.parquet"))
scored = pd.read_parquet(os.path.join(OUT_DIR, "scored_new_sessions.parquet"))
with open(os.path.join(OUT_DIR, "global_session_baseline_model.json")) as f:
    model = json.load(f)

top = scored.sort_values("session_risk_score", ascending=False).head(15)

n_high = int((scored["session_risk_score"] >= 70).sum())
n_med = int(((scored["session_risk_score"] >= 35) & (scored["session_risk_score"] < 70)).sum())
n_low = int((scored["session_risk_score"] < 35).sum())

styles = getSampleStyleSheet()
title_style = styles["Title"]
heading_style = styles["Heading2"]
subtitle_style = ParagraphStyle("subtitle", parent=styles["Normal"], fontSize=12, textColor=colors.grey)
body_style = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, leading=14)
small_style = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, leading=10)

story = []

# ---- Title ----
story.append(Paragraph("CloudTrail Session-Risk Analytics — MVP Report", title_style))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "Global (identity-agnostic) baseline of normal session behavior, scored against "
    "OCSF-normalized incident logs (2018-08-20 to 2018-09-02).",
    subtitle_style,
))
story.append(Spacer(1, 16))

# ---- Methodology ----
story.append(Paragraph("1. Methodology", heading_style))
story.append(Paragraph(
    "This pipeline asks a single question per session: <i>does this short cloud activity "
    "session contain an unusual or suspicious action chain compared to normal global cloud "
    "behavior?</i> identity_id is used only to group events into sessions and for reporting "
    "— it is never used to judge whether a session's behavior is normal for that specific "
    "user. Every session, regardless of who produced it, is compared against one shared "
    "global baseline.",
    body_style,
))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "<b>Training phase:</b> normalize baseline CloudTrail/OCSF logs &#8594; map each "
    "event_name to a broad action category (Auth, Discovery, DataAccess, PermissionChange, "
    "CredentialAccess, Persistence, DefenseEvasion, NetworkChange, ComputeChange, "
    "StorageChange, Other) &#8594; sessionize per identity_id with a 30-minute inactivity "
    "gap &#8594; extract session-level sequence/timing features &#8594; build a global "
    "baseline of category n-gram frequencies, transition probabilities, and numeric feature "
    "distributions.",
    body_style,
))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "<b>Scoring phase:</b> the same normalize/sessionize/feature-extraction logic is applied "
    "to new logs, then each session is scored against the global baseline (not against its "
    "own identity's history) across five components: sequence rarity (0-25), suspicious "
    "chain presence (0-30), timing/burst (0-20), feature deviation (0-15), and sensitive "
    "action volume (0-10), summed and capped to a final 0-100 session_risk_score.",
    body_style,
))
story.append(Spacer(1, 10))

# ---- Dataset summary ----
story.append(Paragraph("2. Dataset Summary", heading_style))
summary_rows = [
    ["", "Sessions", "Identities", "Events"],
    ["Baseline (training)", str(len(baseline_sessions)), str(baseline_sessions["identity_id"].nunique()),
     str(int(baseline_sessions["num_events"].sum()))],
    ["Incident logs (scored)", str(len(scored)), str(scored["identity_id"].nunique()),
     str(int(scored["num_events"].sum()))],
]
t0 = Table(summary_rows, repeatRows=1)
t0.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F7")]),
]))
story.append(t0)
story.append(Spacer(1, 10))

story.append(Paragraph(
    f"Of {len(scored)} scored incident-window sessions: "
    f"<b>{n_high} high-risk</b> (score &#8805; 70), "
    f"<b>{n_med} medium-risk</b> (35-70), and "
    f"<b>{n_low} low-risk</b> (&lt; 35).",
    body_style,
))
story.append(Spacer(1, 10))

# ---- Top risky sessions ----
story.append(Paragraph("3. Top Risky Sessions", heading_style))
story.append(Spacer(1, 6))

headers = ["Identity", "Events", "Duration\n(min)", "Rarity", "Chain", "Timing", "Deviation", "Sensitive", "Risk\nScore"]
table_data = [headers]
for _, row in top.iterrows():
    table_data.append([
        row["identity_id"],
        str(row["num_events"]),
        f"{row['duration_minutes']:.1f}",
        f"{row['sequence_rarity_score']:.1f}",
        f"{row['suspicious_chain_score']:.1f}",
        f"{row['timing_burst_score']:.1f}",
        f"{row['feature_deviation_score']:.1f}",
        f"{row['sensitive_action_score']:.1f}",
        f"{row['session_risk_score']:.1f}",
    ])

t = Table(table_data, repeatRows=1)
t.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTSIZE", (0, 0), (-1, -1), 8),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F7")]),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("TOPPADDING", (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FADBD8")),
]))
story.append(t)
story.append(Spacer(1, 12))

# ---- Key finding ----
top1 = top.iloc[0]
story.append(Paragraph("4. Key Finding", heading_style))
story.append(Paragraph(
    f"The single highest-risk session belongs to <b>{top1['identity_id']}</b> "
    f"(session_id {top1['session_id']}): {int(top1['num_events'])} events over "
    f"~{top1['duration_minutes']:.0f} minutes, risk score "
    f"<b>{top1['session_risk_score']:.1f}/100</b>. {top1['risk_explanation']}",
    body_style,
))
story.append(Spacer(1, 10))

story.append(PageBreak())

# ---- All top-15 explanations ----
story.append(Paragraph("5. Risk Explanations (Top 15)", heading_style))
story.append(Spacer(1, 6))
for _, row in top.iterrows():
    story.append(Paragraph(
        f"<b>{row['session_id']}</b> (identity: {row['identity_id']}, score: "
        f"{row['session_risk_score']:.1f}) — {row['risk_explanation']}",
        small_style,
    ))
    story.append(Spacer(1, 5))
story.append(Spacer(1, 10))

# ---- Limitations / next steps ----
story.append(Paragraph("6. Limitations &amp; Next Steps", heading_style))
for item in [
    "Baseline is built from a single synthetic baseline log; a longer pre-incident "
    "window per identity would sharpen the global n-gram and feature-distribution estimates.",
    "OCSF records in this dataset carry no request_parameters/user_agent/error_code "
    "detail, so feature_deviation and failed_event_ratio signals are weaker than they "
    "would be on full raw CloudTrail logs.",
    "Suspicious event-pair and chain lists are hand-curated; consider mining them "
    "automatically from confirmed-malicious sessions as more incidents are labeled.",
]:
    story.append(Paragraph(f"&bull; {item}", body_style))
    story.append(Spacer(1, 4))

doc = SimpleDocTemplate(OUTPUT_PDF, pagesize=letter, topMargin=40, bottomMargin=40, leftMargin=40, rightMargin=40)
doc.build(story)
print(f"Wrote {OUTPUT_PDF}")
