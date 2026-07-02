"""Builds a standalone PDF explaining the methodology and every metric/score
produced by the pipeline -- meant as a reference doc, not a results report.

Output: ../methodology_and_metrics.pdf

Usage:
    python3 build_methodology_report.py
"""
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, ListFlowable, ListItem,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PDF = os.path.join(ROOT, "methodology_and_metrics.pdf")

styles = getSampleStyleSheet()
title_style = styles["Title"]
heading_style = styles["Heading2"]
sub_heading_style = styles["Heading3"]
subtitle_style = ParagraphStyle("subtitle", parent=styles["Normal"], fontSize=12, textColor=colors.grey)
body_style = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, leading=14)
small_style = ParagraphStyle("small", parent=styles["Normal"], fontSize=9, leading=13)

story = []

# ---------------------------------------------------------------- Title ----
story.append(Paragraph("Methodology &amp; Metrics", title_style))
story.append(Spacer(1, 4))
story.append(Paragraph(
    "How the CloudTrail session-risk pipeline decides a session is normal vs. suspicious.",
    subtitle_style,
))
story.append(Spacer(1, 18))

# ------------------------------------------------------------ Overview -----
story.append(Paragraph("1. Core Idea", heading_style))
story.append(Paragraph(
    "Instead of asking <i>\"is this normal for this specific user?\"</i>, the pipeline asks "
    "<i>\"is this short action sequence normal for cloud activity in general?\"</i> "
    "identity_id is used only to group raw events into sessions and to label results in "
    "reports -- it is never consulted when deciding whether a chain of actions is risky. "
    "Every session, no matter who produced it, is judged against one shared global baseline "
    "built from normal historical behavior across all identities. This matters because "
    "attackers often pivot across users/roles/accounts, so a per-user baseline would miss "
    "exactly the chains we care about.",
    body_style,
))
story.append(Spacer(1, 10))

# ----------------------------------------------------------- Pipeline -----
story.append(Paragraph("2. Pipeline Stages", heading_style))
stage_rows = [
    ["Stage", "What happens"],
    ["Normalize", "Raw CloudTrail / OCSF records are flattened into one schema: event_time, "
                  "event_name, event_source, identity_id, identity_type, source_ip, aws_region, "
                  "user_agent, account_id, request_parameters, resources, error_code."],
    ["Categorize", "Each event_name is mapped to one broad action category: Auth, Discovery, "
                   "DataAccess, PermissionChange, CredentialAccess, Persistence, DefenseEvasion, "
                   "NetworkChange, ComputeChange, StorageChange, or Other."],
    ["Sessionize", "Events are grouped per identity_id, sorted by time; a new session starts "
                   "whenever the gap since the previous event for that identity exceeds 30 "
                   "minutes."],
    ["Extract features", "Each session is reduced to ~25 numeric/sequence features: event "
                          "counts per category, ordered event/category sequences, timing stats, "
                          "unique services/regions/IPs, failure ratio, etc."],
    ["Build baseline (training only)", "Baseline sessions feed a global model: n-gram "
                                        "frequencies, category transition probabilities, and "
                                        "mean/std/percentiles for key numeric features."],
    ["Score (new logs only)", "Each new session's features are compared against the global "
                              "baseline model (not against its own identity's history) to "
                              "produce a 0-100 risk score plus a plain-English explanation."],
]
t_stage = Table(stage_rows, colWidths=[110, 360], repeatRows=1)
t_stage.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F7")]),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
]))
story.append(t_stage)
story.append(Spacer(1, 10))

story.append(PageBreak())

# -------------------------------------------------------- Descriptive ------
story.append(Paragraph("3. Descriptive Columns (not scored)", heading_style))
desc_rows = [
    ["Column", "Meaning"],
    ["session_id", "identity_id + sequence number, e.g. alice_m_s1 (her 1st session)."],
    ["identity_id", "Who performed the actions. Used for grouping/labeling only."],
    ["session_start / session_end", "Timestamp of the first / last event in the session."],
    ["num_events", "Total API calls in the session."],
    ["duration_minutes", "session_end - session_start, in minutes."],
]
t_desc = Table(desc_rows, colWidths=[150, 320], repeatRows=1)
t_desc.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F7")]),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
]))
story.append(t_desc)
story.append(Spacer(1, 14))

# ------------------------------------------------------- Score components --
story.append(Paragraph("4. The Five Risk Score Components", heading_style))
story.append(Paragraph(
    "session_risk_score is the sum of five independently-computed components, clipped to "
    "the range [0, 100]. They are added rather than blended, so a session can rack up points "
    "from more than one component for what is really a single root cause -- this is a "
    "deliberate MVP trade-off favoring explainability over a single unified statistic.",
    body_style,
))
story.append(Spacer(1, 8))

def add_component(name, max_score, summary, detail_items):
    story.append(Paragraph(f"{name} (0&ndash;{max_score})", sub_heading_style))
    story.append(Paragraph(summary, body_style))
    story.append(ListFlowable(
        [ListItem(Paragraph(item, small_style), leftIndent=14) for item in detail_items],
        bulletType="bullet", start="circle",
    ))
    story.append(Spacer(1, 10))

add_component(
    "1. sequence_rarity_score", 25,
    "Measures how unusual the session's action-category sequence is, independent of whether "
    "any single chain is \"known bad.\"",
    [
        "The session's ordered category list (e.g. Discovery, DataAccess, PermissionChange) is "
        "broken into overlapping 2-step and 3-step chunks (bigrams / trigrams).",
        "Each chunk is looked up in the baseline's chunk-frequency table. A chunk that never "
        "occurred in the baseline gets rarity = 1.0; a chunk that's common in the baseline gets "
        "rarity close to 0.",
        "Score = average rarity across all chunks in the session, scaled up to 25.",
        "Effect: a session built entirely from chains the baseline has never seen scores near "
        "25; a session using only everyday chains scores near 0.",
    ],
)

add_component(
    "2. suspicious_chain_score", 30,
    "Rule-based detector for known attacker patterns, regardless of how rare they are "
    "statistically.",
    [
        "Checks for specific category chains: Discovery&#8594;PermissionChange, "
        "Discovery&#8594;CredentialAccess, Discovery&#8594;DataAccess, "
        "PermissionChange&#8594;CredentialAccess, PermissionChange&#8594;DataAccess "
        "(+6 pts each if both ends are present in order).",
        "Checks three-step chains: Auth&#8594;Discovery&#8594;DataAccess and "
        "Auth&#8594;Discovery&#8594;PermissionChange (+4 pts each).",
        "Checks specific raw event pairs: GetBucketPolicy&#8594;PutBucketPolicy, "
        "ListRoles&#8594;AssumeRole, CreateAccessKey&#8594;GetObject, and a few others "
        "(+5 pts each).",
        "Flags \"bulk access\": ListBuckets followed by 5+ GetObject calls (+6 pts).",
        "Flags DefenseEvasion (e.g. StopLogging, DeleteTrail) occurring as the very first "
        "action before anything else (+8 pts) -- a classic \"cover tracks first\" pattern.",
        "All matches are summed and capped at 30.",
    ],
)

add_component(
    "3. timing_burst_score", 20,
    "Flags sessions that move faster or denser than normal, or that race from recon to "
    "impact unusually quickly.",
    [
        "Compares events_per_minute and max_events_in_5min against the baseline's 95th "
        "percentile for those features; exceeding it adds points proportional to how far over.",
        "Computes minutes between the first Discovery action and the first "
        "PermissionChange / CredentialAccess / DataAccess action. If that gap is &#8804;10 "
        "minutes, +6 pts per such fast transition.",
        "Capped at 20.",
    ],
)

add_component(
    "4. feature_deviation_score", 15,
    "A standard z-score check: how far this session's overall numeric profile sits from the "
    "baseline's typical session, independent of order or known patterns.",
    [
        "For num_events, duration_minutes, unique_services, num_getobject_events, "
        "num_sensitive_actions, and failed_event_ratio: z = |value &minus; baseline_mean| / "
        "baseline_std.",
        "Score = average z-score across those six features, scaled so an average z of 4 "
        "or more earns the full 15 points.",
        "Catches sessions that are statistically odd in scale (e.g. way more events than "
        "anyone normally has) even if the sequence itself looks unremarkable.",
    ],
)

add_component(
    "5. sensitive_action_score", 10,
    "Rewards the raw presence/volume of high-impact action categories, regardless of order "
    "or timing.",
    [
        "+3 pts per PermissionChange action (capped at 6 from this category).",
        "+3 pts per CredentialAccess action (capped at 6).",
        "+2 pts per Persistence action (capped at 4).",
        "+3 pts per DefenseEvasion action (capped at 6).",
        "+2 pts flat if DataAccess actions in the session reach 20+ (high-volume read/exfil).",
        "Sum capped at 10 overall.",
    ],
)

story.append(PageBreak())

# ------------------------------------------------------------ Final score --
story.append(Paragraph("5. Final Score &amp; Explanation", heading_style))
story.append(Paragraph(
    "<b>session_risk_score</b> = sequence_rarity_score + suspicious_chain_score + "
    "timing_burst_score + feature_deviation_score + sensitive_action_score, clipped to "
    "[0, 100].",
    body_style,
))
story.append(Spacer(1, 6))
risk_rows = [
    ["Score range", "Risk level"],
    ["0 &ndash; 34", "Low"],
    ["35 &ndash; 69", "Medium"],
    ["70 &ndash; 100", "High"],
]
t_risk = Table(risk_rows, colWidths=[150, 150])
t_risk.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F7")]),
]))
story.append(t_risk)
story.append(Spacer(1, 10))
story.append(Paragraph(
    "<b>risk_explanation</b> is built by collecting the human-readable \"reason\" strings "
    "generated by each component above (e.g. \"Discovery &#8594; PermissionChange chain "
    "present\", \"events_per_minute=12.0 exceeds baseline p95 (4.0)\"), taking the first 5 "
    "across all components, and appending a sentence noting the session's duration and event "
    "count. If no component produced a reason, the session is reported as matching normal "
    "baseline behavior.",
    body_style,
))
story.append(Spacer(1, 14))

# -------------------------------------------------------------- Caveats ----
story.append(Paragraph("6. Known Limitations", heading_style))
for item in [
    "The five components are added, not normalized against each other -- one underlying "
    "cause (e.g. a fast Discovery&#8594;PermissionChange chain) can earn points from "
    "suspicious_chain_score AND timing_burst_score simultaneously, inflating the total.",
    "suspicious_chain_score's event/category pairs are hand-curated from known attacker "
    "TTPs, not learned from data -- they will miss novel chain types and can occasionally "
    "flag legitimate but unusual workflows.",
    "feature_deviation_score and failed_event_ratio are weaker on OCSF-derived logs that "
    "lack request_parameters/error_code detail compared to full raw CloudTrail.",
    "The global baseline assumes the baseline log itself is free of attacker activity; any "
    "contamination there would suppress detection of similar real chains later.",
]:
    story.append(Paragraph(f"&bull; {item}", body_style))
    story.append(Spacer(1, 4))

doc = SimpleDocTemplate(OUTPUT_PDF, pagesize=letter, topMargin=42, bottomMargin=42, leftMargin=46, rightMargin=46)
doc.build(story)
print(f"Wrote {OUTPUT_PDF}")
