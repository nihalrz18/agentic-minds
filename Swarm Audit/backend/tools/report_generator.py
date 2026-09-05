"""
ReportLab-based PDF report generator for SwarmAudit.
Generates professional penetration testing reports.
"""
import datetime
import os

from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ─── Colour palette ───────────────────────────────────────────────────────────
DARK_BG        = HexColor("#1a1a2e")
DARK_SECONDARY = HexColor("#16213e")
ACCENT_BLUE    = HexColor("#0f3460")
CRITICAL_RED   = HexColor("#c0392b")
HIGH_ORANGE    = HexColor("#e67e22")
MEDIUM_YELLOW  = HexColor("#f39c12")
LOW_GREEN      = HexColor("#27ae60")
INFO_BLUE      = HexColor("#2980b9")
WHITE          = HexColor("#ffffff")
LIGHT_GRAY     = HexColor("#ecf0f1")
TEXT_DARK      = HexColor("#2c3e50")
CODE_BG        = HexColor("#1e1e1e")
CODE_TEXT      = HexColor("#d4d4d4")
GRAY_BORDER    = HexColor("#cccccc")

SEVERITY_COLORS = {
    "CRITICAL": CRITICAL_RED,
    "HIGH":     HIGH_ORANGE,
    "MEDIUM":   MEDIUM_YELLOW,
    "LOW":      LOW_GREEN,
    "INFO":     INFO_BLUE,
}


def _styles():
    base = getSampleStyleSheet()
    extra = {
        "title_s": ParagraphStyle(
            "CustomTitle", parent=base["Title"],
            fontSize=24, textColor=WHITE, spaceAfter=6,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"],
            fontSize=16, textColor=DARK_BG, spaceAfter=6, spaceBefore=12,
            fontName="Helvetica-Bold",
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"],
            fontSize=13, textColor=ACCENT_BLUE, spaceAfter=4, spaceBefore=8,
            fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "Body", parent=base["Normal"],
            fontSize=10, textColor=TEXT_DARK, spaceAfter=4, leading=14,
        ),
        "code": ParagraphStyle(
            "Code", parent=base["Code"],
            fontSize=7, fontName="Courier", textColor=CODE_TEXT,
            backColor=CODE_BG, leftIndent=6, rightIndent=6,
            spaceAfter=4, spaceBefore=4, leading=10,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["Normal"],
            fontSize=8, textColor=HexColor("#7f8c8d"),
        ),
    }
    return base, extra


# ─── Header ───────────────────────────────────────────────────────────────────
def _build_header(session_id: str, timestamp: str, styles_extra: dict) -> list:
    base, s = styles_extra
    header_data = [[
        Paragraph(
            '<font color="white" size="20"><b>🔐 SwarmAudit</b></font>',
            base["Normal"],
        ),
        Paragraph(
            f'<font color="#00d4ff" size="10">Autonomous Security Audit Report<br/>'
            f'<font color="#aaaaaa">Session: {session_id[:8].upper()} | {timestamp}</font></font>',
            base["Normal"],
        ),
    ]]
    tbl = Table(header_data, colWidths=[2.5 * inch, 4.5 * inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
        ("TEXTCOLOR",  (0, 0), (-1, -1), WHITE),
        ("ALIGN",      (0, 0), (0, 0), "LEFT"),
        ("ALIGN",      (1, 0), (1, 0), "RIGHT"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING",    (0, 0), (-1, -1), 12),
    ]))
    return [tbl, Spacer(1, 0.2 * inch)]


# ─── Stats table ──────────────────────────────────────────────────────────────
def _build_stats(vulns: list, file_count: int, total_risk: float) -> list:
    critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high     = sum(1 for v in vulns if v.get("severity") == "HIGH")
    medium   = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    low      = sum(1 for v in vulns if v.get("severity") in ("LOW", "INFO"))

    data = [
        ["Files Scanned", "Critical", "High", "Medium", "Low", "Risk (USD)"],
        [str(file_count), str(critical), str(high), str(medium), str(low),
         f"${total_risk:,.0f}"],
    ]
    col = [1.1 * inch] * 6
    tbl = Table(data, colWidths=col)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK_SECONDARY),
        ("TEXTCOLOR",  (0, 0), (-1, 0), LIGHT_GRAY),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0), 9),
        ("FONTSIZE",   (0, 1), (-1, 1), 14),
        ("FONTNAME",   (0, 1), (-1, 1), "Helvetica-Bold"),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING",    (0, 0), (-1, -1), 8),
        ("GRID",       (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("BACKGROUND", (1, 1), (1, 1), CRITICAL_RED),
        ("TEXTCOLOR",  (1, 1), (1, 1), WHITE),
        ("BACKGROUND", (2, 1), (2, 1), HIGH_ORANGE),
        ("TEXTCOLOR",  (2, 1), (2, 1), WHITE),
        ("BACKGROUND", (3, 1), (3, 1), MEDIUM_YELLOW),
        ("BACKGROUND", (4, 1), (4, 1), LOW_GREEN),
        ("TEXTCOLOR",  (4, 1), (4, 1), WHITE),
        ("BACKGROUND", (5, 1), (5, 1), CRITICAL_RED if total_risk > 100_000 else HIGH_ORANGE),
        ("TEXTCOLOR",  (5, 1), (5, 1), WHITE),
    ]
    tbl.setStyle(TableStyle(style))
    return [tbl, Spacer(1, 0.2 * inch), HRFlowable(width="100%", thickness=2, color=DARK_BG), Spacer(1, 0.1 * inch)]


# ─── Attack chains ────────────────────────────────────────────────────────────
def _build_chains(chains: list, styles_extra: dict) -> list:
    base, s = styles_extra
    elems = [Spacer(1, 0.15 * inch), Paragraph("Attack Chain Analysis", s["h1"])]
    elems.append(Paragraph(
        "Multi-layer attack chains represent combined vulnerability paths that "
        "an attacker could exploit to achieve significant impact.",
        s["body"],
    ))
    elems.append(Spacer(1, 0.1 * inch))

    for i, chain in enumerate(chains):
        impact = chain.get("business_impact_usd", 0)
        hdr_data = [[
            Paragraph(
                f'<b><font color="white">Chain {i+1}: {chain.get("name","Unknown")}</font></b>',
                base["Normal"],
            ),
            Paragraph(
                f'<font color="#ff4444">Risk: {chain.get("risk_level","HIGH")} | '
                f'CVSS: {chain.get("cvss_overall",0):.1f} | Impact: ${impact:,.0f}</font>',
                base["Normal"],
            ),
        ]]
        hdr_tbl = Table(hdr_data, colWidths=[3.5 * inch, 3.5 * inch])
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ACCENT_BLUE),
            ("PADDING",    (0, 0), (-1, -1), 8),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elems.append(hdr_tbl)

        steps = chain.get("chain_steps", [])
        if steps:
            step_data = [["#", "Title", "Layer", "Description"]]
            for step in steps:
                step_data.append([
                    str(step.get("step_num", "")),
                    str(step.get("title", ""))[:50],
                    str(step.get("layer", "code")),
                    str(step.get("description", ""))[:100],
                ])
            st = Table(step_data, colWidths=[0.4 * inch, 1.8 * inch, 0.8 * inch, 4.0 * inch])
            st.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), DARK_SECONDARY),
                ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("GRID",          (0, 0), (-1, -1), 0.5, GRAY_BORDER),
                ("PADDING",       (0, 0), (-1, -1), 4),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
            ]))
            elems.append(st)

        path = chain.get("exploit_path", "")
        if path:
            elems.append(Paragraph(f"<b>Attack Path:</b> {path}", s["body"]))
        elems.append(Spacer(1, 0.15 * inch))

    elems.append(HRFlowable(width="100%", thickness=1, color=GRAY_BORDER))
    return elems


# ─── Vulnerability table ──────────────────────────────────────────────────────
def _build_vuln_table(vulns: list, styles_extra: dict, validation_results: list = None) -> list:
    base, s = styles_extra
    elems = [Spacer(1, 0.15 * inch), Paragraph("Detailed Findings", s["h1"])]
    if not vulns:
        elems.append(Paragraph("No vulnerabilities found.", s["body"]))
        return elems

    # Build validation verdict lookup
    val_map: dict = {}
    for v in (validation_results or []):
        val_map[v.get("vuln_id", "")] = v.get("verdict", "SKIPPED")

    has_validation = bool(val_map)

    sorted_v = sorted(vulns, key=lambda v: float(v.get("cvss_score", 0)), reverse=True)

    if has_validation:
        hdr = ["#", "Title", "Severity", "Verdict", "File", "CVSS", "OWASP"]
        col_w = [0.3*inch, 1.8*inch, 0.7*inch, 0.9*inch, 1.3*inch, 0.4*inch, 1.6*inch]
    else:
        hdr = ["#", "Title", "Severity", "File", "CVSS", "OWASP"]
        col_w = [0.3*inch, 2.2*inch, 0.7*inch, 1.5*inch, 0.4*inch, 1.9*inch]

    rows = [hdr]
    verdict_short = {
        "VERIFIED":     "✓ VERIF",
        "UNVERIFIED":   "~ UNVER",
        "INCONCLUSIVE": "? INCNC",
        "SKIPPED":      "— SKIP",
    }
    for i, v in enumerate(sorted_v[:50]):
        vid = v.get("id", "")
        if has_validation:
            rows.append([
                str(i + 1),
                str(v.get("title", ""))[:55],
                str(v.get("severity", "MEDIUM")),
                verdict_short.get(val_map.get(vid, "SKIPPED"), "—"),
                str(v.get("file_path", ""))[:35],
                f'{v.get("cvss_score", 0):.1f}',
                str(v.get("owasp_category", ""))[:28],
            ])
        else:
            rows.append([
                str(i + 1),
                str(v.get("title", ""))[:60],
                str(v.get("severity", "MEDIUM")),
                str(v.get("file_path", ""))[:40],
                f'{v.get("cvss_score", 0):.1f}',
                str(v.get("owasp_category", ""))[:30],
            ])

    tbl = Table(rows, colWidths=col_w)
    style = [
        ("BACKGROUND",    (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("PADDING",       (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
    ]
    sev_col = 2
    for i, v in enumerate(sorted_v[:50], start=1):
        sev = v.get("severity", "MEDIUM")
        color = SEVERITY_COLORS.get(sev, MEDIUM_YELLOW)
        style.append(("BACKGROUND", (sev_col, i), (sev_col, i), color))
        if sev in ("CRITICAL", "HIGH"):
            style.append(("TEXTCOLOR", (sev_col, i), (sev_col, i), WHITE))

        # Colour the verdict column
        if has_validation:
            vid = v.get("id", "")
            verdict = val_map.get(vid, "SKIPPED")
            v_colors = {
                "VERIFIED":     CRITICAL_RED,
                "UNVERIFIED":   HIGH_ORANGE,
                "INCONCLUSIVE": MEDIUM_YELLOW,
                "SKIPPED":      LIGHT_GRAY,
            }
            if verdict in v_colors:
                style.append(("BACKGROUND", (3, i), (3, i), v_colors[verdict]))
                if verdict == "VERIFIED":
                    style.append(("TEXTCOLOR", (3, i), (3, i), WHITE))

    tbl.setStyle(TableStyle(style))
    elems.append(tbl)
    elems.append(Spacer(1, 0.2 * inch))
    return elems


# ─── Validation summary section ───────────────────────────────────────────────
def _build_validation_summary(validation_results: list, styles_extra: dict) -> list:
    base, s = styles_extra
    elems = [PageBreak(), Paragraph("Sandbox Exploit Validation", s["h1"])]
    elems.append(Paragraph(
        "Each finding was tested in an isolated Docker sandbox (or via static analysis "
        "when Docker is unavailable). A VERIFIED verdict confirms practical exploitability.",
        s["body"],
    ))
    elems.append(Spacer(1, 0.1 * inch))

    counts = {"VERIFIED": 0, "UNVERIFIED": 0, "INCONCLUSIVE": 0, "SKIPPED": 0}
    for v in validation_results:
        verdict = v.get("verdict", "SKIPPED")
        counts[verdict] = counts.get(verdict, 0) + 1

    summary_data = [
        ["Verdict", "Count", "Meaning"],
        ["🔴 VERIFIED",     str(counts["VERIFIED"]),     "Exploit confirmed in sandbox"],
        ["🟡 UNVERIFIED",   str(counts["UNVERIFIED"]),   "No evidence of exploitation"],
        ["🟠 INCONCLUSIVE", str(counts["INCONCLUSIVE"]), "Unable to determine (insufficient data)"],
        ["⚪ SKIPPED",      str(counts["SKIPPED"]),      "No suitable validation profile"],
    ]
    tbl = Table(summary_data, colWidths=[1.5*inch, 0.7*inch, 4.8*inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("GRID",          (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("PADDING",       (0, 0), (-1, -1), 6),
        ("BACKGROUND",    (0, 1), (-1, 1), HexColor("#fde8e8")),
        ("BACKGROUND",    (0, 2), (-1, 2), HexColor("#fefae0")),
        ("BACKGROUND",    (0, 3), (-1, 3), HexColor("#fff3cd")),
        ("BACKGROUND",    (0, 4), (-1, 4), LIGHT_GRAY),
    ]))
    elems.append(tbl)
    elems.append(Spacer(1, 0.15 * inch))

    # Detail rows for VERIFIED findings
    verified = [v for v in validation_results if v.get("verdict") == "VERIFIED"]
    if verified:
        elems.append(Paragraph("Verified Exploitable Findings", s["h2"]))
        for v in verified[:5]:
            elems.append(Paragraph(
                f'<b>Finding ID:</b> {v.get("vuln_id","?")}&nbsp;&nbsp;'
                f'<b>Method:</b> {v.get("method","")}&nbsp;&nbsp;'
                f'<b>Duration:</b> {v.get("duration_ms",0)}ms',
                s["body"],
            ))
            stdout = v.get("stdout_excerpt", "")
            if stdout:
                safe = stdout[:400].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                elems.append(Paragraph(safe, s["code"]))
            if v.get("notes"):
                elems.append(Paragraph(f'<i>{v["notes"][:200]}</i>', s["small"]))
            elems.append(Spacer(1, 0.08 * inch))

    elems.append(HRFlowable(width="100%", thickness=1, color=GRAY_BORDER))
    return elems


# ─── Compliance blast radius section ─────────────────────────────────────────
def _build_compliance_section(blast_radius: dict, plain_summary: str, styles_extra: dict) -> list:
    base, s = styles_extra
    elems = [PageBreak(), Paragraph("Compliance Impact Analysis", s["h1"])]

    if plain_summary:
        elems.append(Paragraph(plain_summary, s["body"]))
        elems.append(Spacer(1, 0.1 * inch))

    fw_counts = blast_radius.get("framework_counts", {})
    if fw_counts:
        elems.append(Paragraph("Framework Exposure", s["h2"]))
        rows = [["Framework", "Controls at Risk"]]
        for fw, count in sorted(fw_counts.items(), key=lambda x: x[1], reverse=True):
            rows.append([fw, str(count)])
        tbl = Table(rows, colWidths=[3 * inch, 4 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), DARK_BG),
            ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("GRID",          (0, 0), (-1, -1), 0.5, GRAY_BORDER),
            ("PADDING",       (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ]))
        elems.append(tbl)
        elems.append(Spacer(1, 0.1 * inch))

    top_controls = blast_radius.get("top_high_risk_controls", [])
    if top_controls:
        elems.append(Paragraph("Top Impacted Controls", s["h2"]))
        rows = [["Framework", "Control ID", "Control Name"]]
        for c in top_controls[:10]:
            rows.append([
                str(c.get("framework", "")),
                str(c.get("control_id", "")),
                str(c.get("control_name", ""))[:60],
            ])
        tbl = Table(rows, colWidths=[1.5*inch, 1.5*inch, 4*inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), ACCENT_BLUE),
            ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.5, GRAY_BORDER),
            ("PADDING",       (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ]))
        elems.append(tbl)
        elems.append(Spacer(1, 0.1 * inch))

    elems.append(HRFlowable(width="100%", thickness=1, color=GRAY_BORDER))
    return elems


# ─── PoC Exploits ─────────────────────────────────────────────────────────────
def _build_exploits(exploits: list, styles_extra: dict) -> list:
    base, s = styles_extra
    if not exploits:
        return []
    elems = [PageBreak(), Paragraph("Proof of Concept Exploits", s["h1"])]
    elems.append(Paragraph(
        "The following scripts demonstrate practical exploitability of identified vulnerabilities.",
        s["body"],
    ))
    elems.append(Spacer(1, 0.1 * inch))
    for ex in exploits[:8]:
        elems.append(Paragraph(
            f'<b>PoC for: {ex.get("vuln_id", "?")} ({ex.get("language","python")})</b>',
            s["h2"],
        ))
        code = str(ex.get("poc_code", ""))[:1500]
        if code:
            safe = code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            elems.append(Paragraph(safe, s["code"]))
        elems.append(Spacer(1, 0.1 * inch))
    return elems


# ─── Patches ──────────────────────────────────────────────────────────────────
def _build_patches(patches: list, styles_extra: dict) -> list:
    base, s = styles_extra
    if not patches:
        return []
    elems = [PageBreak(), Paragraph("Remediation Patches", s["h1"])]
    elems.append(Paragraph(
        "Context-aware patches generated to fix identified vulnerabilities.",
        s["body"],
    ))
    elems.append(Spacer(1, 0.1 * inch))
    for p in patches[:8]:
        elems.append(Paragraph(
            f'<b>Patch: {p.get("vuln_id","?")} — {p.get("file_path","")}</b>',
            s["h2"],
        ))
        if p.get("explanation"):
            elems.append(Paragraph(str(p["explanation"]), s["body"]))
        diff = str(p.get("patch_diff", ""))[:2000]
        if diff:
            safe = diff.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            elems.append(Paragraph(safe, s["code"]))
        elems.append(Spacer(1, 0.1 * inch))
    return elems


# ─── Remediation matrix ───────────────────────────────────────────────────────
def _build_remediation(vulns: list, report_data: dict, styles_extra: dict) -> list:
    base, s = styles_extra
    elems = [PageBreak(), Paragraph("Remediation Priority Matrix", s["h1"])]
    intro = report_data.get(
        "remediation_intro",
        "Prioritize fixes based on CVSS score, exploitability, and business impact. "
        "Address Critical and High findings within 24 hours.",
    )
    elems.append(Paragraph(intro, s["body"]))
    elems.append(Spacer(1, 0.1 * inch))

    for title, filt, _ in [
        ("🔴 Immediate (0-24h) — Critical", [v for v in vulns if v.get("severity") == "CRITICAL"], CRITICAL_RED),
        ("🟠 Short-term (1 week) — High",   [v for v in vulns if v.get("severity") == "HIGH"], HIGH_ORANGE),
        ("🟡 Medium-term (1 month) — Medium",[v for v in vulns if v.get("severity") == "MEDIUM"], MEDIUM_YELLOW),
        ("🟢 Long-term — Low/Info",          [v for v in vulns if v.get("severity") in ("LOW","INFO")], LOW_GREEN),
    ]:
        if filt:
            elems.append(Paragraph(title, s["h2"]))
            for f in filt[:10]:
                elems.append(Paragraph(
                    f'• <b>{f.get("title","")}</b> — {f.get("file_path","")} '
                    f'(CVSS: {f.get("cvss_score",0):.1f})',
                    s["body"],
                ))
            elems.append(Spacer(1, 0.05 * inch))
    return elems


# ─── Business risk ────────────────────────────────────────────────────────────
def _build_risk(risk_data: dict, report_data: dict, styles_extra: dict) -> list:
    base, s = styles_extra
    if not risk_data:
        return []
    elems = [PageBreak(), Paragraph("Business Risk Analysis", s["h1"])]

    items = [
        ("Total Breach Exposure",  f'${risk_data.get("total_risk_usd", 0):,.0f}', CRITICAL_RED),
        ("Regulatory Fine Risk",   f'${risk_data.get("regulatory_fine_usd", 0):,.0f}', HIGH_ORANGE),
        ("Fix Investment",         f'{risk_data.get("fix_investment_hours", 0):.0f} engineer-hours', MEDIUM_YELLOW),
        ("ROI of Fixing",          f'{risk_data.get("roi_ratio", 0):.1f}x return', LOW_GREEN),
    ]
    rows = [["Metric", "Value"]] + [[m, v] for m, v, _ in items]
    tbl = Table(rows, colWidths=[3 * inch, 4 * inch])
    tstyle = [
        ("BACKGROUND",    (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("GRID",          (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("PADDING",       (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
    ]
    for i, (_, _, color) in enumerate(items, start=1):
        tstyle += [
            ("TEXTCOLOR", (1, i), (1, i), color),
            ("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"),
            ("FONTSIZE",  (1, i), (1, i), 13),
        ]
    tbl.setStyle(TableStyle(tstyle))
    elems.append(tbl)
    elems.append(Spacer(1, 0.2 * inch))

    conclusion = report_data.get(
        "conclusion",
        "Immediate remediation of critical findings is strongly recommended. "
        f"The estimated ROI of fixing all vulnerabilities is "
        f'{risk_data.get("roi_ratio", 0):.0f}x the remediation cost.',
    )
    elems.append(Paragraph("Conclusion", s["h1"]))
    elems.append(Paragraph(conclusion, s["body"]))
    return elems


# ─── Public entry point ───────────────────────────────────────────────────────
def generate_pdf_report(session_id: str, report_data: dict) -> str:
    """Generates professional PDF pentest report. Returns file path."""
    os.makedirs("/tmp/reports", exist_ok=True)
    output_path = f"/tmp/reports/{session_id}_report.pdf"

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=1 * inch,
        bottomMargin=0.75 * inch,
        title="SwarmAudit Security Report",
        author="SwarmAudit",
    )

    base_styles, extra_styles = _styles()
    styles_pair = (base_styles, extra_styles)

    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    vulns = report_data.get("vulnerabilities", [])
    scan_result = report_data.get("scan_result", {})
    file_count = scan_result.get("file_count", 0)
    risk_data = report_data.get("risk", {})
    total_risk = float(risk_data.get("total_risk_usd", 0)) if risk_data else 0.0

    elements = []

    # Header
    elements.extend(_build_header(session_id, timestamp, styles_pair))

    # Stats bar
    elements.extend(_build_stats(vulns, file_count, total_risk))

    # Executive summary
    elements.append(Paragraph("Executive Summary", extra_styles["h1"]))
    exec_summary = report_data.get(
        "executive_summary",
        f"This audit identified {len(vulns)} vulnerabilities across {file_count} files. "
        f"The estimated breach exposure is ${total_risk:,.0f}. "
        f"Immediate action is recommended on critical findings.",
    )
    elements.append(Paragraph(exec_summary, extra_styles["body"]))
    tech_stack = scan_result.get("tech_stack", [])
    if tech_stack:
        elements.append(Paragraph(
            f"<b>Technology Stack:</b> {', '.join(tech_stack)}",
            extra_styles["body"],
        ))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(HRFlowable(width="100%", thickness=1, color=GRAY_BORDER))

    # Attack chains
    chains = report_data.get("attack_chains", [])
    if chains:
        elements.extend(_build_chains(chains, styles_pair))

    # Vulnerability table (with validation verdict column if available)
    elements.extend(_build_vuln_table(
        vulns, styles_pair,
        validation_results=report_data.get("validation_results", []),
    ))

    # PoC exploits
    elements.extend(_build_exploits(report_data.get("exploits", []), styles_pair))

    # Patches
    elements.extend(_build_patches(report_data.get("patches", []), styles_pair))

    # Validation summary
    if report_data.get("validation_results"):
        elements.extend(_build_validation_summary(report_data["validation_results"], styles_pair))

    # Compliance blast radius
    if report_data.get("compliance_mappings"):
        elements.extend(_build_compliance_section(
            report_data.get("compliance_blast_radius", {}),
            report_data.get("plain_language_summary", ""),
            styles_pair,
        ))

    # Remediation matrix
    elements.extend(_build_remediation(vulns, report_data, styles_pair))

    # Business risk
    elements.extend(_build_risk(risk_data, report_data, styles_pair))

    # Footer
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRAY_BORDER))
    footer = (
        f"SwarmAudit | Generated: {timestamp} | "
        f"Session: {session_id[:8].upper()} | "
        "For authorized security testing only."
    )
    elements.append(Paragraph(footer, extra_styles["small"]))

    doc.build(elements)
    return output_path
