"""PDF generation utility for legal/audit-ready RTI exports."""

import hashlib
from pathlib import Path
from typing import Dict, List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


PAGE_MARGIN = 20 * mm
CONTENT_WIDTH = A4[0] - (PAGE_MARGIN * 2)


styles = getSampleStyleSheet()

TITLE_STYLE = ParagraphStyle(
    name="ReportTitle",
    parent=styles["Title"],
    fontName="Helvetica-Bold",
    fontSize=16,
    leading=20,
    alignment=0,
    spaceAfter=12,
    textColor=colors.black,
)

DISCLAIMER_STYLE = ParagraphStyle(
    name="Disclaimer",
    fontName="Helvetica",
    fontSize=8,
    leading=10,
    textColor=colors.black,
    wordWrap="CJK",
    splitLongWords=True,
)

HEADING_STYLE = ParagraphStyle(
    name="SectionHeading",
    fontName="Helvetica-Bold",
    fontSize=11,
    leading=14,
    textColor=colors.black,
    spaceBefore=4,
    spaceAfter=6,
    keepWithNext=True,
    wordWrap="CJK",
    splitLongWords=True,
)

BODY_STYLE = ParagraphStyle(
    name="BodyText",
    fontName="Helvetica",
    fontSize=9,
    leading=12,
    textColor=colors.black,
    wordWrap="CJK",
    splitLongWords=True,
)

SMALL_STYLE = ParagraphStyle(
    name="SmallText",
    parent=BODY_STYLE,
    fontSize=8,
    leading=10,
)

LABEL_STYLE = ParagraphStyle(
    name="LabelText",
    parent=BODY_STYLE,
    fontName="Helvetica-Bold",
)

URL_STYLE = ParagraphStyle(
    name="URLText",
    parent=BODY_STYLE,
    textColor=colors.HexColor("#0b5394"),
)


def _para(value: str, style: ParagraphStyle = BODY_STYLE) -> Paragraph:
    """Create a wrapping paragraph with safe escaping and soft line handling."""
    text = escape(str(value or "").strip())
    text = text.replace("\n", "<br/>")
    # Ensure empty cells stay visible but unobtrusive
    text = text if text else "N/A"
    return Paragraph(text, style)


def _kv_table(rows: List[List[str]]) -> Table:
    table_rows = []
    for idx, (label, value) in enumerate(rows):
        label_style = LABEL_STYLE if idx == 0 else LABEL_STYLE
        table_rows.append([_para(label, label_style), _para(value, BODY_STYLE)])

    table = Table(table_rows, colWidths=[60 * mm, CONTENT_WIDTH - (60 * mm)], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _list_block(title: str, items: List[str]) -> Table:
    rows = [[title, ""]]
    if not items:
        rows.append(["", "Not available"])
    else:
        for item in items:
            rows.append(["", item])
    table_rows = []
    for idx, row in enumerate(rows):
        is_header = idx == 0
        table_rows.append([
            _para(row[0], LABEL_STYLE if is_header else LABEL_STYLE),
            _para(row[1], BODY_STYLE),
        ])

    table = Table(table_rows, colWidths=[40 * mm, CONTENT_WIDTH - (40 * mm)], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _table_with_header(rows: List[List[str]], col_widths: List[float]) -> Table:
    formatted_rows: List[List] = []
    for idx, row in enumerate(rows):
        is_header = idx == 0
        formatted_row = []
        for cell in row:
            if isinstance(cell, Paragraph):
                formatted_row.append(cell)
            else:
                formatted_row.append(_para(cell, LABEL_STYLE if is_header else BODY_STYLE))
        formatted_rows.append(formatted_row)

    table = Table(formatted_rows, colWidths=col_widths, repeatRows=1, splitByRow=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def generate_pdf(payload: Dict, output_path: str) -> str:
    """Generate a monochrome, audit-ready PDF and return its sha256 checksum."""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=PAGE_MARGIN,
        rightMargin=PAGE_MARGIN,
        topMargin=PAGE_MARGIN,
        bottomMargin=PAGE_MARGIN,
        title="RTI / Legal Evidence Report",
        allowSplitting=True,
    )

    story: List = []
    story.append(Paragraph("RTI / Legal Evidence Report", TITLE_STYLE))
    story.append(
        Paragraph(
            "Generated by system. For RTI / legal use only. Document is read-only and contains digital traceability markers.",
            DISCLAIMER_STYLE,
        )
    )
    story.append(Spacer(1, 8))

    meta_rows = [
        ["Document Metadata", ""],
        ["Reference ID", payload.get("reference_id", "")],
        ["Generated At (UTC)", payload.get("generated_at", "")],
        ["Entity Type", payload.get("entity_type", "")],
        ["Entity ID", payload.get("entity_id", "")],
        ["Checksum (sha256)", payload.get("checksum", "Pending")],
    ]
    story.append(_kv_table(meta_rows))
    story.append(Spacer(1, 10))

    if payload.get("project"):
        project = payload["project"]
        story.append(Paragraph("1. Project Details", HEADING_STYLE))
        project_rows = [
            ["", ""],
            ["Project Name", project.get("project_name", "")],
            ["Project Type", project.get("project_type", "")],
            ["Status", project.get("current_status", "")],
            ["Cost", project.get("project_cost", "")],
            ["Start Date", project.get("start_date", "")],
            ["Expected End", project.get("expected_end_date", "")],
            ["Location", project.get("location_name", "")],
            ["Coordinates", project.get("coordinates", "")],
        ]
        story.append(_kv_table(project_rows))
        story.append(Spacer(1, 8))

    if payload.get("contractor"):
        contractor = payload["contractor"]
        story.append(Paragraph("2. Contractor Details", HEADING_STYLE))
        contractor_rows = [
            ["", ""],
            ["Name", contractor.get("name", "")],
            ["Company", contractor.get("company_name", "")],
            ["Registration", contractor.get("registration_number", "")],
            ["Email", contractor.get("email", "")],
            ["Phone", contractor.get("phone", "")],
            ["Address", contractor.get("office_address", "")],
            ["Rating", contractor.get("rating_display", "")],
        ]
        story.append(_kv_table(contractor_rows))
        story.append(Spacer(1, 8))

    if payload.get("department"):
        dept = payload["department"]
        story.append(Paragraph("3. Department & Officer Details", HEADING_STYLE))
        dept_rows = [
            ["", ""],
            ["Department", dept.get("department_name", "")],
            ["Level", dept.get("ministry_level", "")],
            ["Email", dept.get("official_email", "")],
            ["Phone", dept.get("official_phone", "")],
            ["Office Address", dept.get("office_address", "")],
        ]
        story.append(_kv_table(dept_rows))
        officer_lines = [
            f"{o.get('officer_name', '')} ({o.get('designation', '')}) - {o.get('official_email', 'N/A')}"
            for o in dept.get("officers", [])
        ]
        story.append(_list_block("Responsible Officers", officer_lines))
        story.append(Spacer(1, 8))

    if payload.get("tenders"):
        story.append(Paragraph("4. Tender References", HEADING_STYLE))
        tender_rows = [["Tender ID", "Portal", "Published", "URL"]]
        for tender in payload.get("tenders", []):
            tender_rows.append(
                [
                    tender.get("tender_id", ""),
                    tender.get("tender_portal_name", ""),
                    tender.get("published_date", ""),
                    _para(tender.get("tender_url", ""), URL_STYLE),
                ]
            )
        tender_table = _table_with_header(
            [[cell if isinstance(cell, str) else cell for cell in row] for row in tender_rows],
            col_widths=[35 * mm, 40 * mm, 35 * mm, CONTENT_WIDTH - (35 * mm + 40 * mm + 35 * mm)],
        )
        story.append(tender_table)
        story.append(Spacer(1, 8))

    if payload.get("timeline"):
        story.append(Paragraph("5. Timeline & Status History", HEADING_STYLE))
        timeline_rows = [["When", "Event", "Details"]]
        for entry in payload.get("timeline", []):
            timeline_rows.append([entry.get("timestamp", ""), entry.get("label", ""), entry.get("detail", "")])
        timeline_table = _table_with_header(
            timeline_rows,
            col_widths=[35 * mm, 45 * mm, CONTENT_WIDTH - (35 * mm + 45 * mm)],
        )
        story.append(timeline_table)
        story.append(Spacer(1, 8))

    if payload.get("complaint"):
        complaint = payload["complaint"]
        story.append(Paragraph("6. Complaint Details", HEADING_STYLE))
        complaint_rows = [
            ["", ""],
            ["Complaint ID", complaint.get("id", "")],
            ["Type", complaint.get("complaint_type", "")],
            ["Severity", complaint.get("severity_level", "")],
            ["Status", complaint.get("status", "")],
            ["Filed At", complaint.get("created_at", "")],
        ]
        story.append(_kv_table(complaint_rows))
        story.append(Spacer(1, 6))
        story.append(_para(f"Summary: {complaint.get('description', '')}", BODY_STYLE))
        story.append(Spacer(1, 6))

    if payload.get("ai_findings"):
        findings = payload["ai_findings"]
        story.append(Paragraph("7. AI Findings (Read-Only)", HEADING_STYLE))
        findings_rows = [
            ["", ""],
            ["Detected Issue", findings.get("issue_type", "")],
            ["Suggested Severity", findings.get("suggested_severity", "")],
            ["Authenticity", findings.get("authenticity_flag", "")],
            ["AI Summary", findings.get("ai_summary", "")],
        ]
        story.append(_kv_table(findings_rows))
        reasons = findings.get("authenticity_reasons") or []
        story.append(_list_block("Authenticity Notes", reasons))
        story.append(Spacer(1, 8))

    if payload.get("communications"):
        story.append(Paragraph("8. Email Communication Log", HEADING_STYLE))
        comm_rows = [["When", "Subject", "Status", "Recipients"]]
        for log in payload.get("communications", []):
            comm_rows.append(
                [
                    log.get("sent_at", ""),
                    log.get("subject", ""),
                    log.get("delivery_status", ""),
                    log.get("recipient_email", ""),
                ]
            )
        comm_table = _table_with_header(
            comm_rows,
            col_widths=[30 * mm, 55 * mm, 25 * mm, CONTENT_WIDTH - (30 * mm + 55 * mm + 25 * mm)],
        )
        story.append(comm_table)
        story.append(Spacer(1, 8))

    if payload.get("source_links"):
        story.append(Paragraph("9. Source Links", HEADING_STYLE))
        source_table = _list_block("Verified Sources", payload.get("source_links", []))
        story.append(source_table)
        story.append(Spacer(1, 6))

    story.append(Paragraph("10. Legal Disclaimer", HEADING_STYLE))
    story.append(
        _para(
            "This document is system-generated, read-only, and intended for Right to Information (RTI), court, or audit use. Any alteration invalidates the checksum. Verify checksum against registry before submission.",
            BODY_STYLE,
        )
    )

    doc.build(story)

    with open(output_path, "rb") as handle:
        checksum = hashlib.sha256(handle.read()).hexdigest()

    return checksum
