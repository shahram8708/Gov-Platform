"""Utilities for normalizing AI output into sanitized markdown and HTML."""
import re
from typing import Dict, List, Optional

import bleach
from markdown_it import MarkdownIt


# Single parser reused for performance; HTML disabled for safety
_md = MarkdownIt("commonmark", {'linkify': True, 'typographer': True, 'html': False}).enable(["linkify", "table", "strikethrough"])

WEB_ALLOWED_TAGS = [
    "p",
    "ul",
    "ol",
    "li",
    "strong",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "blockquote",
    "code",
    "pre",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "hr",
    "a",
    "br",
]

EMAIL_ALLOWED_TAGS = [
    "p",
    "ul",
    "ol",
    "li",
    "strong",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "hr",
    "a",
    "br",
]

ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "rel", "target"],
    "th": ["colspan", "rowspan", "align"],
    "td": ["colspan", "rowspan", "align"],
}


def _normalize_whitespace(text: str) -> str:
    cleaned = re.sub(r"[\r\t]+", " ", text or "")
    cleaned = re.sub(r" +", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _render_markdown(md_text: str) -> str:
    rendered = _md.render(md_text or "")
    return rendered


def markdown_to_html(md_text: str, *, for_email: bool = False) -> str:
    rendered = _render_markdown(_normalize_whitespace(md_text))
    allowed = EMAIL_ALLOWED_TAGS if for_email else WEB_ALLOWED_TAGS
    sanitized = bleach.clean(rendered, tags=allowed, attributes=ALLOWED_ATTRIBUTES, strip=True)
    return sanitized


def markdown_to_email_html(md_text: str) -> str:
    safe_html = markdown_to_html(md_text, for_email=True)
    return (
        "<div style=\"font-family: 'Segoe UI', Arial, sans-serif; font-size: 14px; line-height: 1.6; color: #0f172a;\">"
        f"{safe_html}"
        "</div>"
    )


def markdown_to_plaintext(md_text: str) -> str:
    rendered = markdown_to_html(md_text, for_email=False)
    text_only = bleach.clean(rendered, tags=[], attributes={}, strip=True)
    text_only = re.sub(r"\s+", " ", text_only).strip()
    return text_only


def format_sections(sections: List[Dict[str, object]]) -> str:
    """Build markdown from an ordered list of sections."""
    parts: List[str] = []
    for section in sections:
        title = _normalize_whitespace(str(section.get("title", "") or ""))
        if title:
            parts.append(f"## {title}")
        bullets = section.get("bullets") or []
        body = section.get("body") or ""
        if isinstance(bullets, list):
            for bullet in bullets:
                if bullet is None:
                    continue
                bullet_text = _normalize_whitespace(str(bullet))
                if bullet_text:
                    parts.append(f"- {bullet_text}")
        if body:
            parts.append(_normalize_whitespace(str(body)))
        parts.append("")
    return "\n".join([p for p in parts if p.strip()])


def format_complaint_markdown(complaint: Dict[str, object], analysis: Dict[str, object], *, context: Optional[Dict[str, object]] = None) -> str:
    severity = complaint.get("severity") or complaint.get("severity_level")
    location = complaint.get("location") or {}
    sections = [
        {
            "title": "Issue Summary",
            "bullets": [
                f"Title: {complaint.get('title', '')}",
                f"Type: {complaint.get('complaint_type', '')}",
                f"Severity: {severity}",
            ],
        },
        {
            "title": "AI Observations",
            "body": analysis.get("ai_summary")
            or analysis.get("suggested_description")
            or complaint.get("description"),
            "bullets": [
                f"Detected Issue: {analysis.get('issue_type') or complaint.get('complaint_type', '')}",
                f"Recommendations: {', '.join(analysis.get('recommendations', []) or [])}" if analysis.get("recommendations") else None,
            ],
        },
        {
            "title": "Authenticity",
            "bullets": [
                f"Flag: {analysis.get('authenticity_flag', 'UNVERIFIABLE')}",
                *(analysis.get("authenticity_reasons") or []),
            ],
        },
    ]
    if location:
        loc_label = location.get("location_name") or location.get("project_name") or location.get("name")
        coords = None
        lat = location.get("latitude")
        lng = location.get("longitude")
        if lat and lng:
            coords = f"Lat {lat}, Lng {lng}"
        sections.append(
            {
                "title": "Location",
                "bullets": [v for v in [loc_label, coords] if v],
            }
        )
    if context and context.get("follow_up"):
        sections.append(
            {
                "title": "Follow-up",
                "bullets": [
                    f"Level: {context['follow_up'].get('level')}",
                    f"Reason: {context['follow_up'].get('reason')}",
                ],
            }
        )
    return format_sections(sections)


def format_project_discovery_markdown(location: Dict[str, object], projects: List[Dict[str, object]]) -> str:
    header = location.get("name") or "Requested Location"
    sections: List[Dict[str, object]] = [
        {
            "title": "Location",
            "bullets": [
                f"Name: {header}",
                f"Coordinates: {location.get('latitude')} , {location.get('longitude')}" if location.get("latitude") and location.get("longitude") else None,
            ],
        }
    ]
    for project in projects:
        sections.append(
            {
                "title": f"Project: {project.get('project_name', '')}",
                "bullets": [
                    f"Type: {project.get('project_type', '')}",
                    f"Status: {project.get('current_status', '')}",
                    f"Contractor: {(project.get('contractor') or {}).get('name', '')}",
                    f"Department: {(project.get('government_department') or {}).get('department_name', '')}",
                ],
                "body": "Sources: " + ", ".join(project.get("source_links") or []),
            }
        )
    return format_sections(sections)


def format_verification_markdown(user_name: str, verification_link: str, expires_at: str) -> str:
    sections = [
        {
            "title": "Verify Your Account",
            "body": f"Hello {user_name}, please confirm your email to activate your account.",
            "bullets": [f"Verification link: {verification_link}", f"Expires at: {expires_at} UTC"],
        },
        {
            "title": "Security Reminder",
            "bullets": ["If you did not request this, ignore this email."],
        },
    ]
    return format_sections(sections)


def format_rti_ready_markdown(reference_id: str, download_url: str) -> str:
    sections = [
        {
            "title": "RTI Report Ready",
            "bullets": [f"Reference: {reference_id}", f"Download: {download_url}"],
            "body": "Your RTI / legal-ready PDF has been generated. The checksum will be required for validation.",
        },
        {
            "title": "Next Steps",
            "bullets": ["Store the PDF and checksum securely.", "Share only with authorized parties."],
        },
    ]
    return format_sections(sections)
