"""SMTP-backed email dispatcher for complaint notifications and follow-ups."""
import hashlib
import mimetypes
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from datetime import datetime
from typing import Dict, List, Tuple

from flask import current_app, render_template

from extensions import db
from sqlalchemy import func

from models import Complaint, EmailAuditLog, User
from utils.ai_markdown_formatter import (
    format_complaint_markdown,
    format_rti_ready_markdown,
    format_verification_markdown,
    markdown_to_email_html,
    markdown_to_plaintext,
)


class EmailDeliveryError(Exception):
    """Raised when email dispatch fails."""


def _audit_metadata(metadata: List[Dict], template: str, markdown_body: str) -> List[Dict]:
    """Append template and markdown trace for audit logging."""
    traced = list(metadata or [])
    traced.append({"template": template, "markdown": markdown_body})
    return traced


def _render_email_content(template: str, subject: str, markdown_body: str, context: Dict) -> Tuple[str, str]:
    """Return plaintext and HTML bodies using a shared markdown source."""
    text_body = markdown_to_plaintext(markdown_body)
    ctx = dict(context or {})
    preheader = ctx.pop("preheader", "")
    html_body = render_template(
        template,
        subject=subject,
        content_html=markdown_to_email_html(markdown_body),
        preheader=preheader,
        **ctx,
    )
    return text_body, html_body


def _complaint_context(complaint: Complaint) -> Dict:
    project = complaint.project
    location = complaint.location_snapshot or {}
    return {
        "complaint_id": str(complaint.id),
        "citizen_name": complaint.user.full_name if complaint.user else "Citizen",
        "citizen_email": complaint.user.email if complaint.user else "",
        "project_name": project.project_name if project else "",
        "project_type": project.project_type if project else "",
        "complaint_type": complaint.complaint_type,
        "severity": complaint.severity_level,
        "status": complaint.status,
        "location": location,
    }


def _resolve_sender(fallback: str | None) -> str:
    return current_app.config.get("MAIL_DEFAULT_SENDER") or (fallback or "")


def _safe_attachment_path(path: str, upload_root: str) -> str:
    abs_root = os.path.abspath(upload_root)
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(abs_root):
        raise EmailDeliveryError("Attachment path rejected: outside allowed upload root")
    if not os.path.isfile(abs_path):
        raise EmailDeliveryError("Attachment missing on disk")
    return abs_path


def _attachment_metadata(path: str, recorded_hash: str | None = None) -> Dict:
    size_bytes = os.path.getsize(path)
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    digest = sha256.hexdigest()
    mime_type, _ = mimetypes.guess_type(path)
    return {
        "filename": os.path.basename(path),
        "size_bytes": size_bytes,
        "sha256": digest,
        "recorded_hash": recorded_hash,
        "mime_type": mime_type or "application/octet-stream",
    }


def _prepare_attachments(complaint: Complaint) -> Tuple[List[Tuple[str, bytes, str]], List[Dict]]:
    attachments: List[Tuple[str, bytes, str]] = []
    metadata: List[Dict] = []
    upload_root = current_app.config.get("COMPLAINT_UPLOAD_FOLDER")
    max_bytes = int(current_app.config.get("MAX_IMAGE_UPLOAD_BYTES", 8 * 1024 * 1024))

    for image in complaint.images:
        path = _safe_attachment_path(image.image_path, upload_root)
        meta = _attachment_metadata(path, recorded_hash=image.image_hash)
        if meta["size_bytes"] > max_bytes:
            raise EmailDeliveryError("Attachment exceeds allowed size limit")
        with open(path, "rb") as f:
            payload = f.read()
        if hashlib.sha256(payload).hexdigest() != image.image_hash:
            raise EmailDeliveryError("Attachment integrity check failed")
        mime_type = meta["mime_type"]
        if mime_type not in ("image/jpeg", "image/png", "image/webp"):
            raise EmailDeliveryError("Attachment type not permitted for email dispatch")
        attachments.append((os.path.basename(path), payload, mime_type))
        metadata.append(meta)
    return attachments, metadata


def _recipient_mapping(complaint: Complaint) -> Tuple[List[str], List[str]]:
    recipients: List[str] = []
    cc_list: List[str] = []
    project = complaint.project
    contractor_email = getattr(project.contractor, "email", None) if project and project.contractor else None
    dept_email = getattr(project.department, "official_email", None) if project and project.department else None
    monitor_email = current_app.config.get("MAIL_MONITOR_ADDRESS")
    higher_auth_email = current_app.config.get("MAIL_HIGHER_AUTHORITY")

    for address in (contractor_email, dept_email):
        if address and address not in recipients:
            recipients.append(address)

    for cc in (higher_auth_email, monitor_email):
        if cc and cc not in recipients and cc not in cc_list:
            cc_list.append(cc)

    return recipients, cc_list


def _resolve_user_from_emails(addresses: List[str]) -> User | None:
    for address in addresses:
        normalized = (address or "").strip().lower()
        if not normalized:
            continue
        user = User.query.filter(func.lower(User.email) == normalized, User.is_email_verified.is_(True)).first()
        if user:
            return user
    return None


def _compose_report(complaint: Complaint) -> str:
    analysis = complaint.images[0].ai_analysis_result if complaint.images else {}
    location = complaint.location_snapshot or {}
    markdown_body = format_complaint_markdown(
        {
            "title": complaint.title,
            "complaint_type": complaint.complaint_type,
            "severity": complaint.severity_level,
            "description": complaint.description,
            "location": location,
        },
        analysis or {},
    )
    return markdown_body


def build_initial_payload(complaint: Complaint):
    sender = _resolve_sender(complaint.user.email if complaint.user else None)
    if not sender:
        raise EmailDeliveryError("Complaint submitter email missing")
    recipients, cc = _recipient_mapping(complaint)
    markdown_body = _compose_report(complaint)
    attachments, metadata = _prepare_attachments(complaint)
    subject = f"Official Complaint Notice - Reference {complaint.id}"
    context = {
        **_complaint_context(complaint),
        "preheader": "Action required on registered citizen complaint.",
    }
    text_body, html_body = _render_email_content(
        "email/authority_notification.html", subject, markdown_body, context
    )
    audit_meta = _audit_metadata(metadata, "email/authority_notification.html", markdown_body)
    return sender, recipients, cc, subject, text_body, html_body, attachments, audit_meta


def _dispatch_email(subject: str, text_body: str, html_body: str, sender: str, recipients: List[str], cc: List[str], attachments: List[Tuple[str, bytes, str]]) -> None:
    if not recipients:
        raise EmailDeliveryError("No recipients resolved for email dispatch")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Reply-To"] = sender
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    fallback_text = text_body or markdown_to_plaintext(html_body)
    msg.set_content(fallback_text)
    msg.add_alternative(html_body, subtype="html")

    for filename, payload, mime_type in attachments:
        maintype, subtype = (mime_type.split("/", 1) if "/" in mime_type else ("application", "octet-stream"))
        msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)

    host = current_app.config.get("MAIL_SERVER")
    port = int(current_app.config.get("MAIL_PORT", 25))
    username = current_app.config.get("MAIL_USERNAME")
    password = current_app.config.get("MAIL_PASSWORD")
    use_tls = bool(current_app.config.get("MAIL_USE_TLS"))
    use_ssl = bool(current_app.config.get("MAIL_USE_SSL"))

    if not host:
        raise EmailDeliveryError("MAIL_SERVER is not configured")

    try:
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context) as server:
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port) as server:
                server.ehlo()
                if use_tls:
                    server.starttls(context=ssl.create_default_context())
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
    except Exception as exc:  # pragma: no cover - external I/O
        raise EmailDeliveryError(str(exc)) from exc


def _persist_audit(
    complaint: Complaint,
    sender: str,
    recipients: List[str],
    cc: List[str],
    subject: str,
    body: str,
    metadata: List[Dict],
    status: str,
    error: str | None = None,
) -> None:
    resolved_user = _resolve_user_from_emails(recipients + cc)
    log = EmailAuditLog(
        complaint_id=complaint.id,
        sender_email=sender,
        recipient_email=", ".join(recipients),
        cc_emails=cc,
        resolved_user_id=resolved_user.id if resolved_user else None,
        subject=subject,
        email_body_snapshot=body,
        attachments_metadata=metadata,
        delivery_status=status,
        error_message=error,
    )
    db.session.add(log)


def send_initial_complaint_email(complaint: Complaint) -> None:
    existing = EmailAuditLog.query.filter(
        EmailAuditLog.complaint_id == complaint.id,
        EmailAuditLog.delivery_status == "SENT",
        EmailAuditLog.subject.ilike("Official Complaint Notice%"),
    ).first()
    if existing:
        return
    sender, recipients, cc, subject, text_body, html_body, attachments, metadata = build_initial_payload(complaint)

    _dispatch_email(subject, text_body, html_body, sender, recipients, cc, attachments)
    _persist_audit(complaint, sender, recipients, cc, subject, html_body, metadata, status="SENT")
    complaint.notification_sent_at = complaint.notification_sent_at or datetime.utcnow()
    complaint.last_email_status = "SENT"
    db.session.commit()


def build_follow_up_payload(complaint: Complaint, level: int, reason: str):
    sender = _resolve_sender(complaint.user.email if complaint.user else None)
    if not sender:
        raise EmailDeliveryError("Complaint submitter email missing")
    recipients, cc = _recipient_mapping(complaint)
    attachments, metadata = _prepare_attachments(complaint)
    escalation_note = "URGENT" if level > 1 else "Reminder"
    subject = f"{escalation_note}: Complaint {complaint.id} requires action (Follow-up {level})"
    markdown_body = format_complaint_markdown(
        {
            "title": complaint.title,
            "complaint_type": complaint.complaint_type,
            "severity": complaint.severity_level,
            "description": complaint.description,
            "location": complaint.location_snapshot or {},
        },
        complaint.images[0].ai_analysis_result if complaint.images else {},
        context={"follow_up": {"level": level, "reason": reason}},
    )
    context = {
        **_complaint_context(complaint),
        "preheader": "Reminder: complaint pending action.",
        "follow_up_level": level,
        "follow_up_reason": reason,
    }
    text_body, html_body = _render_email_content(
        "email/follow_up_reminder.html", subject, markdown_body, context
    )
    audit_meta = _audit_metadata(metadata, "email/follow_up_reminder.html", markdown_body)
    return sender, recipients, cc, subject, text_body, html_body, attachments, audit_meta


def send_follow_up_email(complaint: Complaint, level: int, reason: str) -> None:
    sender, recipients, cc, subject, text_body, html_body, attachments, metadata = build_follow_up_payload(complaint, level, reason)

    _dispatch_email(subject, text_body, html_body, sender, recipients, cc, attachments)
    _persist_audit(complaint, sender, recipients, cc, subject, html_body, metadata, status="SENT")
    complaint.follow_up_count = (complaint.follow_up_count or 0) + 1
    complaint.last_follow_up_at = datetime.utcnow()
    complaint.last_email_status = "SENT"
    db.session.commit()


def record_failed_email(complaint: Complaint, sender: str, recipients: List[str], cc: List[str], subject: str, body: str, metadata: List[Dict], error: str) -> None:
    _persist_audit(complaint, sender, recipients, cc, subject, body, metadata, status="FAILED", error=error)
    complaint.notification_sent_at = complaint.notification_sent_at or datetime.utcnow()
    complaint.last_email_status = "FAILED"
    db.session.commit()


def send_citizen_confirmation_email(complaint: Complaint) -> None:
    """Send confirmation to the citizen with the markdown-normalized AI summary."""
    if not complaint.user or not complaint.user.email:
        return
    analysis = complaint.images[0].ai_analysis_result if complaint.images else {}
    markdown_body = format_complaint_markdown(
        {
            "title": complaint.title,
            "complaint_type": complaint.complaint_type,
            "severity": complaint.severity_level,
            "description": complaint.description,
            "location": complaint.location_snapshot or {},
        },
        analysis or {},
    )
    subject = f"Complaint {complaint.id} submitted"
    context = {
        **_complaint_context(complaint),
        "preheader": "Your complaint has been logged and routed to authorities.",
    }
    text_body, html_body = _render_email_content("email/complaint_submitted.html", subject, markdown_body, context)
    _dispatch_email(subject, text_body, html_body, _resolve_sender(context["citizen_email"]), [complaint.user.email], [], [])


def send_verification_email(recipient: str, user_name: str, verification_link: str, expires_at: str) -> None:
    markdown_body = format_verification_markdown(user_name, verification_link, expires_at)
    subject = "Verify your account"
    context = {
        "preheader": "Confirm your email to activate your account.",
        "verification_link": verification_link,
        "user_name": user_name,
        "expires_at": expires_at,
    }
    text_body, html_body = _render_email_content("email/verify_email.html", subject, markdown_body, context)
    sender = current_app.config.get("MAIL_DEFAULT_SENDER") or recipient
    _dispatch_email(subject, text_body, html_body, sender, [recipient], [], [])


def send_rti_ready_email(recipient: str, reference_id: str, download_url: str) -> None:
    markdown_body = format_rti_ready_markdown(reference_id, download_url)
    subject = f"RTI report ready: {reference_id}"
    context = {
        "preheader": "Your RTI / legal-ready PDF is available for download.",
        "reference_id": reference_id,
        "download_url": download_url,
    }
    text_body, html_body = _render_email_content("email/rti_report_ready.html", subject, markdown_body, context)
    sender = current_app.config.get("MAIL_DEFAULT_SENDER") or recipient
    _dispatch_email(subject, text_body, html_body, sender, [recipient], [], [])
