"""Automated follow-up agent to enforce complaint accountability."""
from datetime import datetime, timedelta
from typing import List, Tuple

from flask import current_app

from extensions import db
from models import Complaint
from utils.email_service import (
    EmailDeliveryError,
    build_follow_up_payload,
    record_failed_email,
    send_follow_up_email,
)


def _due_complaints(now: datetime, first_after: int, interval: int, max_reminders: int) -> List[Tuple[Complaint, datetime]]:
    candidates = Complaint.query.filter(
        Complaint.notification_sent_at.isnot(None),
        Complaint.status.notin_(["RESOLVED", "CLOSED"]),
    ).all()
    due: List[Tuple[Complaint, datetime]] = []
    for complaint in candidates:
        if (complaint.follow_up_count or 0) >= max_reminders:
            continue
        if complaint.follow_up_count == 0:
            reference_time = complaint.notification_sent_at or complaint.created_at
            due_at = reference_time + timedelta(days=first_after)
            reason = f"No acknowledgement within {first_after} day(s)"
        else:
            reference_time = complaint.last_follow_up_at or complaint.notification_sent_at or complaint.created_at
            due_at = reference_time + timedelta(days=interval)
            reason = f"Complaint still unresolved after prior follow-up #{complaint.follow_up_count}"
        if now >= due_at:
            due.append((complaint, reason))
    return due


def run_follow_up_cycle(app) -> None:
    with app.app_context():
        now = datetime.utcnow()
        first_after = int(current_app.config.get("FOLLOW_UP_FIRST_AFTER_DAYS", 2))
        interval = int(current_app.config.get("FOLLOW_UP_INTERVAL_DAYS", 3))
        max_reminders = int(current_app.config.get("FOLLOW_UP_MAX_REMINDERS", 3))

        for complaint, reason in _due_complaints(now, first_after, interval, max_reminders):
            level = (complaint.follow_up_count or 0) + 1
            try:
                send_follow_up_email(complaint, level=level, reason=reason)
                current_app.logger.info(
                    "Follow-up email dispatched",
                    extra={"complaint_id": str(complaint.id), "level": level, "reason": reason},
                )
            except EmailDeliveryError as exc:
                try:
                    payload = build_follow_up_payload(complaint, level=level, reason=reason)
                    sender, recipients, cc, subject, _text, html_body, _attachments, metadata = payload
                except Exception:
                    sender = complaint.user.email if complaint.user else ""
                    recipients = []
                    cc = []
                    subject = f"Follow-up attempt failed for complaint {complaint.id}"
                    html_body = reason
                    metadata = []
                record_failed_email(
                    complaint,
                    sender=sender,
                    recipients=recipients,
                    cc=cc,
                    subject=subject,
                    body=html_body,
                    metadata=metadata,
                    error=str(exc),
                )
                current_app.logger.warning(
                    "Follow-up dispatch failed",
                    extra={"complaint_id": str(complaint.id), "level": level, "error": str(exc)},
                )
                db.session.rollback()
            except Exception as exc:  # pragma: no cover - defensive logging
                current_app.logger.exception(
                    "Unexpected follow-up dispatch error",
                    extra={"complaint_id": str(complaint.id), "level": level},
                )
                db.session.rollback()
