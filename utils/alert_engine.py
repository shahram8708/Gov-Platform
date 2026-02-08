"""Smart alerting and notification orchestration without third-party services."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from flask import current_app
from sqlalchemy import and_, or_

from extensions import db
from models import ALERT_STATUSES, ALERT_SEVERITIES, SmartAlert, CorruptionFlag


def _dedup_key(alert_type: str, entity_type: Optional[str], entity_id: Optional[str]) -> str:
    entity_key = f"{entity_type}:{entity_id}" if entity_type and entity_id else "GLOBAL"
    return f"{alert_type}:{entity_key}".lower()


def create_alert(
    alert_type: str,
    severity: str,
    message: str,
    *,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    target_role: Optional[str] = None,
    target_user_id: Optional[str] = None,
    metadata: Optional[Dict] = None,
    dedup_window_hours: int = 24,
) -> SmartAlert:
    if severity not in ALERT_SEVERITIES:
        raise ValueError("Invalid alert severity")
    key = _dedup_key(alert_type, entity_type, entity_id)
    cutoff = datetime.utcnow() - timedelta(hours=dedup_window_hours)
    existing = SmartAlert.query.filter(
        SmartAlert.dedup_key == key,
        SmartAlert.created_at >= cutoff,
        SmartAlert.status.in_(["OPEN", "ACKED"]),
    ).first()
    if existing:
        existing.extra_metadata = metadata or existing.extra_metadata
        existing.severity = severity
        return existing

    alert = SmartAlert(
        alert_type=alert_type,
        severity=severity,
        message=message,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id else None,
        target_role=target_role,
        target_user_id=target_user_id,
        extra_metadata=metadata,
        dedup_key=key,
    )
    db.session.add(alert)
    db.session.commit()
    current_app.logger.info("Smart alert created", extra={"type": alert_type, "key": key})
    return alert


def acknowledge_alert(alert_id, user_id=None) -> None:
    alert = SmartAlert.query.get(alert_id)
    if not alert:
        return
    alert.status = "ACKED"
    alert.acknowledged_at = datetime.utcnow()
    alert.extra_metadata = alert.extra_metadata or {}
    if user_id:
        alert.extra_metadata.setdefault("ack_by", str(user_id))
    db.session.commit()


def resolve_alert(alert_id, notes: Optional[str] = None) -> None:
    alert = SmartAlert.query.get(alert_id)
    if not alert:
        return
    alert.status = "RESOLVED"
    alert.resolved_at = datetime.utcnow()
    if notes:
        alert.extra_metadata = alert.extra_metadata or {}
        alert.extra_metadata.setdefault("resolution_notes", []).append(notes)
    db.session.commit()


def alerts_for_user(user) -> List[SmartAlert]:
    role_name = (user.role.name if getattr(user, "role", None) else "").lower()
    return (
        SmartAlert.query.filter(
            or_(SmartAlert.target_user_id == user.id, SmartAlert.target_user_id.is_(None)),
            or_(SmartAlert.target_role.is_(None), SmartAlert.target_role.ilike(role_name)),
            SmartAlert.status.in_(["OPEN", "ACKED"]),
        )
        .order_by(SmartAlert.severity.desc(), SmartAlert.created_at.desc())
        .limit(50)
        .all()
    )


def auto_alert_from_flag(flag: CorruptionFlag, risk_threshold: int) -> Optional[SmartAlert]:
    if not flag or flag.status != "ACTIVE":
        return None
    if flag.risk_score < risk_threshold:
        return None
    severity = "HIGH" if flag.risk_score >= 80 else "MEDIUM"
    message = f"Risk flag {flag.pattern_code} on {flag.entity_type} {flag.entity_id} scored {flag.risk_score}"
    return create_alert(
        alert_type=f"FLAG_{flag.pattern_code}",
        severity=severity,
        message=message,
        entity_type=flag.entity_type,
        entity_id=flag.entity_id,
        target_role="admin",
        metadata={"evidence": flag.evidence, "risk_score": flag.risk_score},
    )
