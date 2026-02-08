"""Deterministic corruption intelligence engine (no AI dependencies)."""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional
import statistics
import re

from flask import current_app
from sqlalchemy import func

from extensions import db
from models import (
    ALERT_SEVERITIES,
    CorruptionFlag,
    CorruptionPattern,
    FLAG_ENTITY_TYPES,
    InfrastructureProject,
    Complaint,
    LocationQuery,
)
from utils.rating import SEVERITY_WEIGHTS


_DEFAULT_PATTERNS: List[Dict] = [
    {
        "code": "REPEAT_CONTRACTOR_COMPLAINTS",
        "description": "Same contractor has repeated complaints across projects",
        "threshold_value": 3,
        "severity_weight": 3,
        "metric": "complaints_per_contractor",
    },
    {
        "code": "COST_OVERRUN_THRESHOLD",
        "description": "Project shows potential cost overrun beyond allowed threshold",
        "threshold_value": 15.0,
        "severity_weight": 4,
        "metric": "cost_overrun_pct",
    },
    {
        "code": "TIMELINE_DELAY_THRESHOLD",
        "description": "Project delayed beyond allowed days from expected end date",
        "threshold_value": 30,
        "severity_weight": 4,
        "metric": "delay_days",
    },
    {
        "code": "REPEAT_GEOGRAPHY_COMPLAINTS",
        "description": "Repeated complaints in the same geography/location",
        "threshold_value": 4,
        "severity_weight": 2,
        "metric": "complaints_per_location",
    },
    {
        "code": "UNRESOLVED_COMPLAINT_LOAD",
        "description": "Multiple unresolved complaints across projects",
        "threshold_value": 5,
        "severity_weight": 5,
        "metric": "unresolved_complaints",
    },
]


def seed_patterns() -> None:
    """Ensure baseline patterns exist for deterministic detection."""
    for pattern in _DEFAULT_PATTERNS:
        existing = CorruptionPattern.query.filter_by(code=pattern["code"]).first()
        if existing:
            continue
        db.session.add(CorruptionPattern(**pattern))
    db.session.commit()


def _record_flag(pattern_code: str, entity_type: str, entity_id: str, risk_score: int, evidence: Dict, location_key: Optional[str] = None) -> CorruptionFlag:
    if entity_type not in FLAG_ENTITY_TYPES:
        raise ValueError("Unsupported entity type for corruption flag")
    existing = (
        CorruptionFlag.query.filter_by(
            pattern_code=pattern_code,
            entity_type=entity_type,
            entity_id=str(entity_id),
            status="ACTIVE",
        )
        .order_by(CorruptionFlag.flagged_at.desc())
        .first()
    )
    if existing:
        existing.risk_score = max(existing.risk_score, risk_score)
        existing.evidence = evidence
        existing.location_key = location_key or existing.location_key
        return existing

    flag = CorruptionFlag(
        pattern_code=pattern_code,
        entity_type=entity_type,
        entity_id=str(entity_id),
        risk_score=risk_score,
        evidence=evidence,
        location_key=location_key,
    )
    db.session.add(flag)
    return flag


def _risk_from_complaints(count: int, severity_sum: int, weight: int) -> int:
    base = min(count * weight * 5, 100)
    severity_factor = min(severity_sum * 3, 60)
    return min(base + severity_factor, 100)


def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


def _parse_cost(cost_str: Optional[str]) -> Optional[float]:
    if not cost_str:
        return None
    try:
        clean = re.sub(r"[^0-9.]", "", str(cost_str))
        if not clean:
            return None
        return float(clean)
    except Exception:
        return None


def evaluate_corruption_risks(config) -> List[CorruptionFlag]:
    """Run deterministic checks over historical data to flag suspicious patterns."""
    seed_patterns()
    thresholds = config.get("CORRUPTION_THRESHOLDS", {}) if hasattr(config, "get") else {}
    flags: List[CorruptionFlag] = []

    # 1. Repeat complaints per contractor
    repeat_threshold = int(thresholds.get("repeat_complaints_per_contractor", 3))
    contractor_rows = (
           db.session.query(InfrastructureProject.contractor_id, func.count(Complaint.id))
        .join(Complaint, Complaint.project_id == InfrastructureProject.id)
        .filter(InfrastructureProject.contractor_id.isnot(None))
        .group_by(InfrastructureProject.contractor_id)
        .all()
    )
    for contractor_id, count in contractor_rows:
        if not contractor_id or count < repeat_threshold:
            continue
        severity_sum = 0
        for complaint in Complaint.query.join(InfrastructureProject, Complaint.project_id == InfrastructureProject.id).filter(InfrastructureProject.contractor_id == contractor_id).all():
            severity_sum += SEVERITY_WEIGHTS.get(complaint.severity_level, 1)
        risk_score = _risk_from_complaints(count, severity_sum, weight=3)
        evidence = {
            "total_complaints": int(count),
            "severity_weight": severity_sum,
            "projects_involved": [str(c.project_id) for c in Complaint.query.join(InfrastructureProject, Complaint.project_id == InfrastructureProject.id).filter(InfrastructureProject.contractor_id == contractor_id).all()],
        }
        flags.append(_record_flag("REPEAT_CONTRACTOR_COMPLAINTS", "CONTRACTOR", contractor_id, risk_score, evidence))

    # 2. Cost overrun vs peer median
    overrun_threshold_pct = float(thresholds.get("cost_overrun_pct", 15.0))
    costs_by_type: Dict[str, List] = {}
    for project in InfrastructureProject.query.all():
        cost_val = _parse_cost(project.project_cost)
        if cost_val is None:
            continue
        costs_by_type.setdefault(project.project_type or "UNKNOWN", []).append((project, cost_val))
    for ptype, entries in costs_by_type.items():
        values = [cost for _p, cost in entries]
        if not values:
            continue
        median_cost = statistics.median(values)
        if median_cost <= 0:
            continue
        limit = median_cost * (1 + overrun_threshold_pct / 100)
        for project, cost_val in entries:
            if cost_val <= limit:
                continue
            risk_score = min(int((cost_val / median_cost) * 10 * 2), 100)
            evidence = {
                "project_cost": cost_val,
                "median_cost_for_type": median_cost,
                "project_type": ptype,
                "threshold_pct": overrun_threshold_pct,
            }
            flags.append(_record_flag("COST_OVERRUN_THRESHOLD", "PROJECT", project.id, risk_score, evidence, location_key=project.location_query.location_name if project.location_query else None))

    # 3. Timeline delays vs planned timelines
    delay_threshold = int(thresholds.get("delay_days", 30))
    today = datetime.utcnow().date()
    delayed_projects = []
    for project in InfrastructureProject.query.all():
        expected_date = _parse_date(project.expected_end_date)
        if not expected_date:
            continue
        if project.current_status not in ("Completed", "On Track") and (today - expected_date.date()).days > delay_threshold:
            delayed_projects.append(project)
    for project in delayed_projects:
        expected_date = _parse_date(project.expected_end_date)
        delay_days = (today - expected_date.date()).days if expected_date else 0
        risk_score = min(50 + delay_days, 100)
        evidence = {
            "delay_days": delay_days,
            "expected_end_date": project.expected_end_date,
            "current_status": project.current_status,
        }
        flags.append(_record_flag("TIMELINE_DELAY_THRESHOLD", "PROJECT", project.id, risk_score, evidence, location_key=project.location_query.location_name if project.location_query else None))

    # 4. Repeat complaints per geography
    geo_threshold = int(thresholds.get("repeat_complaints_per_location", 4))
    geo_rows = (
        db.session.query(LocationQuery.location_name, func.count(Complaint.id))
        .join(InfrastructureProject, InfrastructureProject.location_query_id == LocationQuery.id)
        .join(Complaint, Complaint.project_id == InfrastructureProject.id)
        .group_by(LocationQuery.location_name)
        .all()
    )
    for location_name, count in geo_rows:
        if count < geo_threshold:
            continue
        complaints = Complaint.query.join(InfrastructureProject, Complaint.project_id == InfrastructureProject.id).join(LocationQuery, LocationQuery.id == InfrastructureProject.location_query_id).filter(LocationQuery.location_name == location_name).all()
        severity_sum = sum(SEVERITY_WEIGHTS.get(c.severity_level, 1) for c in complaints)
        risk_score = _risk_from_complaints(count, severity_sum, weight=2)
        evidence = {
            "location": location_name,
            "complaint_ids": [str(c.id) for c in complaints],
            "count": count,
        }
        flags.append(_record_flag("REPEAT_GEOGRAPHY_COMPLAINTS", "LOCATION", location_name, risk_score, evidence, location_key=location_name))

    # 5. Unresolved complaints across projects
    unresolved_threshold = int(thresholds.get("unresolved_complaints", 5))
    unresolved_rows = Complaint.query.filter(Complaint.status.notin_(["RESOLVED", "CLOSED"])).all()
    if len(unresolved_rows) >= unresolved_threshold:
        grouped: Dict[str, List[str]] = {}
        for row in unresolved_rows:
            grouped.setdefault(str(row.project_id), []).append(str(row.id))
        for project_id, ids in grouped.items():
            risk_score = min(len(ids) * 10, 95)
            evidence = {"unresolved_complaints": ids}
            flags.append(_record_flag("UNRESOLVED_COMPLAINT_LOAD", "PROJECT", project_id, risk_score, evidence))

    db.session.commit()
    if flags:
        current_app.logger.info("Corruption intelligence run completed", extra={"flags": len(flags)})
    return flags
