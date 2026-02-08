"""Logic-driven analytics agent for transparency dashboards."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from flask import current_app
from sqlalchemy import func

from extensions import db
from models import AnalyticsSnapshot, Complaint, Contractor, GovernmentDepartment, InfrastructureProject, LocationQuery
from utils.rating import SEVERITY_WEIGHTS, compute_contractor_rating
from utils.corruption_intelligence import evaluate_corruption_risks
from utils.alert_engine import auto_alert_from_flag


def _city_key(location_name: str | None) -> str:
    if not location_name:
        return "Unknown"
    return location_name.split(",")[0].strip() or "Unknown"


def _complaint_filters(filters: Optional[Dict] = None):
    query = Complaint.query
    if not filters:
        return query
    if filters.get("severity"):
        query = query.filter(Complaint.severity_level == filters["severity"])
    if filters.get("date_from"):
        query = query.filter(Complaint.created_at >= filters["date_from"])
    if filters.get("date_to"):
        query = query.filter(Complaint.created_at <= filters["date_to"])
    return query


def _collect_contractor_metrics(filters: Optional[Dict] = None) -> Dict[int, Dict]:
    metrics: Dict[int, Dict] = {}
    complaints = (
        _complaint_filters(filters)
        .join(InfrastructureProject, Complaint.project_id == InfrastructureProject.id)
        .filter(InfrastructureProject.contractor_id.isnot(None))
        .all()
    )
    for complaint in complaints:
        contractor_id = complaint.project.contractor_id
        if contractor_id is None:
            continue
        record = metrics.setdefault(
            contractor_id,
            {
                "total_projects": InfrastructureProject.query.filter_by(contractor_id=contractor_id).count(),
                "total_complaints": 0,
                "resolved": 0,
                "weighted_score": 0,
                "resolution_hours": [],
                "repeat_tracker": {},
            },
        )
        record["total_complaints"] += 1
        record["weighted_score"] += SEVERITY_WEIGHTS.get(complaint.severity_level, 1)
        record["repeat_tracker"][str(complaint.project_id)] = record["repeat_tracker"].get(str(complaint.project_id), 0) + 1
        if complaint.status in {"RESOLVED", "CLOSED"}:
            record["resolved"] += 1
        for hist in complaint.status_history:
            if hist.new_status in {"RESOLVED", "CLOSED"}:
                record["resolution_hours"].append((hist.changed_at - complaint.created_at).total_seconds() / 3600)
                break
    return metrics


def _collect_department_metrics(filters: Optional[Dict] = None) -> Dict[int, Dict]:
    metrics: Dict[int, Dict] = {}
    complaints = (
        _complaint_filters(filters)
        .join(InfrastructureProject, Complaint.project_id == InfrastructureProject.id)
        .filter(InfrastructureProject.department_id.isnot(None))
        .all()
    )
    for complaint in complaints:
        department_id = complaint.project.department_id
        if department_id is None:
            continue
        record = metrics.setdefault(
            department_id,
            {
                "complaints_received": 0,
                "resolved": 0,
                "response_delays": [],
                "escalations": 0,
                "rti_requests": 0,
            },
        )
        record["complaints_received"] += 1
        if complaint.status in {"RESOLVED", "CLOSED"}:
            record["resolved"] += 1
        for hist in complaint.status_history:
            if hist.new_status in {"UNDER_REVIEW", "IN_PROGRESS"}:
                record["response_delays"].append((hist.changed_at - complaint.created_at).total_seconds() / 3600)
            if hist.new_status in {"RESOLVED", "CLOSED"}:
                break
        if complaint.follow_up_count and complaint.follow_up_count > 0:
            record["escalations"] += complaint.follow_up_count
    return metrics


def _collect_city_overview(filters: Optional[Dict] = None):
    overview: Dict[str, Dict] = {}
    data = (
        db.session.query(
            LocationQuery.location_name,
            func.count(InfrastructureProject.id),
        )
        .join(InfrastructureProject, InfrastructureProject.location_query_id == LocationQuery.id)
        .group_by(LocationQuery.location_name)
        .all()
    )
    for location_name, project_count in data:
        city = _city_key(location_name)
        overview.setdefault(city, {"total_projects": 0, "active_complaints": 0, "resolved": 0, "critical": 0})
        overview[city]["total_projects"] += project_count

    complaint_rows = (
        _complaint_filters(filters)
        .join(InfrastructureProject, Complaint.project_id == InfrastructureProject.id)
        .join(LocationQuery, InfrastructureProject.location_query_id == LocationQuery.id)
        .add_entity(LocationQuery)
        .all()
    )
    for complaint, location_query in complaint_rows:
        city = _city_key(location_query.location_name)
        record = overview.setdefault(city, {"total_projects": 0, "active_complaints": 0, "resolved": 0, "critical": 0})
        if complaint.status in {"RESOLVED", "CLOSED"}:
            record["resolved"] += 1
        else:
            record["active_complaints"] += 1
        if complaint.severity_level in {"HIGH", "CRITICAL"}:
            record["critical"] += 1
    return overview


def _persist_snapshot(snapshot_type: str, entity_type: str | None, entity_id: str | None, payload: Dict) -> None:
    snapshot = AnalyticsSnapshot(
        snapshot_type=snapshot_type,
        entity_type=entity_type,
        entity_id=entity_id,
        payload=payload,
    )
    db.session.add(snapshot)


def run_analytics(cache_results: bool = True, filters: Optional[Dict] = None) -> Dict:
    now = datetime.utcnow()
    contractor_metrics = _collect_contractor_metrics(filters)
    contractor_results: Dict[int, Dict] = {}
    for contractor_id, data in contractor_metrics.items():
        contractor_obj = Contractor.query.get(contractor_id)
        rating = compute_contractor_rating(contractor_obj) if contractor_obj else {"rating": 0, "rating_display": "N/A"}
        repeat_complaints = sum(1 for val in data["repeat_tracker"].values() if val > 1)
        avg_resolution_hours = sum(data["resolution_hours"]) / len(data["resolution_hours"]) if data["resolution_hours"] else None
        contractor_results[contractor_id] = {
            "name": contractor_obj.name if contractor_obj else f"Contractor {contractor_id}",
            "total_projects": data["total_projects"],
            "total_complaints": data["total_complaints"],
            "severity_weight": data["weighted_score"],
            "resolution_rate": round((data["resolved"] / data["total_complaints"]) * 100, 2) if data["total_complaints"] else 0,
            "avg_resolution_hours": avg_resolution_hours,
            "repeat_complaints": repeat_complaints,
            "rating": rating.get("rating"),
            "rating_display": rating.get("rating_display"),
        }
        if cache_results:
            _persist_snapshot("contractor_metrics", "CONTRACTOR", str(contractor_id), contractor_results[contractor_id])

    if cache_results:
        _persist_snapshot("contractor_metrics", "CONTRACTOR", "ALL", contractor_results)

    department_metrics = _collect_department_metrics(filters)
    department_results: Dict[int, Dict] = {}
    for dept_id, data in department_metrics.items():
        avg_response_hours = sum(data["response_delays"]) / len(data["response_delays"]) if data["response_delays"] else None
        department_results[dept_id] = {
            "name": GovernmentDepartment.query.get(dept_id).department_name if GovernmentDepartment.query.get(dept_id) else f"Department {dept_id}",
            "complaints_received": data["complaints_received"],
            "complaints_resolved": data["resolved"],
            "average_response_hours": avg_response_hours,
            "escalation_count": data["escalations"],
            "rti_requests": 0,
        }
        if cache_results:
            _persist_snapshot("department_metrics", "DEPARTMENT", str(dept_id), department_results[dept_id])

    if cache_results:
        _persist_snapshot("department_metrics", "DEPARTMENT", "ALL", department_results)

    city_overview = _collect_city_overview(filters)
    if cache_results:
        _persist_snapshot("city_overview", "CITY", "ALL", city_overview)

    db.session.commit()

    try:
        flags = evaluate_corruption_risks(current_app.config)
        threshold = int(current_app.config.get("RISK_SCORE_ALERT_THRESHOLD", 70))
        for flag in flags:
            auto_alert_from_flag(flag, threshold)
    except Exception:
        current_app.logger.exception("Corruption intelligence execution failed during analytics run")

    return {
        "contractors": contractor_results,
        "departments": department_results,
        "cities": city_overview,
        "computed_at": now,
    }


def latest_snapshot(snapshot_type: str, entity_type: str | None = None, entity_id: str | None = None) -> AnalyticsSnapshot | None:
    query = AnalyticsSnapshot.query.filter_by(snapshot_type=snapshot_type)
    if entity_type is not None:
        query = query.filter_by(entity_type=entity_type)
    if entity_id is not None:
        query = query.filter_by(entity_id=entity_id)
    return query.order_by(AnalyticsSnapshot.computed_at.desc()).first()
