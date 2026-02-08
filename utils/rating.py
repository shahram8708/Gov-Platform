"""Deterministic contractor rating computation."""
from __future__ import annotations

from datetime import timedelta
from typing import Dict

from models import Complaint, Contractor, InfrastructureProject

SEVERITY_WEIGHTS = {"LOW": 1, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 5}


def _resolution_hours(complaint: Complaint) -> float | None:
    resolved_at = None
    for hist in complaint.status_history:
        if hist.new_status in {"RESOLVED", "CLOSED"}:
            resolved_at = hist.changed_at
            break
    if resolved_at:
        delta = resolved_at - complaint.created_at
        return delta.total_seconds() / 3600
    return None


def compute_contractor_rating(contractor: Contractor) -> Dict:
    projects = InfrastructureProject.query.filter_by(contractor_id=contractor.id).all()
    if not projects:
        return {"rating": 5.0, "rating_display": "5.0 / 5", "explanation": "No complaints recorded."}

    total_complaints = 0
    resolved = 0
    weighted_score = 0
    repeat_counter: Dict[str, int] = {}
    resolution_hours: list[float] = []

    for project in projects:
        for complaint in project.complaints:
            total_complaints += 1
            weight = SEVERITY_WEIGHTS.get(complaint.severity_level, 1)
            weighted_score += weight
            repeat_counter[str(project.id)] = repeat_counter.get(str(project.id), 0) + 1
            if complaint.status in {"RESOLVED", "CLOSED"}:
                resolved += 1
            hours = _resolution_hours(complaint)
            if hours is not None:
                resolution_hours.append(hours)

    resolution_rate = (resolved / total_complaints) if total_complaints else 0
    avg_resolution_hours = sum(resolution_hours) / len(resolution_hours) if resolution_hours else None
    repeat_complaints = sum(1 for count in repeat_counter.values() if count > 1)

    severity_penalty = min(weighted_score / max(1, len(projects)), 8) * 0.1
    resolution_bonus = resolution_rate * 2
    repeat_penalty = repeat_complaints * 0.3
    time_penalty = 0
    if avg_resolution_hours:
        time_penalty = min(avg_resolution_hours / 24 / 7, 3)  # weeks delayed

    raw_score = 5 - severity_penalty - repeat_penalty - time_penalty + resolution_bonus
    rating = max(1.0, min(5.0, round(raw_score, 2)))
    explanation = (
        f"Severity penalty: -{severity_penalty:.2f}; repeat penalty: -{repeat_penalty:.2f}; "
        f"time penalty: -{time_penalty:.2f}; resolution bonus: +{resolution_bonus:.2f}."
    )
    return {
        "rating": rating,
        "rating_display": f"{rating:.1f} / 5",
        "resolution_rate": round(resolution_rate * 100, 2),
        "avg_resolution_hours": avg_resolution_hours,
        "repeat_complaints": repeat_complaints,
        "weighted_score": weighted_score,
        "explanation": explanation,
    }
