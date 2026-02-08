"""Blueprint registration, public routes, and dashboards."""
import time

from flask import Blueprint, render_template, redirect, request, url_for, abort, current_app, make_response, jsonify
from flask_login import current_user, login_required

from extensions import db
from models import Complaint, ComplaintStatusHistory, InfrastructureProject, LocationQuery, RTIRequest
from utils.alert_engine import alerts_for_user
from utils.decorators import roles_required
from utils.i18n import persist_user_locale, supported_languages
from utils.security import sanitize_input
from .auth import auth_bp
from .complaints import complaints_bp
from .project_discovery import project_bp
from .transparency import transparency_bp

main_bp = Blueprint("main", __name__)

HOME_CACHE: dict[tuple[str, str], dict] = {}


def _cache_key(city: str | None, project_type: str | None) -> tuple[str, str]:
    return ((city or "").strip().lower(), (project_type or "").strip().lower())


def _build_activity_feed(limit: int = 12) -> list[dict]:
    events: list[dict] = []
    projects = (
        InfrastructureProject.public_query()
        .order_by(InfrastructureProject.created_at.desc())
        .limit(limit)
        .all()
    )
    for project in projects:
        events.append(
            {
                "kind": "project_added",
                "title": project.project_name,
                "status": project.current_status,
                "timestamp": project.created_at,
                "area": project.area_label,
            }
        )

    complaint_submissions = (
        Complaint.public_query()
        .order_by(Complaint.created_at.desc())
        .limit(limit)
        .all()
    )
    for complaint in complaint_submissions:
        events.append(
            {
                "kind": "complaint_filed",
                "title": complaint.project.project_name if complaint.project else "Complaint filed",
                "status": complaint.status,
                "timestamp": complaint.created_at,
                "area": complaint.public_payload().get("area"),
                "severity": complaint.severity_level,
            }
        )

    complaint_resolutions = (
        ComplaintStatusHistory.query.join(Complaint)
        .filter(
            ComplaintStatusHistory.new_status == "RESOLVED",
            Complaint.is_public.is_(True),
            Complaint.visibility_level != "PRIVATE",
        )
        .order_by(ComplaintStatusHistory.changed_at.desc())
        .limit(limit)
        .all()
    )
    for history in complaint_resolutions:
        events.append(
            {
                "kind": "complaint_resolved",
                "title": history.complaint.project.project_name if history.complaint and history.complaint.project else "Complaint resolved",
                "status": history.new_status,
                "timestamp": history.changed_at,
                "area": history.complaint.public_payload().get("area") if history.complaint else None,
            }
        )

    rti_events = (
        RTIRequest.query.filter(RTIRequest.is_public.is_(True), RTIRequest.visibility_level == "PUBLIC")
        .order_by(RTIRequest.generated_at.desc())
        .limit(limit)
        .all()
    )
    for rti in rti_events:
        events.append(
            {
                "kind": "rti_generated",
                "title": f"RTI for {rti.entity_type.title()}",
                "status": "RTI",
                "timestamp": rti.generated_at,
                "area": None,
            }
        )

    ordered = sorted(events, key=lambda e: e.get("timestamp") or 0, reverse=True)
    return ordered[:limit]


def _build_home_context(filters: dict) -> dict:
    city_filter = filters.get("city")
    project_type_filter = filters.get("project_type")

    project_query = InfrastructureProject.public_query().join(LocationQuery)
    if city_filter:
        project_query = project_query.filter(LocationQuery.location_name.ilike(f"%{city_filter}%"))
    if project_type_filter:
        project_query = project_query.filter(InfrastructureProject.project_type.ilike(f"%{project_type_filter}%"))

    projects = project_query.order_by(InfrastructureProject.created_at.desc()).limit(8).all()
    complaints = (
        Complaint.public_query()
        .join(InfrastructureProject)
        .order_by(Complaint.created_at.desc())
        .limit(6)
        .all()
    )

    project_groups: dict[str, list[dict]] = {}
    for proj in projects:
        payload = proj.public_payload()
        group_key = payload.get("area") or "Unspecified area"
        project_groups.setdefault(group_key, []).append(payload)

    complaint_payloads = [c.public_payload() for c in complaints]
    activity_feed = _build_activity_feed()
    context = {
        "project_groups": project_groups,
        "projects": [p.public_payload() for p in projects],
        "complaints": complaint_payloads,
        "activity_feed": activity_feed,
        "filters": {"city": city_filter or "", "project_type": project_type_filter or ""},
        "cache_window": int(current_app.config.get("PUBLIC_HOME_CACHE_SECONDS", 120)),
        "status_badges": {
            "Completed": "success",
            "On Track": "success",
            "In Progress": "info",
            "Delayed": "warning",
            "Stalled": "danger",
            "Critical": "danger",
            "Cancelled": "secondary",
        },
        "complaint_status_badges": {
            "SUBMITTED": "secondary",
            "UNDER_REVIEW": "info",
            "IN_PROGRESS": "primary",
            "RESOLVED": "success",
            "CLOSED": "dark",
        },
        "complaint_severity_badges": {
            "LOW": "secondary",
            "MEDIUM": "info",
            "HIGH": "warning",
            "CRITICAL": "danger",
        },
    }

    current_app.logger.info(
        "public_home_data_compiled",
        extra={
            "project_ids": [p.get("id") for p in context["projects"]],
            "complaint_ids": [c.get("id") for c in complaint_payloads],
            "activity_items": len(activity_feed),
            "filters": context["filters"],
            "visibility_enforced": True,
        },
    )

    return context


@main_bp.route("/")
def index():
    filters = sanitize_input(request.args)
    city_filter = filters.get("city")
    project_type_filter = filters.get("project_type")
    key = _cache_key(city_filter, project_type_filter)
    cache_ttl = int(current_app.config.get("PUBLIC_HOME_CACHE_SECONDS", 120))
    now = time.time()
    cached = HOME_CACHE.get(key)
    if cached and cached.get("expires", 0) > now:
        context = cached.get("data", {})
    else:
        context = _build_home_context(filters)
        HOME_CACHE[key] = {"data": context, "expires": now + cache_ttl}
    return render_template("home/public_home.html", page_title="Public Transparency Hub", **context)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    role = (current_user.role.name if current_user.role else "").lower()
    if role == "citizen":
        return render_template("dashboard/citizen.html", page_title="Citizen Dashboard")
    if role in ("government officer", "officer"):
        return render_template("dashboard/officer.html", page_title="Officer Dashboard")
    if role == "contractor":
        return render_template("dashboard/contractor.html", page_title="Contractor Dashboard")
    if role == "admin":
        return render_template("dashboard/admin.html", page_title="Admin Dashboard")
    return render_template("dashboard/citizen.html", page_title="Dashboard")


@main_bp.route("/dashboard/citizen")
@login_required
@roles_required("Citizen")
def citizen_dashboard():
    return render_template("dashboard/citizen.html", page_title="Citizen Dashboard")


@main_bp.route("/dashboard/officer")
@login_required
@roles_required("Government Officer", "Officer", "Admin")
def officer_dashboard():
    return render_template("dashboard/officer.html", page_title="Officer Dashboard")


@main_bp.route("/dashboard/contractor")
@login_required
@roles_required("Contractor", "Admin")
def contractor_dashboard():
    return render_template("dashboard/contractor.html", page_title="Contractor Dashboard")


@main_bp.route("/dashboard/admin")
@login_required
@roles_required("Admin")
def admin_dashboard():
    return render_template("dashboard/admin.html", page_title="Admin Dashboard")


@main_bp.route("/lang/<lang_code>", methods=["GET"])
def set_language(lang_code):
    langs = supported_languages(current_app.config)
    if lang_code not in langs:
        abort(404)
    if current_user.is_authenticated:
        persist_user_locale(current_user, lang_code)
        db.session.commit()
    resp = make_response(redirect(request.referrer or url_for("main.dashboard")))
    resp.set_cookie("gov_locale", lang_code, max_age=60 * 60 * 24 * 365, samesite="Lax", secure=current_app.config.get("SESSION_COOKIE_SECURE", True))
    return resp


@main_bp.route("/api/alerts", methods=["GET"])
@login_required
def alerts_feed():
    alerts = alerts_for_user(current_user)
    return jsonify(
        [
            {
                "id": str(a.id),
                "type": a.alert_type,
                "severity": a.severity,
                "message": a.message,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ]
    )


__all__ = ["main_bp", "auth_bp", "project_bp", "complaints_bp", "transparency_bp"]

