"""Transparency, RTI, and analytics routes."""
import uuid
from datetime import datetime

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from extensions import db
from models import Complaint, Contractor, GovernmentDepartment, InfrastructureProject, RTIRequest, RTI_ENTITY_TYPES
from utils.analytics_agent import latest_snapshot, run_analytics
from utils.decorators import roles_required
from utils.rti_service import RTIServiceError, generate_rti_report, record_download
from utils.security import sanitize_input
from utils.email_service import send_rti_ready_email
from utils.ai_markdown_formatter import markdown_to_html
from utils.identity_linker import complaint_access_allowed, project_access_allowed

transparency_bp = Blueprint("transparency", __name__, url_prefix="/transparency")


def _int_keyed(data):
    if not isinstance(data, dict):
        return data or {}
    normalized = {}
    for key, value in data.items():
        try:
            normalized[int(key)] = value
        except (TypeError, ValueError):
            normalized[key] = value
    return normalized


def _normalize_int_keys(data):
    normalized = {}
    for key, value in (data or {}).items():
        try:
            normalized[int(key)] = value
        except (TypeError, ValueError):
            normalized[key] = value
    return normalized


def _uuid_candidates(value):
    candidates = []
    if value:
        candidates.append(str(value))
    try:
        parsed = uuid.UUID(str(value))
        candidates.append(str(parsed))
    except (TypeError, ValueError):
        parsed = None
    # dedupe while preserving order
    seen = set()
    unique = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def _project_or_404(project_id):
    ids = _uuid_candidates(project_id)
    project = InfrastructureProject.query.filter(InfrastructureProject.id.in_(ids)).first()
    if not project:
        abort(404)
    if not project_access_allowed(project, current_user):
        abort(403)
    return project


def _complaint_or_404(complaint_id):
    ids = _uuid_candidates(complaint_id)
    complaint = Complaint.query.filter(Complaint.id.in_(ids)).first()
    if not complaint:
        abort(404)
    if not complaint_access_allowed(complaint, current_user):
        abort(403)
    return complaint


@transparency_bp.route("/rti/my", methods=["GET"])
@login_required
def rti_my_requests():
    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    page = 1 if page < 1 else page

    default_page_size = int(current_app.config.get("RTI_PER_PAGE", 10))
    per_page = max(1, min(default_page_size, 50))

    entity_filter = request.args.get("entity") or None
    query = RTIRequest.query.filter_by(generated_by=current_user.id)
    if entity_filter and entity_filter in RTI_ENTITY_TYPES:
        query = query.filter(RTIRequest.entity_type == entity_filter)

    pagination = (
        query.order_by(RTIRequest.generated_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    return render_template(
        "rti/list.html",
        requests=pagination.items,
        pagination=pagination,
        entity_filter=entity_filter,
        entity_options=RTI_ENTITY_TYPES,
        page_title="My RTI Requests",
    )


@transparency_bp.route("/rti/project/<string:project_id>", methods=["GET"])
@login_required
def rti_project(project_id):
    project = _project_or_404(project_id)
    try:
        record, checksum = generate_rti_report("PROJECT", project_id, current_user.id)
        try:
            send_rti_ready_email(
                current_user.email,
                record.reference_id,
                url_for("transparency.rti_download", reference_id=record.reference_id, _external=True),
            )
        except Exception:
            current_app.logger.warning("RTI ready email failed", extra={"reference_id": record.reference_id})
        flash("RTI report generated for project.", "success")
        return redirect(url_for("transparency.rti_view", reference_id=record.reference_id))
    except RTIServiceError as exc:
        flash(str(exc), "danger")
        return redirect(request.referrer or url_for("main.dashboard"))


@transparency_bp.route("/rti/complaint/<string:complaint_id>", methods=["GET"])
@login_required
def rti_complaint(complaint_id):
    complaint = _complaint_or_404(complaint_id)
    try:
        record, checksum = generate_rti_report("COMPLAINT", complaint_id, current_user.id)
        try:
            send_rti_ready_email(
                current_user.email,
                record.reference_id,
                url_for("transparency.rti_download", reference_id=record.reference_id, _external=True),
            )
        except Exception:
            current_app.logger.warning("RTI ready email failed", extra={"reference_id": record.reference_id})
        flash("RTI report generated for complaint.", "success")
        return redirect(url_for("transparency.rti_view", reference_id=record.reference_id))
    except RTIServiceError as exc:
        flash(str(exc), "danger")
        return redirect(request.referrer or url_for("main.dashboard"))


@transparency_bp.route("/rti/view/<reference_id>", methods=["GET"])
@login_required
def rti_view(reference_id):
    record = RTIRequest.query.filter_by(reference_id=reference_id).first_or_404()
    project = complaint = None
    ai_markdown_html = None
    if record.entity_type == "PROJECT":
        project = InfrastructureProject.query.filter_by(id=record.entity_id).first()
        if project and not project_access_allowed(project, current_user):
            abort(403)
    else:
        complaint = Complaint.query.filter_by(id=record.entity_id).first()
        if complaint and not complaint_access_allowed(complaint, current_user):
            abort(403)
        if complaint and complaint.images:
            analysis = complaint.images[0].ai_analysis_result or {}
            md_source = analysis.get("markdown") or complaint.ai_generated_summary
            ai_markdown_html = markdown_to_html(md_source or "")
    return render_template(
        "rti/report.html",
        record=record,
        project=project,
        complaint=complaint,
        ai_markdown_html=ai_markdown_html,
        page_title="RTI Report Preview",
    )


@transparency_bp.route("/rti/download/<reference_id>", methods=["GET"])
@login_required
def rti_download(reference_id):
    try:
        record = record_download(reference_id, current_user.id)
    except RTIServiceError as exc:
        flash(str(exc), "danger")
        abort(404)
    if not record or not record.pdf_path:
        abort(404)
    if record.entity_type == "PROJECT":
        project = InfrastructureProject.query.filter_by(id=record.entity_id).first()
        if project and not project_access_allowed(project, current_user):
            abort(403)
    else:
        complaint = Complaint.query.filter_by(id=record.entity_id).first()
        if complaint and not complaint_access_allowed(complaint, current_user):
            abort(403)
    return send_file(record.pdf_path, as_attachment=True, download_name=f"{record.reference_id}.pdf")


@transparency_bp.route("/dashboard", methods=["GET"])
def public_dashboard():
    cache_minutes = int(current_app.config.get("ANALYTICS_CACHE_MINUTES", 30))
    snapshot = latest_snapshot("city_overview", "CITY", "ALL")
    contractor_snapshot = latest_snapshot("contractor_metrics", "CONTRACTOR", "ALL")
    department_snapshot = latest_snapshot("department_metrics", "DEPARTMENT", "ALL")

    filters = sanitize_input(request.args)
    severity_filter = filters.get("severity")
    city_filter = filters.get("city")
    contractor_filter = filters.get("contractor")
    department_filter = filters.get("department")

    date_from = filters.get("date_from")
    date_to = filters.get("date_to")
    parsed_from = parsed_to = None
    try:
        if date_from:
            parsed_from = datetime.fromisoformat(date_from)
    except ValueError:
        parsed_from = None
    try:
        if date_to:
            parsed_to = datetime.fromisoformat(date_to)
    except ValueError:
        parsed_to = None

    analytics_filters = {
        k: v
        for k, v in {
            "severity": severity_filter,
            "date_from": parsed_from,
            "date_to": parsed_to,
        }.items()
        if v
    }

    should_refresh = True
    if not analytics_filters:
        all_snapshots_present = snapshot and contractor_snapshot and department_snapshot
        if all_snapshots_present:
            latest_computed_at = max(snapshot.computed_at, contractor_snapshot.computed_at, department_snapshot.computed_at)
            if (datetime.utcnow() - latest_computed_at).total_seconds() < cache_minutes * 60:
                should_refresh = False

    if should_refresh:
        data = run_analytics(cache_results=not bool(analytics_filters), filters=analytics_filters or None)
        city_data = data["cities"]
        contractor_data = data["contractors"]
        department_data = data["departments"]
    else:
        city_data = snapshot.payload if snapshot else {}
        contractor_data = contractor_snapshot.payload if contractor_snapshot else {}
        department_data = department_snapshot.payload if department_snapshot else {}

    contractor_data = _int_keyed(contractor_data)
    department_data = _int_keyed(department_data)

    filtered_city = {k: v for k, v in city_data.items() if not city_filter or city_filter.lower() in k.lower()}

    if contractor_filter:
        contractor_data = {k: v for k, v in contractor_data.items() if str(k) == contractor_filter}
    if department_filter:
        department_data = {k: v for k, v in department_data.items() if str(k) == department_filter}

    contractor_records = Contractor.query.all()
    department_records = GovernmentDepartment.query.all()

    contractor_data = _normalize_int_keys(contractor_data)
    department_data = _normalize_int_keys(department_data)

    return render_template(
        "dashboard/transparency.html",
        city_overview=filtered_city,
        contractor_metrics=contractor_data,
        department_metrics=department_data,
        contractors=contractor_records,
        departments=department_records,
        filters=filters,
        page_title="Transparency Dashboard",
    )


@transparency_bp.route("/analytics/recalculate", methods=["POST"])
@login_required
@roles_required("Admin")
def recalc_analytics():
    run_analytics(cache_results=True)
    flash("Analytics recalculated and cached.", "success")
    return redirect(url_for("transparency.public_dashboard"))
