"""Location-based project discovery blueprint."""
from typing import List
import os
import uuid
from datetime import datetime
from urllib.parse import urlparse

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy.exc import SQLAlchemyError
from wtforms import SelectField, SelectMultipleField, StringField, SubmitField
from wtforms.validators import Length

from extensions import db, csrf
from models import (
    Contractor,
    DepartmentOfficer,
    GovernmentDepartment,
    InfrastructureProject,
    LocationQuery,
    MaintenanceAuthority,
    ProjectSourceLink,
    ProjectStatusHistory,
    TenderReference,
    ProjectSnapshot,
    AnalyticsSnapshot,
    SectionDataFetchLog,
    AuditLog,
)
from utils.ai_project_discovery import AIProjectDiscoveryError, fetch_ai_projects
from utils.rating import compute_contractor_rating
from utils.decorators import roles_required
from utils.blockchain_ready import record_anchor, hash_record
from utils.image_utils import persist_image, ALLOWED_IMAGE_EXTENSIONS, build_location_snapshot
from utils.security import sanitize_input, track_attempt
from utils.ai_markdown_formatter import format_project_discovery_markdown, markdown_to_html
from utils.ai_section_fetcher import (
    SectionDataFetchError,
    build_markdown as build_section_markdown,
    fetch_section_payload,
    is_missing_value,
)
from utils.identity_linker import project_access_allowed

project_bp = Blueprint("projects", __name__, url_prefix="/projects")

PROJECT_TYPE_CHOICES = [
    ("Bridge", "Bridge"),
    ("Road", "Road"),
    ("Building", "Building"),
    ("Flyover", "Flyover"),
    ("Drainage", "Drainage"),
    ("Water Pipeline", "Water Pipeline"),
    ("Electricity", "Electricity"),
    ("Solar", "Solar"),
]

STATUS_BADGE_CLASS = {
    "Completed": "success",
    "On Track": "success",
    "In Progress": "info",
    "Delayed": "warning",
    "Stalled": "danger",
    "Critical": "danger",
    "Cancelled": "secondary",
}


def _parse_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        try:
            return uuid.UUID(hex=str(value).replace("-", ""))
        except (TypeError, ValueError):
            return None


def _normalize_uuid(value, abort_status: int = 404) -> str:
    parsed = _parse_uuid(value)
    if not parsed:
        abort(abort_status)
    return str(parsed)


def _uuid_candidates(value) -> list[str]:
    candidates: list[str] = []
    if value:
        candidates.append(str(value))
    parsed = _parse_uuid(value)
    if parsed:
        candidates.append(str(parsed))
    # dedupe while preserving order
    seen = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


class ProjectDiscoveryForm(FlaskForm):
    manual_location = StringField("Enter location", validators=[Length(max=255)])
    latitude = StringField("Latitude", validators=[Length(max=50)])
    longitude = StringField("Longitude", validators=[Length(max=50)])
    project_types = SelectMultipleField("Project Types", choices=PROJECT_TYPE_CHOICES, validate_choice=False)
    ai_model = SelectField(
        "AI Model",
        choices=[("gemini", "Gemini (Google Search Grounded)"), ("perplexity", "Perplexity (Coming Soon)")],
        default="gemini",
        validate_choice=True,
    )
    submit = SubmitField("Find Projects")

    def validate(self, extra_validators=None):  # type: ignore[override]
        base_valid = super().validate(extra_validators)
        if not base_valid:
            return False

        has_manual = bool(self.manual_location.data and self.manual_location.data.strip())
        has_coords = bool(self.latitude.data and self.longitude.data)

        if not (has_manual or has_coords):
            self.manual_location.errors.append("Share GPS or enter a location.")
            return False

        if has_coords:
            try:
                lat_val = float(self.latitude.data)
                lng_val = float(self.longitude.data)
            except ValueError:
                self.latitude.errors.append("Latitude/longitude must be numeric.")
                return False
            if not (-90 <= lat_val <= 90 and -180 <= lng_val <= 180):
                self.latitude.errors.append("Latitude/longitude are out of valid range.")
                return False

        if not self.project_types.data:
            self.project_types.errors.append("Select at least one infrastructure type.")
            return False

        allowed_models = {"gemini"}
        if (self.ai_model.data or "").lower() not in allowed_models:
            self.ai_model.errors.append("Perplexity is coming soon; use Gemini (Google) for now.")
            return False
        return True


def _domain_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlparse(url).netloc or None
    except ValueError:
        return None


def _badge_for_status(status: str | None) -> str:
    return STATUS_BADGE_CLASS.get(status or "", "secondary")


def _is_value_missing(value) -> bool:
    if is_missing_value(value):
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"not available", "unknown", "n/a", "na", "nil"}
    return False


def _missing_fields_for_project(project: InfrastructureProject) -> dict[str, list[str]]:
    missing: dict[str, list[str]] = {}

    contractor_fields = ["name", "email", "phone", "office_address", "company_name", "registration_number"]
    if project.contractor:
        missing["contractor_details"] = [
            field
            for field in contractor_fields
            if _is_value_missing(getattr(project.contractor, field if field != "company_name" else "company_name", None))
        ]
    else:
        missing["contractor_details"] = contractor_fields

    dept_fields = ["department_name", "ministry_level", "official_email", "official_phone", "office_address"]
    if project.department:
        missing["department_details"] = [
            field for field in dept_fields if _is_value_missing(getattr(project.department, field, None))
        ]
    else:
        missing["department_details"] = dept_fields

    officer_fields = ["officer_name", "designation", "official_email", "official_phone"]
    target_officer = None
    if project.department and project.department.officers:
        active = [o for o in project.department.officers if o.is_active]
        target_officer = active[0] if active else project.department.officers[0]
    if target_officer:
        missing["officer_contact"] = [field for field in officer_fields if _is_value_missing(getattr(target_officer, field, None))]
    else:
        missing["officer_contact"] = officer_fields

    tender_fields = ["tender_id", "tender_portal_name", "tender_url", "published_date"]
    tender = project.tender_references[0] if project.tender_references else None
    if tender:
        missing["tender_information"] = [field for field in tender_fields if _is_value_missing(getattr(tender, field, None))]
    else:
        missing["tender_information"] = tender_fields

    maintenance_fields = ["authority_name", "contact_email", "contact_phone", "office_address"]
    if project.maintenance_authority:
        missing["maintenance_authority"] = [
            field for field in maintenance_fields if _is_value_missing(getattr(project.maintenance_authority, field, None))
        ]
    else:
        missing["maintenance_authority"] = maintenance_fields

    timeline_fields = ["start_date", "expected_end_date", "current_status"]
    timeline_missing = [field for field in timeline_fields if _is_value_missing(getattr(project, field, None))]
    if not project.status_history:
        timeline_missing.append("status_history")
    missing["project_timeline"] = timeline_missing

    return missing


def _apply_section_updates(project: InfrastructureProject, section: str, payload: dict, requested_fields: list[str]) -> dict[str, object]:
    updated: dict[str, object] = {}

    if section == "contractor_details":
        data = payload.get("contractor") or {}
        mapping = {
            "name": "name",
            "email": "email",
            "phone": "phone",
            "office_address": "office_address",
            "company_name": "company_name",
            "registration_number": "registration_number",
        }
        contractor = project.contractor
        has_new_data = any(data.get(field) for field in mapping.keys())
        if not contractor and has_new_data:
            contractor = Contractor()
            db.session.add(contractor)
            db.session.flush()
            project.contractor = contractor
        if not contractor:
            return updated
        for field, attr in mapping.items():
            if field not in requested_fields:
                continue
            new_val = data.get(field)
            current_val = getattr(contractor, attr, None)
            if _is_value_missing(current_val) and new_val:
                setattr(contractor, attr, new_val)
                updated[field] = new_val

    elif section == "department_details":
        data = payload.get("department") or {}
        mapping = {
            "department_name": "department_name",
            "ministry_level": "ministry_level",
            "official_email": "official_email",
            "official_phone": "official_phone",
            "office_address": "office_address",
        }
        department = project.department
        has_new_data = any(data.get(field) for field in mapping.keys())
        if not department and has_new_data:
            department = GovernmentDepartment()
            db.session.add(department)
            db.session.flush()
            project.department = department
        if not department:
            return updated
        for field, attr in mapping.items():
            if field not in requested_fields:
                continue
            new_val = data.get(field)
            current_val = getattr(department, attr, None)
            if _is_value_missing(current_val) and new_val:
                setattr(department, attr, new_val)
                updated[field] = new_val

    elif section == "officer_contact":
        data = payload.get("officer") or {}
        mapping = {
            "officer_name": "officer_name",
            "designation": "designation",
            "official_email": "official_email",
            "official_phone": "official_phone",
        }
        department = project.department
        has_new_data = any(data.get(field) for field in mapping.keys())
        if not department and has_new_data:
            department = GovernmentDepartment()
            db.session.add(department)
            db.session.flush()
            project.department = department
        if not department or not has_new_data:
            return updated
        officers = [o for o in department.officers if o.is_active]
        officer = officers[0] if officers else None
        if not officer:
            officer = DepartmentOfficer(department_id=department.id, officer_name="")
            db.session.add(officer)
            db.session.flush()
        for field, attr in mapping.items():
            if field not in requested_fields:
                continue
            new_val = data.get(field)
            current_val = getattr(officer, attr, None)
            if _is_value_missing(current_val) and new_val:
                setattr(officer, attr, new_val)
                updated[field] = new_val

    elif section == "tender_information":
        tender = project.tender_references[0] if project.tender_references else None
        data = payload.get("tender") or {}
        mapping = {
            "tender_id": "tender_id",
            "tender_portal_name": "tender_portal_name",
            "tender_url": "tender_url",
            "published_date": "published_date",
        }
        has_new_data = any(data.get(field) for field in mapping.keys())
        if not tender and has_new_data:
            tender = TenderReference(project_id=project.id)
            db.session.add(tender)
            db.session.flush()
        if not tender:
            return updated
        for field, attr in mapping.items():
            if field not in requested_fields:
                continue
            new_val = data.get(field)
            current_val = getattr(tender, attr, None)
            if _is_value_missing(current_val) and new_val:
                setattr(tender, attr, new_val)
                updated[field] = new_val

    elif section == "maintenance_authority":
        data = payload.get("maintenance") or {}
        mapping = {
            "authority_name": "authority_name",
            "contact_email": "contact_email",
            "contact_phone": "contact_phone",
            "office_address": "office_address",
        }
        authority = project.maintenance_authority
        has_new_data = any(data.get(field) for field in mapping.keys())
        if not authority and has_new_data:
            authority = MaintenanceAuthority()
            db.session.add(authority)
            db.session.flush()
            project.maintenance_authority = authority
        if not authority:
            return updated
        for field, attr in mapping.items():
            if field not in requested_fields:
                continue
            new_val = data.get(field)
            current_val = getattr(authority, attr, None)
            if _is_value_missing(current_val) and new_val:
                setattr(authority, attr, new_val)
                updated[field] = new_val

    elif section == "project_timeline":
        timeline = payload.get("timeline") or {}
        allowed_statuses = set(STATUS_BADGE_CLASS.keys())
        for field in ["start_date", "expected_end_date", "current_status"]:
            if field not in requested_fields:
                continue
            new_val = timeline.get(field)
            if field == "current_status" and new_val and new_val not in allowed_statuses:
                continue
            current_val = getattr(project, field, None)
            if _is_value_missing(current_val) and new_val:
                setattr(project, field, new_val)
                updated[field] = new_val

        if "status_history" in requested_fields and not project.status_history:
            for entry in timeline.get("status_history") or []:
                if not entry.get("status"):
                    continue
                if entry.get("status") not in allowed_statuses:
                    continue
                db.session.add(
                    ProjectStatusHistory(
                        project_id=project.id,
                        status=entry.get("status"),
                        remarks=entry.get("remarks"),
                        status_date_text=entry.get("status_date"),
                        updated_by="AI Section Fetch",
                    )
                )
                updated.setdefault("status_history", []).append(entry)
    else:
        raise SectionDataFetchError(f"Unsupported section: {section}")

    return updated


def _persist_results(location_label: str, lat: float | None, lng: float | None, query_type: str, project_types: List[str], ai_payload: dict):
    """Persist validated AI payload to the database."""
    location_meta = ai_payload.get("location") or {}
    ai_lat_raw = location_meta.get("latitude")
    ai_lng_raw = location_meta.get("longitude")
    try:
        ai_lat = float(ai_lat_raw) if ai_lat_raw is not None else None
    except (TypeError, ValueError):
        ai_lat = None
    try:
        ai_lng = float(ai_lng_raw) if ai_lng_raw is not None else None
    except (TypeError, ValueError):
        ai_lng = None

    loc_record = LocationQuery(
        user_id=current_user.id,
        location_name=location_meta.get("name") or location_label,
        manual_input=location_label if query_type == "manual" else None,
        latitude=ai_lat if ai_lat is not None else lat,
        longitude=ai_lng if ai_lng is not None else lng,
        query_type=query_type,
        project_types=project_types,
    )
    db.session.add(loc_record)
    db.session.flush()

    for project in ai_payload.get("projects", []):
        contractor_payload = project.get("contractor") or {}
        department_payload = project.get("government_department") or {}
        maintenance_payload = project.get("maintenance_authority") or {}

        contractor_obj: Contractor | None = None
        if contractor_payload.get("name"):
            existing = Contractor.query.filter_by(
                name=contractor_payload.get("name"),
                company_name=contractor_payload.get("company"),
            ).first()
            if existing:
                contractor_obj = existing
            else:
                contractor_obj = Contractor(
                    name=contractor_payload.get("name"),
                    company_name=contractor_payload.get("company"),
                    registration_number=contractor_payload.get("registration_number"),
                    email=contractor_payload.get("email"),
                    phone=contractor_payload.get("phone"),
                    office_address=contractor_payload.get("office_address"),
                    public_image_url=contractor_payload.get("public_image_url"),
                    public_image_source_domain=contractor_payload.get("image_source_domain") or _domain_from_url(contractor_payload.get("public_image_url")),
                )
                db.session.add(contractor_obj)
                db.session.flush()

        department_obj: GovernmentDepartment | None = None
        if department_payload.get("department_name"):
            existing_dept = GovernmentDepartment.query.filter_by(
                department_name=department_payload.get("department_name"),
                ministry_level=department_payload.get("ministry_level"),
            ).first()
            if existing_dept:
                department_obj = existing_dept
            else:
                department_obj = GovernmentDepartment(
                    department_name=department_payload.get("department_name"),
                    ministry_level=department_payload.get("ministry_level"),
                    official_email=department_payload.get("official_email"),
                    official_phone=department_payload.get("official_phone"),
                    office_address=department_payload.get("office_address"),
                )
                db.session.add(department_obj)
                db.session.flush()

        if department_obj:
            for officer_payload in department_payload.get("officers") or []:
                officer_name = officer_payload.get("officer_name") or officer_payload.get("name")
                if not officer_name:
                    continue
                existing_officer = DepartmentOfficer.query.filter_by(
                    department_id=department_obj.id,
                    officer_name=officer_name,
                ).first()
                if existing_officer:
                    existing_officer.designation = officer_payload.get("designation") or existing_officer.designation
                    existing_officer.official_email = officer_payload.get("official_email") or existing_officer.official_email
                    existing_officer.official_phone = officer_payload.get("official_phone") or existing_officer.official_phone
                    existing_officer.public_image_url = officer_payload.get("public_image_url") or existing_officer.public_image_url
                    existing_officer.public_image_source_domain = officer_payload.get("image_source_domain") or existing_officer.public_image_source_domain
                    continue
                db.session.add(
                    DepartmentOfficer(
                        department_id=department_obj.id,
                        officer_name=officer_name,
                        designation=officer_payload.get("designation"),
                        official_email=officer_payload.get("official_email"),
                        official_phone=officer_payload.get("official_phone"),
                        public_image_url=officer_payload.get("public_image_url"),
                        public_image_source_domain=officer_payload.get("image_source_domain") or _domain_from_url(officer_payload.get("public_image_url")),
                    )
                )

        maintenance_obj: MaintenanceAuthority | None = None
        if maintenance_payload.get("authority_name"):
            existing_m = MaintenanceAuthority.query.filter_by(authority_name=maintenance_payload.get("authority_name")).first()
            if existing_m:
                maintenance_obj = existing_m
            else:
                maintenance_obj = MaintenanceAuthority(
                    authority_name=maintenance_payload.get("authority_name"),
                    contact_email=maintenance_payload.get("contact_email"),
                    contact_phone=maintenance_payload.get("contact_phone"),
                    office_address=maintenance_payload.get("office_address"),
                )
                db.session.add(maintenance_obj)
                db.session.flush()

        project_record = InfrastructureProject(
            location_query_id=loc_record.id,
            project_type=project.get("project_type"),
            project_name=project.get("project_name"),
            project_cost=project.get("project_cost"),
            start_date=project.get("start_date"),
            expected_end_date=project.get("expected_end_date"),
            current_status=project.get("current_status"),
            is_public=True,
            visibility_level="PUBLIC",
            contractor_id=contractor_obj.id if contractor_obj else None,
            department_id=department_obj.id if department_obj else None,
            maintenance_authority_id=maintenance_obj.id if maintenance_obj else None,
        )
        db.session.add(project_record)
        db.session.flush()
        project_record.integrity_hash = hash_record(
            {
                "project_name": project_record.project_name,
                "project_type": project_record.project_type,
                "project_cost": project_record.project_cost,
                "expected_end_date": project_record.expected_end_date,
                "contractor_id": project_record.contractor_id,
            }
        )
        anchor = record_anchor("PROJECT", str(project_record.id), {"integrity_hash": project_record.integrity_hash})
        project_record.blockchain_anchor_id = anchor.id

        if project.get("tender_reference"):
            tender_payload = project.get("tender_reference")
            tender_obj = None
            if any(tender_payload.get(key) for key in ("tender_id", "tender_portal_name", "tender_url")):
                tender_obj = TenderReference(
                    project_id=project_record.id,
                    tender_id=tender_payload.get("tender_id"),
                    tender_portal_name=tender_payload.get("tender_portal_name"),
                    tender_url=tender_payload.get("tender_url"),
                    published_date=tender_payload.get("published_date"),
                )
                tender_obj.data_hash = hash_record(
                    {
                        "project_id": str(project_record.id),
                        "tender_id": tender_payload.get("tender_id"),
                        "portal": tender_payload.get("tender_portal_name"),
                        "url": tender_payload.get("tender_url"),
                        "published": tender_payload.get("published_date"),
                    }
                )
                db.session.add(tender_obj)
                db.session.flush()
                anchor = record_anchor("TENDER", str(tender_obj.id), {"data_hash": tender_obj.data_hash})
                tender_obj.blockchain_anchor_id = anchor.id

        for status_entry in project.get("status_history") or []:
            db.session.add(
                ProjectStatusHistory(
                    project_id=project_record.id,
                    status=status_entry.get("status"),
                    remarks=status_entry.get("remarks"),
                    status_date_text=status_entry.get("status_date"),
                    updated_by=status_entry.get("updated_by"),
                )
            )

        links = project.get("source_links") or []
        if not links:
            current_app.logger.warning("Project missing source links despite validation", extra={"project": project})
        for link in links:
            db.session.add(ProjectSourceLink(project_id=project_record.id, url=link))

    markdown_body = format_project_discovery_markdown(ai_payload.get("location", {}), ai_payload.get("projects", []))
    db.session.add(
        AnalyticsSnapshot(
            snapshot_type="ai_markdown_project_discovery",
            entity_type="LOCATION_QUERY",
            entity_id=str(loc_record.id),
            payload={"markdown": markdown_body},
        )
    )
    db.session.commit()
    return loc_record


def _latest_markdown_html(location_query_id) -> str | None:
    snapshot = (
        AnalyticsSnapshot.query.filter_by(
            snapshot_type="ai_markdown_project_discovery",
            entity_type="LOCATION_QUERY",
            entity_id=str(location_query_id),
        )
        .order_by(AnalyticsSnapshot.computed_at.desc())
        .first()
    )
    if not snapshot:
        return None
    markdown_body = snapshot.payload.get("markdown") if snapshot.payload else None
    return markdown_to_html(markdown_body) if markdown_body else None


def _serialize_contractor(contractor: Contractor | None) -> dict | None:
    if not contractor:
        return None
    return {
        "id": contractor.id,
        "name": contractor.name,
        "company_name": contractor.company_name,
        "registration_number": contractor.registration_number,
        "email": contractor.email,
        "phone": contractor.phone,
        "office_address": contractor.office_address,
        "public_image_url": contractor.public_image_url,
        "image_source_domain": contractor.public_image_source_domain,
        "public_image_note": contractor.public_image_note,
    }


def _serialize_officer(officer: DepartmentOfficer) -> dict:
    return {
        "id": officer.id,
        "officer_name": officer.officer_name,
        "designation": officer.designation,
        "official_email": officer.official_email,
        "official_phone": officer.official_phone,
        "public_image_url": officer.public_image_url,
        "image_source_domain": officer.public_image_source_domain,
        "public_image_note": officer.public_image_note,
    }


def _serialize_department(department: GovernmentDepartment | None) -> dict | None:
    if not department:
        return None
    return {
        "id": department.id,
        "department_name": department.department_name,
        "ministry_level": department.ministry_level,
        "official_email": department.official_email,
        "official_phone": department.official_phone,
        "office_address": department.office_address,
        "officers": [_serialize_officer(officer) for officer in department.officers if officer.is_active],
    }


def _serialize_maintenance(authority: MaintenanceAuthority | None) -> dict | None:
    if not authority:
        return None
    return {
        "id": authority.id,
        "authority_name": authority.authority_name,
        "contact_email": authority.contact_email,
        "contact_phone": authority.contact_phone,
        "office_address": authority.office_address,
    }


def _serialize_project(project: InfrastructureProject) -> dict:
    return {
        "id": str(project.id),
        "project_name": project.project_name,
        "project_type": project.project_type,
        "project_cost": project.project_cost,
        "start_date": project.start_date,
        "expected_end_date": project.expected_end_date,
        "current_status": project.current_status,
        "status_history": [
            {
                "status": hist.status,
                "remarks": hist.remarks,
                "status_date": hist.status_date_text,
                "updated_at": hist.updated_at.isoformat(),
                "updated_by": hist.updated_by,
            }
            for hist in project.status_history
        ],
        "contractor": _serialize_contractor(project.contractor),
        "department": _serialize_department(project.department),
        "maintenance_authority": _serialize_maintenance(project.maintenance_authority),
        "tender_references": [
            {
                "tender_id": tender.tender_id,
                "tender_portal_name": tender.tender_portal_name,
                "tender_url": tender.tender_url,
                "published_date": tender.published_date,
            }
            for tender in project.tender_references
        ],
        "source_links": [link.url for link in project.source_links],
        "location": {
            "name": project.location_query.location_name if project.location_query else None,
            "latitude": float(project.location_query.latitude) if project.location_query and project.location_query.latitude else None,
            "longitude": float(project.location_query.longitude) if project.location_query and project.location_query.longitude else None,
        },
    }


def _safe_snapshot_path(path: str) -> str:
    root = current_app.config.get("PROJECT_SNAPSHOT_DIR")
    abs_root = os.path.abspath(root)
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(abs_root):
        abort(403)
    if not os.path.isfile(abs_path):
        abort(404)
    return abs_path


@project_bp.route("/public", methods=["GET"])
def public_projects():
    filters = sanitize_input(request.args)
    city_filter = filters.get("city")
    project_type_filter = filters.get("type") or filters.get("project_type")
    limit = min(int(current_app.config.get("PUBLIC_MAX_PROJECTS", 50)), 100)

    query = InfrastructureProject.public_query().join(LocationQuery)
    if city_filter:
        query = query.filter(LocationQuery.location_name.ilike(f"%{city_filter}%"))
    if project_type_filter:
        query = query.filter(InfrastructureProject.project_type.ilike(f"%{project_type_filter}%"))

    projects = query.order_by(InfrastructureProject.created_at.desc()).limit(limit).all()
    current_app.logger.info(
        "public_projects_list",
        extra={
            "count": len(projects),
            "filters": {"city": city_filter, "project_type": project_type_filter},
            "visibility_enforced": True,
        },
    )
    return render_template(
        "projects/public_list.html",
        projects=projects,
        filters={"city": city_filter or "", "project_type": project_type_filter or ""},
        status_badges=STATUS_BADGE_CLASS,
        page_title="Public Projects",
    )


@project_bp.route("/public/<string:project_id>", methods=["GET"])
def public_project_detail(project_id):
    project_uuid = _normalize_uuid(project_id)
    project = InfrastructureProject.public_query().filter_by(id=project_uuid).first()
    if not project:
        abort(404)
    return render_template(
        "projects/public_detail.html",
        project=project,
        status_badges=STATUS_BADGE_CLASS,
        page_title="Public Project Transparency",
    )


@project_bp.route("/discovery", methods=["GET", "POST"])
@login_required
def discovery():
    form = ProjectDiscoveryForm()
    form.project_types.data = list(form.project_types.data or [])
    projects: List[InfrastructureProject] = []
    map_data: dict | None = None
    markdown_html: str | None = None
    saved_query = None

    if form.validate_on_submit():
        lat = float(form.latitude.data) if form.latitude.data else None
        lng = float(form.longitude.data) if form.longitude.data else None
        location_label = form.manual_location.data.strip() if form.manual_location.data else f"{lat}, {lng}"
        selected_types = [t for t in form.project_types.data if t]
        ai_provider = (form.ai_model.data or "gemini").lower()
        query_type = "gps" if lat is not None and lng is not None else "manual"

        try:
            ai_payload = fetch_ai_projects(
                location_label,
                str(lat) if lat is not None else None,
                str(lng) if lng is not None else None,
                selected_types,
                ai_model=ai_provider,
            )
            projects_payload = ai_payload.get("projects") or []
            if not projects_payload:
                flash("AI did not return any projects; nothing was saved.", "warning")
                map_data = {"location": ai_payload.get("location") or {}, "projects": []}
                # Skip persistence when AI returns zero results.
                raise StopIteration
            loc_record = _persist_results(location_label, lat, lng, query_type, selected_types, ai_payload)
            projects = list(loc_record.projects.order_by(InfrastructureProject.created_at.desc()))
            markdown_body = format_project_discovery_markdown(ai_payload.get("location", {}), ai_payload.get("projects", []))
            markdown_html = markdown_to_html(markdown_body)
            saved_query = loc_record
            map_data = {
                "location": ai_payload.get("location") or {},
                "projects": [
                    {
                        "name": p.project_name,
                        "type": p.project_type,
                        "status": p.current_status,
                    }
                    for p in projects
                ],
            }
            flash("Projects fetched and stored successfully.", "success")
        except AIProjectDiscoveryError as exc:
            current_app.logger.warning(
                "AI validation failed",
                extra={
                    "error": str(exc),
                    "location_label": location_label,
                    "latitude": lat,
                    "longitude": lng,
                    "query_type": query_type,
                    "project_types": selected_types,
                    "debug_hint": "Check raw_ai_text and cleaned_ai_text logs for the AI response and ensure statuses match allowed set.",
                },
            )
            flash(str(exc), "danger")
            db.session.rollback()
        except StopIteration:
            # Handled zero-project case; nothing persisted.
            pass
        except SQLAlchemyError:
            current_app.logger.exception("Database error while saving project discovery results")
            flash("Unable to save project data. Please try again.", "danger")
            db.session.rollback()
        except Exception as exc:  # pragma: no cover - safety net
            current_app.logger.exception("Unexpected error during project discovery")
            flash("An unexpected error occurred. Please retry shortly.", "danger")
            db.session.rollback()

    return render_template(
        "projects/discovery.html",
        form=form,
        projects=projects,
        map_data=map_data,
        discovery_markdown_html=markdown_html,
        saved_query=saved_query,
        page_title="Project Discovery",
        status_badges=STATUS_BADGE_CLASS,
    )


def _project_or_404(project_id):
    ids = _uuid_candidates(project_id)
    project = InfrastructureProject.query.filter(InfrastructureProject.id.in_(ids)).first()
    if not project:
        abort(404)
    if current_user.is_authenticated:
        role = (current_user.role.name if current_user.role else "").lower()
        if role in {"contractor", "government officer", "officer"}:
            if not project_access_allowed(project, current_user):
                abort(403)
    return project


def _location_query_or_404(query_id):
    ids = _uuid_candidates(query_id)
    query = (
        LocationQuery.query.filter(LocationQuery.id.in_(ids), LocationQuery.user_id == current_user.id)
        .order_by(LocationQuery.created_at.desc())
        .first()
    )
    if not query:
        abort(404)
    return query


@project_bp.route("/discovery/history", methods=["GET"])
@login_required
def discovery_history():
    queries = (
        LocationQuery.query.filter_by(user_id=current_user.id)
        .order_by(LocationQuery.created_at.desc())
        .all()
    )
    return render_template(
        "projects/discovery_history.html",
        queries=queries,
        status_badges=STATUS_BADGE_CLASS,
        page_title="Saved Discoveries",
    )


@project_bp.route("/discovery/<string:query_id>", methods=["GET"])
@login_required
def discovery_record(query_id):
    location_query = _location_query_or_404(query_id)
    projects = list(location_query.projects.order_by(InfrastructureProject.created_at.desc()))
    map_data = {
        "location": {
            "name": location_query.location_name,
            "latitude": float(location_query.latitude) if location_query.latitude is not None else None,
            "longitude": float(location_query.longitude) if location_query.longitude is not None else None,
            "query_type": location_query.query_type,
        },
        "projects": [
            {
                "name": p.project_name,
                "type": p.project_type,
                "status": p.current_status,
            }
            for p in projects
        ],
    }
    markdown_html = _latest_markdown_html(location_query.id)
    return render_template(
        "projects/discovery_record.html",
        location_query=location_query,
        projects=projects,
        map_data=map_data,
        discovery_markdown_html=markdown_html,
        status_badges=STATUS_BADGE_CLASS,
        page_title="Saved Discovery Detail",
    )


@project_bp.route("/discovery/<string:query_id>/delete", methods=["POST"])
@login_required
def delete_discovery(query_id):
    location_query = _location_query_or_404(query_id)
    try:
        # Remove analytics snapshots linked to this discovery
        AnalyticsSnapshot.query.filter_by(entity_type="LOCATION_QUERY", entity_id=str(location_query.id)).delete()

        # Delete associated projects (cascades will clean dependent rows)
        for project in location_query.projects.all():
            db.session.delete(project)

        db.session.delete(location_query)
        db.session.commit()
        flash("Discovery deleted.", "success")
    except Exception:
        current_app.logger.exception("Failed to delete discovery", extra={"query_id": query_id})
        db.session.rollback()
        flash("Could not delete discovery. Please try again.", "danger")

    return redirect(url_for("projects.discovery_history"))


@project_bp.route("/<string:project_id>", methods=["GET"])
@login_required
def project_detail(project_id):
    project = _project_or_404(project_id)
    section_missing = _missing_fields_for_project(project)
    return render_template(
        "projects/project_detail.html",
        project=project,
        status_badges=STATUS_BADGE_CLASS,
        section_missing=section_missing,
        page_title="Project Transparency Detail",
    )


@project_bp.route("/<string:project_id>/snapshots", methods=["POST"])
@login_required
def upload_snapshot(project_id):
    project = _project_or_404(project_id)
    if not track_attempt(f"snapshot:{current_user.id}", limit=15):
        flash("Snapshot rate limit reached. Try again later.", "danger")
        return redirect(request.referrer or url_for("projects.project_detail", project_id=project.id))
    file = request.files.get("snapshot")
    if not file or not file.filename:
        flash("No snapshot uploaded", "warning")
        return redirect(request.referrer or url_for("projects.project_detail", project_id=project.id))
    ext = (file.filename.rsplit(".", 1)[1].lower() if "." in file.filename else "")
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        flash("Unsupported snapshot type", "danger")
        return redirect(request.referrer or url_for("projects.project_detail", project_id=project.id))
    snapshot_dir = current_app.config.get("PROJECT_SNAPSHOT_DIR")
    stored = persist_image(file, snapshot_dir, max_bytes=int(current_app.config.get("MAX_IMAGE_UPLOAD_BYTES", 8 * 1024 * 1024)))
    duplicate = ProjectSnapshot.query.filter_by(image_hash=stored["image_hash"]).first()
    if duplicate:
        flash("Duplicate snapshot ignored", "warning")
        return redirect(request.referrer or url_for("projects.project_detail", project_id=project.id))
    capture_raw = request.form.get("capture_date")
    try:
        capture_date = datetime.fromisoformat(capture_raw).date() if capture_raw else datetime.utcnow().date()
    except Exception:
        capture_date = datetime.utcnow().date()
    source_type = (request.form.get("source_type") or "CITIZEN").upper()
    if source_type not in {"CITIZEN", "PUBLIC", "OFFICIAL"}:
        source_type = "CITIZEN"
    snapshot = ProjectSnapshot(
        project_id=project.id,
        image_path=stored["path"],
        image_hash=stored["image_hash"],
        capture_date=capture_date,
        source_type=source_type,
        location_metadata=build_location_snapshot(project),
    )
    db.session.add(snapshot)
    db.session.commit()
    flash("Snapshot recorded for time-lapse monitoring.", "success")
    return redirect(request.referrer or url_for("projects.project_detail", project_id=project.id))


@project_bp.route("/snapshots/<string:snapshot_id>", methods=["GET"])
@login_required
def view_snapshot(snapshot_id):
    ids = _uuid_candidates(snapshot_id)
    snapshot = ProjectSnapshot.query.filter(ProjectSnapshot.id.in_(ids)).first_or_404()
    path = _safe_snapshot_path(snapshot.image_path)
    _, ext = os.path.splitext(path.lower())
    mime = "image/jpeg"
    if ext == ".png":
        mime = "image/png"
    elif ext == ".webp":
        mime = "image/webp"
    return send_file(path, mimetype=mime, as_attachment=False, download_name=os.path.basename(path))


@project_bp.route("/api/<string:project_id>", methods=["GET"])
@login_required
def project_detail_api(project_id):
    project = _project_or_404(project_id)
    return jsonify(_serialize_project(project))


@project_bp.route("/api/project/find-missing-info", methods=["POST"])
@csrf.exempt
@login_required
def find_missing_info_api():
    # Allow all authenticated users but still audit; downstream rate limits and validations apply.

    payload = request.get_json(silent=True) or {}
    project_id = payload.get("project_id")
    section = payload.get("section_name")
    missing_fields = payload.get("missing_fields") or []

    if not project_id or not section:
        return jsonify({"error": "project_id and section_name are required"}), 400

    project_uuid = _parse_uuid(project_id)
    if not project_uuid:
        return jsonify({"error": "Invalid project_id"}), 400

    if section not in {
        "contractor_details",
        "department_details",
        "officer_contact",
        "tender_information",
        "maintenance_authority",
        "project_timeline",
    }:
        return jsonify({"error": "Unsupported section"}), 400

    if not isinstance(missing_fields, list) or not missing_fields:
        return jsonify({"error": "missing_fields must be a non-empty list"}), 400

    if not track_attempt(f"section-fetch:{current_user.id}:{section}", limit=5):
        return jsonify({"error": "Rate limit reached. Try again later."}), 429

    project = _project_or_404(project_uuid)

    try:
        ai_payload = fetch_section_payload(project, section, [str(f) for f in missing_fields])
        updated_fields = _apply_section_updates(project, section, ai_payload, [str(f) for f in missing_fields])
        markdown = build_section_markdown(section, ai_payload)

        log_entry = SectionDataFetchLog(
            project_id=project.id,
            section_name=section,
            missing_fields=[str(f) for f in missing_fields],
            fetched_payload=ai_payload,
            markdown=markdown,
            triggered_by=current_user.id,
            notes="Updated via AI – Section Fetch",
        )
        db.session.add(log_entry)
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                action_type="SECTION_FETCH",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "unknown"),
            )
        )
        db.session.commit()

        refreshed_missing = _missing_fields_for_project(project).get(section, [])
        return (
            jsonify(
                {
                    "section": section,
                    "updated_fields": updated_fields,
                    "remaining_missing": refreshed_missing,
                    "markdown_html": markdown_to_html(markdown),
                    "sources": ai_payload.get("sources") or {},
                }
            ),
            200,
        )
    except SectionDataFetchError as exc:
        db.session.rollback()
        current_app.logger.warning("Section fetch failed", extra={"section": section, "error": str(exc)})
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive
        db.session.rollback()
        current_app.logger.exception("Unexpected error during section fetch", extra={"section": section})
        return jsonify({"error": "Unable to fetch information at this time."}), 500


@project_bp.route("/contractors/<int:contractor_id>", methods=["GET"])
@login_required
def contractor_profile(contractor_id):
    contractor = Contractor.query.get_or_404(contractor_id)
    rating = compute_contractor_rating(contractor)
    projects = (
        InfrastructureProject.query.filter_by(contractor_id=contractor.id)
        .order_by(InfrastructureProject.created_at.desc())
        .all()
    )
    return render_template(
        "contractors/contractor_profile.html",
        contractor=contractor,
        rating=rating,
        projects=projects,
        status_badges=STATUS_BADGE_CLASS,
        page_title="Contractor Profile",
    )


@project_bp.route("/api/contractors/<int:contractor_id>", methods=["GET"])
@login_required
def contractor_profile_api(contractor_id):
    contractor = Contractor.query.get_or_404(contractor_id)
    projects = InfrastructureProject.query.filter_by(contractor_id=contractor.id).all()
    return jsonify(
        {
            "contractor": _serialize_contractor(contractor),
            "projects": [_serialize_project(p) for p in projects],
        }
    )


@project_bp.route("/departments/<int:department_id>", methods=["GET"])
@login_required
def department_detail(department_id):
    department = GovernmentDepartment.query.get_or_404(department_id)
    projects = (
        InfrastructureProject.query.filter_by(department_id=department.id)
        .order_by(InfrastructureProject.created_at.desc())
        .all()
    )
    return render_template(
        "departments/department_detail.html",
        department=department,
        projects=projects,
        status_badges=STATUS_BADGE_CLASS,
        page_title="Department Detail",
    )


@project_bp.route("/api/departments/<int:department_id>", methods=["GET"])
@login_required
def department_detail_api(department_id):
    department = GovernmentDepartment.query.get_or_404(department_id)
    projects = InfrastructureProject.query.filter_by(department_id=department.id).all()
    return jsonify(
        {
            "department": _serialize_department(department),
            "projects": [_serialize_project(p) for p in projects],
        }
    )
