"""RTI Mode services for tamper-proof report compilation and PDF export."""
import os
import uuid
from datetime import datetime
from typing import Dict, List, Tuple

from flask import current_app, request
from sqlalchemy.orm import joinedload

from extensions import db
from models import (
    AnalyticsSnapshot,
    Complaint,
    ComplaintStatusHistory,
    EmailAuditLog,
    InfrastructureProject,
    GovernmentDepartment,
    RTIAuditLog,
    RTIRequest,
    RTI_ENTITY_TYPES,
)
from utils.pdf_generator import generate_pdf
from utils.rating import compute_contractor_rating
from utils.ai_markdown_formatter import markdown_to_plaintext


class RTIServiceError(Exception):
    """Raised when RTI generation fails."""


def _reference_id() -> str:
    return f"RTI-{datetime.utcnow():%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"


def _project_or_error(project_id: uuid.UUID) -> InfrastructureProject:
    project = (
        InfrastructureProject.query.options(
            joinedload(InfrastructureProject.contractor),
            joinedload(InfrastructureProject.department).joinedload(GovernmentDepartment.officers),
            joinedload(InfrastructureProject.tender_references),
            joinedload(InfrastructureProject.status_history),
            joinedload(InfrastructureProject.source_links),
            joinedload(InfrastructureProject.complaints)
            .joinedload(Complaint.status_history)
            .joinedload(ComplaintStatusHistory.actor),
            joinedload(InfrastructureProject.complaints).joinedload(Complaint.email_logs),
            joinedload(InfrastructureProject.location_query),
        )
        .filter_by(id=project_id)
        .first()
    )
    if not project:
        raise RTIServiceError("Project not found")
    return project


def _complaint_or_error(complaint_id: uuid.UUID) -> Complaint:
    complaint = (
        Complaint.query.options(
            joinedload(Complaint.project).joinedload(InfrastructureProject.contractor),
            joinedload(Complaint.project)
            .joinedload(InfrastructureProject.department)
            .joinedload(GovernmentDepartment.officers),
            joinedload(Complaint.project).joinedload(InfrastructureProject.tender_references),
            joinedload(Complaint.status_history),
            joinedload(Complaint.email_logs),
            joinedload(Complaint.images),
        )
        .filter_by(id=complaint_id)
        .first()
    )
    if not complaint:
        raise RTIServiceError("Complaint not found")
    return complaint


def _complaint_payload(complaint: Complaint) -> Dict:
    ai_payload = complaint.images[0].ai_analysis_result if complaint.images else {}
    authenticity_notes = ai_payload.get("authenticity_reasons", []) if ai_payload else []
    ai_section = None
    if ai_payload:
        summary_text = ai_payload.get("ai_summary") or complaint.ai_generated_summary
        ai_section = {
            "issue_type": ai_payload.get("issue_type"),
            "ai_summary": markdown_to_plaintext(summary_text or ""),
            "suggested_severity": ai_payload.get("suggested_severity"),
            "authenticity_flag": ai_payload.get("authenticity_flag"),
            "authenticity_reasons": authenticity_notes,
            "markdown": ai_payload.get("markdown") or complaint.ai_generated_summary,
        }
    return {
        "id": str(complaint.id),
        "complaint_type": complaint.complaint_type,
        "severity_level": complaint.severity_level,
        "status": complaint.status,
        "created_at": complaint.created_at.strftime("%Y-%m-%d %H:%M"),
        "description": complaint.description,
        "ai_section": ai_section,
    }


def _timeline(project: InfrastructureProject, complaint: Complaint | None = None) -> List[Dict]:
    entries: List[Dict] = []
    for hist in project.status_history:
        entries.append(
            {
                "timestamp": hist.updated_at.strftime("%Y-%m-%d %H:%M"),
                "label": f"Project {hist.status}",
                "detail": hist.remarks or hist.status,
            }
        )
    if complaint:
        entries.append(
            {
                "timestamp": complaint.created_at.strftime("%Y-%m-%d %H:%M"),
                "label": "Complaint submitted",
                "detail": complaint.title,
            }
        )
        for hist in complaint.status_history:
            entries.append(
                {
                    "timestamp": hist.changed_at.strftime("%Y-%m-%d %H:%M"),
                    "label": f"Complaint moved to {hist.new_status}",
                    "detail": hist.remarks or hist.new_status,
                }
            )
        for log in complaint.email_logs:
            entries.append(
                {
                    "timestamp": log.sent_at.strftime("%Y-%m-%d %H:%M") if log.sent_at else "",
                    "label": "Email dispatch",
                    "detail": f"{log.delivery_status}: {log.subject}",
                }
            )
    return sorted(entries, key=lambda e: e.get("timestamp", ""))


def _communications_from_complaint(complaint: Complaint) -> List[Dict]:
    communications: List[Dict] = []
    for log in complaint.email_logs:
        communications.append(
            {
                "sent_at": log.sent_at.strftime("%Y-%m-%d %H:%M") if log.sent_at else "",
                "subject": log.subject,
                "delivery_status": log.delivery_status,
                "recipient_email": log.recipient_email,
                "cc_emails": log.cc_emails,
            }
        )
    return communications


def _contractor_section(project: InfrastructureProject) -> Dict:
    contractor = project.contractor
    if not contractor:
        return {}
    metrics = compute_contractor_rating(contractor)
    return {
        "name": contractor.name,
        "company_name": contractor.company_name,
        "registration_number": contractor.registration_number,
        "email": contractor.email,
        "phone": contractor.phone,
        "office_address": contractor.office_address,
        "rating_display": metrics.get("rating_display"),
    }


def _department_section(project: InfrastructureProject) -> Dict:
    department = project.department
    if not department:
        return {}
    return {
        "department_name": department.department_name,
        "ministry_level": department.ministry_level,
        "official_email": department.official_email,
        "official_phone": department.official_phone,
        "office_address": department.office_address,
        "officers": [
            {
                "officer_name": officer.officer_name,
                "designation": officer.designation,
                "official_email": officer.official_email,
            }
            for officer in department.officers
            if officer.is_active
        ],
    }


def _tender_section(project: InfrastructureProject) -> List[Dict]:
    return [
        {
            "tender_id": tender.tender_id,
            "tender_portal_name": tender.tender_portal_name,
            "tender_url": tender.tender_url,
            "published_date": tender.published_date,
        }
        for tender in project.tender_references
    ]


def _project_section(project: InfrastructureProject) -> Dict:
    coords = ""
    if project.location_query and project.location_query.latitude and project.location_query.longitude:
        coords = f"{float(project.location_query.latitude):.6f}, {float(project.location_query.longitude):.6f}"
    return {
        "id": str(project.id),
        "project_name": project.project_name,
        "project_type": project.project_type,
        "project_cost": project.project_cost,
        "start_date": project.start_date,
        "expected_end_date": project.expected_end_date,
        "current_status": project.current_status,
        "location_name": project.location_query.location_name if project.location_query else "",
        "coordinates": coords,
    }


def _source_links(project: InfrastructureProject, complaint: Complaint | None = None) -> List[str]:
    links = [link.url for link in project.source_links]
    for tender in project.tender_references:
        if tender.tender_url:
            links.append(tender.tender_url)
    if complaint:
        for log in complaint.email_logs:
            links.append(f"email://{log.id}")
    return list(dict.fromkeys([link for link in links if link]))


def _store_snapshot(kind: str, entity_type: str, entity_id: str, payload: Dict) -> None:
    snapshot = AnalyticsSnapshot(
        snapshot_type=kind,
        entity_type=entity_type,
        entity_id=entity_id,
        payload=payload,
    )
    db.session.add(snapshot)


def generate_rti_report(entity_type: str, entity_id: uuid.UUID, user_id) -> Tuple[RTIRequest, str]:
    normalized = entity_type.upper()
    if normalized not in RTI_ENTITY_TYPES:
        raise RTIServiceError("Unsupported entity type")

    project: InfrastructureProject | None = None
    complaint: Complaint | None = None
    if normalized == "PROJECT":
        project = _project_or_error(entity_id)
    else:
        complaint = _complaint_or_error(entity_id)
        project = complaint.project

    reference_id = _reference_id()
    output_dir = current_app.config.get("RTI_REPORT_DIR")
    output_path = os.path.join(output_dir, f"{reference_id}.pdf")

    contractor_section = _contractor_section(project)
    department_section = _department_section(project)
    tender_section = _tender_section(project)

    complaint_section = _complaint_payload(complaint) if complaint else None
    communications = _communications_from_complaint(complaint) if complaint else []
    ai_findings = complaint_section.get("ai_section") if complaint_section else None

    timeline_entries = _timeline(project, complaint)
    sources = _source_links(project, complaint)

    payload = {
        "reference_id": reference_id,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "entity_type": normalized,
        "entity_id": str(entity_id),
        "project": _project_section(project) if project else {},
        "contractor": contractor_section,
        "department": department_section,
        "tenders": tender_section,
        "timeline": timeline_entries,
        "complaint": complaint_section,
        "ai_findings": ai_findings,
        "communications": communications,
        "source_links": sources,
    }

    payload["checksum"] = "Pending"
    checksum = generate_pdf(payload, output_path)
    payload["checksum"] = checksum
    checksum = generate_pdf(payload, output_path)
    payload["checksum"] = checksum

    rti_record = RTIRequest(
        reference_id=reference_id,
        entity_type=normalized,
        entity_id=entity_id,
        generated_by=user_id,
        pdf_path=output_path,
        is_public=True,
        visibility_level="PUBLIC",
        pdf_checksum=checksum,
        hash_algorithm="sha256",
        extra_metadata={
            "source_links": sources,
            "project_name": project.project_name if project else None,
            "complaint_id": str(complaint.id) if complaint else None,
        },
    )
    db.session.add(rti_record)
    db.session.flush()

    audit_log = RTIAuditLog(
        rti_request_id=rti_record.id,
        event_type="GENERATED",
        triggered_by=user_id,
        ip_address=request.remote_addr if request else None,
        user_agent=request.headers.get("User-Agent", "unknown") if request else None,
        notes=f"RTI generated for {normalized}",
    )
    db.session.add(audit_log)
    _store_snapshot("rti_generation", normalized, str(entity_id), payload)
    db.session.commit()

    return rti_record, checksum


def record_download(reference_id: str, user_id) -> RTIRequest:
    record = RTIRequest.query.filter_by(reference_id=reference_id).first()
    if not record:
        raise RTIServiceError("RTI reference not found")

    audit_log = RTIAuditLog(
        rti_request_id=record.id,
        event_type="DOWNLOADED",
        triggered_by=user_id,
        ip_address=request.remote_addr if request else None,
        user_agent=request.headers.get("User-Agent", "unknown") if request else None,
        notes="RTI PDF downloaded",
    )
    db.session.add(audit_log)
    db.session.commit()
    return record
