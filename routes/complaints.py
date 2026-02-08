"""Complaint intake, AI-assisted analysis, and community support blueprint."""
import base64
import json
import os
from datetime import datetime
import uuid
from typing import Any, Dict, Tuple

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from sqlalchemy.exc import SQLAlchemyError
from wtforms import HiddenField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, ValidationError

from extensions import db, csrf
from models import (
    AUTHENTICITY_FLAGS,
    COMPLAINT_SEVERITY,
    COMPLAINT_STATUSES,
    COMPLAINT_TYPES,
    AuditLog,
    Complaint,
    ComplaintImage,
    ComplaintStatusHistory,
    ComplaintSupport,
    ComplaintSupportImage,
    DepartmentOfficer,
    ModerationEvent,
    InfrastructureProject,
    LocationQuery,
)
from utils.ai_vision import AIVisionError, analyze_infrastructure_image
from utils.alert_engine import auto_alert_from_flag, create_alert
from utils.corruption_intelligence import evaluate_corruption_risks
from utils.image_utils import ALLOWED_IMAGE_EXTENSIONS, build_location_snapshot, persist_image
from utils.email_service import (
    EmailDeliveryError,
    _dispatch_email,
    _persist_audit,
    build_initial_payload,
    record_failed_email,
    send_citizen_confirmation_email,
    send_initial_complaint_email,
)
from utils.ai_markdown_formatter import format_complaint_markdown, markdown_to_html, markdown_to_plaintext
from utils.offline_sync import OfflineSyncError, persist_offline_complaints
from utils.security import sanitize_input, track_attempt
from utils.identity_linker import active_entity_context, complaint_access_allowed, project_access_allowed
from utils.blockchain_ready import record_anchor, hash_record
from models import ModerationEvent

complaints_bp = Blueprint("complaints", __name__, url_prefix="/complaints")


class ComplaintIntakeForm(FlaskForm):
    complaint_type = SelectField(
        "Complaint Type",
        choices=[(c, c) for c in COMPLAINT_TYPES],
        validators=[DataRequired()],
    )
    description = TextAreaField("Describe the issue", validators=[Length(max=2000)])
    image = FileField(
        "Upload evidence (jpg, png, webp)",
        validators=[FileRequired(), FileAllowed(list(ALLOWED_IMAGE_EXTENSIONS), "Images only")],
    )
    submit = SubmitField("Analyze Evidence")

    def validate_complaint_type(self, field):  # type: ignore[override]
        if field.data not in COMPLAINT_TYPES:
            raise ValidationError("Invalid complaint type")


class ComplaintFinalizeForm(FlaskForm):
    project_id = HiddenField(validators=[DataRequired()])
    complaint_type = HiddenField(validators=[DataRequired()])
    image_path = HiddenField(validators=[DataRequired()])
    image_hash = HiddenField(validators=[DataRequired()])
    ai_payload = HiddenField(validators=[DataRequired()])
    exif_metadata = HiddenField()
    authenticity_flag = HiddenField(validators=[DataRequired()])
    title = StringField("Title", validators=[DataRequired(), Length(max=255)])
    description = TextAreaField("Description", validators=[DataRequired(), Length(max=3000)])
    severity_level = SelectField(
        "Severity",
        choices=[(s, s.title()) for s in COMPLAINT_SEVERITY],
        validators=[DataRequired()],
    )
    submit = SubmitField("Submit Complaint")


class SupportForm(FlaskForm):
    remark = TextAreaField("Add a short remark", validators=[Length(max=500)])
    image = FileField(
        "Add supporting photo (optional)",
        validators=[FileAllowed(list(ALLOWED_IMAGE_EXTENSIONS), "Images only")],
    )
    submit = SubmitField("Support this complaint")


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
    seen = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


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


def _complaint_or_404(complaint_id):
    ids = _uuid_candidates(complaint_id)
    complaint = Complaint.query.filter(Complaint.id.in_(ids)).first()
    if not complaint:
        abort(404)
    if current_user.is_authenticated:
        if not complaint_access_allowed(complaint, current_user):
            abort(403)
    return complaint


def _safe_path(path: str) -> str:
    upload_root = current_app.config.get("COMPLAINT_UPLOAD_FOLDER")
    if not upload_root:
        abort(500)
    abs_root = os.path.abspath(upload_root)
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(abs_root):
        abort(403)
    if not os.path.isfile(abs_path):
        abort(404)
    return abs_path


@complaints_bp.route("/public", methods=["GET"])
def public_complaints():
    filters = sanitize_input(request.args)
    area_filter = filters.get("area")
    status_filter = filters.get("status")
    severity_filter = filters.get("severity")
    limit = min(int(current_app.config.get("PUBLIC_MAX_COMPLAINTS", 50)), 100)

    query = Complaint.public_query().join(InfrastructureProject).outerjoin(LocationQuery)
    if status_filter and status_filter in COMPLAINT_STATUSES:
        query = query.filter(Complaint.status == status_filter)
    if severity_filter and severity_filter in COMPLAINT_SEVERITY:
        query = query.filter(Complaint.severity_level == severity_filter)
    if area_filter:
        query = query.filter(LocationQuery.location_name.ilike(f"%{area_filter}%"))

    complaints = query.order_by(Complaint.created_at.desc()).limit(limit).all()
    current_app.logger.info(
        "public_complaints_list",
        extra={
            "count": len(complaints),
            "filters": {"area": area_filter, "status": status_filter, "severity": severity_filter},
            "visibility_enforced": True,
        },
    )
    return render_template(
        "complaints/public_list.html",
        complaints=complaints,
        filters={"area": area_filter or "", "status": status_filter or "", "severity": severity_filter or ""},
        status_options=COMPLAINT_STATUSES,
        severity_options=COMPLAINT_SEVERITY,
        page_title="Public Complaints",
    )


@complaints_bp.route("/public/<string:complaint_id>", methods=["GET"])
def public_complaint_detail(complaint_id):
    ids = _uuid_candidates(complaint_id)
    complaint = Complaint.public_query().filter(Complaint.id.in_(ids)).first()
    if not complaint:
        abort(404)
    public_payload = complaint.public_payload()
    return render_template(
        "complaints/public_detail.html",
        complaint=complaint,
        public_payload=public_payload,
        page_title="Public Complaint Status",
    )


def _duplicate_hash_exists(image_hash: str) -> bool:
    if ComplaintImage.query.filter_by(image_hash=image_hash).first():
        return True
    if ComplaintSupportImage.query.filter_by(image_hash=image_hash).first():
        return True
    return False


def _assess_authenticity(ai_flag: str, exif_meta: Dict[str, Any], duplicate: bool) -> Tuple[str, list]:
    reasons = []
    flag = ai_flag or "UNVERIFIABLE"
    capture_iso = exif_meta.get("_normalized_capture_datetime") if exif_meta else None
    if not exif_meta:
        reasons.append("Missing EXIF metadata")
    if capture_iso:
        try:
            captured_at = datetime.fromisoformat(capture_iso)
            delta_days = (datetime.utcnow() - captured_at).days
            if delta_days > 180:
                reasons.append("Image captured more than 180 days ago")
                flag = "SUSPICIOUS"
        except Exception:
            reasons.append("Unable to parse capture date")
    if duplicate:
        reasons.append("Image hash matches an earlier submission")
        flag = "SUSPICIOUS"
    if flag not in AUTHENTICITY_FLAGS:
        flag = "UNVERIFIABLE"
    return flag, reasons


def _record_status(complaint: Complaint, new_status: str, remarks: str | None = None) -> None:
    history = ComplaintStatusHistory(
        complaint=complaint,
        previous_status=complaint.status,
        new_status=new_status,
        remarks=remarks,
        changed_by=current_user.id if current_user and current_user.is_authenticated else None,
    )
    complaint.status = new_status
    db.session.add(history)


@complaints_bp.route("/", methods=["GET"])
@login_required
def list_my_complaints():
    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    page = 1 if page < 1 else page

    default_page_size = int(current_app.config.get("COMPLAINTS_PER_PAGE", 10))
    per_page = max(1, min(default_page_size, 50))

    status_filter = request.args.get("status") or None
    role = (current_user.role.name if current_user.role else "").lower()
    query = Complaint.query.filter_by(user_id=current_user.id)

    if role in {"contractor", "government officer", "officer"}:
        ctx = active_entity_context(current_user)
        if ctx:
            etype = ctx.get("entity_type")
            eid_raw = ctx.get("entity_id")
            eid_int = None
            try:
                eid_int = int(eid_raw)
            except (TypeError, ValueError):
                eid_int = None
            if etype == "CONTRACTOR":
                if eid_int is None:
                    query = Complaint.query.filter(db.text("1=0"))
                else:
                    query = Complaint.query.join(InfrastructureProject).filter(InfrastructureProject.contractor_id == eid_int)
            elif etype == "DEPARTMENT":
                if eid_int is None:
                    query = Complaint.query.filter(db.text("1=0"))
                else:
                    query = Complaint.query.join(InfrastructureProject).filter(InfrastructureProject.department_id == eid_int)
            elif etype == "OFFICER":
                dept_id = None
                try:
                    officer = DepartmentOfficer.query.filter_by(id=eid_int, is_active=True).first()
                    dept_id = officer.department_id if officer else None
                except (TypeError, ValueError):
                    dept_id = None
                if dept_id:
                    query = Complaint.query.join(InfrastructureProject).filter(InfrastructureProject.department_id == dept_id)
                else:
                    query = Complaint.query.filter(db.text("1=0"))
    if status_filter and status_filter in COMPLAINT_STATUSES:
        query = query.filter(Complaint.status == status_filter)

    pagination = (
        query.order_by(Complaint.created_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    return render_template(
        "complaints/complaint_list.html",
        complaints=pagination.items,
        pagination=pagination,
        status_filter=status_filter,
        status_options=COMPLAINT_STATUSES,
        page_title="My Complaints",
    )


@complaints_bp.route("/projects/<string:project_id>/new", methods=["GET", "POST"])
@login_required
def new_complaint(project_id):
    project = _project_or_404(project_id)
    form = ComplaintIntakeForm()
    if request.method == "GET":
        return render_template(
            "complaints/complaint_form.html",
            form=form,
            project=project,
            page_title="Report Infrastructure Issue",
        )

    if not current_user.is_email_verified:
        flash("Verify your email before submitting a complaint.", "warning")
        return redirect(url_for("auth.resend_verification"))

    if form.validate_on_submit():
        try:
            upload_dir = current_app.config.get("COMPLAINT_UPLOAD_FOLDER")
            max_bytes = int(current_app.config.get("MAX_IMAGE_UPLOAD_BYTES", 8 * 1024 * 1024))
            stored = persist_image(form.image.data, upload_dir, max_bytes=max_bytes)
            duplicate = _duplicate_hash_exists(stored["image_hash"])
            if duplicate:
                db.session.add(ModerationEvent(complaint_id=None, user_id=current_user.id, event_type="DUPLICATE_IMAGE", notes="Duplicate during complaint intake"))

            analysis = analyze_infrastructure_image(
                stored["bytes"],
                stored["mime_type"],
                project.project_name,
                project.project_type,
            )
            current_app.logger.info("Gemini analysis response: %s", json.dumps(analysis, ensure_ascii=True))

            authenticity_flag, reasons = _assess_authenticity(
                analysis.get("authenticity_flag", "UNVERIFIABLE"),
                stored.get("exif_metadata") or {},
                duplicate,
            )
            analysis.setdefault("authenticity_reasons", []).extend(reasons)
            analysis["authenticity_flag"] = authenticity_flag
            analysis["duplicate_detected"] = duplicate

            complaint_type_value = analysis.get("issue_type", form.complaint_type.data)
            if complaint_type_value not in COMPLAINT_TYPES:
                complaint_type_value = form.complaint_type.data

            analysis_markdown = format_complaint_markdown(
                {
                    "title": analysis.get("suggested_title") or project.project_name,
                    "complaint_type": complaint_type_value,
                    "severity": analysis.get("suggested_severity"),
                    "description": analysis.get("suggested_description") or form.description.data,
                    "location": build_location_snapshot(project),
                },
                analysis,
            )
            analysis["markdown"] = analysis_markdown
            analysis["markdown_html"] = markdown_to_html(analysis_markdown)
            analysis["ai_summary"] = markdown_to_plaintext(analysis_markdown)
            safe_description = markdown_to_plaintext(analysis_markdown)
            suggested_description = analysis.get("suggested_description") or safe_description or form.description.data

            preview_data = {
                "project_id": str(project.id),
                "complaint_type": complaint_type_value,
                "title": analysis.get("suggested_title"),
                "description": suggested_description,
                "severity": analysis.get("suggested_severity"),
                "ai_payload": analysis,
                "analysis_markdown_html": analysis.get("markdown_html"),
                "image_path": stored["path"],
                "image_hash": stored["image_hash"],
                "authenticity_flag": authenticity_flag,
                "exif_metadata": stored.get("exif_metadata") or {},
                "location_snapshot": build_location_snapshot(project),
                "image_preview_data": f"data:{stored['mime_type']};base64,{base64.b64encode(stored['bytes']).decode()}"
            }
            current_app.logger.info(
                "Complaint preview payload",
                extra={
                    "ai_suggested_description": analysis.get("suggested_description"),
                    "safe_description": safe_description,
                    "preview_description": preview_data["description"],
                    "complaint_type": preview_data["complaint_type"],
                    "severity": preview_data["severity"],
                },
            )
            audit = AuditLog(
                user_id=current_user.id,
                action_type="COMPLAINT_IMAGE_ANALYZED",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "unknown"),
            )
            db.session.add(audit)

            finalize_form = ComplaintFinalizeForm(
                project_id=str(project.id),
                complaint_type=preview_data["complaint_type"],
                title=preview_data["title"],
                description=preview_data["description"],
                severity_level=preview_data["severity"],
                ai_payload=json.dumps(analysis),
                image_path=preview_data["image_path"],
                image_hash=preview_data["image_hash"],
                authenticity_flag=authenticity_flag,
                exif_metadata=json.dumps(preview_data["exif_metadata"]),
            )
            finalize_form.description.data = preview_data["description"]
            finalize_form.title.data = preview_data["title"]
            finalize_form.severity_level.data = preview_data["severity"]

            current_app.logger.info(
                "Complaint preview form values",
                extra={
                    "form_description": finalize_form.description.data,
                    "form_title": finalize_form.title.data,
                    "form_severity": finalize_form.severity_level.data,
                },
            )

            return render_template(
                "complaints/complaint_preview.html",
                data=preview_data,
                finalize_form=finalize_form,
                project=project,
                page_title="Preview Complaint",
            )
        except (ValueError, AIVisionError) as exc:
            current_app.logger.warning("Complaint analysis failed", extra={"error": str(exc)})
            flash(str(exc), "danger")
        except SQLAlchemyError:
            current_app.logger.exception("Database error during complaint analysis")
            flash("Could not analyze complaint right now. Please retry.", "danger")
        except Exception as exc:  # pragma: no cover - safety net
            current_app.logger.exception("Unexpected error during complaint analysis")
            flash("Unexpected error. Please try again shortly.", "danger")
        db.session.rollback()
    return render_template(
        "complaints/complaint_form.html",
        form=form,
        project=project,
        page_title="Report Infrastructure Issue",
    )


@complaints_bp.route("/submit", methods=["POST"])
@login_required
def submit_complaint():
    form = ComplaintFinalizeForm()
    if not form.validate_on_submit():
        flash("Please confirm the complaint details.", "warning")
        return redirect(request.referrer or url_for("main.dashboard"))

    if form.complaint_type.data not in COMPLAINT_TYPES:
        flash("Invalid complaint type.", "danger")
        return redirect(request.referrer or url_for("main.dashboard"))

    if form.severity_level.data not in COMPLAINT_SEVERITY:
        flash("Invalid severity level.", "danger")
        return redirect(request.referrer or url_for("main.dashboard"))

    project = _project_or_404(form.project_id.data)
    ai_payload = {}
    exif_meta = {}
    try:
        ai_payload = json.loads(form.ai_payload.data)
    except Exception:
        ai_payload = {}
    try:
        if form.exif_metadata.data:
            exif_meta = json.loads(form.exif_metadata.data)
    except Exception:
        exif_meta = {}

    try:
        image_path = _safe_path(form.image_path.data)
        duplicate = _duplicate_hash_exists(form.image_hash.data)
        authenticity_flag, reasons = _assess_authenticity(form.authenticity_flag.data, exif_meta, duplicate)
        ai_payload.setdefault("authenticity_reasons", []).extend(reasons)
        ai_payload["authenticity_flag"] = authenticity_flag
        ai_payload["duplicate_detected"] = duplicate

        complaint = Complaint(
            user_id=current_user.id,
            project_id=project.id,
            complaint_type=form.complaint_type.data,
            title=form.title.data.strip(),
            description=form.description.data.strip(),
                ai_generated_summary=ai_payload.get("markdown") or ai_payload.get("ai_summary") or ai_payload.get("suggested_description"),
            severity_level=form.severity_level.data,
            status="SUBMITTED",
            is_public=True,
            visibility_level="ANONYMIZED",
            location_snapshot=build_location_snapshot(project),
        )
        db.session.add(complaint)
        db.session.flush()

        image_record = ComplaintImage(
            complaint_id=complaint.id,
            image_path=image_path,
            image_hash=form.image_hash.data,
            ai_analysis_result=ai_payload,
            authenticity_flag=authenticity_flag,
            exif_metadata=exif_meta,
        )
        db.session.add(image_record)
        _record_status(complaint, "SUBMITTED", remarks="Complaint submitted by citizen")

        audit_entries = [
            AuditLog(
                user_id=current_user.id,
                action_type="COMPLAINT_CREATED",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "unknown"),
            ),
            AuditLog(
                user_id=current_user.id,
                action_type="COMPLAINT_IMAGE_SAVED",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "unknown"),
            ),
        ]
        db.session.add_all(audit_entries)
        db.session.commit()
        try:
            flags = evaluate_corruption_risks(current_app.config)
            threshold = int(current_app.config.get("RISK_SCORE_ALERT_THRESHOLD", 70))
            for flag in flags:
                auto_alert_from_flag(flag, threshold)
        except Exception:
            current_app.logger.exception("Corruption intelligence evaluation failed")
        try:
            create_alert(
                alert_type="COMPLAINT_CRITICAL" if complaint.severity_level == "CRITICAL" else "COMPLAINT_SUBMITTED",
                severity="CRITICAL" if complaint.severity_level == "CRITICAL" else "MEDIUM",
                message=f"Complaint {complaint.id} filed with severity {complaint.severity_level}",
                entity_type="COMPLAINT",
                entity_id=str(complaint.id),
                target_role="officer",
                metadata={"project_id": str(project.id)},
                dedup_window_hours=int(current_app.config.get("ALERT_DEDUP_HOURS", 24)),
            )
        except Exception:
            current_app.logger.warning("Alert dispatch failed for complaint", exc_info=True)
        email_status_category = "success"
        email_status_message = "Complaint submitted successfully. Official notification queued."
        payload = None
        try:
            payload = build_initial_payload(complaint)
            send_initial_complaint_email(complaint)
            email_status_message = "Complaint submitted and official notice dispatched to responsible authorities."
        except EmailDeliveryError as exc:
            try:
                sender, recipients, cc, subject, _text, html_body, _attachments, metadata = payload or build_initial_payload(complaint)
            except Exception:
                sender = complaint.user.email if complaint.user else ""
                recipients = []
                cc = []
                subject = f"Official Complaint Notice - Reference {complaint.id}"
                html_body = complaint.description
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
                "Complaint email dispatch failed",
                extra={"complaint_id": str(complaint.id), "error": str(exc)},
            )
            error_detail = str(exc) or "Unknown error"
            email_status_category = "warning"
            email_status_message = (
                f"Complaint saved, but email delivery failed: {error_detail}. "
                "Administrators have been alerted. You can retry from the complaint detail page."
            )

        try:
            send_citizen_confirmation_email(complaint)
        except Exception:
            current_app.logger.warning(
                "Citizen confirmation email failed",
                extra={"complaint_id": str(complaint.id)},
            )

        flash(email_status_message, email_status_category)
        return redirect(url_for("complaints.view_complaint", complaint_id=complaint.id))
    except SQLAlchemyError:
        current_app.logger.exception("Database error while saving complaint")
        db.session.rollback()
        flash("Unable to save complaint. Please retry.", "danger")
    except Exception as exc:  # pragma: no cover - defensive
        current_app.logger.exception("Unexpected error while saving complaint")
        db.session.rollback()
        flash("Unexpected error. Please retry.", "danger")

    return redirect(request.referrer or url_for("main.dashboard"))


@complaints_bp.route("/<string:complaint_id>", methods=["GET"])
@login_required
def view_complaint(complaint_id):
    complaint = _complaint_or_404(complaint_id)
    support_form = SupportForm()
    supports = complaint.supports
    support_count = len(supports)
    email_logs = list(complaint.email_logs)
    last_failed_log = next((log for log in reversed(email_logs) if log.delivery_status == "FAILED"), None)
    last_email_error = last_failed_log.error_message if last_failed_log else None
    recipient_snapshot = {
        "contractor": complaint.project.contractor.email if complaint.project and complaint.project.contractor else None,
        "department": complaint.project.department.official_email if complaint.project and complaint.project.department else None,
        "monitor": current_app.config.get("MAIL_MONITOR_ADDRESS"),
        "higher": current_app.config.get("MAIL_HIGHER_AUTHORITY"),
    }
    timeline_events = [
        {
            "label": "Complaint submitted",
		"badge_class": "secondary",
		"badge_label": "SUBMITTED",
            "timestamp": complaint.created_at,
            "detail": "Citizen filed complaint",
        }
    ]
    for status in complaint.status_history:
        timeline_events.append(
            {
                "label": f"Status changed to {status.new_status}",
		"badge_class": status_badge_class(status.new_status),
		"badge_label": status.new_status,
                "timestamp": status.changed_at,
                "detail": status.remarks,
            }
        )
    for log in email_logs:
        timeline_events.append(
            {
                "label": "Email sent" if log.delivery_status == "SENT" else "Email failed",
                "badge_class": "primary" if log.delivery_status == "SENT" else "danger",
                "badge_label": log.delivery_status,
                "timestamp": log.sent_at,
                "detail": f"{log.subject} -> {log.recipient_email}",
            }
        )
    timeline_events = sorted(timeline_events, key=lambda x: x.get("timestamp") or datetime.utcnow())
    analysis_payload = complaint.images[0].ai_analysis_result if complaint.images else {}
    analysis_markdown_html = None
    if analysis_payload:
        md_source = analysis_payload.get("markdown") or analysis_payload.get("ai_summary") or complaint.ai_generated_summary
        analysis_markdown_html = markdown_to_html(md_source or "")
    return render_template(
        "complaints/complaint_detail.html",
        complaint=complaint,
        support_form=support_form,
        support_count=support_count,
        email_logs=email_logs,
        recipient_snapshot=recipient_snapshot,
        timeline_events=timeline_events,
        analysis_markdown_html=analysis_markdown_html,
        last_email_error=last_email_error,
        page_title="Complaint Detail",
    )


@complaints_bp.route("/<string:complaint_id>/resend-email", methods=["POST"])
@login_required
def resend_complaint_email(complaint_id):
    complaint = _complaint_or_404(complaint_id)

    try:
        sender, recipients, cc, subject, text_body, html_body, attachments, metadata = build_initial_payload(complaint)
        _dispatch_email(subject, text_body, html_body, sender, recipients, cc, attachments)
        _persist_audit(complaint, sender, recipients, cc, subject, html_body, metadata, status="SENT")
        complaint.notification_sent_at = complaint.notification_sent_at or datetime.utcnow()
        complaint.last_email_status = "SENT"
        db.session.commit()
        flash("Email re-sent successfully to authorities.", "success")
    except EmailDeliveryError as exc:
        db.session.rollback()
        record_failed_email(
            complaint,
            sender=sender if "sender" in locals() else complaint.user.email if complaint.user else "",
            recipients=recipients if "recipients" in locals() else [],
            cc=cc if "cc" in locals() else [],
            subject=subject if "subject" in locals() else f"Official Complaint Notice - Reference {complaint.id}",
            body=html_body if "html_body" in locals() else complaint.description,
            metadata=metadata if "metadata" in locals() else [],
            error=str(exc),
        )
        flash(f"Resend failed: {exc}", "danger")
    except Exception as exc:  # pragma: no cover - defensive
        db.session.rollback()
        flash("Unexpected error during resend. Please try again later.", "danger")

    return redirect(url_for("complaints.view_complaint", complaint_id=complaint.id))


@complaints_bp.route("/offline-sync", methods=["POST"])
@csrf.exempt
@login_required
def offline_sync():
    payload = request.get_json(silent=True) or {}
    items = payload.get("complaints") or []
    max_batch = int(current_app.config.get("OFFLINE_MAX_BATCH", 20))
    if not isinstance(items, list) or not items:
        return jsonify({"error": "No complaints to sync"}), 400
    if len(items) > max_batch:
        return jsonify({"error": "Batch exceeds allowed size"}), 400
    try:
        saved = persist_offline_complaints(current_user, items)
        flags = evaluate_corruption_risks(current_app.config)
        threshold = int(current_app.config.get("RISK_SCORE_ALERT_THRESHOLD", 70))
        for flag in flags:
            auto_alert_from_flag(flag, threshold)
        return jsonify({"synced": len(saved), "ids": [str(c.id) for c in saved]}), 201
    except OfflineSyncError as exc:
        current_app.logger.warning("Offline sync rejected", extra={"error": str(exc)})
        return jsonify({"error": str(exc)}), 400
    except Exception:
        current_app.logger.exception("Offline sync failed")
        return jsonify({"error": "Sync failed"}), 500


@complaints_bp.route("/<string:complaint_id>/support", methods=["POST"])
@login_required
def support_complaint(complaint_id):
    complaint = _complaint_or_404(complaint_id)
    form = SupportForm()
    if not form.validate_on_submit():
        flash("Please provide a valid remark or image.", "warning")
        return redirect(url_for("complaints.view_complaint", complaint_id=complaint.id))

    if not form.remark.data and not (form.image.data and form.image.data.filename):
        flash("Add a remark or image to support.", "warning")
        return redirect(url_for("complaints.view_complaint", complaint_id=complaint.id))

    if not track_attempt(f"support:{current_user.id}", limit=25):
        event = ModerationEvent(complaint_id=complaint.id, user_id=current_user.id, event_type="RATE_LIMIT", notes="Support rate limit breached")
        db.session.add(event)
        db.session.commit()
        flash("Support limit reached. Try again later.", "danger")
        return redirect(url_for("complaints.view_complaint", complaint_id=complaint.id))

    try:
        support = ComplaintSupport(
            complaint_id=complaint.id,
            user_id=current_user.id,
            remark=form.remark.data.strip() if form.remark.data else None,
        )
        db.session.add(support)
        db.session.flush()

        if form.image.data and form.image.data.filename:
            upload_dir = current_app.config.get("COMPLAINT_UPLOAD_FOLDER")
            max_bytes = int(current_app.config.get("MAX_IMAGE_UPLOAD_BYTES", 8 * 1024 * 1024))
            stored = persist_image(form.image.data, upload_dir, max_bytes=max_bytes)
            duplicate = _duplicate_hash_exists(stored["image_hash"])
            if duplicate:
                db.session.add(ModerationEvent(complaint_id=complaint.id, user_id=current_user.id, event_type="DUPLICATE_IMAGE", notes="Support image hash already exists"))
            analysis = analyze_infrastructure_image(
                stored["bytes"],
                stored["mime_type"],
                complaint.project.project_name,
                complaint.project.project_type,
            )
            authenticity_flag, reasons = _assess_authenticity(
                analysis.get("authenticity_flag", "UNVERIFIABLE"),
                stored.get("exif_metadata") or {},
                duplicate,
            )
            analysis.setdefault("authenticity_reasons", []).extend(reasons)
            analysis["authenticity_flag"] = authenticity_flag
            analysis["duplicate_detected"] = duplicate
            analysis_markdown = format_complaint_markdown(
                {
                    "title": analysis.get("suggested_title") or complaint.title,
                    "complaint_type": analysis.get("issue_type") or complaint.complaint_type,
                    "severity": analysis.get("suggested_severity") or complaint.severity_level,
                    "description": analysis.get("suggested_description") or (support.remark or ""),
                    "location": complaint.location_snapshot or {},
                },
                analysis,
            )
            analysis["markdown"] = analysis_markdown
            analysis["markdown_html"] = markdown_to_html(analysis_markdown)
            analysis["ai_summary"] = markdown_to_plaintext(analysis_markdown)
            support_image = ComplaintSupportImage(
                support_id=support.id,
                image_path=stored["path"],
                image_hash=stored["image_hash"],
                ai_analysis_result=analysis,
                authenticity_flag=authenticity_flag,
                exif_metadata=stored.get("exif_metadata") or {},
            )
            db.session.add(support_image)
            audit = AuditLog(
                user_id=current_user.id,
                action_type="COMPLAINT_SUPPORT_IMAGE",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "unknown"),
            )
            db.session.add(audit)

        audit_support = AuditLog(
            user_id=current_user.id,
            action_type="COMPLAINT_SUPPORTED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "unknown"),
        )
        db.session.add(audit_support)
        db.session.commit()
        flash("Support added and recorded.", "success")
    except (ValueError, AIVisionError) as exc:
        current_app.logger.warning("Support evidence failed", extra={"error": str(exc)})
        db.session.rollback()
        flash(str(exc), "danger")
    except SQLAlchemyError:
        current_app.logger.exception("Database error while supporting complaint")
        db.session.rollback()
        flash("Unable to record support right now.", "danger")
    except Exception:
        current_app.logger.exception("Unexpected error while supporting complaint")
        db.session.rollback()
        flash("Unexpected error. Please retry.", "danger")

    return redirect(url_for("complaints.view_complaint", complaint_id=complaint.id))


@complaints_bp.route("/<string:complaint_id>/images/<string:image_id>", methods=["GET"])
@login_required
def view_complaint_image(complaint_id, image_id):
    complaint = _complaint_or_404(complaint_id)
    ids = _uuid_candidates(image_id)
    image = ComplaintImage.query.filter(ComplaintImage.id.in_(ids), ComplaintImage.complaint_id == complaint.id).first_or_404()
    path = _safe_path(image.image_path)
    return send_file(path, mimetype=_guess_mime_from_path(path), as_attachment=False, download_name=os.path.basename(path))


@complaints_bp.route("/support-images/<string:image_id>", methods=["GET"])
@login_required
def view_support_image(image_id):
    ids = _uuid_candidates(image_id)
    image = ComplaintSupportImage.query.filter(ComplaintSupportImage.id.in_(ids)).first_or_404()
    complaint = image.support.complaint if image.support else None
    if not complaint:
        abort(404)
    path = _safe_path(image.image_path)
    return send_file(path, mimetype=_guess_mime_from_path(path), as_attachment=False, download_name=os.path.basename(path))


def _guess_mime_from_path(path: str) -> str:
    _, ext = os.path.splitext(path.lower())
    mapping = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
    }
    return mapping.get(ext, "application/octet-stream")


@complaints_bp.app_template_filter("auth_badge")
def authenticity_badge_class(flag: str | None) -> str:
    mapping = {
        "LIKELY_GENUINE": "success",
        "SUSPICIOUS": "warning",
        "UNVERIFIABLE": "secondary",
    }
    return mapping.get(flag or "", "secondary")


@complaints_bp.app_template_filter("severity_badge")
def severity_badge_class(level: str | None) -> str:
    mapping = {
        "LOW": "secondary",
        "MEDIUM": "info",
        "HIGH": "warning",
        "CRITICAL": "danger",
    }
    return mapping.get(level or "", "secondary")


@complaints_bp.app_template_filter("status_badge")
def status_badge_class(status: str | None) -> str:
    mapping = {
        "SUBMITTED": "secondary",
        "UNDER_REVIEW": "info",
        "IN_PROGRESS": "primary",
        "RESOLVED": "success",
        "CLOSED": "dark",
    }
    return mapping.get((status or "").upper(), "secondary")


@complaints_bp.app_template_filter("mask_email")
def mask_email(value: str | None) -> str:
    if not value:
        return "***"
    addresses = [addr.strip() for addr in value.split(",") if addr.strip()]
    masked_addresses = []
    for address in addresses:
        if "@" not in address:
            masked_addresses.append("***")
            continue
        local, domain = address.split("@", 1)
        if len(local) <= 2:
            masked_local = local[0] + "*" if local else "*"
        else:
            masked_local = local[0] + "***" + local[-1]
        masked_addresses.append(f"{masked_local}@{domain}")
    return ", ".join(masked_addresses) if masked_addresses else "***"
