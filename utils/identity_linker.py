"""Email-based entity linking and access enforcement utilities."""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from flask import current_app, request, session
from sqlalchemy import func

from extensions import db
from models import (
    AuditLog,
    Complaint,
    Contractor,
    DepartmentOfficer,
    GovernmentDepartment,
    InfrastructureProject,
    User,
    UserEntityLink,
)

ENTITY_PRIORITY: tuple[str, ...] = ("OFFICER", "DEPARTMENT", "CONTRACTOR")


def normalize_email(value: str | None) -> str:
    return (value or "").strip().lower()


def _audit(action: str, user: User | None, context: str | None = None, note: str | None = None) -> None:
    try:
        entry = AuditLog(
            user_id=user.id if user else None,
            action_type=action,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get("User-Agent", "system") if request else "system",
            context_entity=context or note,
        )
        db.session.add(entry)
    except Exception:
        if current_app:
            current_app.logger.warning("Audit log failed", extra={"action": action})


def _find_matches(email: str) -> Dict[str, List[object]]:
    matches: Dict[str, List[object]] = {"OFFICER": [], "DEPARTMENT": [], "CONTRACTOR": []}
    if not email:
        return matches
    matches["OFFICER"] = DepartmentOfficer.query.filter(
        DepartmentOfficer.is_active.is_(True), func.lower(DepartmentOfficer.official_email) == email
    ).all()
    matches["DEPARTMENT"] = GovernmentDepartment.query.filter(func.lower(GovernmentDepartment.official_email) == email).all()
    matches["CONTRACTOR"] = Contractor.query.filter(func.lower(Contractor.email) == email).all()
    return matches


def _link_record(user: User, entity_type: str, entity_id: str, note: str | None = None) -> UserEntityLink:
    link = UserEntityLink.query.filter_by(
        user_id=user.id, entity_type=entity_type, entity_id=entity_id
    ).first()
    if link:
        link.is_active = True
        link.linked_at = datetime.utcnow()
        link.notes = note or link.notes
        return link
    link = UserEntityLink(
        user_id=user.id,
        entity_type=entity_type,
        entity_id=entity_id,
        linked_by="EMAIL_MATCH",
        linked_at=datetime.utcnow(),
        is_active=True,
        notes=note,
    )
    db.session.add(link)
    return link


def resolve_user_entity_links(user: User) -> Optional[UserEntityLink]:
    if not user or not user.is_email_verified:
        _audit("AUTO_LINK_SKIPPED", user, note="unverified_email")
        return None

    email = normalize_email(user.email)
    matches = _find_matches(email)

    chosen_type = None
    chosen_entity = None
    for entity_type in ENTITY_PRIORITY:
        hits = matches.get(entity_type) or []
        if not hits:
            continue
        if len(hits) > 1:
            _audit("AUTO_LINK_CONFLICT", user, context=f"{entity_type}:{len(hits)}")
            return None
        chosen_type = entity_type
        chosen_entity = hits[0]
        break

    if not chosen_type or not chosen_entity:
        _audit("AUTO_LINK_NONE", user, note=email)
        session.pop("active_entity_context", None)
        return None

    link = _link_record(user, chosen_type, str(getattr(chosen_entity, "id")), note=email)
    context_label = _context_label(chosen_type, chosen_entity)
    session["active_entity_context"] = {
        "entity_type": chosen_type,
        "entity_id": str(getattr(chosen_entity, "id")),
        "email": email,
        "label": context_label,
        "linked_at": link.linked_at.isoformat(),
    }
    _audit("AUTO_LINK_SUCCESS", user, context=f"{chosen_type}:{getattr(chosen_entity, 'id')}")
    return link


def _context_label(entity_type: str, entity: object) -> str:
    if entity_type == "OFFICER":
        return getattr(entity, "officer_name", "Officer")
    if entity_type == "DEPARTMENT":
        return getattr(entity, "department_name", "Department")
    if entity_type == "CONTRACTOR":
        name = getattr(entity, "name", "Contractor")
        company = getattr(entity, "company_name", None)
        return f"{name} ({company})" if company else name
    return entity_type.title()


def active_entity_context(user: User | None) -> Optional[Dict[str, str]]:
    if not user or not user.is_authenticated:
        return None
    ctx = session.get("active_entity_context")
    if ctx and ctx.get("entity_type") in ENTITY_PRIORITY:
        return ctx

    links = (
        UserEntityLink.query.filter_by(user_id=user.id, is_active=True)
        .order_by(UserEntityLink.linked_at.desc())
        .all()
    )
    prioritized = None
    for priority in ENTITY_PRIORITY:
        target = next((l for l in links if l.entity_type == priority), None)
        if target:
            prioritized = target
            break
    if not prioritized:
        return None
    session["active_entity_context"] = {
        "entity_type": prioritized.entity_type,
        "entity_id": prioritized.entity_id,
        "email": normalize_email(user.email),
        "label": prioritized.notes or prioritized.entity_type,
        "linked_at": prioritized.linked_at.isoformat() if prioritized.linked_at else None,
    }
    return session.get("active_entity_context")


def project_access_allowed(project: InfrastructureProject, user: User) -> bool:
    if not user or not user.is_authenticated:
        return False
    role = (user.role.name if user.role else "").lower()
    if role == "admin":
        return True
    ctx = active_entity_context(user)
    if role in {"citizen", ""}:
        return True
    if not ctx:
        return False
    etype = ctx.get("entity_type")
    eid = ctx.get("entity_id")
    if etype == "CONTRACTOR":
        return str(project.contractor_id) == eid
    if etype == "DEPARTMENT":
        return str(project.department_id) == eid
    if etype == "OFFICER":
        try:
            officer_id = int(eid)
        except (TypeError, ValueError):
            return False
        officer = DepartmentOfficer.query.filter_by(id=officer_id, is_active=True).first()
        return bool(officer and project.department_id == officer.department_id)
    return False


def complaint_access_allowed(complaint: Complaint, user: User) -> bool:
    if not user or not user.is_authenticated:
        return False
    role = (user.role.name if user.role else "").lower()
    if role == "admin":
        return True
    if complaint.user_id == user.id:
        return True
    project = complaint.project
    if not project:
        return False
    return project_access_allowed(project, user)
