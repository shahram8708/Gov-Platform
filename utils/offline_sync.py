"""Offline-first complaint sync orchestrator."""
from __future__ import annotations

import base64
import io
import os
from datetime import datetime
from typing import Dict, List

from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models import Complaint, ComplaintImage, InfrastructureProject
from werkzeug.datastructures import FileStorage
from utils.image_utils import persist_image, build_location_snapshot


class OfflineSyncError(Exception):
    """Raised when offline sync input is invalid."""


def _decode_image(payload: Dict) -> Dict:
    data_uri = payload.get("image_b64")
    if not data_uri:
        raise OfflineSyncError("Missing image payload for offline complaint")
    try:
        header, b64data = data_uri.split(",", 1) if "," in data_uri else ("", data_uri)
        binary = base64.b64decode(b64data)
    except Exception as exc:  # pragma: no cover - defensive
        raise OfflineSyncError("Invalid base64 image payload") from exc
    mime_type = payload.get("image_mime") or "image/jpeg"
    return {"bytes": binary, "mime_type": mime_type}


def persist_offline_complaints(user, items: List[Dict]) -> List[Complaint]:
    saved: List[Complaint] = []
    upload_dir = current_app.config.get("COMPLAINT_UPLOAD_FOLDER")
    max_bytes = int(current_app.config.get("MAX_IMAGE_UPLOAD_BYTES", 8 * 1024 * 1024))

    for item in items:
        project_id = item.get("project_id")
        project = InfrastructureProject.query.filter_by(id=project_id).first()
        if not project:
            raise OfflineSyncError(f"Project {project_id} not found")

        image_payload = _decode_image(item)
        stored = persist_image_bytes(image_payload["bytes"], image_payload["mime_type"], upload_dir, max_bytes)

        complaint = Complaint(
            user_id=user.id,
            project_id=project.id,
            complaint_type=item.get("complaint_type") or "Other",
            title=item.get("title") or "Offline Complaint",
            description=item.get("description") or "Offline submission",
            severity_level=item.get("severity_level") or "MEDIUM",
            status="SUBMITTED",
            is_offline_submission=True,
            sync_status="SYNCED",
            sync_reference=item.get("client_reference"),
            location_snapshot=item.get("location_snapshot") or build_location_snapshot(project),
        )
        db.session.add(complaint)
        db.session.flush()

        image_record = ComplaintImage(
            complaint_id=complaint.id,
            image_path=stored["path"],
            image_hash=stored["image_hash"],
            ai_analysis_result=None,
            authenticity_flag="UNVERIFIABLE",
            exif_metadata=item.get("exif_metadata") or {},
        )
        db.session.add(image_record)
        saved.append(complaint)

    db.session.commit()
    return saved


def persist_image_bytes(payload: bytes, mime_type: str, upload_dir: str, max_bytes: int) -> Dict:
    stream = io.BytesIO(payload)
    file_obj = FileStorage(stream=stream, filename=f"offline-{datetime.utcnow().isoformat()}.jpg", content_type=mime_type)
    return persist_image(file_obj, upload_dir, max_bytes=max_bytes)
