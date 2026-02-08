"""Secure image handling utilities for complaint evidence."""
import hashlib
import imghdr
import io
import os
import uuid
from datetime import datetime
from typing import Dict, Tuple

from PIL import ExifTags, Image
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
DEFAULT_MAX_IMAGE_BYTES = 8 * 1024 * 1024  # 8 MB


def _fail_if(condition: bool, message: str) -> None:
    if condition:
        raise ValueError(message)


def _get_mime_type(ext: str) -> str:
    mapping = {
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "webp": "image/webp",
    }
    return mapping.get(ext, "application/octet-stream")


def compute_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def extract_exif_metadata(image_bytes: bytes) -> Dict:
    metadata: Dict = {}
    with Image.open(io.BytesIO(image_bytes)) as img:
        try:
            exif_data = img.getexif()
        except Exception:
            return metadata
        if not exif_data:
            return metadata
        for tag_id, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if isinstance(value, bytes):
                try:
                    value = value.decode(errors="ignore")
                except Exception:
                    continue
            metadata[tag_name] = value
    return metadata


def _capture_datetime(exif: Dict) -> str | None:
    for key in ("DateTimeOriginal", "DateTime", "DateTimeDigitized"):
        raw = exif.get(key)
        if not raw:
            continue
        try:
            normalized = str(raw).replace("/", ":").replace("-", ":")
            parts = normalized.replace("  ", " ").split()
            if len(parts) == 2:
                date_part, time_part = parts
                date_part = date_part.replace(".", ":")
                cleaned = f"{date_part} {time_part}"
            else:
                cleaned = normalized
            dt = datetime.strptime(cleaned, "%Y:%m:%d %H:%M:%S")
            return dt.isoformat()
        except Exception:
            continue
    return None


def validate_image_file(file: FileStorage, max_bytes: int = DEFAULT_MAX_IMAGE_BYTES) -> Tuple[bytes, str]:
    _fail_if(not file, "No file provided")
    filename = secure_filename(file.filename or "")
    _fail_if(not filename or "." not in filename, "Unsupported file name")
    ext = filename.rsplit(".", 1)[1].lower()
    _fail_if(ext not in ALLOWED_IMAGE_EXTENSIONS, "File type not allowed")

    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    _fail_if(size == 0, "Empty file")
    _fail_if(size > max_bytes, "File exceeds size limits")

    content = file.read()
    _fail_if(len(content) > max_bytes, "File exceeds size limits")
    sniffed = imghdr.what(None, h=content)
    _fail_if(sniffed not in ALLOWED_IMAGE_EXTENSIONS, "Invalid image data")

    try:
        with Image.open(io.BytesIO(content)) as img:
            img.verify()
    except Exception as exc:
        raise ValueError("Image validation failed") from exc

    file.stream.seek(0)
    return content, ext


def save_image_bytes(image_bytes: bytes, upload_dir: str, extension: str) -> Tuple[str, str]:
    os.makedirs(upload_dir, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex}.{extension}"
    safe_name = secure_filename(unique_name)
    path = os.path.join(upload_dir, safe_name)
    with open(path, "wb") as f:
        f.write(image_bytes)
    return path, safe_name


def persist_image(file: FileStorage, upload_dir: str, max_bytes: int = DEFAULT_MAX_IMAGE_BYTES) -> Dict:
    image_bytes, ext = validate_image_file(file, max_bytes=max_bytes)
    image_hash = compute_hash(image_bytes)
    exif_meta = extract_exif_metadata(image_bytes)
    capture_dt = _capture_datetime(exif_meta)
    if capture_dt:
        exif_meta["_normalized_capture_datetime"] = capture_dt

    stored_path, stored_name = save_image_bytes(image_bytes, upload_dir, ext)
    return {
        "path": stored_path,
        "file_name": stored_name,
        "extension": ext,
        "mime_type": _get_mime_type(ext),
        "image_hash": image_hash,
        "exif_metadata": exif_meta,
        "bytes": image_bytes,
    }


def build_location_snapshot(project) -> Dict:
    if not project:
        return {}
    snapshot = {
        "project_id": str(project.id),
        "project_name": project.project_name,
        "project_type": project.project_type,
    }
    if project.location_query:
        snapshot["location_name"] = project.location_query.location_name
        if project.location_query.latitude is not None:
            snapshot["latitude"] = float(project.location_query.latitude)
        if project.location_query.longitude is not None:
            snapshot["longitude"] = float(project.location_query.longitude)
    return snapshot
