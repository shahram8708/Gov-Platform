"""Gemini Vision integration for infrastructure complaint evidence."""
import json
import os
import re
from typing import Any, Dict, List

from flask import current_app
from google import genai
from google.genai import types

from utils.image_utils import ALLOWED_IMAGE_EXTENSIONS


def _normalize_severity(value: str | None) -> str | None:
    if not value:
        return None
    normalized = str(value).strip().upper()
    if normalized in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return normalized
    return None


def _normalize_authenticity(value: str | None) -> str | None:
    if not value:
        return None
    normalized = str(value).strip().upper()
    mapping = {
        "LIKELY_GENUINE": "LIKELY_GENUINE",
        "GENUINE": "LIKELY_GENUINE",
        "SUSPICIOUS": "SUSPICIOUS",
        "UNVERIFIABLE": "UNVERIFIABLE",
    }
    return mapping.get(normalized)


class AIVisionError(Exception):
    """Raised when Gemini Vision cannot return a valid result."""


def _first_json_block(text: str) -> str:
    """Extract the first JSON object block from free-form text."""
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


def _safe_json_loads(raw_text: str) -> Dict[str, Any]:
    """Parse JSON robustly, tolerating leading/trailing noise or code fences."""
    cleaned = raw_text.strip()
    # Remove common code fences if present
    cleaned = re.sub(r"^```[a-zA-Z0-9_-]*", "", cleaned).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        block = _first_json_block(cleaned)
        return json.loads(block)


def _coerce_str(value: Any, field: str, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise AIVisionError(f"Missing required field: {field}")
        return None
    text = str(value).strip()
    if required and not text:
        raise AIVisionError(f"Missing required field: {field}")
    return text


def _coerce_float(value: Any, field: str, required: bool = False) -> float | None:
    if value is None or value == "":
        if required:
            raise AIVisionError(f"Missing numeric field: {field}")
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        if required:
            raise AIVisionError(f"Invalid numeric field: {field}")
        return None


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in {"true", "True", "1", 1}:  # tolerant parsing
        return True
    if value in {"false", "False", "0", 0}:
        return False
    return None


def _coerce_str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        return [str(value).strip()] if str(value).strip() else []
    result = []
    for item in value:
        text = str(item).strip()
        if text:
            result.append(text)
    return result


def build_vision_prompt(project_name: str, project_type: str | None, extensions=ALLOWED_IMAGE_EXTENSIONS) -> str:
    allowed_ext = ", ".join(sorted(extensions))
    return (
        "You are an infrastructure quality and authenticity reviewer for a government redressal platform. "
        "Analyse the image for visible civil works issues such as cracks, leakages, structural damage, poor workmanship, missing safety measures, waterlogging, corruption indicators. "
        "Context: Project name: "
        f"{project_name}. Project type: {project_type or 'Unknown'}. "
        "Return strict JSON with fields: "
        "issue_type (Crack, Leakage, Poor Quality, Delay, Corruption, Other), "
        "suggested_title, suggested_description, suggested_severity (LOW|MEDIUM|HIGH|CRITICAL), "
        "ai_summary, infrastructure_match (boolean), severity_confidence (0-1), detected_elements (array of strings), "
        "authenticity_flag (LIKELY_GENUINE, SUSPICIOUS, UNVERIFIABLE), authenticity_reasons (array), "
        "screenshot_likelihood (0-1), reused_or_old_likelihood (0-1), non_infrastructure_likelihood (0-1), "
        "recommendations (array of short actions). "
        "Do not include markdown. JSON only. Supported file types: "
        f"{allowed_ext}. "
        "Below is an example of the expected JSON response format. "
        "The actual response must follow the same structure but with values derived from the analysed image. "
        "Example JSON: "
        "{"
            "\"issue_type\": \"Crack\","
            "\"suggested_title\": \"Visible cracks in newly constructed road surface\","
            "\"suggested_description\": \"Multiple longitudinal and transverse cracks are visible on the road surface, indicating poor material quality or improper compaction during construction.\","
            "\"suggested_severity\": \"HIGH\","
            "\"ai_summary\": \"The image shows clear surface cracking on a recently constructed road, suggesting substandard workmanship or material failure.\","
            "\"infrastructure_match\": true,"
            "\"severity_confidence\": 0.87,"
            "\"detected_elements\": [\"road surface\", \"visible cracks\", \"uneven asphalt\"],"
            "\"authenticity_flag\": \"LIKELY_GENUINE\","
            "\"authenticity_reasons\": [\"Consistent lighting\", \"No signs of digital alteration\", \"Damage aligns with real-world construction defects\"],"
            "\"screenshot_likelihood\": 0.05,"
            "\"reused_or_old_likelihood\": 0.12,"
            "\"non_infrastructure_likelihood\": 0.02,"
            "\"recommendations\": ["
                "\"Conduct on-site inspection\","
                "\"Check material quality reports\","
                "\"Initiate repair under defect liability period\""
            "]"
        "}"
    )


def analyze_infrastructure_image(image_bytes: bytes, mime_type: str, project_name: str, project_type: str | None = None) -> Dict[str, Any]:
    api_key = current_app.config.get("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise AIVisionError("GEMINI_API_KEY is not configured")

    client = genai.Client(api_key=api_key)
    model_name = current_app.config.get("GEMINI_VISION_MODEL", "gemini-2.5-flash")

    prompt = build_vision_prompt(project_name, project_type)

    current_app.logger.info(
        "Dispatching Gemini Vision analysis",
        extra={"project": project_name, "project_type": project_type, "model": model_name},
    )

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=[
                types.Part.from_bytes(data=image_bytes, mime_type=mime_type),
                types.Part.from_text(text=prompt),
            ],
            config=types.GenerateContentConfig(response_mime_type="application/json"),
        )
    except Exception as exc:  # pragma: no cover - relies on remote service
        current_app.logger.exception("Gemini Vision request failed")
        raise AIVisionError("Gemini Vision request failed") from exc

    raw_text = (response.text or "").strip()
    if not raw_text and getattr(response, "candidates", None):  # defensive fallback
        try:
            parts = response.candidates[0].content.parts if response.candidates else []
            raw_text = "".join(getattr(p, "text", "") for p in parts).strip()
        except Exception:
            raw_text = ""
    if not raw_text.strip():
        raise AIVisionError("Gemini Vision returned empty response")

    try:
        payload = _safe_json_loads(raw_text)
    except Exception as exc:  # pragma: no cover - defensive
        raise AIVisionError("Gemini Vision returned non-JSON output") from exc

    # Basic validation
    issue_type = _coerce_str(payload.get("issue_type"), "issue_type")
    suggested_title = _coerce_str(payload.get("suggested_title"), "suggested_title")
    suggested_description = _coerce_str(payload.get("suggested_description"), "suggested_description")
    suggested_severity = _normalize_severity(payload.get("suggested_severity"))
    authenticity_flag = _normalize_authenticity(payload.get("authenticity_flag"))

    if not issue_type or not suggested_title or not suggested_description:
        raise AIVisionError("Gemini Vision did not return required complaint fields")

    if not suggested_severity:
        raise AIVisionError("Gemini Vision did not return a valid severity level")

    payload["suggested_severity"] = suggested_severity
    payload["authenticity_flag"] = authenticity_flag or "UNVERIFIABLE"
    payload["issue_type"] = issue_type
    payload["suggested_title"] = suggested_title
    payload["suggested_description"] = suggested_description
    payload["ai_summary"] = _coerce_str(payload.get("ai_summary"), "ai_summary", required=False) or suggested_description
    payload["detected_elements"] = _coerce_str_list(payload.get("detected_elements"))
    payload["authenticity_reasons"] = _coerce_str_list(payload.get("authenticity_reasons"))
    payload["recommendations"] = _coerce_str_list(payload.get("recommendations"))
    payload["severity_confidence"] = _coerce_float(payload.get("severity_confidence"), "severity_confidence")
    payload["screenshot_likelihood"] = _coerce_float(payload.get("screenshot_likelihood"), "screenshot_likelihood")
    payload["reused_or_old_likelihood"] = _coerce_float(payload.get("reused_or_old_likelihood"), "reused_or_old_likelihood")
    payload["non_infrastructure_likelihood"] = _coerce_float(payload.get("non_infrastructure_likelihood"), "non_infrastructure_likelihood")
    payload["infrastructure_match"] = _coerce_bool(payload.get("infrastructure_match"))

    return payload
