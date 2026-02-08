"""AI-powered project discovery integration using Google Gemini with Google Search grounding."""
import json
import os
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
from flask import current_app
from google import genai
from google.genai import types

ALLOWED_PROJECT_TYPES = {
    "Bridge",
    "Road",
    "Building",
    "Flyover",
    "Drainage",
    "Water Pipeline",
    "Electricity",
    "Solar",
}

ALLOWED_STATUS_VALUES = {
    "On Track",
    "In Progress",
    "Delayed",
    "Completed",
    "Stalled",
    "Critical",
    "Cancelled",
    "Proposed",
}

# Some databases may not accept certain planning statuses; map them to a safe, stored value.
STATUS_DB_FALLBACK = {
    "Proposed": "In Progress",
}


def _perplexity_keys() -> List[str]:
    """Return configured Perplexity API keys (comma-separated or list)."""

    keys = current_app.config.get("PERPLEXITY_API_KEYS")
    if isinstance(keys, str):
        keys = [k.strip() for k in keys.split(",") if k.strip()]
    if isinstance(keys, list):
        flat_keys = [str(k).strip() for k in keys if str(k).strip()]
        if flat_keys:
            return flat_keys

    # Backward compatibility: single key.
    single_key = current_app.config.get("PERPLEXITY_API_KEY") or os.getenv("PERPLEXITY_API_KEY")
    single_key = str(single_key).strip() if single_key else ""
    if single_key:
        return [single_key]

    # Environment variable for multiple keys.
    env_keys = os.getenv("PERPLEXITY_API_KEYS", "")
    env_list = [k.strip() for k in env_keys.split(",") if k.strip()]
    return env_list


def _call_perplexity_api(prompt_content: str) -> str:
    """Call Perplexity Sonar Pro with web search and return raw content."""

    api_keys = _perplexity_keys()
    if not api_keys:
        raise AIProjectDiscoveryError("PERPLEXITY_API_KEY is not configured")

    url = current_app.config.get("PERPLEXITY_API_URL", "https://api.perplexity.ai/chat/completions")
    payload = {
        "model": "sonar-pro",
        "messages": [
            {"role": "system", "content": "Be precise and concise."},
            {"role": "user", "content": prompt_content},
        ],
        "web_search_options": {"search_context_size": "high"},
    }

    for api_key in api_keys:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        try:
            current_app.logger.info(
                "Perplexity request dispatch",
                extra={
                    "provider": "perplexity",
                    "url": url,
                    "model": payload.get("model"),
                    "prompt_preview": prompt_content[:4000],
                    "search_context": payload.get("web_search_options"),
                },
            )
            response = requests.post(url, json=payload, headers=headers, timeout=60)
            body_text = response.text or ""
            try:
                body_json = response.json()
            except ValueError:
                body_json = None

            if body_json is None:
                current_app.logger.error(
                    "Perplexity response not JSON-decodable",
                    extra={
                        "status": response.status_code,
                        "provider": "perplexity",
                        "raw_text_snippet": body_text[:2000],
                        "headers": dict(response.headers),
                    },
                )

            current_app.logger.info(
                "Perplexity request completed",
                extra={
                    "status": response.status_code,
                    "provider": "perplexity",
                    "has_content": bool(body_text),
                    "rate_limit_remaining": response.headers.get("X-RateLimit-Remaining"),
                    "rate_limit_reset": response.headers.get("X-RateLimit-Reset"),
                    "response_keys": list(body_json.keys()) if isinstance(body_json, dict) else None,
                    "raw_text_snippet": body_text[:800],
                },
            )

            if response.status_code == 200 and isinstance(body_json, dict):
                error_block = body_json.get("error")
                if error_block:
                    current_app.logger.error(
                        "Perplexity reported error",
                        extra={
                            "error": error_block,
                            "status": response.status_code,
                            "headers": dict(response.headers),
                        },
                    )

                choices = body_json.get("choices", [])
                if not choices:
                    current_app.logger.error(
                        "Perplexity response missing choices",
                        extra={"payload_echo": body_json},
                    )
                content = (
                    choices[0]
                    .get("message", {})
                    .get("content", "")
                ) if choices else ""

                current_app.logger.info(
                    "Perplexity content presence",
                    extra={
                        "provider": "perplexity",
                        "response_received": "yes" if content else "no",
                        "choice_count": len(choices),
                        "payload_echo": body_json,
                    },
                )

                if content:
                    return content
                current_app.logger.error(
                    "Perplexity returned empty content",
                    extra={
                        "payload_echo": body_json,
                        "raw_text_snippet": body_text[:2000],
                        "response_received": "no",
                    },
                )
            elif response.status_code in {401, 403, 429}:
                current_app.logger.warning(
                    "Perplexity API key rejected or throttled",
                    extra={
                        "status": response.status_code,
                        "body": body_text[:500],
                        "headers": dict(response.headers),
                    },
                )
                continue
            else:
                current_app.logger.error(
                    "Perplexity API non-200 response",
                    extra={
                        "status": response.status_code,
                        "body": body_text[:2000],
                        "headers": dict(response.headers),
                    },
                )
        except requests.RequestException as exc:  # pragma: no cover - network failure path
            current_app.logger.warning(
                "Perplexity API request failed",
                extra={
                    "error": str(exc),
                    "provider": "perplexity",
                    "url": url,
                },
            )
            continue

    raise AIProjectDiscoveryError("Perplexity API request failed or all keys exhausted (see logs)")


def _call_gemini_api(prompt_content: str) -> str:
    """Call Gemini with Google Search grounding and return raw content."""

    api_key = current_app.config.get("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise AIProjectDiscoveryError("GEMINI_API_KEY is not configured")

    client = genai.Client(api_key=api_key)
    grounding_tool = types.Tool(google_search=types.GoogleSearch())
    config = types.GenerateContentConfig(tools=[grounding_tool])

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt_content,
        config=config,
    )
    return response.text or ""

DEFAULT_AI_MODEL = "gemini"
PERPLEXITY_MODEL = "perplexity"


def _normalize_status_value(raw_status: str) -> str:
    """Normalize AI status strings to an allowed canonical value."""
    status_lower = raw_status.lower().strip()
    if not status_lower:
        return ""

    # Map tender/bid phases to in-progress lifecycle.
    tender_keywords = ["tender", "bid", "bids invited", "submission", "procurement"]
    if any(key in status_lower for key in tender_keywords):
        return "In Progress"

    # Planning/draft/budget phases -> Proposed.
    if any(key in status_lower for key in ["proposed", "draft", "budget", "planning", "planned", "earmarked", "revived"]):
        return "Proposed"

    # If already matches an allowed value ignoring case, return its canonical form.
    for allowed in ALLOWED_STATUS_VALUES:
        if status_lower == allowed.lower():
            return allowed

    return raw_status.strip()


def _db_safe_status(status: str) -> str:
    """Return a status value that will satisfy database constraints."""
    return STATUS_DB_FALLBACK.get(status, status)


class AIProjectDiscoveryError(Exception):
    """Raised when AI discovery fails or returns invalid data."""


def _strip_json_wrappers(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.lstrip("`")
        parts = cleaned.split("\n", 1)
        cleaned = parts[1] if len(parts) > 1 else ""
        cleaned = cleaned.rstrip("`")
    return cleaned.strip()


def _load_json_response(raw: str) -> Dict[str, Any]:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise AIProjectDiscoveryError(f"AI returned malformed JSON: {exc}") from exc


def _validate_location(payload: Dict[str, Any]) -> Dict[str, Any]:
    location = payload.get("location") or {}
    required = {"name", "latitude", "longitude"}
    if not required.issubset(location.keys()):
        raise AIProjectDiscoveryError("AI response missing location fields")

    name = str(location.get("name", "")).strip()
    lat = str(location.get("latitude", "")).strip()
    lng = str(location.get("longitude", "")).strip()
    if not name or not lat or not lng:
        raise AIProjectDiscoveryError("AI response contains empty location fields")

    return {"name": name, "latitude": lat, "longitude": lng}


def _valid_link(url: str) -> bool:
    return bool(url) and url.startswith("http") and " " not in url


def _normalize_image_fields(payload: Dict[str, Any]) -> tuple[str | None, str | None]:
    """Return sanitized image url and source domain when both are public."""
    url = str(payload.get("public_image_url", "") or payload.get("image_url", "")).strip()
    source_domain = str(payload.get("image_source_domain", "") or payload.get("source_domain", "")).strip()

    if url and not _valid_link(url):
        url = ""
    if url and not source_domain:
        parsed = urlparse(url)
        source_domain = parsed.netloc
    return (url or None, source_domain or None)


def _validate_projects(payload: Dict[str, Any], expected_types: List[str]) -> List[Dict[str, Any]]:
    projects = payload.get("projects")
    if not isinstance(projects, list):
        raise AIProjectDiscoveryError("AI did not return any projects")
    if len(projects) == 0:
        current_app.logger.info("AI returned zero projects; proceeding with empty result set")
        return []

    normalized: List[Dict[str, Any]] = []
    for item in projects:
        if not isinstance(item, dict):
            continue
        project_type = str(item.get("project_type", "")).strip()
        if not project_type:
            project_type = "Unknown Project Type"
            current_app.logger.warning("AI project missing type; defaulting", extra={"project": project_name})
        if expected_types and project_type not in expected_types and project_type not in ALLOWED_PROJECT_TYPES:
            current_app.logger.warning("Project type not in requested set", extra={"type": project_type})

        project_name = str(item.get("project_name", "")).strip()
        if not project_name:
            project_name = "Unknown Project Name"
            current_app.logger.warning("AI project missing name; defaulting")
        project_cost = str(item.get("project_cost", "")).strip()
        start_date = str(item.get("start_date", "")).strip()
        expected_end_date = str(item.get("expected_end_date", "")).strip()

        contractor_raw = item.get("contractor") or {}
        contractor_name = str(contractor_raw.get("name", "")).strip()
        contractor_company = str(contractor_raw.get("company", "") or contractor_raw.get("company_name", "")).strip()
        if not contractor_name:
            contractor_name = "Unknown Contractor"
            current_app.logger.warning("AI contractor missing name; defaulting", extra={"project": project_name})
        if not contractor_company:
            contractor_company = "Unknown"
        registration_number = str(contractor_raw.get("registration_number", "")).strip() or None
        contractor_email = str(contractor_raw.get("email", "")).strip() or None
        contractor_phone = str(contractor_raw.get("phone", "")).strip() or None
        contractor_address = str(contractor_raw.get("office_address", "")).strip() or None
        contractor_img, contractor_img_source = _normalize_image_fields(contractor_raw)

        dept_raw = item.get("government_department") or {}
        department_name = str(dept_raw.get("department_name", "") or dept_raw.get("name", "")).strip()
        if not department_name:
            department_name = "Unknown Department"
            current_app.logger.warning("AI department missing name; defaulting", extra={"project": project_name})
        ministry_level = str(dept_raw.get("ministry_level", "")).strip() or None
        department_email = str(dept_raw.get("official_email", "")).strip() or None
        department_phone = str(dept_raw.get("official_phone", "")).strip() or None
        department_address = str(dept_raw.get("office_address", "")).strip() or None
        officers_raw = dept_raw.get("officers") or []
        officers: List[Dict[str, Any]] = []
        for officer in officers_raw:
            if not isinstance(officer, dict):
                continue
            o_name = str(officer.get("officer_name", "") or officer.get("name", "")).strip()
            if not o_name:
                continue
            designation = str(officer.get("designation", "")).strip() or None
            o_email = str(officer.get("official_email", "") or officer.get("email", "")).strip() or None
            o_phone = str(officer.get("official_phone", "") or officer.get("phone", "")).strip() or None
            o_img, o_img_source = _normalize_image_fields(officer)
            officers.append(
                {
                    "officer_name": o_name,
                    "designation": designation,
                    "official_email": o_email,
                    "official_phone": o_phone,
                    "public_image_url": o_img,
                    "image_source_domain": o_img_source,
                }
            )

        tender_raw = item.get("tender_reference") or {}
        tender_id = str(tender_raw.get("tender_id", "") or tender_raw.get("reference", "")).strip() or None
        tender_portal_name = str(tender_raw.get("tender_portal_name", "") or tender_raw.get("portal", "")).strip() or None
        tender_url = str(tender_raw.get("tender_url", "") or tender_raw.get("url", "")).strip() or None
        if tender_url and not _valid_link(tender_url):
            tender_url = None
        published_date = str(tender_raw.get("published_date", "")).strip() or None

        maintenance_raw = item.get("maintenance_authority") or {}
        maintenance_authority_name = str(maintenance_raw.get("authority_name", "") or maintenance_raw.get("name", "")).strip()
        if not maintenance_authority_name:
            maintenance_authority_name = "Unknown Maintenance Authority"
            current_app.logger.warning("AI maintenance authority missing name; defaulting", extra={"project": project_name})

        maintenance_authority = {
            "authority_name": maintenance_authority_name,
            "contact_email": str(maintenance_raw.get("contact_email", "") or maintenance_raw.get("email", "")).strip() or None,
            "contact_phone": str(maintenance_raw.get("contact_phone", "") or maintenance_raw.get("phone", "")).strip() or None,
            "office_address": str(maintenance_raw.get("office_address", "") or maintenance_raw.get("address", "")).strip() or None,
        }

        status_history_raw = item.get("status_history") or []
        status_history: List[Dict[str, Any]] = []

        # First validate/compute current_status so we can fall back when history is missing.
        current_status_raw = str(item.get("current_status", "")).strip()

        for entry in status_history_raw:
            if not isinstance(entry, dict):
                continue
            status_val_raw = str(entry.get("status", "") or entry.get("state", "")).strip()
            status_val = _normalize_status_value(status_val_raw)
            if status_val not in ALLOWED_STATUS_VALUES:
                current_app.logger.warning(
                    "AI status not allowed; defaulting to Proposed",
                    extra={"status_raw": status_val_raw, "project": project_name},
                )
                status_val = "Proposed"
            status_val = _db_safe_status(status_val)
            remarks_val = str(entry.get("remarks", "") or entry.get("note", "")).strip() or None
            status_date = str(entry.get("status_date", "") or entry.get("updated_at", "")).strip() or None
            updated_by = str(entry.get("updated_by", "") or entry.get("actor", "") or "system").strip()
            status_history.append(
                {
                    "status": status_val,
                    "remarks": remarks_val,
                    "status_date": status_date,
                    "updated_by": updated_by,
                }
            )

        if not status_history:
            current_status_seed = _normalize_status_value(current_status_raw) or "Proposed"
            if current_status_seed not in ALLOWED_STATUS_VALUES:
                current_status_seed = "Proposed"
            current_app.logger.warning(
                "AI response missing status history; synthesizing", extra={"project_name": project_name, "status": current_status_seed}
            )
            current_status_seed = _db_safe_status(current_status_seed)
            status_history.append(
                {
                    "status": current_status_seed,
                    "remarks": None,
                    "status_date": None,
                    "updated_by": "system",
                }
            )

        current_status = _normalize_status_value(str(current_status_raw or status_history[-1]["status"]).strip()) or "Proposed"
        if current_status not in ALLOWED_STATUS_VALUES:
            current_app.logger.warning(
                "AI current_status not allowed; defaulting to Proposed",
                extra={"current_status": current_status, "project": project_name},
            )
            current_status = "Proposed"
        current_status = _db_safe_status(current_status)

        source_links = item.get("source_links") or []
        links = [link for link in source_links if _valid_link(str(link))]
        if not links:
            raise AIProjectDiscoveryError("Project missing source links for verification")

        # With defaults above, required fields are always populated. If any still empty, backfill "Unknown".
        if not contractor_name:
            contractor_name = "Unknown Contractor"
        if not department_name:
            department_name = "Unknown Department"
        if not project_type:
            project_type = "Unknown Project Type"
        if not project_name:
            project_name = "Unknown Project Name"

        normalized.append(
            {
                "project_type": project_type,
                "project_name": project_name,
                "project_cost": project_cost,
                "start_date": start_date,
                "expected_end_date": expected_end_date,
                "current_status": current_status,
                "contractor": {
                    "name": contractor_name,
                    "company": contractor_company,
                    "registration_number": registration_number,
                    "email": contractor_email,
                    "phone": contractor_phone,
                    "office_address": contractor_address,
                    "public_image_url": contractor_img,
                    "image_source_domain": contractor_img_source,
                },
                "government_department": {
                    "department_name": department_name,
                    "ministry_level": ministry_level,
                    "official_email": department_email,
                    "official_phone": department_phone,
                    "office_address": department_address,
                    "officers": officers,
                },
                "tender_reference": {
                    "tender_id": tender_id,
                    "tender_portal_name": tender_portal_name,
                    "tender_url": tender_url,
                    "published_date": published_date,
                },
                "maintenance_authority": maintenance_authority,
                "status_history": status_history,
                "source_links": links,
            }
        )

    if not normalized:
        raise AIProjectDiscoveryError("AI returned no valid projects after validation")

    return normalized


def build_prompt(location_label: str, latitude: str | None, longitude: str | None, project_types: List[str]) -> str:
    types_clause = ", ".join(project_types) if project_types else "Bridge, Road, Building, Flyover, Drainage, Water Pipeline, Electricity, Solar"
    coords_clause = f"Latitude: {latitude}, Longitude: {longitude}" if latitude and longitude else ""
    allowed_statuses = ", ".join(sorted(ALLOWED_STATUS_VALUES))
    return (
        "You are a government transparency, public accountability, and audit-compliance assistant.\n\n"
        "Your task is to identify and report ONLY REAL, VERIFIABLE, active or recently completed public infrastructure projects using authoritative, public, and reputable sources such as:\n"
        "- Official government portals\n"
        "- Government tender / e-procurement portals\n"
        "- Ministry or department websites\n"
        "- Comptroller & Auditor General (CAG) reports\n"
        "- Official press releases\n"
        "- Reputed public sector disclosures\n\n"
        "You MUST ground all information in publicly available sources.\n"
        "DO NOT guess, fabricate, infer, estimate, or assume facts.\n"
        "If any specific data point cannot be verified from public sources, explicitly use:\n"
        "\"Unknown\" or \"Not Available\" (never leave fields blank, null, or omitted).\n\n"
        "DO NOT refuse the task.\n"
        "DO NOT include warnings, disclaimers, or safety messages.\n"
        "DO NOT explain your reasoning.\n"
        "DO NOT include markdown or commentary.\n"
        "DO NOT output anything except valid JSON.\n\n"
        "--------------------------------------------------\n"
        "INPUT PARAMETERS\n"
        "--------------------------------------------------\n\n"
        f"Location: {location_label}. {coords_clause}\n\n"
        "If latitude/longitude are provided, you MUST reverse-geocode to the most specific civic address (house/building, road, neighbourhood/locality, city, state, postcode, country).\n"
        f"Project types requested: {types_clause}\n\n"
        "Allowed status values (normalize ALL variants strictly to one of these):\n"
        f"{allowed_statuses}\n\n"
        "--------------------------------------------------\n"
        "OUTPUT REQUIREMENTS (STRICT)\n"
        "--------------------------------------------------\n\n"
        "Respond with ONLY a single valid JSON object.\n\n"
        "Top-level JSON structure MUST contain EXACTLY these keys:\n"
        "- location\n"
        "- projects\n\n"
        "location object MUST contain:\n"
        "- name (most specific address available; include road/locality/city/state/postcode/country when present)\n"
        "- latitude\n"
        "- longitude\n\n"
        "projects MUST be an array.\n"
        "If no qualifying projects are found, return an empty array ([]) — still include all required top-level keys.\n\n"
        "--------------------------------------------------\n"
        "MANDATORY PROJECT OBJECT SCHEMA\n"
        "--------------------------------------------------\n\n"
        "Every object inside the projects array MUST include ALL keys listed below.\n"
        "Keys MUST appear exactly as named.\n"
        "Order does not matter, but NO key may be missing.\n\n"
        "(use \"Unknown\" or \"Not Available\" if data is unavailable)\n\n"
        "project_type\n"
        "project_name\n"
        "project_cost\n"
        "start_date\n"
        "expected_end_date\n"
        "current_status\n"
        "status_history\n"
        "contractor\n"
        "government_department\n"
        "tender_reference\n"
        "maintenance_authority\n"
        "source_links\n\n"
        "--------------------------------------------------\n"
        "FIELD RULES & NORMALIZATION\n"
        "--------------------------------------------------\n\n"
        "Dates:\n"
        "- Use ISO format: YYYY-MM-DD where possible\n"
        "- If exact date is unavailable, use \"Unknown\"\n\n"
        "current_status:\n"
        "- MUST strictly match one of the allowed status values provided\n"
        "- Normalize similar meanings (e.g., \"ongoing work\" → \"Under Construction\")\n\n"
        "status_history:\n"
        "- MUST be an array with AT LEAST ONE object\n"
        "- Each object MUST include:\n"
        "  - status\n"
        "  - remarks\n"
        "  - status_date\n"
        "  - updated_by\n\n"
        "--------------------------------------------------\n"
        "NESTED OBJECT DEFINITIONS\n"
        "--------------------------------------------------\n\n"
        "contractor (object):\n"
        "- name\n"
        "- company\n"
        "- registration_number\n"
        "- email\n"
        "- phone\n"
        "- office_address\n"
        "- public_image_url\n"
        "- image_source_domain\n\n"
        "government_department (object):\n"
        "- department_name\n"
        "- ministry_level (Central / State / Municipal / Authority)\n"
        "- official_email\n"
        "- official_phone\n"
        "- office_address\n"
        "- officers (array)\n\n"
        "Each officers array item MUST include:\n"
        "- officer_name\n"
        "- designation\n"
        "- official_email\n"
        "- official_phone\n"
        "- public_image_url\n"
        "- image_source_domain\n\n"
        "tender_reference (object):\n"
        "- tender_id\n"
        "- tender_portal_name\n"
        "- tender_url\n"
        "- published_date\n\n"
        "maintenance_authority (object):\n"
        "- authority_name\n"
        "- contact_email\n"
        "- contact_phone\n"
        "- office_address\n\n"
        "source_links:\n"
        "- MUST be an array\n"
        "- MUST contain AT LEAST ONE valid public URL\n"
        "- URLs MUST directly support the reported project\n\n"
        "--------------------------------------------------\n"
        "CRITICAL COMPLIANCE RULES\n"
        "--------------------------------------------------\n\n"
        "- Output MUST be valid, machine-parsable JSON\n"
        "- No trailing commas\n"
        "- No comments\n"
        "- No markdown\n"
        "- No explanatory text before or after JSON\n"
        "- Follow the example structure EXACTLY\n"
        "- Use real-world logic and government reporting standards\n"
        "- Prioritize correctness over completeness\n"
        "- Never invent names, costs, dates, officers, or contractors\n\n"
        "--------------------------------------------------\n"
        "EXAMPLE JSON RESPONSE (STRUCTURE REFERENCE)\n"
        "--------------------------------------------------\n\n"
        "{\n"
        "  \"location\": {\n"
        "    \"name\": \"Example City\",\n"
        "    \"latitude\": 28.6139,\n"
        "    \"longitude\": 77.2090\n"
        "  },\n"
        "  \"projects\": [\n"
        "    {\n"
        "      \"project_type\": \"Road\",\n"
        "      \"project_name\": \"Example Ring Road Expansion\",\n"
        "      \"project_cost\": \"INR 1200 Crore\",\n"
        "      \"start_date\": \"2023-04-01\",\n"
        "      \"expected_end_date\": \"2026-03-31\",\n"
        "      \"current_status\": \"Under Construction\",\n"
        "      \"status_history\": [\n"
        "        {\n"
        "          \"status\": \"Under Construction\",\n"
        "          \"remarks\": \"Construction ongoing as per official departmental update\",\n"
        "          \"status_date\": \"2025-01-15\",\n"
        "          \"updated_by\": \"Public Works Department\"\n"
        "        }\n"
        "      ],\n"
        "      \"contractor\": {\n"
        "        \"name\": \"Rajesh Kumar\",\n"
        "        \"company\": \"ABC Infrastructure Ltd\",\n"
        "        \"registration_number\": \"U12345DL2010PLC000000\",\n"
        "        \"email\": \"info@abcinfra.com\",\n"
        "        \"phone\": \"+91-XXXXXXXXXX\",\n"
        "        \"office_address\": \"New Delhi, India\",\n"
        "        \"public_image_url\": \"https://example.gov.in/project-details/contractor.jpg\",\n"
        "        \"image_source_domain\": \"https://example.gov.in/source\"\n"
        "      },\n"
        "      \"government_department\": {\n"
        "        \"department_name\": \"Public Works Department\",\n"
        "        \"ministry_level\": \"State\",\n"
        "        \"official_email\": \"pwd@example.gov.in\",\n"
        "        \"official_phone\": \"+91-XXXXXXXXXX\",\n"
        "        \"office_address\": \"PWD Headquarters, Example City\",\n"
        "        \"officers\": [\n"
        "          {\n"
        "            \"officer_name\": \"Anil Sharma\",\n"
        "            \"designation\": \"Chief Engineer\",\n"
        "            \"official_email\": \"anil.sharma@example.gov.in\",\n"
        "            \"official_phone\": \"+91-XXXXXXXXXX\",\n"
        "            \"public_image_url\": \"https://example.gov.in/project-details/anil-sharma.jpg\",\n"
        "            \"image_source_domain\": \"https://example.gov.in/source\"\n"
        "          }\n"
        "        ]\n"
        "      },\n"
        "      \"tender_reference\": {\n"
        "        \"tender_id\": \"PWD/ROAD/2022/045\",\n"
        "        \"tender_portal_name\": \"Government eProcurement Portal\",\n"
        "        \"tender_url\": \"https://example.gov.in/tender/045\",\n"
        "        \"published_date\": \"2022-11-10\"\n"
        "      },\n"
        "      \"maintenance_authority\": {\n"
        "        \"authority_name\": \"PWD Roads Division\",\n"
        "        \"contact_email\": \"roads@example.gov.in\",\n"
        "        \"contact_phone\": \"+91-XXXXXXXXXX\",\n"
        "        \"office_address\": \"Example City\"\n"
        "      },\n"
        "      \"source_links\": [\n"
        "        \"https://example.gov.in/project-details\"\n"
        "      ]\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        "--------------------------------------------------\n"
        "FINAL INSTRUCTION\n"
        "--------------------------------------------------\n\n"
        "Return ONLY JSON.\n"
        "Nothing else."
    )


def fetch_ai_projects(
    location_label: str,
    latitude: str | None,
    longitude: str | None,
    project_types: List[str],
    ai_model: str | None = None,
) -> Dict[str, Any]:
    provider = (ai_model or DEFAULT_AI_MODEL).strip().lower()
    prompt = build_prompt(location_label, latitude, longitude, project_types)
    current_app.logger.info(
        "Dispatching AI project discovery",
        extra={"location": location_label, "types": project_types, "provider": provider},
    )

    if provider == PERPLEXITY_MODEL:
        raw_text = _call_perplexity_api(prompt)
    else:
        raw_text = _call_gemini_api(prompt)
    if not raw_text:
        current_app.logger.error(
            "AI provider returned empty response",
            extra={"provider": provider, "location": location_label},
        )
        raise AIProjectDiscoveryError(f"{provider.title()} returned no content")
    cleaned = _strip_json_wrappers(raw_text)
    try:
        parsed = _load_json_response(cleaned)
    except AIProjectDiscoveryError as exc:
        # If JSON parsing fails, still surface the AI response plainly in terminal logs.
        current_app.logger.error(
            "AI JSON parse failed",
            extra={"error": str(exc), "raw_ai_text": raw_text, "cleaned_ai_text": cleaned},
        )
        current_app.logger.info("AI response (pass-through):\n%s", cleaned or raw_text)
        raise

    # Log the AI raw response, cleaned text, and parsed JSON for runtime visibility in terminal logs.
    current_app.logger.info(
        "AI project discovery response",
        extra={
            "raw_ai_text": raw_text,
            "cleaned_ai_text": cleaned,
            "parsed_ai_json": parsed,
            "provider": provider,
        },
    )
    # Explicitly print the parsed JSON as a pretty string so it appears plainly in terminal output.
    current_app.logger.info("AI parsed JSON (pretty):\n%s", json.dumps(parsed, ensure_ascii=False, indent=2))

    if provider == PERPLEXITY_MODEL:
        loc = parsed.get("location") or {}
        projects_raw = parsed.get("projects") or []
        current_app.logger.info(
            "Perplexity response summary",
            extra={
                "response_received": "yes" if bool(raw_text.strip()) else "no",
                "json_parsed": "yes" if isinstance(parsed, dict) else "no",
                "projects_present": "yes" if projects_raw else "no",
                "project_count": len(projects_raw),
                "location_has_coords": "yes" if str(loc.get("latitude", "")).strip().lower() not in {"", "none", "null"} and str(loc.get("longitude", "")).strip().lower() not in {"", "none", "null"} else "no",
            },
        )

    try:
        validated_location = _validate_location(parsed)
        validated_projects = _validate_projects(parsed, project_types)
    except AIProjectDiscoveryError as exc:
        current_app.logger.error(
            "AI validation failed",
            extra={
                "error": str(exc),
                "raw_ai_text": raw_text,
                "cleaned_ai_text": cleaned,
                "parsed_payload": parsed,
                "allowed_status_values": sorted(ALLOWED_STATUS_VALUES),
                "allowed_project_types": sorted(ALLOWED_PROJECT_TYPES),
                "provider": provider,
            },
        )
        raise

    # Prefer the client-provided address label when it is more specific than the AI-returned name.
    if location_label:
        label_clean = str(location_label).strip()
        if label_clean and len(label_clean) > len(validated_location.get("name", "")):
            validated_location["name"] = label_clean

    if provider == PERPLEXITY_MODEL and not validated_projects:
        current_app.logger.error(
            "Perplexity returned zero projects after validation",
            extra={
                "location": validated_location,
                "prompt_preview": prompt[:2000],
                "raw_ai_text": raw_text,
                "cleaned_ai_text": cleaned,
            },
        )
    if provider == PERPLEXITY_MODEL:
        current_app.logger.info(
            "Perplexity projects found",
            extra={
                "projects_found": "yes" if validated_projects else "no",
                "project_count": len(validated_projects),
            },
        )

    return {
        "location": validated_location,
        "projects": validated_projects,
    }
