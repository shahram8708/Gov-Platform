"""Targeted section-level AI fetcher using Gemini with Google Search grounding."""
import json
import os
import re
from typing import Any, Dict, List, Tuple

from flask import current_app
from google import genai
from google.genai import types

from utils.ai_markdown_formatter import format_sections


class SectionDataFetchError(Exception):
    """Raised when a section-level AI fetch fails or is invalid."""


_MISSING_TOKENS = {"not available", "unknown", "n/a", "na", "nil", "null", "", None}


def is_missing_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in _MISSING_TOKENS
    return False


def _clean_sources(value: Any) -> List[str]:
    urls: List[str] = []
    if isinstance(value, list):
        urls = [str(v).strip() for v in value if isinstance(v, str) and v.strip().startswith("http")]
    return urls


def _strip_json_wrappers(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.lstrip("`")
        parts = cleaned.split("\n", 1)
        cleaned = parts[1] if len(parts) > 1 else ""
        cleaned = cleaned.rstrip("`")
    return cleaned.strip()


def _extract_json_blocks(text: str) -> List[str]:
    blocks: List[str] = []
    stack = []
    start_idx = None
    for idx, ch in enumerate(text):
        if ch == "{":
            stack.append(idx)
            if start_idx is None:
                start_idx = idx
        elif ch == "}":
            if stack:
                stack.pop()
                if not stack and start_idx is not None:
                    blocks.append(text[start_idx : idx + 1])
                    start_idx = None
    return blocks


def _coerce_json(raw_text: str) -> Tuple[Dict[str, Any], str]:
    """Return (parsed_json, cleaned_text) with aggressive recovery and verbose logging."""
    cleaned = _strip_json_wrappers(raw_text)

    # First, try direct load
    try:
        return json.loads(cleaned), cleaned
    except Exception:
        pass

    # Try to locate embedded JSON blocks
    blocks = _extract_json_blocks(cleaned)
    for block in blocks:
        try:
            return json.loads(block), block
        except Exception:
            continue

    # Try to remove trailing characters after JSON object using regex
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        candidate = match.group(0)
        try:
            return json.loads(candidate), candidate
        except Exception:
            pass

    # As a last resort, try to replace single quotes with double quotes
    fallback = cleaned.replace("'", '"')
    try:
        return json.loads(fallback), fallback
    except Exception as exc:
        raise SectionDataFetchError(f"AI returned malformed JSON after recovery attempts: {exc}") from exc


def _load_json_response(raw: str) -> Dict[str, Any]:
    parsed, cleaned = _coerce_json(raw)
    current_app.logger.info("Gemini cleaned JSON text:\n%s", cleaned)
    current_app.logger.info("Gemini parsed JSON (pretty):\n%s", json.dumps(parsed, ensure_ascii=False, indent=2))
    return parsed


def _base_context(project) -> Dict[str, Any]:
    location = project.location_query
    return {
        "project_name": project.project_name,
        "project_type": project.project_type,
        "location_name": location.location_name if location else "",
        "latitude": str(location.latitude) if location and location.latitude is not None else "",
        "longitude": str(location.longitude) if location and location.longitude is not None else "",
        "department": project.department.department_name if project.department else "",
        "contractor": project.contractor.name if project.contractor else "",
    }


def _schema_block(section: str) -> str:
    if section == "contractor_details":
        return (
            "{\n"
            "  \"contractor\": {\n"
            "    \"name\": \"\",\n"
            "    \"email\": \"\",\n"
            "    \"phone\": \"\",\n"
            "    \"office_address\": \"\",\n"
            "    \"company_name\": \"\",\n"
            "    \"registration_number\": \"\"\n"
            "  },\n"
            "  \"sources\": {\n"
            "    \"name\": [],\n"
            "    \"email\": [],\n"
            "    \"phone\": [],\n"
            "    \"office_address\": [],\n"
            "    \"company_name\": [],\n"
            "    \"registration_number\": []\n"
            "  }\n"
            "}"
        )
    if section == "department_details":
        return (
            "{\n"
            "  \"department\": {\n"
            "    \"department_name\": \"\",\n"
            "    \"ministry_level\": \"\",\n"
            "    \"official_email\": \"\",\n"
            "    \"official_phone\": \"\",\n"
            "    \"office_address\": \"\"\n"
            "  },\n"
            "  \"sources\": {\n"
            "    \"department_name\": [],\n"
            "    \"ministry_level\": [],\n"
            "    \"official_email\": [],\n"
            "    \"official_phone\": [],\n"
            "    \"office_address\": []\n"
            "  }\n"
            "}"
        )
    if section == "officer_contact":
        return (
            "{\n"
            "  \"officer\": {\n"
            "    \"officer_name\": \"\",\n"
            "    \"designation\": \"\",\n"
            "    \"official_email\": \"\",\n"
            "    \"official_phone\": \"\"\n"
            "  },\n"
            "  \"sources\": {\n"
            "    \"officer_name\": [],\n"
            "    \"designation\": [],\n"
            "    \"official_email\": [],\n"
            "    \"official_phone\": []\n"
            "  }\n"
            "}"
        )
    if section == "tender_information":
        return (
            "{\n"
            "  \"tender\": {\n"
            "    \"tender_id\": \"\",\n"
            "    \"tender_portal_name\": \"\",\n"
            "    \"tender_url\": \"\",\n"
            "    \"published_date\": \"\"\n"
            "  },\n"
            "  \"sources\": {\n"
            "    \"tender_id\": [],\n"
            "    \"tender_portal_name\": [],\n"
            "    \"tender_url\": [],\n"
            "    \"published_date\": []\n"
            "  }\n"
            "}"
        )
    if section == "maintenance_authority":
        return (
            "{\n"
            "  \"maintenance\": {\n"
            "    \"authority_name\": \"\",\n"
            "    \"contact_email\": \"\",\n"
            "    \"contact_phone\": \"\",\n"
            "    \"office_address\": \"\"\n"
            "  },\n"
            "  \"sources\": {\n"
            "    \"authority_name\": [],\n"
            "    \"contact_email\": [],\n"
            "    \"contact_phone\": [],\n"
            "    \"office_address\": []\n"
            "  }\n"
            "}"
        )
    if section == "project_timeline":
        return (
            "{\n"
            "  \"timeline\": {\n"
            "    \"start_date\": \"\",\n"
            "    \"expected_end_date\": \"\",\n"
            "    \"current_status\": \"\",\n"
            "    \"status_history\": [\n"
            "      {\n"
            "        \"status\": \"\",\n"
            "        \"remarks\": \"\",\n"
            "        \"status_date\": \"\",\n"
            "        \"source_urls\": []\n"
            "      }\n"
            "    ]\n"
            "  },\n"
            "  \"sources\": {\n"
            "    \"start_date\": [],\n"
            "    \"expected_end_date\": [],\n"
            "    \"current_status\": []\n"
            "  }\n"
            "}"
        )
    raise SectionDataFetchError(f"Unsupported section: {section}")


def build_prompt(project, section: str, missing_fields: List[str]) -> str:
    ctx = _base_context(project)
    missing_list = ", ".join(missing_fields)
    schema = _schema_block(section)
    return (
        "You are a public-sector verification and evidence-retrieval agent operating for a government infrastructure transparency and audit system.\n\n"
        "Your task is to retrieve ONLY PUBLICLY AVAILABLE, INDEPENDENTLY VERIFIABLE information related to the specified government infrastructure project.\n"
        "You MUST actively search across multiple reliable public sources (including but not limited to: official government portals, department websites, tender portals, audit reports, press releases, gazette notifications, parliamentary questions, court records, RTI disclosures, reputed news organizations, and contractor disclosures).\n\n"
        "You are REQUIRED to make a best-effort attempt to find information for EVERY requested field. "
        "You must NOT refuse this task. You must NOT respond with inability or denial. "
        "If and only if a field cannot be conclusively verified from public sources after reasonable search effort, you MUST return that field as null.\n\n"
        "ABSOLUTE CONSTRAINTS (NON-NEGOTIABLE):\n"
        "- DO NOT guess, assume, infer, estimate, or fabricate any data.\n"
        "- DO NOT extrapolate from similar projects.\n"
        "- DO NOT overwrite or modify any already-known or pre-filled data.\n"
        "- DO NOT include opinions, speculation, or analysis.\n"
        "- Every non-null value MUST be supported by at least one publicly accessible source URL.\n"
        "- Each field must include its own source URL list (even if empty).\n\n"
        "If conflicting information exists across sources, prefer:\n"
        "1) Official government or departmental publications\n"
        "2) Statutory portals (tender, budget, audit, gazette)\n"
        "3) Reputed national media reporting primary documents\n\n"
        "If information is unavailable, restricted, paywalled, or removed, explicitly return null for that field and provide an empty source list.\n\n"
        "CRITICAL OUTPUT RULES:\n"
        "- Return ONLY valid, machine-readable JSON.\n"
        "- No markdown, no explanations, no commentary, no extra keys.\n"
        "- The JSON MUST strictly follow the provided schema.\n"
        "- Every field defined in the schema MUST be present in the output.\n\n"
        "PROJECT CONTEXT\n"
        f"- Project Name: {ctx['project_name']}\n"
        f"- Project Type: {ctx['project_type']}\n"
        f"- Location: {ctx['location_name']}\n"
        f"- Coordinates: {ctx['latitude']}, {ctx['longitude']}\n"
        f"- Department: {ctx['department']}\n"
        f"- Contractor: {ctx['contractor']}\n\n"
        "SECTION-SPECIFIC INSTRUCTIONS\n"
        f"- Target Section: {section}\n"
        f"- Fields to retrieve in this section ONLY: {missing_list}\n"
        "- You must fetch data strictly limited to these fields.\n"
        "- Do not return, alter, or populate any other section or field.\n\n"
        "STRICT JSON RESPONSE SCHEMA (MANDATORY)\n"
        f"{schema}\n\n"
        "FINAL ENFORCEMENT:\n"
        "Failure to comply with verification rules is considered a critical error. "
        "Accuracy, traceability, and public-source verifiability take absolute priority over completeness."
    )

def _normalized_payload(section: str, payload: Dict[str, Any], missing_fields: List[str]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if section == "contractor_details":
        contractor = payload.get("contractor") or {}
        sources = payload.get("sources") or {}
        result = {
            "contractor": {k: (contractor.get(k) if k in missing_fields else None) for k in ["name", "email", "phone", "office_address", "company_name", "registration_number"]},
            "sources": {k: _clean_sources(sources.get(k)) for k in ["name", "email", "phone", "office_address", "company_name", "registration_number"]},
        }
    elif section == "department_details":
        dept = payload.get("department") or {}
        sources = payload.get("sources") or {}
        result = {
            "department": {k: (dept.get(k) if k in missing_fields else None) for k in ["department_name", "ministry_level", "official_email", "official_phone", "office_address"]},
            "sources": {k: _clean_sources(sources.get(k)) for k in ["department_name", "ministry_level", "official_email", "official_phone", "office_address"]},
        }
    elif section == "officer_contact":
        officer = payload.get("officer") or {}
        sources = payload.get("sources") or {}
        result = {
            "officer": {k: (officer.get(k) if k in missing_fields else None) for k in ["officer_name", "designation", "official_email", "official_phone"]},
            "sources": {k: _clean_sources(sources.get(k)) for k in ["officer_name", "designation", "official_email", "official_phone"]},
        }
    elif section == "tender_information":
        tender = payload.get("tender") or {}
        sources = payload.get("sources") or {}
        result = {
            "tender": {k: (tender.get(k) if k in missing_fields else None) for k in ["tender_id", "tender_portal_name", "tender_url", "published_date"]},
            "sources": {k: _clean_sources(sources.get(k)) for k in ["tender_id", "tender_portal_name", "tender_url", "published_date"]},
        }
    elif section == "maintenance_authority":
        maintenance = payload.get("maintenance") or {}
        sources = payload.get("sources") or {}
        result = {
            "maintenance": {k: (maintenance.get(k) if k in missing_fields else None) for k in ["authority_name", "contact_email", "contact_phone", "office_address"]},
            "sources": {k: _clean_sources(sources.get(k)) for k in ["authority_name", "contact_email", "contact_phone", "office_address"]},
        }
    elif section == "project_timeline":
        timeline = payload.get("timeline") or {}
        sources = payload.get("sources") or {}
        status_history = []
        for entry in timeline.get("status_history") or []:
            if not isinstance(entry, dict):
                continue
            status_history.append(
                {
                    "status": entry.get("status"),
                    "remarks": entry.get("remarks"),
                    "status_date": entry.get("status_date"),
                    "source_urls": _clean_sources(entry.get("source_urls")),
                }
            )
        result = {
            "timeline": {
                "start_date": timeline.get("start_date") if "start_date" in missing_fields else None,
                "expected_end_date": timeline.get("expected_end_date") if "expected_end_date" in missing_fields else None,
                "current_status": timeline.get("current_status") if "current_status" in missing_fields else None,
                "status_history": status_history,
            },
            "sources": {
                "start_date": _clean_sources(sources.get("start_date")),
                "expected_end_date": _clean_sources(sources.get("expected_end_date")),
                "current_status": _clean_sources(sources.get("current_status")),
            },
        }
    else:
        raise SectionDataFetchError(f"Unsupported section: {section}")

    for field in missing_fields:
        if section == "project_timeline" and field == "status_history":
            continue
        sources_map = result.get("sources") or {}
        if field in sources_map and sources_map[field] is None:
            sources_map[field] = []
    return result


def validate_section_payload(section: str, payload: Dict[str, Any], missing_fields: List[str]) -> Dict[str, Any]:
    normalized = _normalized_payload(section, payload, missing_fields)
    if not isinstance(normalized, dict):
        raise SectionDataFetchError("AI response did not conform to expected structure")
    return normalized


def fetch_section_payload(project, section: str, missing_fields: List[str]) -> Dict[str, Any]:
    api_key = current_app.config.get("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise SectionDataFetchError("GEMINI_API_KEY is not configured")

    client = genai.Client(api_key=api_key)
    grounding_tool = types.Tool(google_search=types.GoogleSearch())
    config = types.GenerateContentConfig(tools=[grounding_tool])

    prompt = build_prompt(project, section, missing_fields)
    current_app.logger.info(
        "Dispatching section fetch", extra={"section": section, "missing_fields": missing_fields, "config": str(config)}
    )

    # Echo full prompt to stdout for traceability in terminal.
    print(
        "\n=== Gemini section prompt ===\n",
        f"section: {section}\nmissing_fields: {missing_fields}\nconfig: {config}\n",
        prompt,
        "\n=== end prompt ===\n",
        sep="",
        flush=True,
    )

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config=config,
    )

    raw_text = response.text or ""
    # Echo raw Gemini response to stdout for debugging.
    print("\n=== Gemini raw response ===\n", raw_text, "\n=== end response ===\n", sep="", flush=True)

    grounding_used = False
    grounding_details: List[str] = []
    for cand in getattr(response, "candidates", []) or []:
        gm = getattr(cand, "grounding_metadata", None) or getattr(cand, "groundingMetadata", None)
        if gm:
            grounding_used = True
            grounding_details.append(str(gm))
    usage_meta = getattr(response, "usage_metadata", None)

    current_app.logger.info(
        "Gemini grounding diagnostics",
        extra={"grounding_used": grounding_used, "grounding_details": grounding_details, "usage": str(usage_meta)},
    )
    print(
        "\n=== Gemini grounding diagnostics ===\n",
        {"grounding_used": grounding_used, "grounding_details": grounding_details, "usage": str(usage_meta)},
        "\n=== end grounding diagnostics ===\n",
        sep="",
        flush=True,
    )
    parsed = _load_json_response(raw_text)

    current_app.logger.info(
        "AI section response",
        extra={"section": section, "raw_ai_text": raw_text, "parsed_ai_json": parsed},
    )

    validated = validate_section_payload(section, parsed, missing_fields)
    return validated


def build_markdown(section: str, payload: Dict[str, Any]) -> str:
    if section == "contractor_details":
        contractor = payload.get("contractor") or {}
        sources = payload.get("sources") or {}
        bullets = [
            f"Name: {contractor.get('name') or 'Unknown'}",
            f"Email: {contractor.get('email') or 'Unknown'}",
            f"Phone: {contractor.get('phone') or 'Unknown'}",
            f"Office: {contractor.get('office_address') or 'Unknown'}",
            f"Company: {contractor.get('company_name') or 'Unknown'}",
            f"Registration: {contractor.get('registration_number') or 'Unknown'}",
        ]
        body = "Sources: " + "; ".join([f"{k}: {', '.join(v or [])}" for k, v in (sources or {}).items() if v])
        return format_sections([{ "title": "Contractor Details (AI Section Fetch)", "bullets": bullets, "body": body }])

    if section == "department_details":
        dept = payload.get("department") or {}
        sources = payload.get("sources") or {}
        bullets = [
            f"Name: {dept.get('department_name') or 'Unknown'}",
            f"Level: {dept.get('ministry_level') or 'Unknown'}",
            f"Email: {dept.get('official_email') or 'Unknown'}",
            f"Phone: {dept.get('official_phone') or 'Unknown'}",
            f"Office: {dept.get('office_address') or 'Unknown'}",
        ]
        body = "Sources: " + "; ".join([f"{k}: {', '.join(v or [])}" for k, v in (sources or {}).items() if v])
        return format_sections([{ "title": "Department Details (AI Section Fetch)", "bullets": bullets, "body": body }])

    if section == "officer_contact":
        officer = payload.get("officer") or {}
        sources = payload.get("sources") or {}
        bullets = [
            f"Officer: {officer.get('officer_name') or 'Unknown'}",
            f"Designation: {officer.get('designation') or 'Unknown'}",
            f"Email: {officer.get('official_email') or 'Unknown'}",
            f"Phone: {officer.get('official_phone') or 'Unknown'}",
        ]
        body = "Sources: " + "; ".join([f"{k}: {', '.join(v or [])}" for k, v in (sources or {}).items() if v])
        return format_sections([{ "title": "Department Officer (AI Section Fetch)", "bullets": bullets, "body": body }])

    if section == "tender_information":
        tender = payload.get("tender") or {}
        sources = payload.get("sources") or {}
        bullets = [
            f"Tender ID: {tender.get('tender_id') or 'Unknown'}",
            f"Portal: {tender.get('tender_portal_name') or 'Unknown'}",
            f"URL: {tender.get('tender_url') or 'Unknown'}",
            f"Published: {tender.get('published_date') or 'Unknown'}",
        ]
        body = "Sources: " + "; ".join([f"{k}: {', '.join(v or [])}" for k, v in (sources or {}).items() if v])
        return format_sections([{ "title": "Tender Information (AI Section Fetch)", "bullets": bullets, "body": body }])

    if section == "maintenance_authority":
        maintenance = payload.get("maintenance") or {}
        sources = payload.get("sources") or {}
        bullets = [
            f"Authority: {maintenance.get('authority_name') or 'Unknown'}",
            f"Email: {maintenance.get('contact_email') or 'Unknown'}",
            f"Phone: {maintenance.get('contact_phone') or 'Unknown'}",
            f"Office: {maintenance.get('office_address') or 'Unknown'}",
        ]
        body = "Sources: " + "; ".join([f"{k}: {', '.join(v or [])}" for k, v in (sources or {}).items() if v])
        return format_sections([{ "title": "Maintenance Authority (AI Section Fetch)", "bullets": bullets, "body": body }])

    if section == "project_timeline":
        timeline = payload.get("timeline") or {}
        sources = payload.get("sources") or {}
        hist = timeline.get("status_history") or []
        bullets = [
            f"Start Date: {timeline.get('start_date') or 'Unknown'}",
            f"Expected End: {timeline.get('expected_end_date') or 'Unknown'}",
            f"Current Status: {timeline.get('current_status') or 'Unknown'}",
        ]
        for entry in hist:
            bullets.append(
                f"History: {entry.get('status') or 'Unknown'} on {entry.get('status_date') or 'Unknown'} ({entry.get('remarks') or 'No remarks'})"
            )
        body = "Sources: " + "; ".join([f"{k}: {', '.join(v or [])}" for k, v in (sources or {}).items() if v])
        return format_sections([{ "title": "Project Timeline (AI Section Fetch)", "bullets": bullets, "body": body }])

    raise SectionDataFetchError(f"Unsupported section: {section}")
