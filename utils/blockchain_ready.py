"""Integrity hashing utilities to prepare for blockchain anchoring."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from extensions import db
from models import BlockchainAnchor


def hash_record(payload: Dict[str, Any]) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def record_anchor(record_type: str, record_id: str, payload: Dict[str, Any], tx_reference: str | None = None) -> BlockchainAnchor:
    digest = hash_record(payload)
    existing = BlockchainAnchor.query.filter_by(record_type=record_type, record_id=str(record_id), data_hash=digest).first()
    if existing:
        return existing
    anchor = BlockchainAnchor(record_type=record_type, record_id=str(record_id), data_hash=digest, tx_reference=tx_reference, status="PENDING")
    db.session.add(anchor)
    db.session.commit()
    return anchor
