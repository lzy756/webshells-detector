from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)


class CommanderOutput(BaseModel):
    action: Literal["investigate", "consult", "finalize"] = "finalize"
    verdict: Literal["malicious", "benign", "suspicious", "unknown"] = "unknown"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reasoning: str = ""
    evidences: list[dict[str, Any]] = Field(default_factory=list)
    missing_info: str = ""
    consult_question: str = ""


class AdvisorOutput(BaseModel):
    assessment: Literal["agree", "disagree", "uncertain"] = "uncertain"
    alternative_verdict: Literal["malicious", "benign", "suspicious", "unknown"] | None = None
    reasoning: str = ""
    overlooked_patterns: list[str] = Field(default_factory=list)
    suggested_investigations: list[str] = Field(default_factory=list)


class ValidatorOutput(BaseModel):
    decision: Literal["accept", "challenge"] = "accept"
    challenge_reason: str = ""
    evidence_gaps: list[str] = Field(default_factory=list)
    confidence_adjustment: float = Field(default=0.0, ge=-0.15, le=0.15)


def _extract_json(raw: str) -> str:
    m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', raw)
    if m:
        return m.group(1)
    m = re.search(r'\{[\s\S]*\}', raw)
    return m.group(0) if m else raw


def parse_commander_output(raw: str) -> CommanderOutput:
    try:
        return CommanderOutput(**json.loads(_extract_json(raw)))
    except (json.JSONDecodeError, ValidationError) as e:
        logger.warning("Commander output parse failed: %s", e)
        return CommanderOutput(action="finalize", verdict="unknown", confidence=0.5, missing_info=f"Parse error: {e}")


def parse_advisor_output(raw: str) -> AdvisorOutput:
    try:
        return AdvisorOutput(**json.loads(_extract_json(raw)))
    except (json.JSONDecodeError, ValidationError) as e:
        logger.warning("Advisor output parse failed: %s", e)
        return AdvisorOutput()


def parse_validator_output(raw: str) -> ValidatorOutput:
    try:
        return ValidatorOutput(**json.loads(_extract_json(raw)))
    except (json.JSONDecodeError, ValidationError) as e:
        logger.warning("Validator output parse failed: %s", e)
        return ValidatorOutput()
