from __future__ import annotations

import pytest
from pydantic import ValidationError

from wsa.agents.schemas import (
    CommanderOutput,
    AdvisorOutput,
    ValidatorOutput,
    parse_commander_output,
    parse_advisor_output,
    parse_validator_output,
)


class TestCommanderOutput:
    def test_valid(self):
        o = CommanderOutput(action="finalize", verdict="malicious", confidence=0.9, reasoning="test")
        assert o.action == "finalize"
        assert o.verdict == "malicious"

    def test_defaults(self):
        o = CommanderOutput()
        assert o.action == "finalize"
        assert o.verdict == "unknown"
        assert o.confidence == 0.5

    def test_confidence_bounds(self):
        with pytest.raises(ValidationError):
            CommanderOutput(confidence=1.5)
        with pytest.raises(ValidationError):
            CommanderOutput(confidence=-0.1)

    def test_invalid_action(self):
        with pytest.raises(ValidationError):
            CommanderOutput(action="invalid")


class TestAdvisorOutput:
    def test_valid(self):
        o = AdvisorOutput(assessment="disagree", alternative_verdict="benign", reasoning="test")
        assert o.assessment == "disagree"

    def test_defaults(self):
        o = AdvisorOutput()
        assert o.assessment == "uncertain"


class TestValidatorOutput:
    def test_valid(self):
        o = ValidatorOutput(decision="challenge", challenge_reason="test", confidence_adjustment=-0.1)
        assert o.decision == "challenge"

    def test_adjustment_bounds(self):
        with pytest.raises(ValidationError):
            ValidatorOutput(confidence_adjustment=0.5)
        with pytest.raises(ValidationError):
            ValidatorOutput(confidence_adjustment=-0.2)


class TestParsing:
    def test_parse_commander_valid_json(self):
        raw = '{"action": "finalize", "verdict": "malicious", "confidence": 0.85, "reasoning": "found exec"}'
        o = parse_commander_output(raw)
        assert o.verdict == "malicious"
        assert o.confidence == 0.85

    def test_parse_commander_code_block(self):
        raw = '```json\n{"action": "finalize", "verdict": "benign", "confidence": 0.2}\n```'
        o = parse_commander_output(raw)
        assert o.verdict == "benign"

    def test_parse_commander_invalid_degrades(self):
        o = parse_commander_output("not json at all")
        assert o.action == "finalize"
        assert o.verdict == "unknown"

    def test_parse_advisor_valid(self):
        raw = '{"assessment": "disagree", "reasoning": "missed reflection"}'
        o = parse_advisor_output(raw)
        assert o.assessment == "disagree"

    def test_parse_advisor_invalid_degrades(self):
        o = parse_advisor_output("garbage")
        assert o.assessment == "uncertain"

    def test_parse_validator_valid(self):
        raw = '{"decision": "accept", "confidence_adjustment": 0.05}'
        o = parse_validator_output(raw)
        assert o.decision == "accept"
        assert o.confidence_adjustment == 0.05

    def test_parse_validator_invalid_degrades(self):
        o = parse_validator_output("garbage")
        assert o.decision == "accept"
