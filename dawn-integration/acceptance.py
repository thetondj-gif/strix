#!/usr/bin/env python3
"""Offline scope validator for the DAWN Application Assurance adapter.

This runner does not scan, probe or connect to any target. It only proves that
an explicitly authorised, bounded test request would be eligible for a later
isolated canary.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
SAFE_METHODS = {
    "passive_headers",
    "tls_configuration",
    "dependency_inventory",
    "authentication_review_plan",
    "authorisation_review_plan",
    "input_validation_review_plan",
}
PROHIBITED = {
    "destructive_testing", "persistence", "credential_attack", "denial_of_service",
    "data_exfiltration", "unsanctioned_exploitation", "lateral_movement",
}


def validate(scope: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if scope.get("schema_version") != 1:
        errors.append("schema_version")
    if scope.get("authorised") is not True:
        errors.append("written_authority_required")
    if not scope.get("authority_evidence_ref"):
        errors.append("authority_evidence_ref")
    target = scope.get("target") if isinstance(scope.get("target"), dict) else {}
    url = urlparse(str(target.get("url", "")))
    if url.scheme != "https" or not url.hostname:
        errors.append("https_target_required")
    if target.get("exact_host_only") is not True:
        errors.append("exact_host_boundary")
    if target.get("production") is not False:
        errors.append("production_target_prohibited")
    methods = set(scope.get("methods", []))
    if not methods or not methods.issubset(SAFE_METHODS):
        errors.append("method_allowlist")
    if methods & PROHIBITED or set(scope.get("prohibited_methods", [])) & methods:
        errors.append("prohibited_method")
    if scope.get("network_execution") is not False:
        errors.append("offline_gate_only")
    if not 1 <= int(scope.get("timeout_minutes", 0)) <= 30:
        errors.append("timeout_limit")
    if scope.get("evidence_redaction") is not True:
        errors.append("evidence_redaction")
    return errors


def evaluate(scope: dict[str, Any]) -> dict[str, Any]:
    errors = validate(scope)
    return {
        "schema_version": 1,
        "capability": "dawn-application-assurance",
        "operation": "validate-authorised-scope",
        "status": "blocked" if errors else "success",
        "evidence": [str(scope.get("authority_evidence_ref", ""))] if not errors else [],
        "data": {"scope_approved": not errors, "scan_executed": False},
        "warnings": errors,
        "cost": {"currency": "USD", "estimated": 0},
        "external_actions_performed": False,
    }


def main() -> int:
    valid = json.loads((ROOT / "fixtures" / "valid-scope.json").read_text())
    invalid = json.loads((ROOT / "fixtures" / "invalid-scope.json").read_text())
    accepted = evaluate(valid)
    refused = evaluate(invalid)
    assertions = [
        accepted["status"] == "success",
        accepted["data"]["scan_executed"] is False,
        accepted["external_actions_performed"] is False,
        refused["status"] == "blocked",
        "written_authority_required" in refused["warnings"],
        "production_target_prohibited" in refused["warnings"],
        "method_allowlist" in refused["warnings"],
    ]
    report = {
        "capability": "dawn-application-assurance",
        "status": "passed" if all(assertions) else "failed",
        "tests": len(assertions),
        "passed": sum(assertions),
        "network_used": False,
        "credentials_required": False,
        "scan_performed": False,
        "external_actions_performed": False,
    }
    print(json.dumps(report, indent=2))
    return 0 if all(assertions) else 1


if __name__ == "__main__":
    sys.exit(main())
