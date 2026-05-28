#!/usr/bin/env python3
"""Shared SWE-bench outcome classification helpers for the mac_10 proof pilot."""

import json
import os
from typing import Any, Dict, Tuple

PATCH_APPLY_FAILURE_MARKERS = (
    "patch apply failed",
    "failed to apply patch",
    "patch failed to apply",
    "can't find file to patch",
    "cannot find file to patch",
    "unexpected end of file in patch",
    "patch unexpectedly ends",
    "patch unexpectedly ends in middle of line",
    "unexpected end of file",
    "malformed patch",
    "corrupt patch",
    "hunk failed",
    "rejected hunk",
)

SETUP_BUILD_FAILURE_MARKERS = (
    "build failed",
    "setup failed",
    "dependency failed",
    "could not install",
    "failed to build",
    "environment failed",
    "docker",
    "timeout",
)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _read_lower(path: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read().lower()


def classify_actual_result(task_id: str, result_path: str, test_log_path: str) -> Tuple[bool, str, str]:
    """Return (resolved, outcome_type, outcome_detail) from SWE-bench result/log artifacts.

    This function is intentionally shared by receipt generation and verification. If the
    result-classification rules change, receipts and the verifier stay in lockstep.
    """
    result = load_json(result_path)
    log_text = _read_lower(test_log_path)

    if task_id in result and isinstance(result[task_id], dict):
        task_result = result[task_id]
        resolved = bool(task_result.get("resolved", False))
        if resolved:
            return True, "resolved", "SWE-bench reported resolved=true."
        if task_result.get("patch_successfully_applied") is True:
            return False, "tests_executed_unresolved", "Patch applied and tests executed, but SWE-bench reported resolved=false."
        if any(marker in log_text for marker in PATCH_APPLY_FAILURE_MARKERS):
            return False, "patch_apply_failure", "Patch failed to apply."
        return False, "setup_build_failure", "SWE-bench returned a task object, but the patch did not complete successfully."

    status = str(result.get("status", "")).lower()
    message = str(result.get("message", ""))
    combined = f"{status}\n{message.lower()}\n{log_text}"

    if any(marker in combined for marker in PATCH_APPLY_FAILURE_MARKERS):
        return False, "patch_apply_failure", message or "Patch failed to apply."
    if status == "error" or any(marker in combined for marker in SETUP_BUILD_FAILURE_MARKERS):
        return False, "setup_build_failure", message or "Evaluation setup/build failed."
    return False, "unknown_failure", message or "Unresolved with unrecognized result shape."
