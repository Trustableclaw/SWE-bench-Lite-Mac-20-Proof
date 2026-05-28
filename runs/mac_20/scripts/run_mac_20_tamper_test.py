#!/usr/bin/env python3
"""
TrustableClaw verification and tamper test suite for the 20-task proof-pipeline pilot.

This verifier is intentionally strict:
- all 20 allowlisted tasks must be present;
- the package must contain exactly six expected receipt kinds per task;
- receipt chain seals must be valid;
- artifact_hashes.json is required and must match the artifacts on disk;
- proof_manifest.json must carry the expected task IDs for standalone package verification;
- predictions.jsonl must contain one prediction for every expected task;
- every predictions.jsonl model_patch must exactly match patches/<instance_id>.patch;
- every agent_started receipt requested_model/model must match predictions.jsonl model_name_or_path;
- every agent_started receipt must hash and identify the matching agent inference log;
- requested_model and actual_response_model are tracked separately when OpenAI returns a dated snapshot model;
- agent log/patch/test/result artifacts must exist for every expected task;
- result_recorded.resolved and outcome_type must match the actual SWE-bench result JSON/log;
- tamper tests modify a temporary copy of the real proof package and run this verifier against it.
"""

import copy
import json
import hashlib
import os
import shutil
import tempfile
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List

from outcome_classification import classify_actual_result

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_DIR = os.path.dirname(SCRIPT_DIR)
ALLOWLIST_PATH = os.path.join(os.path.dirname(os.path.dirname(RUN_DIR)), "task_sets", "swebench_lite_mac_20.txt")
PROOF_MANIFEST_NAME = "proof_manifest.json"
VERIFICATION_PATH = os.path.join(RUN_DIR, "trustableclaw_verification_results.json")
TAMPER_PATH = os.path.join(RUN_DIR, "tamper_test_results.json")

EXPECTED_RECEIPT_KINDS = [
    "trustableclaw.swebench.task_selected",
    "trustableclaw.swebench.agent_started",
    "trustableclaw.swebench.patch_generated",
    "trustableclaw.swebench.tests_executed",
    "trustableclaw.swebench.result_recorded",
    "trustableclaw.swebench.verification_completed",
]
EXPECTED_RECEIPTS_PER_TASK = len(EXPECTED_RECEIPT_KINDS)


def path_for(run_dir: str, *parts: str) -> str:
    return os.path.join(run_dir, *parts)


def compute_sha256_of_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_sha256_of_receipt(receipt_data: Dict[str, Any]) -> str:
    tmp = dict(receipt_data)
    tmp.pop("hash", None)
    serialized = json.dumps(tmp, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def add_error(errors: List[str], message: str) -> None:
    if message not in errors:
        errors.append(message)


def _validate_task_ids(task_ids: List[str], source: str) -> List[str]:
    if len(task_ids) != 20:
        raise RuntimeError(f"Expected exactly 20 tasks in {source}, got {len(task_ids)}")
    if len(set(task_ids)) != len(task_ids):
        raise RuntimeError(f"{source} contains duplicate task IDs")
    return task_ids


def load_allowlist(path: str = ALLOWLIST_PATH) -> List[str]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Allowlist file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        task_ids = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")][:20]
    return _validate_task_ids(task_ids, path)


def load_expected_task_ids(run_dir: str, errors: List[str]) -> List[str]:
    """Load and strictly validate expected task IDs from the run package itself.

    The package is intentionally self-contained: proof_manifest.json is the source of
    truth for the expected task list and expected proof shape. The repo-level allowlist
    is only a developer fallback so local tooling can surface a clearer error when the
    manifest is absent. Missing proof_manifest.json is still a verification failure.
    """
    manifest_path = path_for(run_dir, PROOF_MANIFEST_NAME)
    if os.path.exists(manifest_path):
        manifest = load_json(manifest_path)
        task_ids = manifest.get("expected_task_ids")
        if not isinstance(task_ids, list) or not all(isinstance(t, str) for t in task_ids):
            raise RuntimeError("proof_manifest.json expected_task_ids must be a list of strings")
        task_ids = _validate_task_ids(task_ids, "proof_manifest.json")

        expected_task_count = manifest.get("expected_task_count")
        expected_receipts_per_task = manifest.get("expected_receipts_per_task")
        expected_receipt_count = manifest.get("expected_receipt_count")

        if expected_task_count != len(task_ids):
            add_error(
                errors,
                "proof_manifest expected_task_count mismatch: "
                f"expected {len(task_ids)}, got {expected_task_count!r}"
            )
        if expected_receipts_per_task != EXPECTED_RECEIPTS_PER_TASK:
            add_error(
                errors,
                "proof_manifest expected_receipts_per_task mismatch: "
                f"expected {EXPECTED_RECEIPTS_PER_TASK}, got {expected_receipts_per_task!r}"
            )
        computed_receipt_count = len(task_ids) * EXPECTED_RECEIPTS_PER_TASK
        if expected_receipt_count != computed_receipt_count:
            add_error(
                errors,
                "proof_manifest expected_receipt_count mismatch: "
                f"expected {computed_receipt_count}, got {expected_receipt_count!r}"
            )
        return task_ids

    errors.append("required proof_manifest.json is missing")
    return load_allowlist()


def load_expected_task_count(run_dir: str) -> int:
    try:
        return len(load_expected_task_ids(run_dir, []))
    except Exception:
        return 20


def load_receipts(run_dir: str) -> List[Dict[str, Any]]:
    receipts_dir = path_for(run_dir, "trustableclaw_receipts")
    if not os.path.isdir(receipts_dir):
        raise FileNotFoundError(f"Receipts directory not found: {receipts_dir}")
    receipt_files = sorted(f for f in os.listdir(receipts_dir) if f.endswith(".json"))
    if not receipt_files:
        raise RuntimeError("Receipts directory is empty. Run generate_mac_10_receipts.py first.")
    return [load_json(os.path.join(receipts_dir, rf)) for rf in receipt_files]


def load_predictions(run_dir: str) -> List[Dict[str, Any]]:
    pred_path = path_for(run_dir, "predictions.jsonl")
    predictions: List[Dict[str, Any]] = []
    with open(pred_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                predictions.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Invalid JSONL at predictions.jsonl:{line_no}: {exc}") from exc
    return predictions


def verify_required_package_shape(run_dir: str, receipts: List[Dict[str, Any]], manifest_hashes: Dict[str, str], errors: List[str]) -> None:
    expected_tasks = load_expected_task_ids(run_dir, errors)
    expected_task_set = set(expected_tasks)

    expected_receipt_count = len(expected_tasks) * EXPECTED_RECEIPTS_PER_TASK
    if len(receipts) != expected_receipt_count:
        errors.append(f"receipt count mismatch: expected {expected_receipt_count}, got {len(receipts)}")

    receipts_by_task: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    kinds_by_task: Dict[str, Counter[str]] = defaultdict(Counter)
    for receipt in receipts:
        data = receipt.get("data", {})
        task_id = data.get("instance_id")
        if task_id:
            receipts_by_task[task_id].append(receipt)
            kinds_by_task[task_id][receipt.get("kind", "")] += 1

    extra_tasks = sorted(set(receipts_by_task) - expected_task_set)
    missing_tasks = [task_id for task_id in expected_tasks if task_id not in receipts_by_task]
    if missing_tasks:
        errors.append(f"missing receipt task IDs: {missing_tasks}")
    if extra_tasks:
        errors.append(f"unexpected receipt task IDs: {extra_tasks}")

    for task_id in expected_tasks:
        task_receipts = receipts_by_task.get(task_id, [])
        if len(task_receipts) != EXPECTED_RECEIPTS_PER_TASK:
            errors.append(f"receipt count mismatch for {task_id}: expected {EXPECTED_RECEIPTS_PER_TASK}, got {len(task_receipts)}")
        for kind in EXPECTED_RECEIPT_KINDS:
            count = kinds_by_task.get(task_id, Counter()).get(kind, 0)
            if count != 1:
                errors.append(f"receipt kind count mismatch for {task_id} {kind}: expected 1, got {count}")

    required_artifacts = [PROOF_MANIFEST_NAME, "predictions.jsonl"]
    for task_id in expected_tasks:
        required_artifacts.extend([
            f"agent_logs/{task_id}_inference.log",
            f"patches/{task_id}.patch",
            f"swebench_results/{task_id}_test.log",
            f"swebench_results/{task_id}_result.json",
        ])
    for rel in required_artifacts:
        path = path_for(run_dir, rel)
        if not os.path.exists(path):
            errors.append(f"required artifact missing: {rel}")
        if rel not in manifest_hashes:
            errors.append(f"required artifact missing from artifact_hashes.json: {rel}")

    try:
        predictions = load_predictions(run_dir)
    except Exception as exc:
        errors.append(str(exc))
        return

    pred_ids = [p.get("instance_id") for p in predictions]
    pred_counter = Counter(pred_ids)
    if len(predictions) != len(expected_tasks):
        errors.append(f"prediction count mismatch: expected {len(expected_tasks)}, got {len(predictions)}")
    missing_predictions = [task_id for task_id in expected_tasks if pred_counter.get(task_id, 0) == 0]
    duplicate_predictions = [task_id for task_id, count in pred_counter.items() if task_id and count > 1]
    extra_predictions = sorted(set(pred_ids) - expected_task_set - {None})
    if missing_predictions:
        errors.append(f"missing predictions for tasks: {missing_predictions}")
    if duplicate_predictions:
        errors.append(f"duplicate predictions for tasks: {duplicate_predictions}")
    if extra_predictions:
        errors.append(f"unexpected prediction task IDs: {extra_predictions}")


def predictions_by_task(run_dir: str) -> Dict[str, Dict[str, Any]]:
    predictions = load_predictions(run_dir)
    by_task: Dict[str, Dict[str, Any]] = {}
    for prediction in predictions:
        task_id = prediction.get("instance_id")
        if isinstance(task_id, str) and task_id not in by_task:
            by_task[task_id] = prediction
    return by_task


def verify_prediction_patch_consistency(run_dir: str, errors: List[str]) -> bool:
    """Ensure SWE-bench predictions evaluate the exact patches that receipts hash."""
    ok = True
    try:
        expected_tasks = load_expected_task_ids(run_dir, errors)
        prediction_map = predictions_by_task(run_dir)
    except Exception as exc:
        errors.append(f"prediction patch consistency verification failed: {exc}")
        return False

    for task_id in expected_tasks:
        prediction = prediction_map.get(task_id)
        patch_path = path_for(run_dir, "patches", f"{task_id}.patch")
        if prediction is None:
            errors.append(f"prediction patch mismatch for {task_id}: missing prediction")
            ok = False
            continue
        model_patch = prediction.get("model_patch")
        if not isinstance(model_patch, str):
            errors.append(f"prediction patch mismatch for {task_id}: model_patch is not a string")
            ok = False
            continue
        if not os.path.exists(patch_path):
            errors.append(f"prediction patch mismatch for {task_id}: patch file missing")
            ok = False
            continue
        with open(patch_path, "r", encoding="utf-8", errors="strict") as f:
            patch_file_text = f.read()
        if model_patch != patch_file_text:
            errors.append(
                f"prediction patch mismatch for {task_id}: "
                "predictions.jsonl model_patch does not exactly match "
                f"patches/{task_id}.patch"
            )
            ok = False
    return ok


def verify_prediction_model_metadata(run_dir: str, receipts: List[Dict[str, Any]], errors: List[str]) -> bool:
    """Ensure agent_started receipt model metadata matches predictions.jsonl."""
    ok = True
    try:
        expected_tasks = load_expected_task_ids(run_dir, errors)
        prediction_map = predictions_by_task(run_dir)
    except Exception as exc:
        errors.append(f"prediction model metadata verification failed: {exc}")
        return False

    agent_started_by_task: Dict[str, Dict[str, Any]] = {}
    for receipt in receipts:
        if receipt.get("kind") != "trustableclaw.swebench.agent_started":
            continue
        data = receipt.get("data", {})
        task_id = data.get("instance_id")
        if isinstance(task_id, str) and task_id not in agent_started_by_task:
            agent_started_by_task[task_id] = receipt

    for task_id in expected_tasks:
        prediction = prediction_map.get(task_id)
        receipt = agent_started_by_task.get(task_id)
        if prediction is None:
            errors.append(f"prediction model mismatch for {task_id}: missing prediction")
            ok = False
            continue
        if receipt is None:
            errors.append(f"prediction model mismatch for {task_id}: missing agent_started receipt")
            ok = False
            continue
        predicted_model = prediction.get("model_name_or_path")
        receipt_model = receipt.get("data", {}).get("model")
        if not isinstance(predicted_model, str) or not predicted_model:
            errors.append(f"prediction model mismatch for {task_id}: prediction model_name_or_path is invalid")
            ok = False
            continue
        if receipt_model != predicted_model:
            errors.append(
                f"prediction model mismatch for {task_id}: "
                f"receipt model={receipt_model!r} prediction model_name_or_path={predicted_model!r}"
            )
            ok = False
    return ok


def load_agent_log(run_dir: str, task_id: str) -> Dict[str, Any]:
    log_path = path_for(run_dir, "agent_logs", f"{task_id}_inference.log")
    return load_json(log_path)


def verify_agent_log_consistency(run_dir: str, receipts: List[Dict[str, Any]], errors: List[str]) -> tuple[bool, bool]:
    """Verify raw inference logs are preserved and match receipt metadata.

    The requested model is the model submitted in predictions.jsonl. The actual
    response model is the concrete provider model/snapshot recorded in the raw
    OpenAI response log. These can differ, and the verifier records that as long
    as both are explicitly preserved and hashed.
    """
    hash_ok = True
    model_ok = True
    try:
        expected_tasks = load_expected_task_ids(run_dir, errors)
        prediction_map = predictions_by_task(run_dir)
    except Exception as exc:
        errors.append(f"agent log consistency verification failed: {exc}")
        return False, False

    agent_started_by_task: Dict[str, Dict[str, Any]] = {}
    for receipt in receipts:
        if receipt.get("kind") != "trustableclaw.swebench.agent_started":
            continue
        data = receipt.get("data", {})
        task_id = data.get("instance_id")
        if isinstance(task_id, str) and task_id not in agent_started_by_task:
            agent_started_by_task[task_id] = receipt

    for task_id in expected_tasks:
        receipt = agent_started_by_task.get(task_id)
        prediction = prediction_map.get(task_id)
        expected_rel = f"agent_logs/{task_id}_inference.log"
        log_path = path_for(run_dir, expected_rel)
        if receipt is None:
            errors.append(f"agent log mismatch for {task_id}: missing agent_started receipt")
            hash_ok = False
            model_ok = False
            continue
        data = receipt.get("data", {})
        if data.get("agent_log_file") != expected_rel:
            errors.append(
                f"agent log mismatch for {task_id}: receipt agent_log_file={data.get('agent_log_file')!r} expected={expected_rel!r}"
            )
            hash_ok = False
        if not os.path.exists(log_path):
            errors.append(f"agent log mismatch for {task_id}: missing {expected_rel}")
            hash_ok = False
            model_ok = False
            continue
        expected_log_hash = data.get("agent_log_sha256")
        actual_log_hash = compute_sha256_of_file(log_path)
        if expected_log_hash != actual_log_hash:
            errors.append(f"agent log hash mismatch for {task_id}")
            hash_ok = False
        try:
            log_json = load_agent_log(run_dir, task_id)
        except Exception as exc:
            errors.append(f"agent log model mismatch for {task_id}: invalid log JSON: {exc}")
            model_ok = False
            continue
        prediction_model = prediction.get("model_name_or_path") if prediction else None
        receipt_model = data.get("model")
        requested_model = data.get("requested_model")
        actual_response_model = data.get("actual_response_model")
        log_response_model = log_json.get("model")
        if receipt_model != prediction_model or requested_model != prediction_model:
            errors.append(
                f"agent log model mismatch for {task_id}: "
                f"receipt model={receipt_model!r} requested_model={requested_model!r} "
                f"prediction model_name_or_path={prediction_model!r}"
            )
            model_ok = False
        if not isinstance(log_response_model, str) or not log_response_model:
            errors.append(f"agent log model mismatch for {task_id}: agent log missing response model")
            model_ok = False
        elif actual_response_model != log_response_model:
            errors.append(
                f"agent log model mismatch for {task_id}: "
                f"receipt actual_response_model={actual_response_model!r} log model={log_response_model!r}"
            )
            model_ok = False
    return hash_ok, model_ok


def update_manifest_hash(run_dir: str, rel_path: str) -> None:
    manifest_path = path_for(run_dir, "artifact_hashes.json")
    manifest = load_json(manifest_path)
    manifest[rel_path] = "sha256:" + compute_sha256_of_file(path_for(run_dir, rel_path))
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")


def verify_hash_manifest(run_dir: str, manifest_hashes: Dict[str, str], errors: List[str]) -> bool:
    ok = True
    for rel, expected in manifest_hashes.items():
        path = path_for(run_dir, rel)
        if not os.path.exists(path):
            errors.append(f"manifest artifact missing: {rel}")
            ok = False
            continue
        actual = "sha256:" + compute_sha256_of_file(path)
        if actual != expected:
            errors.append(f"manifest hash mismatch for {rel}")
            ok = False
    return ok


def verify_package(run_dir: str = RUN_DIR, write_results: bool = True) -> Dict[str, Any]:
    errors: List[str] = []
    manifest_path = path_for(run_dir, "artifact_hashes.json")
    if not os.path.exists(manifest_path):
        errors.append("required artifact_hashes.json is missing")
        manifest_hashes: Dict[str, str] = {}
    else:
        manifest_hashes = load_json(manifest_path)

    receipts_load_ok = True
    try:
        receipts = load_receipts(run_dir)
    except Exception as exc:
        receipts = []
        receipts_load_ok = False
        errors.append(str(exc))

    # Always verify the required shape, even when receipts are missing/empty.
    # This makes the verifier fail closed instead of silently accepting zero receipts.
    try:
        verify_required_package_shape(run_dir, receipts, manifest_hashes, errors)
    except Exception as exc:
        errors.append(f"required package shape verification failed: {exc}")

    prev_hash = ""
    for i, receipt in enumerate(receipts):
        if receipt.get("index") != i:
            errors.append(f"ledger index mismatch at {i}: got {receipt.get('index')}")
        calculated_hash = compute_sha256_of_receipt(receipt)
        if receipt.get("hash") != calculated_hash:
            errors.append(f"receipt hash mismatch at index {i}")
        if receipt.get("prev_hash") != prev_hash:
            errors.append(f"prev_hash linkage mismatch at index {i}")
        prev_hash = receipt.get("hash", "")

    manifest_hash_match = bool(manifest_hashes) and verify_hash_manifest(run_dir, manifest_hashes, errors)
    agent_log_hash_match = True
    agent_log_model_match = True
    patch_hash_match = True
    test_log_hash_match = True
    result_hash_match = True
    outcome_match = True
    verification_receipts_not_overstated = True
    prediction_patch_match = verify_prediction_patch_consistency(run_dir, errors)
    prediction_model_match = verify_prediction_model_metadata(run_dir, receipts, errors)
    agent_log_hash_match, agent_log_model_match = verify_agent_log_consistency(run_dir, receipts, errors)

    result_receipts = [r for r in receipts if r.get("kind") == "trustableclaw.swebench.result_recorded"]
    for receipt in result_receipts:
        data = receipt.get("data", {})
        task_id = data.get("instance_id")
        result_file = data.get("result_file")
        result_path = path_for(run_dir, result_file or "")
        test_log_file = f"swebench_results/{task_id}_test.log"
        test_log_path = path_for(run_dir, test_log_file)
        if not task_id or not result_file or not os.path.exists(result_path):
            errors.append(f"missing result artifact for receipt {receipt.get('receipt_id')}")
            result_hash_match = False
            continue

        actual_resolved, actual_outcome_type, _actual_detail = classify_actual_result(task_id, result_path, test_log_path)
        if data.get("resolved") != actual_resolved:
            outcome_match = False
            errors.append(f"resolved mismatch for {task_id}: receipt={data.get('resolved')} actual={actual_resolved}")
        if data.get("outcome_type") != actual_outcome_type:
            outcome_match = False
            errors.append(f"outcome_type mismatch for {task_id}: receipt={data.get('outcome_type')} actual={actual_outcome_type}")
        expected_result_hash = data.get("result_sha256")
        actual_result_hash = compute_sha256_of_file(result_path)
        if expected_result_hash != actual_result_hash:
            result_hash_match = False
            errors.append(f"result hash mismatch for {task_id}")

    for receipt in receipts:
        data = receipt.get("data", {})
        task_id = data.get("instance_id")
        if receipt.get("kind") == "trustableclaw.swebench.agent_started":
            rel = data.get("agent_log_file")
            path = path_for(run_dir, rel or "")
            expected = data.get("agent_log_sha256")
            if not rel or not os.path.exists(path) or expected != compute_sha256_of_file(path):
                agent_log_hash_match = False
                errors.append(f"agent log hash mismatch or missing artifact for {task_id}")
        elif receipt.get("kind") == "trustableclaw.swebench.patch_generated":
            rel = data.get("patch_file")
            path = path_for(run_dir, rel or "")
            expected = data.get("patch_sha256")
            if not rel or not os.path.exists(path) or expected != compute_sha256_of_file(path):
                patch_hash_match = False
                errors.append(f"patch hash mismatch or missing artifact for {task_id}")
        elif receipt.get("kind") == "trustableclaw.swebench.tests_executed":
            rel = data.get("test_log_file")
            path = path_for(run_dir, rel or "")
            expected = data.get("test_log_sha256")
            if not rel or not os.path.exists(path) or expected != compute_sha256_of_file(path):
                test_log_hash_match = False
                errors.append(f"test log hash mismatch or missing artifact for {task_id}")
        elif receipt.get("kind") == "trustableclaw.swebench.verification_completed":
            resolved = data.get("resolved")
            assertions_passed = data.get("assertions_passed")
            status = data.get("verification_status")
            if resolved is False and (assertions_passed is True or status == "PASSED"):
                verification_receipts_not_overstated = False
                errors.append(f"verification receipt overstates unresolved task {task_id}")

    ledger_ok = receipts_load_ok and not any("ledger" in e or "prev_hash" in e or "receipt hash" in e for e in errors)
    receipt_shape_error_markers = (
        "Receipts directory not found",
        "Receipts directory is empty",
        "receipt count",
        "receipt kind",
        "missing receipt",
        "unexpected receipt",
    )
    receipts_ok = receipts_load_ok and ledger_ok and not any(marker in e for e in errors for marker in receipt_shape_error_markers)
    required_shape_error_markers = (
        "required artifact missing",
        "required package shape verification failed",
        "required proof_manifest.json is missing",
        "proof_manifest expected_task_count mismatch",
        "proof_manifest expected_receipts_per_task mismatch",
        "proof_manifest expected_receipt_count mismatch",
        "prediction patch mismatch",
        "prediction patch consistency verification failed",
        "prediction model mismatch",
        "prediction model metadata verification failed",
        "agent log mismatch",
        "agent log hash mismatch",
        "agent log model mismatch",
        "agent log consistency verification failed",
        "missing predictions",
        "duplicate predictions",
        "unexpected prediction",
        "prediction count mismatch",
        "artifact_hashes.json is missing",
        "missing from artifact_hashes",
        "Receipts directory not found",
        "Receipts directory is empty",
    )
    required_shape_ok = receipts_load_ok and bool(receipts) and not any(
        marker in e
        for e in errors
        for marker in required_shape_error_markers
    )
    proof_package_ok = (
        not errors
        and receipts_ok
        and required_shape_ok
        and manifest_hash_match
        and agent_log_hash_match
        and agent_log_model_match
        and patch_hash_match
        and test_log_hash_match
        and result_hash_match
        and outcome_match
        and verification_receipts_not_overstated
        and prediction_patch_match
        and prediction_model_match
    )

    verification_results = {
        "ok": proof_package_ok,
        "required_shape_ok": required_shape_ok,
        "receipts_load_ok": receipts_load_ok,
        "receipts_ok": receipts_ok,
        "ledger_ok": ledger_ok,
        "manifest_hash_match": manifest_hash_match,
        "agent_log_hash_match": agent_log_hash_match,
        "agent_log_model_match": agent_log_model_match,
        "patch_hash_match": patch_hash_match,
        "test_log_hash_match": test_log_hash_match,
        "result_hash_match": result_hash_match,
        "outcome_match": outcome_match,
        "verification_receipts_not_overstated": verification_receipts_not_overstated,
        "prediction_patch_match": prediction_patch_match,
        "prediction_model_match": prediction_model_match,
        "proof_package_ok": proof_package_ok,
        "expected_tasks": load_expected_task_count(run_dir),
        "expected_receipts": load_expected_task_count(run_dir) * EXPECTED_RECEIPTS_PER_TASK,
        "actual_receipts": len(receipts),
        "errors": errors,
    }
    if write_results:
        with open(path_for(run_dir, "trustableclaw_verification_results.json"), "w", encoding="utf-8") as f:
            json.dump(verification_results, f, indent=2)
            f.write("\n")
    return verification_results


def append_to_file(path: str, text: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def first_receipt_of_kind(receipts: Iterable[Dict[str, Any]], kind: str) -> Dict[str, Any]:
    for receipt in receipts:
        if receipt.get("kind") == kind:
            return receipt
    raise RuntimeError(f"no receipt found for kind {kind}")


def run_tampered_package_check(label: str, mutate_fn) -> bool:
    with tempfile.TemporaryDirectory(prefix=f"trustableclaw_{label}_") as tmp_dir:
        temp_run_dir = os.path.join(tmp_dir, "mac_20")
        shutil.copytree(RUN_DIR, temp_run_dir, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        mutate_fn(temp_run_dir)
        result = verify_package(temp_run_dir, write_results=False)
        return result.get("ok") is False


def _write_predictions_and_reseal_manifest(run_dir: str, predictions: List[Dict[str, Any]]) -> None:
    predictions_path = path_for(run_dir, "predictions.jsonl")
    with open(predictions_path, "w", encoding="utf-8") as f:
        for prediction in predictions:
            f.write(json.dumps(prediction, sort_keys=True) + "\n")
    update_manifest_hash(run_dir, "predictions.jsonl")


def _tamper_agent_log_and_reseal_manifest(run_dir: str) -> None:
    expected_count = load_expected_task_count(run_dir)
    predictions = load_predictions(run_dir)
    if not predictions:
        raise RuntimeError("no predictions to identify agent log")
    task_id = predictions[0]["instance_id"]
    rel = f"agent_logs/{task_id}_inference.log"
    log_path = path_for(run_dir, rel)
    log_json = load_json(log_path)
    log_json["model"] = "tampered-log-model"
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(log_json, f, indent=2, sort_keys=True)
        f.write("\n")
    # Deliberately update artifact_hashes.json so this proves the receipt/log
    # semantic check catches the mismatch, not just a stale manifest hash.
    update_manifest_hash(run_dir, rel)


def _tamper_prediction_patch_and_reseal_manifest(run_dir: str) -> None:
    predictions = load_predictions(run_dir)
    if not predictions:
        raise RuntimeError("no predictions to tamper")
    predictions[0]["model_patch"] = str(predictions[0].get("model_patch", "")) + "\n# unauthorized predictions.jsonl-only tamper\n"
    # Deliberately update artifact_hashes.json so this test proves the verifier
    # catches semantic mismatch between predictions.jsonl and patch files, not just
    # a stale file hash.
    _write_predictions_and_reseal_manifest(run_dir, predictions)


def _tamper_prediction_patch_trailing_whitespace_and_reseal_manifest(run_dir: str) -> None:
    predictions = load_predictions(run_dir)
    if not predictions:
        raise RuntimeError("no predictions to tamper")
    predictions[0]["model_patch"] = str(predictions[0].get("model_patch", "")) + " "
    # Deliberately update artifact_hashes.json so this proves exact comparison
    # catches trailing whitespace mismatches, not just stale file hashes.
    _write_predictions_and_reseal_manifest(run_dir, predictions)


def _tamper_prediction_model_metadata_and_reseal_manifest(run_dir: str) -> None:
    predictions = load_predictions(run_dir)
    if not predictions:
        raise RuntimeError("no predictions to tamper")
    predictions[0]["model_name_or_path"] = "tampered-model-name"
    # Deliberately update artifact_hashes.json so this proves receipt/prediction
    # model metadata mismatch is detected semantically.
    _write_predictions_and_reseal_manifest(run_dir, predictions)


def _tamper_proof_manifest_counts_and_reseal_manifest(run_dir: str) -> None:
    proof_manifest_path = path_for(run_dir, PROOF_MANIFEST_NAME)
    proof_manifest = load_json(proof_manifest_path)
    proof_manifest["expected_task_count"] = 19
    proof_manifest["expected_receipts_per_task"] = 5
    proof_manifest["expected_receipt_count"] = 95
    with open(proof_manifest_path, "w", encoding="utf-8") as f:
        json.dump(proof_manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    # Deliberately update artifact_hashes.json so this proves semantic manifest
    # validation catches false count metadata, not just a stale file hash.
    update_manifest_hash(run_dir, PROOF_MANIFEST_NAME)


def main() -> None:
    print("Initializing TrustableClaw Verification Suite...")
    verification_results = verify_package(write_results=True)
    print(f"[INFO] Verification ok={verification_results['ok']}. Results saved: {VERIFICATION_PATH}")

    receipts = load_receipts(RUN_DIR)
    first_patch = first_receipt_of_kind(receipts, "trustableclaw.swebench.patch_generated")
    first_log = first_receipt_of_kind(receipts, "trustableclaw.swebench.tests_executed")
    first_result = first_receipt_of_kind(receipts, "trustableclaw.swebench.result_recorded")

    patch_rel = first_patch["data"]["patch_file"]
    log_rel = first_log["data"]["test_log_file"]
    result_rel = first_result["data"]["result_file"]
    receipt_filename = sorted(f for f in os.listdir(path_for(RUN_DIR, "trustableclaw_receipts")) if f.endswith(".json"))[0]

    tamper_results = {
        "ok": False,
        "patch_tamper_detected_by_real_verifier": run_tampered_package_check(
            "patch_tamper",
            lambda rd: append_to_file(path_for(rd, patch_rel), "\n# unauthorized patch tamper\n"),
        ),
        "test_log_tamper_detected_by_real_verifier": run_tampered_package_check(
            "log_tamper",
            lambda rd: append_to_file(path_for(rd, log_rel), "\nUNAUTHORIZED LOG TAMPER\n"),
        ),
        "result_tamper_detected_by_real_verifier": run_tampered_package_check(
            "result_tamper",
            lambda rd: append_to_file(path_for(rd, result_rel), "\n"),
        ),
        "receipt_json_tamper_detected_by_real_verifier": run_tampered_package_check(
            "receipt_tamper",
            lambda rd: _tamper_receipt(path_for(rd, "trustableclaw_receipts", receipt_filename)),
        ),
        "missing_receipt_detected_by_real_verifier": run_tampered_package_check(
            "missing_receipt",
            lambda rd: os.remove(path_for(rd, "trustableclaw_receipts", receipt_filename)),
        ),
        "missing_manifest_detected_by_real_verifier": run_tampered_package_check(
            "missing_manifest",
            lambda rd: os.remove(path_for(rd, "artifact_hashes.json")),
        ),
        "missing_proof_manifest_detected_by_real_verifier": run_tampered_package_check(
            "missing_proof_manifest",
            lambda rd: os.remove(path_for(rd, PROOF_MANIFEST_NAME)),
        ),
        "proof_manifest_count_tamper_detected_by_real_verifier": run_tampered_package_check(
            "proof_manifest_count_tamper",
            _tamper_proof_manifest_counts_and_reseal_manifest,
        ),
        "agent_log_tamper_detected_by_real_verifier": run_tampered_package_check(
            "agent_log_tamper",
            _tamper_agent_log_and_reseal_manifest,
        ),
        "prediction_patch_mismatch_detected_by_real_verifier": run_tampered_package_check(
            "prediction_patch_mismatch",
            _tamper_prediction_patch_and_reseal_manifest,
        ),
        "prediction_patch_trailing_whitespace_mismatch_detected_by_real_verifier": run_tampered_package_check(
            "prediction_patch_trailing_whitespace_mismatch",
            _tamper_prediction_patch_trailing_whitespace_and_reseal_manifest,
        ),
        "prediction_model_metadata_mismatch_detected_by_real_verifier": run_tampered_package_check(
            "prediction_model_metadata_mismatch",
            _tamper_prediction_model_metadata_and_reseal_manifest,
        ),
        "empty_receipts_dir_detected_by_real_verifier": run_tampered_package_check(
            "empty_receipts_dir",
            lambda rd: _empty_receipts_dir(path_for(rd, "trustableclaw_receipts")),
        ),
        "missing_receipts_dir_detected_by_real_verifier": run_tampered_package_check(
            "missing_receipts_dir",
            lambda rd: shutil.rmtree(path_for(rd, "trustableclaw_receipts")),
        ),
    }
    tamper_results["ok"] = all(v for k, v in tamper_results.items() if k != "ok")

    with open(TAMPER_PATH, "w", encoding="utf-8") as f:
        json.dump(tamper_results, f, indent=2)
        f.write("\n")
    print(f"[SUCCESS] Tamper testing completed. Results saved: {TAMPER_PATH}")


def _tamper_receipt(path: str) -> None:
    receipt = load_json(path)
    receipt.setdefault("data", {})["tampered"] = True
    with open(path, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, sort_keys=True)
        f.write("\n")


def _empty_receipts_dir(path: str) -> None:
    for name in os.listdir(path):
        child = os.path.join(path, name)
        if os.path.isdir(child):
            shutil.rmtree(child)
        else:
            os.remove(child)


if __name__ == "__main__":
    main()
