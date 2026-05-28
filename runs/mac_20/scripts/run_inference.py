#!/usr/bin/env python3
"""
TrustableClaw Live Batch Inference Runner

This script automates generation of evaluation patches for allowlisted tasks.
It retrieves task statements from the Hugging Face princeton-nlp/SWE-bench_Lite
split and prompts the OpenAI Chat Completions API using standard-library urllib
requests.

The runner is intentionally strict for publishable proof pilots:
- it validates every reused or newly generated patch before adding it to
  predictions.jsonl;
- it retries malformed model outputs before failing the run;
- it writes predictions.jsonl atomically through a temporary file;
- it uses default TLS certificate verification for OpenAI API calls;
- it fails closed if any allowlisted task is missing from the dataset;
- it can rebuild predictions.jsonl from existing validated patch files without
  requiring OPENAI_API_KEY, network access, or the Hugging Face datasets library.
"""

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

# Path configurations relative to script root
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_DIR = os.path.dirname(SCRIPT_DIR)
ALLOWLIST_PATH = os.path.join(os.path.dirname(os.path.dirname(RUN_DIR)), "task_sets", "swebench_lite_mac_20.txt")
PREDICTIONS_PATH = os.path.join(RUN_DIR, "predictions.jsonl")
PATCHES_DIR = os.path.join(RUN_DIR, "patches")
LOGS_DIR = os.path.join(RUN_DIR, "agent_logs")

# API Configuration
MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.4-mini")
MAX_PATCH_ATTEMPTS = int(os.environ.get("TRUSTABLECLAW_PATCH_ATTEMPTS", "3"))


def load_allowlist(path: str) -> List[str]:
    """Load the first twenty allowed evaluation task IDs for the Mac proof pilot."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Allowlist file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    task_ids = lines[:20]
    if len(task_ids) != 20:
        raise RuntimeError(f"Expected exactly 20 allowlisted tasks, found {len(task_ids)}")
    if len(set(task_ids)) != len(task_ids):
        raise RuntimeError("Allowlist contains duplicate task IDs")
    return task_ids


def strip_markdown_fences(raw: str) -> str:
    patch = raw.strip()
    for prefix in ("```diff", "```patch", "```"):
        if patch.startswith(prefix):
            patch = patch[len(prefix):].strip()
            break
    if patch.endswith("```"):
        patch = patch[:-3].strip()
    return patch


def validate_unified_diff(patch: str) -> None:
    """Fail fast when the model returns prose, markdown, empty output, or obvious truncation."""
    stripped = patch.strip()
    if not stripped:
        raise ValueError("model returned an empty patch")
    if "```" in stripped:
        raise ValueError("patch still contains markdown fences")
    if "diff --git " not in stripped and "--- " not in stripped:
        raise ValueError("patch does not contain a unified diff header")
    if "+++ " not in stripped or "@@" not in stripped:
        raise ValueError("patch does not contain required +++ header and hunk marker")
    if stripped.endswith("...") or "<snip>" in stripped.lower() or "# rest of" in stripped.lower():
        raise ValueError("patch appears truncated or abbreviated")


def atomic_write_text(path: str, content: str) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def build_prompt(task_id: str, record: Dict[str, Any]) -> str:
    problem_statement = record.get("problem_statement", "")
    base_commit = record.get("base_commit", "")
    repo = record.get("repo", "")
    return (
        "You are a professional software engineering assistant.\n"
        f"We are resolving the bug ticket for task ID: {task_id} on repo: {repo}.\n"
        f"Base Commit: {base_commit}\n\n"
        f"Problem Statement:\n{problem_statement}\n\n"
        "Please generate a complete, valid git diff patch that resolves the issue described above.\n"
        "CRITICAL: Output ONLY the raw unified diff format patch. "
        "Do NOT wrap the output in markdown blocks, do not use backticks, and do not provide any explanations outside the raw diff content. "
        "The response must be valid unified diff format representing the code modifications."
    )


def call_openai(api_key: str, prompt: str) -> Tuple[str, Dict[str, Any]]:
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are a precise developer who outputs raw unified diff patches without markdown formatting or preambles.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
    }

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")
    
    import ssl
    try:
        import certifi
        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()

    # Do not pass ssl._create_unverified_context(): default urllib TLS verifies certificates.
    with urllib.request.urlopen(req, timeout=120, context=context) as response:
        res_data = response.read().decode("utf-8")
    res_json = json.loads(res_data)
    raw_patch = res_json["choices"][0]["message"]["content"]
    return raw_patch, res_json


def generate_patch_with_retries(api_key: str, task_id: str, record: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    prompt = build_prompt(task_id, record)
    last_error: Exception | None = None
    last_response: Dict[str, Any] = {}
    for attempt in range(1, MAX_PATCH_ATTEMPTS + 1):
        try:
            print(f"[*] Dispatching inference call to OpenAI using model {MODEL} (attempt {attempt}/{MAX_PATCH_ATTEMPTS})...")
            raw_patch, res_json = call_openai(api_key, prompt)
            patch = strip_markdown_fences(raw_patch)
            validate_unified_diff(patch)
            return patch, res_json
        except (ValueError, KeyError, IndexError, json.JSONDecodeError, urllib.error.URLError) as exc:
            last_error = exc
            if isinstance(exc, urllib.error.URLError):
                last_response = {"error": str(exc), "attempt": attempt, "type": "url_error"}
            else:
                last_response = {"error": str(exc), "attempt": attempt, "type": "invalid_patch"}
            print(f"[-] Attempt {attempt} failed for {task_id}: {exc}")
    raise RuntimeError(f"Failed to generate a valid unified diff for {task_id} after {MAX_PATCH_ATTEMPTS} attempts: {last_error}; last_response={last_response}")



def read_patch_file_exact(path: str) -> str:
    """Read a patch exactly as stored so predictions.jsonl can be byte-faithful."""
    with open(path, "r", encoding="utf-8") as pf:
        return pf.read()


def build_prediction_records_from_patches(task_ids: List[str]) -> List[Dict[str, str]]:
    """Rebuild predictions.jsonl from existing patch files without API/dataset access."""
    prediction_records: List[Dict[str, str]] = []
    missing: List[str] = []
    for task_id in task_ids:
        patch_file_path = os.path.join(PATCHES_DIR, f"{task_id}.patch")
        if not os.path.exists(patch_file_path):
            missing.append(task_id)
            continue
        patch = read_patch_file_exact(patch_file_path)
        validate_unified_diff(patch)
        prediction_records.append({
            "instance_id": task_id,
            "model_patch": patch,
            "model_name_or_path": MODEL,
        })
    if missing:
        raise FileNotFoundError(f"missing patch files for tasks: {missing}")
    if len(prediction_records) != len(task_ids):
        raise RuntimeError(f"expected {len(task_ids)} predictions, got {len(prediction_records)}")
    return prediction_records


def write_predictions(prediction_records: List[Dict[str, str]]) -> None:
    predictions_content = "".join(json.dumps(record) + "\n" for record in prediction_records)
    print(f"[*] Atomically writing predictions to: {PREDICTIONS_PATH}")
    atomic_write_text(PREDICTIONS_PATH, predictions_content)


def main() -> None:
    print("Starting TrustableClaw Batch Inference Runner...")
    parser = argparse.ArgumentParser(description="Run live inference for the mac_20 SWE-bench Lite proof pilot.")
    parser.add_argument("--force", action="store_true", help="Regenerate patches even when patch files already exist.")
    parser.add_argument(
        "--rebuild-from-patches",
        action="store_true",
        help="Only rebuild predictions.jsonl from existing patch files; do not require OPENAI_API_KEY, datasets, or network access.",
    )
    args = parser.parse_args()

    try:
        task_ids = load_allowlist(ALLOWLIST_PATH)
        print(f"Loaded {len(task_ids)} target tasks for the mac_20 proof pilot.")
    except Exception as e:
        print(f"[-] Error loading allowlist: {e}")
        sys.exit(1)

    os.makedirs(PATCHES_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

    all_patch_files_exist = all(os.path.exists(os.path.join(PATCHES_DIR, f"{task_id}.patch")) for task_id in task_ids)
    if args.rebuild_from_patches or (all_patch_files_exist and not args.force):
        mode = "explicit --rebuild-from-patches" if args.rebuild_from_patches else "all patch files already exist"
        print(f"[*] Rebuilding predictions.jsonl from existing patch files ({mode}).")
        try:
            prediction_records = build_prediction_records_from_patches(task_ids)
            write_predictions(prediction_records)
        except Exception as e:
            print(f"[-] Error rebuilding predictions from patches: {e}")
            sys.exit(1)
        print("\n[SUCCESS] predictions.jsonl rebuilt from existing validated patch files.")
        return

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("[-] Error: OPENAI_API_KEY environment variable not found and at least one patch file is missing or --force was used.")
        print("For live inference, export it first: export OPENAI_API_KEY='your-key'")
        print("To rebuild predictions from existing patches without API access, run: python scripts/run_inference.py --rebuild-from-patches")
        sys.exit(1)

    try:
        from datasets import load_dataset
    except ImportError:
        print("[-] Error: Hugging Face 'datasets' library is not installed.")
        print("Please install it in your environment for live inference: pip install datasets")
        sys.exit(1)

    print("[*] Downloading and loading Hugging Face dataset (princeton-nlp/SWE-bench_Lite)...")
    records = {}
    for split in ("test", "dev"):
        remaining = [t for t in task_ids if t not in records]
        if not remaining:
            break
        print(f"[*] Checking SWE-bench_Lite ({split}) split for remaining {len(remaining)} tasks...")
        try:
            dataset = load_dataset("princeton-nlp/SWE-bench_Lite", split=split)
            for row in dataset:
                inst_id = row["instance_id"]
                if inst_id in task_ids:
                    records[inst_id] = row
        except Exception as e:
            print(f"[-] Error downloading dataset ({split} split): {e}")
            sys.exit(1)

    missing = [task_id for task_id in task_ids if task_id not in records]
    if missing:
        print(f"[-] Error: allowlisted task IDs missing from dataset: {missing}")
        sys.exit(1)
    print(f"Loaded {len(records)} matching task records from dataset.")

    prediction_records: List[Dict[str, str]] = []
    for idx, task_id in enumerate(task_ids):
        print(f"\n[{idx + 1}/{len(task_ids)}] Processing task: {task_id}")
        patch_file_path = os.path.join(PATCHES_DIR, f"{task_id}.patch")
        log_file_path = os.path.join(LOGS_DIR, f"{task_id}_inference.log")

        if os.path.exists(patch_file_path) and not args.force:
            print(f"[*] Patch already exists at {patch_file_path}. Reusing it exactly in predictions.jsonl. Use --force to regenerate.")
            patch = read_patch_file_exact(patch_file_path)
            validate_unified_diff(patch)
        else:
            try:
                patch, res_json = generate_patch_with_retries(api_key, task_id, records[task_id])
            except Exception as e:
                print(f"[-] Unexpected error during processing of task {task_id}: {e}")
                sys.exit(1)
            print(f"[*] Writing validated generated patch to: {patch_file_path}")
            # Store one canonical trailing newline in the patch file and then read
            # it back exactly. The verifier requires predictions.jsonl model_patch
            # to exactly match this receipt-backed patch file content, including
            # trailing whitespace/newlines.
            atomic_write_text(patch_file_path, patch.rstrip("\n") + "\n")
            patch = read_patch_file_exact(patch_file_path)
            print(f"[*] Saving agent logs to: {log_file_path}")
            atomic_write_text(log_file_path, json.dumps(res_json, indent=2) + "\n")

        prediction_records.append({
            "instance_id": task_id,
            "model_patch": patch,
            "model_name_or_path": MODEL,
        })
        print(f"[SUCCESS] Task {task_id} prediction prepared successfully.")

    if len(prediction_records) != len(task_ids):
        print(f"[-] Error: expected {len(task_ids)} predictions, got {len(prediction_records)}")
        sys.exit(1)

    write_predictions(prediction_records)
    print("\n[SUCCESS] Batch inference run completed. All predictions are generated and validated!")


if __name__ == "__main__":
    main()
