import copy
import datetime
import json
import logging
import os
import time

import requests

from lib.cuckoo.common.genai_report_curator import json_size_bytes, massage_report

log = logging.getLogger(__name__)

try:
    import orjson

    HAVE_ORJSON = True
except ImportError:
    HAVE_ORJSON = False


RETRYABLE_HTTP = {408, 429, 500, 502, 503, 504}
SCHEMA_VERSION = "1.0"

OPTION_DEFAULTS = {
    "genai_endpoint": "http://127.0.0.1:9055/analyze",
    # Model requested from the GenAI service; empty = the service's own default.
    "model": "",
    "timeout_secs": 30,
    "max_payload_bytes": 1500000,
    "redact_enabled": True,
    "write_txt": True,
    "max_retries": 5,
    "auth_token": "",
}


def build_genai_options(opts_source):
    """Build the effective options dict from a dict-like source (reporting module
    options or the reporting.conf [genai_enrich] section)."""
    return {key: opts_source.get(key, default) for key, default in OPTION_DEFAULTS.items()}


def _json_load(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    if HAVE_ORJSON:
        return orjson.loads(raw)
    return json.loads(raw.decode("utf-8"))


def _json_dump_bytes(data):
    if HAVE_ORJSON:
        return orjson.dumps(data, option=orjson.OPT_INDENT_2)
    return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")


def _json_dump_compact(data):
    if HAVE_ORJSON:
        return orjson.dumps(data)
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _write_json_atomic(path, data):
    tmp = "{0}.tmp".format(path)
    with open(tmp, "wb") as handle:
        handle.write(_json_dump_bytes(data))
    os.replace(tmp, path)


def _write_text_atomic(path, text):
    tmp = "{0}.tmp".format(path)
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


def _to_int(value, default_value):
    try:
        return int(value)
    except Exception:
        return default_value


def _to_bool(value, default_value):
    if isinstance(value, bool):
        return value
    if value is None:
        return default_value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _iso_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _retry_after_seconds(response):
    header = response.headers.get("Retry-After")
    if not header:
        return None
    header = header.strip()
    if header.isdigit():
        return int(header)
    return None


def _backoff(attempt):
    return min(300, 2 ** (attempt - 1))


def _sanitize_genai_response(data):
    if not isinstance(data, dict):
        return {"summary": str(data), "verdict": "unknown", "confidence": 0.0, "errors": ["response_not_json_object"]}
    return data


def _build_payload(task_id, sha256, report_obj, created_ts, model=""):
    payload = {
        "task_id": task_id,
        "sha256": sha256,
        "report": report_obj,
        "context": {
            "schema_version": SCHEMA_VERSION,
            "source": "CAPEv2",
            "analysis_id": task_id,
            "created_ts": created_ts or _iso_now(),
        },
    }
    if model:
        payload["model"] = model
    return payload


def _call_genai(endpoint, payload, headers, timeout_secs, max_retries):
    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            started = time.time()
            # Compact body: matches json_size_bytes measurements and avoids the
            # ~7% overhead of requests' default spaced separators.
            response = requests.post(endpoint, data=_json_dump_compact(payload), headers=headers, timeout=timeout_secs)
            elapsed_ms = int((time.time() - started) * 1000)
        except requests.RequestException as exc:
            last_error = "request_exception: {0}".format(exc)
            if attempt >= max_retries:
                break
            time.sleep(_backoff(attempt))
            continue

        if response.status_code in RETRYABLE_HTTP:
            wait_for = _retry_after_seconds(response)
            if wait_for is None:
                wait_for = _backoff(attempt)
            last_error = "retryable_http_status: {0}".format(response.status_code)
            if attempt >= max_retries:
                break
            time.sleep(wait_for)
            continue

        if response.status_code >= 400:
            body = response.text[:400]
            raise RuntimeError("non_retryable_http_status={0} body={1}".format(response.status_code, body))

        try:
            parsed = response.json()
        except Exception as exc:
            raise RuntimeError("invalid_json_response: {0}".format(exc))

        return _sanitize_genai_response(parsed), elapsed_ms, response.status_code

    raise RuntimeError(last_error or "genai_request_failed")


def _trim_for_limit(curated, max_payload_bytes):
    candidate = copy.deepcopy(curated)
    if json_size_bytes(candidate) <= max_payload_bytes:
        return candidate

    sections = ["strings", "behavior", "network", "dropped", "iocs", "signatures"]
    for section in sections:
        if section not in candidate:
            continue
        if isinstance(candidate[section], dict):
            for key in list(candidate[section].keys()):
                value = candidate[section][key]
                if isinstance(value, list) and len(value) > 20:
                    candidate[section][key] = value[:20]
                elif isinstance(value, str) and len(value) > 500:
                    candidate[section][key] = value[:500]
        elif isinstance(candidate[section], list):
            candidate[section] = candidate[section][:20]

        if json_size_bytes(candidate) <= max_payload_bytes:
            return candidate

    # hard fallback
    return {
        "target": candidate.get("target", {}),
        "signatures": (candidate.get("signatures", []) or [])[:20],
        "iocs": candidate.get("iocs", {}),
    }


def _render_txt(task_id, response_data):
    lines = []
    lines.append("Task: {0}".format(task_id))
    lines.append("Verdict: {0}".format(response_data.get("verdict", "unknown")))
    lines.append("Confidence: {0}".format(response_data.get("confidence", 0.0)))
    lines.append("")
    lines.append("Summary:")
    lines.append(response_data.get("summary", ""))
    lines.append("")

    families = response_data.get("family_hypothesis", []) or []
    if families:
        lines.append("Family hypothesis:")
        for item in families[:10]:
            lines.append("- {0} ({1})".format(item.get("name", "unknown"), item.get("confidence", 0)))
        lines.append("")

    behaviors = response_data.get("key_behaviors", []) or []
    if behaviors:
        lines.append("Key behaviors:")
        for item in behaviors[:20]:
            lines.append("- {0}".format(item))
        lines.append("")

    mitre = response_data.get("mitre", []) or []
    if mitre:
        lines.append("MITRE:")
        for item in mitre[:20]:
            lines.append("- {0} {1}".format(item.get("technique", ""), item.get("name", "")))
        lines.append("")

    recs = response_data.get("recommendations", []) or []
    if recs:
        lines.append("Recommendations:")
        for item in recs[:20]:
            lines.append("- {0}".format(item))
    return "\n".join(lines).strip() + "\n"


def _build_headers(auth_token):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CAPEv2-GenAI-Enricher/1.0",
    }
    if auth_token:
        headers["Authorization"] = "Bearer {0}".format(auth_token)
    return headers


def _build_mongo_summary(response_data, metadata):
    return {
        "verdict": response_data.get("verdict", "unknown"),
        "confidence": response_data.get("confidence", 0.0),
        "summary": (response_data.get("summary") or "")[:2000],
        "model": metadata.get("model"),
        "http_status": metadata.get("http_status"),
        "mode": metadata.get("mode"),
        "written_ts": metadata.get("written_ts"),
    }


def _update_mongo(task_id, fields):
    try:
        from lib.cuckoo.common.config import Config

        if not Config("reporting").mongodb.enabled:
            return False
    except Exception as exc:
        log.warning("GenAI MongoDB config check failed for task %s: %s", task_id, exc)
        return False

    try:
        from dev_utils.mongodb import mongo_update_one
    except Exception as exc:
        log.warning("GenAI MongoDB module unavailable for task %s: %s", task_id, exc)
        return False

    try:
        result = mongo_update_one(
            "analysis",
            {"info.id": int(task_id)},
            {"$set": fields},
            bypass_document_validation=True,
        )
        if getattr(result, "matched_count", 0) == 0:
            log.warning("GenAI MongoDB update found no analysis document for task %s", task_id)
            return False
        return True
    except Exception as exc:
        log.warning("GenAI MongoDB update failed for task %s: %s", task_id, exc)
        return False


def _store_genai_in_mongo(task_id, output):
    return _update_mongo(
        task_id,
        {
            "genai": output,
            "genai_summary": _build_mongo_summary(output.get("response", {}), output.get("metadata", {})),
            "genai_updated_ts": _iso_now(),
            "genai_status": "done",
        },
    )


def _mark_failed_in_mongo(task_id, error):
    _update_mongo(task_id, {"genai_status": "failed", "genai_error": str(error)[:500]})


def _load_existing(existing_path):
    if not os.path.exists(existing_path):
        return None
    try:
        return _json_load(existing_path)
    except Exception as exc:
        log.warning("Failed to parse existing genai report %s: %s", existing_path, exc)
        return None


def _is_same_output(existing, sha256):
    if not isinstance(existing, dict):
        return False
    if existing.get("schema_version") != SCHEMA_VERSION:
        return False
    meta = existing.get("metadata", {}) or {}
    return meta.get("sha256") == sha256


def genai_enrich_task(task_id, report_path, sha256=None, created_ts=None, options=None, force=False):
    """Curate report.json, POST it to the configured GenAI endpoint and store the
    result (reports/genai.json, optional genai.txt, MongoDB genai* fields)."""
    options = options or {}
    timeout_secs = _to_int(options.get("timeout_secs", 30), 30)
    max_payload_bytes = _to_int(options.get("max_payload_bytes", 1500000), 1500000)
    redact_enabled = _to_bool(options.get("redact_enabled", True), True)
    write_txt = _to_bool(options.get("write_txt", True), True)
    max_retries = max(1, _to_int(options.get("max_retries", 5), 5))
    endpoint = options.get("genai_endpoint", "http://127.0.0.1:9055/analyze")
    auth_token = options.get("auth_token", "")
    model = (options.get("model") or "").strip()

    reports_dir = os.path.dirname(report_path)
    output_json = os.path.join(reports_dir, "genai.json")
    output_txt = os.path.join(reports_dir, "genai.txt")

    if not force and _is_same_output(_load_existing(output_json), sha256):
        log.info("GenAI enrichment already present for task %s, skipping", task_id)
        return {"status": "skipped_existing", "task_id": task_id}

    try:
        if not os.path.exists(report_path):
            raise RuntimeError("report_json_missing: {0}".format(report_path))

        full_report = _json_load(report_path)
        curated, stats = massage_report(full_report, {"redact_enabled": redact_enabled})
        request_bytes = json_size_bytes(curated)

        mode = "single"
        if request_bytes > max_payload_bytes:
            curated = _trim_for_limit(curated, max_payload_bytes)
            request_bytes = json_size_bytes(curated)
            mode = "single_trimmed"

        payload = _build_payload(task_id=task_id, sha256=sha256, report_obj=curated, created_ts=created_ts, model=model)
        if json_size_bytes(payload) > max_payload_bytes:
            payload = _build_payload(
                task_id=task_id,
                sha256=sha256,
                report_obj={"target": curated.get("target", {}), "iocs": curated.get("iocs", {})},
                created_ts=created_ts,
                model=model,
            )
        headers = _build_headers(auth_token)
        response_data, elapsed_ms, status_code = _call_genai(endpoint, payload, headers, timeout_secs, max_retries)
    except Exception as exc:
        log.warning("GenAI enrichment failed for task %s: %s", task_id, exc)
        _mark_failed_in_mongo(task_id, exc)
        raise

    output = {
        "schema_version": SCHEMA_VERSION,
        "task_id": task_id,
        "created_ts": created_ts or _iso_now(),
        "response": response_data,
        "metadata": {
            "sha256": sha256,
            "mode": mode,
            "request_size_bytes": request_bytes,
            "elapsed_ms": elapsed_ms,
            "http_status": status_code,
            "chunk_count": 1,
            "endpoint": endpoint,
            "model": response_data.get("model"),
            "prompt_hash": response_data.get("prompt_hash"),
            "written_ts": _iso_now(),
        },
        "massage_stats": stats,
    }
    _write_json_atomic(output_json, output)

    if write_txt:
        _write_text_atomic(output_txt, _render_txt(task_id, response_data))
    mongo_updated = _store_genai_in_mongo(task_id, output)

    log.info(
        "GenAI enrichment complete for task %s (mode=%s, bytes=%s, mongo=%s)",
        task_id,
        mode,
        request_bytes,
        "updated" if mongo_updated else "skipped",
    )
    return {
        "status": "ok",
        "task_id": task_id,
        "mode": mode,
        "request_size_bytes": request_bytes,
        "mongo_updated": mongo_updated,
    }
