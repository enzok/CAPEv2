import asyncio
import base64
import json
import os
import sys
import mimetypes
import re
from typing import Any, Dict, Optional

# Ensure CAPE root is in path for lib imports
CAPE_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CAPE_ROOT)

try:
    import httpx
    from fastmcp import FastMCP
except ImportError:
    sys.exit("poetry run pip install .[mcp]")

try:
    from lib.cuckoo.common.config import Config
    from lib.cuckoo.common.web_utils import (
        search_term_map,
        perform_search_filters,
        hash_searches,
        normalized_lower_terms,
    )
except ImportError:
    sys.exit("Could not import lib.cuckoo.common.config. Ensure you are running from CAPE root.")

# Initialize CAPE Config
api_config = Config("api")

# Configuration from Environment or Config File
# Run with: CAPE_API_URL=http://127.0.0.1:8000/apiv2 CAPE_API_TOKEN=your_token poetry run python mcp/server.py
API_URL = os.environ.get("CAPE_API_URL")
if not API_URL:
    # Try to get from api.conf [api] url
    try:
        base_url = api_config.api.url.rstrip("/")
        API_URL = f"{base_url}/apiv2"
    except AttributeError:
        API_URL = "http://127.0.0.1:8000/apiv2"

API_TOKEN = os.environ.get("CAPE_API_TOKEN", "")

# Timeouts: a generous default for API calls, and a long read window for
# large binary downloads. Without these a stalled CAPE host would wedge the agent.
DEFAULT_TIMEOUT = httpx.Timeout(30.0, read=60.0)
DOWNLOAD_TIMEOUT = httpx.Timeout(30.0, read=300.0)

# Inline retrieval cap (see _download_file). Above this, callers must save to disk.
MAX_INLINE_BYTES = 5 * 1024 * 1024

# Task statuses that mean "done, stop polling".
_TERMINAL_STATUSES = {"reported"}

# Valid options for extended_search, derived from CAPE's own search map so the
# schema/docstring stays in sync with the backend.
VALID_SEARCH_OPTIONS = sorted(set(search_term_map) | set(hash_searches))

# Proactively map enabled MCP tools. Default is NO.
ENABLED_MCP_TOOLS = set()
for section_name in api_config.get_config():
    if section_name == "api":
        continue
    try:
        section = api_config.get(section_name)
        if getattr(section, "mcp", False):
            ENABLED_MCP_TOOLS.add(section_name)
    except Exception:
        continue

def check_mcp_enabled(section: str) -> bool:
    """Check if a specific section is enabled for MCP."""
    return section in ENABLED_MCP_TOOLS

# Initialize FastMCP
mcp = FastMCP("cape-sandbox")

def mcp_tool(section: str):
    """
    Conditional decorator that only registers the tool with FastMCP
    if the corresponding section is enabled in api.conf.
    """
    def decorator(func):
        if check_mcp_enabled(section):
            return mcp.tool()(func)
        return func
    return decorator

def mcp_resource(section: str, uri: str):
    """Conditional resource decorator, gated on the api.conf section."""
    def decorator(func):
        if check_mcp_enabled(section):
            return mcp.resource(uri)(func)
        return func
    return decorator

def is_auth_required() -> bool:
    """Check if token authorization is enabled globally."""
    try:
        return api_config.api.token_auth_enabled
    except AttributeError:
        return False

# Startup Check: Warn if Auth is enabled but no default token is provided
if is_auth_required() and not API_TOKEN:
    print("WARNING: Token authentication is enabled in api.conf, but CAPE_API_TOKEN is not set.", file=sys.stderr)
    print("         All MCP tool calls must include a valid 'token' argument.", file=sys.stderr)

# Security: Restrict file submission to a specific directory
# Defaults to current working directory if not set
ALLOWED_SUBMISSION_DIR = os.environ.get("CAPE_ALLOWED_SUBMISSION_DIR", os.getcwd())

# Shared HTTP client (connection pooling). Created lazily inside the event loop.
_http_client: Optional[httpx.AsyncClient] = None

def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    return _http_client

def get_headers(token: str = "") -> Dict[str, str]:
    headers = {}
    auth_token = token if token else API_TOKEN

    if auth_token:
        headers["Authorization"] = f"Token {auth_token}"
    return headers

def _auth_error(token: str = "") -> Optional[Dict[str, Any]]:
    """Return an error dict if auth is required but unavailable, else None."""
    if is_auth_required() and not (token or API_TOKEN):
        return {"error": True, "message": "Authentication required but no token provided."}
    return None

def _check_submission_path(file_path: str) -> Optional[Dict[str, Any]]:
    """Validate a submission path exists and is contained in the allowed dir.

    Returns an error dict on failure, or None if the path is safe.
    """
    if not os.path.exists(file_path):
        return {"error": True, "message": "File not found"}

    abs_file_path = os.path.abspath(file_path)
    abs_allowed_dir = os.path.abspath(ALLOWED_SUBMISSION_DIR)
    # commonpath containment — not a string prefix (which would let
    # /data/cape-evil past a /data/cape allowlist).
    try:
        contained = os.path.commonpath([abs_file_path, abs_allowed_dir]) == abs_allowed_dir
    except ValueError:
        # Different drives on Windows, etc.
        contained = False
    if not contained:
        return {
            "error": True,
            "message": f"Security Violation: File submission is restricted to {abs_allowed_dir}",
        }
    return None

async def _request(method: str, endpoint: str, token: str = "", **kwargs) -> Any:
    err = _auth_error(token)
    if err:
        return err

    url = f"{API_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    client = _get_client()
    try:
        response = await client.request(method, url, headers=get_headers(token), **kwargs)
        # We don't raise_for_status immediately to handle API errors gracefully in JSON
        if response.status_code >= 400:
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"error": True, "message": f"HTTP {response.status_code}", "body": response.text}

        try:
            return response.json()
        except json.JSONDecodeError:
            return {"error": False, "data": response.text}
    except httpx.HTTPStatusError as e:
        return {"error": True, "message": str(e), "body": e.response.text}
    except Exception as e:
        return {"error": True, "message": str(e)}

async def _download_file(
    endpoint: str,
    destination: str = "",
    default_filename: str = "downloaded_file.bin",
    token: str = "",
    inline: bool = False,
) -> str:
    """Download a file from an API endpoint.

    Save mode (default): streams to `destination` (a directory on the MCP
    server host). Inline mode: returns the content in the JSON response
    (text as-is, binary as base64), capped at MAX_INLINE_BYTES.
    """
    err = _auth_error(token)
    if err:
        return json.dumps(err, indent=2)

    if not inline and not os.path.isdir(destination):
        return json.dumps({"error": True, "message": "Destination directory does not exist (or pass inline=true)"}, indent=2)

    url = f"{API_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    headers = get_headers(token)
    client = _get_client()

    try:
        async with client.stream("GET", url, headers=headers, timeout=DOWNLOAD_TIMEOUT) as response:
            if response.status_code != 200:
                content = await response.read()
                return json.dumps({"error": True, "message": f"HTTP {response.status_code}", "body": content.decode("utf-8", errors="ignore")}, indent=2)

            if inline:
                chunks = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_INLINE_BYTES:
                        return json.dumps({
                            "error": True,
                            "message": f"Content exceeds inline cap ({MAX_INLINE_BYTES} bytes); call again with inline=false and a 'destination' directory to save it.",
                        }, indent=2)
                    chunks.append(chunk)
                content = b"".join(chunks)
                try:
                    text = content.decode("utf-8")
                    if "\x00" not in text:
                        return json.dumps({"error": False, "encoding": "utf-8", "content": text}, indent=2)
                except UnicodeDecodeError:
                    pass
                return json.dumps({"error": False, "encoding": "base64", "content": base64.b64encode(content).decode("ascii")}, indent=2)

            filename = default_filename
            content_disposition = response.headers.get("content-disposition")
            if content_disposition:
                match = re.search(r'filename="?([^"]+)"?', content_disposition)
                if match:
                    filename = os.path.basename(match.group(1))

            filepath = os.path.join(destination, filename)
            with open(filepath, "wb") as f:
                async for chunk in response.aiter_bytes():
                    f.write(chunk)

            return json.dumps({"error": False, "message": f"Saved to {filepath}", "path": filepath}, indent=2)
    except Exception as e:
        return json.dumps({"error": True, "message": str(e)}, indent=2)

def _build_submission_data(**kwargs) -> Dict[str, str]:
    """Helper to build submission data dictionary, handling type conversions."""
    data = {}
    for key, value in kwargs.items():
        # Skip empty values (None, "", 0, False) to match original behavior
        if not value:
            continue

        if isinstance(value, bool):
            data[key] = "1"
        elif isinstance(value, int):
            data[key] = str(value)
        else:
            data[key] = value
    return data

def _extract_task_id(result: Any) -> Optional[int]:
    """Pull the first task id out of a submission response, across shapes."""
    if not isinstance(result, dict):
        return None
    candidates = [result]
    if isinstance(result.get("data"), dict):
        candidates.append(result["data"])
    for container in candidates:
        ids = container.get("task_ids")
        if isinstance(ids, list) and ids:
            return ids[0]
        if container.get("task_id"):
            return container["task_id"]
    return None

# --- Submission core helpers (shared by tools and *_and_wait variants) ---

async def _submit_file_core(file_path: str, token: str = "", **opts) -> Dict[str, Any]:
    err = _auth_error(token)
    if err:
        return err
    path_err = _check_submission_path(file_path)
    if path_err:
        return path_err

    filename = os.path.basename(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    data = _build_submission_data(**opts)
    url = f"{API_URL.rstrip('/')}/tasks/create/file/"
    client = _get_client()
    try:
        with open(file_path, "rb") as f:
            files = {"file": (filename, f, mime_type)}
            response = await client.post(url, data=data, files=files, headers=get_headers(token))
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"error": response.status_code >= 400, "data": response.text}
    except Exception as e:
        return {"error": True, "message": str(e)}

async def _submit_url_core(url_value: str, token: str = "", **opts) -> Dict[str, Any]:
    data = {"url": url_value}
    data.update(_build_submission_data(**opts))
    return await _request("POST", "tasks/create/url/", token=token, data=data)

# --- Tasks Creation ---

@mcp_tool("filecreate")
async def submit_file(
    file_path: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    timeout: int = 0,
    platform: str = "",
    memory: bool = False,
    enforce_timeout: bool = False,
    clock: str = "",
    custom: str = "",
    token: str = ""
) -> str:
    """
    Submit a local file for analysis.
    """
    result = await _submit_file_core(
        file_path, token=token, machine=machine, package=package, options=options, tags=tags,
        priority=priority, timeout=timeout, platform=platform, memory=memory,
        enforce_timeout=enforce_timeout, clock=clock, custom=custom,
    )
    return json.dumps(result, indent=2)

@mcp_tool("urlcreate")
async def submit_url(
    url: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    timeout: int = 0,
    platform: str = "",
    memory: bool = False,
    enforce_timeout: bool = False,
    clock: str = "",
    custom: str = "",
    token: str = ""
) -> str:
    """Submit a URL for analysis."""
    result = await _submit_url_core(
        url, token=token, machine=machine, package=package, options=options, tags=tags,
        priority=priority, timeout=timeout, platform=platform, memory=memory,
        enforce_timeout=enforce_timeout, clock=clock, custom=custom,
    )
    return json.dumps(result, indent=2)

@mcp_tool("dlnexeccreate")
async def submit_dlnexec(
    url: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    token: str = ""
) -> str:
    """Submit a URL for Download & Execute analysis."""
    data = {"dlnexec": url}
    data.update(_build_submission_data(
        machine=machine, package=package, options=options, tags=tags, priority=priority
    ))

    result = await _request("POST", "tasks/create/dlnexec/", token=token, data=data)
    return json.dumps(result, indent=2)

@mcp_tool("staticextraction")
async def submit_static(
    file_path: str,
    priority: int = 1,
    options: str = "",
    token: str = ""
) -> str:
    """Submit a file for static extraction only."""
    err = _auth_error(token)
    if err:
        return json.dumps(err)
    path_err = _check_submission_path(file_path)
    if path_err:
        return json.dumps(path_err)

    filename = os.path.basename(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    data = _build_submission_data(priority=priority, options=options)
    url = f"{API_URL.rstrip('/')}/tasks/create/static/"
    client = _get_client()
    try:
        with open(file_path, "rb") as f:
            files = {"file": (filename, f, mime_type)}
            response = await client.post(url, data=data, files=files, headers=get_headers(token))
            try:
                result = response.json()
            except json.JSONDecodeError:
                result = {"error": response.status_code >= 400, "data": response.text}
    except Exception as e:
        result = {"error": True, "message": str(e)}

    return json.dumps(result, indent=2)

# --- Wait / one-shot triage ---

def _is_terminal_status(status: Any) -> bool:
    if not isinstance(status, str):
        return False
    return status in _TERMINAL_STATUSES or status.startswith("failed")

async def _wait_for_task(task_id: int, timeout_secs: int, poll_interval: int, token: str = "") -> Dict[str, Any]:
    elapsed = 0
    last_status = None
    poll_interval = max(1, poll_interval)
    while elapsed <= timeout_secs:
        result = await _request("GET", f"tasks/status/{task_id}/", token=token)
        if isinstance(result, dict):
            if result.get("error"):
                return {"error": True, "task_id": task_id, "message": result.get("message") or result.get("error_value"), "last_status": last_status}
            last_status = result.get("data", result.get("status"))
        if _is_terminal_status(last_status):
            return {"error": False, "task_id": task_id, "status": last_status, "timed_out": False}
        await asyncio.sleep(poll_interval)
        elapsed += poll_interval
    return {"error": False, "task_id": task_id, "status": last_status, "timed_out": True,
            "message": f"Task did not reach a terminal state within {timeout_secs}s; poll again or raise timeout_secs."}

@mcp_tool("taskstatus")
async def wait_for_task(task_id: int, timeout_secs: int = 600, poll_interval: int = 10, token: str = "") -> str:
    """Poll a task until it finishes (reported/failed) or the timeout elapses.

    Returns the final status. Use this after submitting instead of calling
    get_task_status in a loop yourself.
    """
    result = await _wait_for_task(task_id, timeout_secs, poll_interval, token=token)
    return json.dumps(result, indent=2)

@mcp_tool("filecreate")
async def submit_file_and_wait(
    file_path: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    timeout: int = 0,
    platform: str = "",
    timeout_secs: int = 600,
    poll_interval: int = 10,
    token: str = ""
) -> str:
    """Submit a file, wait for the analysis to finish, and return the lean report.

    One call for the whole triage loop. On analysis timeout, returns the task id
    and last status so you can resume with wait_for_task / get_task_report.
    """
    submission = await _submit_file_core(
        file_path, token=token, machine=machine, package=package, options=options,
        tags=tags, priority=priority, timeout=timeout, platform=platform,
    )
    task_id = _extract_task_id(submission)
    if task_id is None:
        return json.dumps({"error": True, "message": "Submission failed or no task id returned", "submission": submission}, indent=2)

    waited = await _wait_for_task(task_id, timeout_secs, poll_interval, token=token)
    if waited.get("timed_out") or waited.get("error"):
        return json.dumps({"submitted_task_id": task_id, "wait": waited}, indent=2)

    report = await _fetch_lean_report(task_id, token=token)
    return json.dumps({"task_id": task_id, "status": waited.get("status"), "report": report}, indent=2)

@mcp_tool("urlcreate")
async def submit_url_and_wait(
    url: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    timeout: int = 0,
    platform: str = "",
    timeout_secs: int = 600,
    poll_interval: int = 10,
    token: str = ""
) -> str:
    """Submit a URL, wait for the analysis to finish, and return the lean report."""
    submission = await _submit_url_core(
        url, token=token, machine=machine, package=package, options=options,
        tags=tags, priority=priority, timeout=timeout, platform=platform,
    )
    task_id = _extract_task_id(submission)
    if task_id is None:
        return json.dumps({"error": True, "message": "Submission failed or no task id returned", "submission": submission}, indent=2)

    waited = await _wait_for_task(task_id, timeout_secs, poll_interval, token=token)
    if waited.get("timed_out") or waited.get("error"):
        return json.dumps({"submitted_task_id": task_id, "wait": waited}, indent=2)

    report = await _fetch_lean_report(task_id, token=token)
    return json.dumps({"task_id": task_id, "status": waited.get("status"), "report": report}, indent=2)

# --- Task Management & Search ---

def _summarize_configs(cape_field: Any) -> list:
    """Compact the CAPE config-extraction blob to a token-friendly summary."""
    raw = cape_field
    if isinstance(raw, dict):
        raw = raw.get("configs", [])
    if not isinstance(raw, list):
        return []
    summary = []
    for entry in raw[:10]:
        if not isinstance(entry, dict):
            continue
        compact = {}
        for key, value in entry.items():
            if isinstance(value, str):
                compact[key] = value[:200]
            elif isinstance(value, bool) or isinstance(value, (int, float)):
                compact[key] = value
            elif isinstance(value, list):
                compact[key] = [str(item)[:200] for item in value[:10]]
            elif isinstance(value, dict):
                compact[key] = {k: str(v)[:200] for k, v in list(value.items())[:20]}
            else:
                compact[key] = str(type(value).__name__)
        summary.append(compact)
    return summary

def get_lean_cape_report(raw_cape_json):
    """Filters a large CAPE report down to a compact LLM payload."""
    if not isinstance(raw_cape_json, dict):
        return raw_cape_json
    network = raw_cape_json.get("network", {}) or {}
    behavior_summary = raw_cape_json.get("behavior", {}).get("summary", {}) if isinstance(raw_cape_json.get("behavior"), dict) else {}
    if not isinstance(behavior_summary, dict):
        behavior_summary = {}
    domains = network.get("domains") if isinstance(network.get("domains"), list) else []
    https = network.get("http") if isinstance(network.get("http"), list) else []
    return {
        "score": raw_cape_json.get("info", {}).get("score", 0),
        "family": raw_cape_json.get("malfamily") or raw_cape_json.get("detections", {}).get("family") or "Unknown",
        "extracted_configs": _summarize_configs(raw_cape_json.get("CAPE", [])),
        "high_severity_signatures": [
            {"name": sig.get("name"), "desc": sig.get("description")}
            for sig in raw_cape_json.get("signatures", [])
            if isinstance(sig, dict) and sig.get("severity", 0) >= 3
        ],
        "network": {
            "domains": [d.get("domain") for d in domains if isinstance(d, dict) and d.get("domain")],
            "http_uris": [h.get("uri") for h in https if isinstance(h, dict) and h.get("uri")],
        },
        "indicators": {
            "mutexes": behavior_summary.get("mutexes", []),
            "commands": behavior_summary.get("executed_commands", []),
        },
    }

def _apply_lean_report(result):
    if isinstance(result, dict):
        if result.get("error") is False and "data" in result:
            if isinstance(result["data"], list):
                result["data"] = [get_lean_cape_report(item) for item in result["data"]]
            elif isinstance(result["data"], dict):
                result["data"] = get_lean_cape_report(result["data"])
        elif "info" in result:
             return get_lean_cape_report(result)
    elif isinstance(result, list):
        return [get_lean_cape_report(item) for item in result]
    return result

async def _fetch_lean_report(task_id: int, token: str = "") -> Any:
    data = {"option": "id", "argument": str(task_id), "lean": True}
    result = await _request("POST", "tasks/extendedsearch/", token=token, data=data)
    if isinstance(result, dict) and not result.get("error") and isinstance(result.get("data"), list) and result["data"]:
        return get_lean_cape_report(result["data"][0])
    return {"error": True, "message": "Report not found via lean search.", "raw": result}

@mcp_tool("tasksearch")
async def search_task(hash_value: str, lean: bool = True, token: str = "") -> str:
    """Search for tasks by MD5 (32), SHA1 (40), or SHA256 (64 hex chars)."""
    if not re.match(r"^[a-fA-F0-9]+$", hash_value):
        return json.dumps({"error": True, "message": "Invalid hash value provided. Only hexadecimal characters are allowed."}, indent=2)

    algo_by_len = {32: "md5", 40: "sha1", 64: "sha256"}
    algo = algo_by_len.get(len(hash_value))
    if algo is None:
        return json.dumps({"error": True, "message": "Invalid hash length. Expected 32 (md5), 40 (sha1), or 64 (sha256) hex characters."}, indent=2)

    result = await _request("GET", f"tasks/search/{algo}/{hash_value}/", token=token)
    if lean:
        result = _apply_lean_report(result)
    return json.dumps(result, indent=2)

@mcp_tool("extendedtasksearch")
async def extended_search(option: str, argument: str, lean: bool = True, token: str = "") -> str:
    """
    Search tasks using extended options.

    Valid `option` values include: id, name, type, string, ssdeep, crc32, file,
    command, resolvedapi, key, mutex, domain, ip, signature, signame, configs, etc.
    Call get_search_info for the full authoritative list.
    """
    if option not in VALID_SEARCH_OPTIONS:
        return json.dumps({
            "error": True,
            "message": f"Invalid search option '{option}'.",
            "valid_options": VALID_SEARCH_OPTIONS,
        }, indent=2)

    data = {"option": option, "argument": argument}
    if lean:
        data["lean"] = True
    result = await _request("POST", "tasks/extendedsearch/", token=token, data=data)
    if lean:
        result = _apply_lean_report(result)
    return json.dumps(result, indent=2)

@mcp_tool("extendedtasksearch")
async def search_configs(argument: str, lean: bool = True, token: str = "") -> str:
    """Hunt across the corpus for tasks whose extracted config matches a value
    (e.g. a C2 URL, family name, campaign id, or mutex from a config)."""
    data = {"option": "configs", "argument": argument}
    if lean:
        data["lean"] = True
    result = await _request("POST", "tasks/extendedsearch/", token=token, data=data)
    if lean:
        result = _apply_lean_report(result)
    return json.dumps(result, indent=2)

@mcp_tool("extendedtasksearch")
async def get_search_info() -> str:
    """
    Retrieve the available advanced search terms, filters, and hash types.
    Use this information to construct valid queries for `extended_search`.
    """
    return json.dumps({
        "search_term_map": search_term_map,
        "perform_search_filters": perform_search_filters,
        "hash_searches": hash_searches,
        "normalized_lower_terms": normalized_lower_terms
    }, indent=2, default=str)

def _diff_lean_reports(a: dict, b: dict) -> dict:
    def _set(rep, *keys):
        node = rep
        for key in keys:
            node = node.get(key, {}) if isinstance(node, dict) else {}
        return set(node) if isinstance(node, (list, set)) else set()

    a_dom, b_dom = _set(a, "network", "domains"), _set(b, "network", "domains")
    a_mtx, b_mtx = _set(a, "indicators", "mutexes"), _set(b, "indicators", "mutexes")
    a_sig = {s.get("name") for s in a.get("high_severity_signatures", []) if isinstance(s, dict)}
    b_sig = {s.get("name") for s in b.get("high_severity_signatures", []) if isinstance(s, dict)}
    return {
        "family_match": a.get("family") == b.get("family"),
        "families": {"a": a.get("family"), "b": b.get("family")},
        "shared_domains": sorted(a_dom & b_dom),
        "shared_mutexes": sorted(a_mtx & b_mtx),
        "shared_signatures": sorted(x for x in (a_sig & b_sig) if x),
        "only_a_domains": sorted(a_dom - b_dom),
        "only_b_domains": sorted(b_dom - a_dom),
    }

@mcp_tool("taskreport")
async def compare_tasks(task_id_a: int, task_id_b: int, token: str = "") -> str:
    """Compare two analyses: returns each lean report plus a shared/unique diff
    of domains, mutexes, signatures, and family."""
    report_a = await _fetch_lean_report(task_id_a, token=token)
    report_b = await _fetch_lean_report(task_id_b, token=token)
    diff = {}
    if isinstance(report_a, dict) and isinstance(report_b, dict) and not report_a.get("error") and not report_b.get("error"):
        diff = _diff_lean_reports(report_a, report_b)
    return json.dumps({"a": report_a, "b": report_b, "diff": diff}, indent=2)

@mcp_tool("tasklist")
async def list_tasks(limit: int = 10, offset: int = 0, status: str = "", token: str = "") -> str:
    """List tasks with optional limit, offset and status filter."""
    params = {}
    if status:
        params["status"] = status

    endpoint = f"tasks/list/{limit}/{offset}/"
    result = await _request("GET", endpoint, token=token, params=params)
    return json.dumps(result, indent=2)

@mcp_tool("taskview")
async def view_task(task_id: int, token: str = "") -> str:
    """Get details of a specific task."""
    result = await _request("GET", f"tasks/view/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskresched")
async def reschedule_task(task_id: int, token: str = "") -> str:
    """Reschedule a task."""
    result = await _request("GET", f"tasks/reschedule/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskreprocess")
async def reprocess_task(task_id: int, token: str = "") -> str:
    """Reprocess a task."""
    result = await _request("GET", f"tasks/reprocess/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskdelete")
async def delete_task(task_id: int, token: str = "") -> str:
    """Delete a task and its stored analysis data."""
    result = await _request("GET", f"tasks/delete/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskstatus")
async def get_task_status(task_id: int, token: str = "") -> str:
    """Get the status of a task."""
    result = await _request("GET", f"tasks/status/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("tasks_latest")
async def get_latest_tasks(hours: int = 24, token: str = "") -> str:
    """Get IDs of tasks finished in the last X hours."""
    result = await _request("GET", f"tasks/get/latests/{hours}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("statistics")
async def get_statistics(days: int = 7, token: str = "") -> str:
    """Get task statistics for the last X days."""
    result = await _request("GET", f"tasks/statistics/{days}/", token=token)
    return json.dumps(result, indent=2)

# --- Reports & IOCs ---

@mcp_tool("taskreport")
async def get_task_report(task_id: int, format: str = "json", token: str = "") -> str:
    """Get the analysis report for a task (json, lite, maec, metadata, lean)."""
    allowed_formats = {"json", "lite", "maec", "metadata", "lean"}
    if format not in allowed_formats:
        return json.dumps({"error": True, "message": f"Invalid format provided. Allowed formats: {', '.join(allowed_formats)}"}, indent=2)

    if format == "lean":
        return json.dumps(await _fetch_lean_report(task_id, token=token), indent=2)

    result = await _request("GET", f"tasks/get/report/{task_id}/{format}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskiocs")
async def get_task_iocs(task_id: int, detailed: bool = False, token: str = "") -> str:
    """Get IOCs for a task."""
    endpoint = f"tasks/get/iocs/{task_id}/"
    if detailed:
        endpoint += "detailed/"
    result = await _request("GET", endpoint, token=token)
    return json.dumps(result, indent=2)

@mcp_tool("capeconfig")
async def get_task_config(task_id: int, token: str = "") -> str:
    """Get the extracted malware configuration for a task."""
    result = await _request("GET", f"tasks/get/config/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskgenai")
async def get_genai_summary(task_id: int, token: str = "") -> str:
    """Get the GenAI enrichment summary (verdict, confidence, summary, status)
    for a task. Requires GenAI enrichment to be configured (reporting.conf
    [genai_enrich])."""
    result = await _request("GET", f"tasks/get/genai/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskanalysislog")
async def get_task_analysis_log(task_id: int, tail_lines: int = 0, max_bytes: int = 0, token: str = "") -> str:
    """Get analysis.log text for a task."""
    params = {}
    if tail_lines > 0:
        params["tail_lines"] = tail_lines
    if max_bytes > 0:
        params["max_bytes"] = max_bytes
    result = await _request("GET", f"tasks/get/analysislog/{task_id}/", token=token, params=params)
    return json.dumps(result, indent=2)

# --- File Downloads ---
# NOTE: for save mode, `destination` is a directory on the MCP SERVER host.
# For remote (http/sse) transports where the agent can't read that host, pass
# inline=true to receive the content in the response (text as-is, binary base64,
# capped at 5MB).

@mcp_tool("taskscreenshot")
async def download_task_screenshot(task_id: int, destination: str = "", screenshot_id: str = "all", inline: bool = False, token: str = "") -> str:
    """Download task screenshots (zip or single image). `destination` is on the MCP server host; use inline=true to get bytes in the response."""
    return await _download_file(f"tasks/get/screenshot/{task_id}/{screenshot_id}/", destination, f"{task_id}_screenshots.zip", token=token, inline=inline)

@mcp_tool("taskpcap")
async def download_task_pcap(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download the PCAP file for a task. `destination` is on the MCP server host; use inline=true to get bytes in the response."""
    return await _download_file(f"tasks/get/pcap/{task_id}/", destination, f"{task_id}_dump.pcap", token=token, inline=inline)

@mcp_tool("tasktlspcap")
async def download_task_tlspcap(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download the TLS PCAP file for a task."""
    return await _download_file(f"tasks/get/tlspcap/{task_id}/", destination, f"{task_id}_tls.pcap", token=token, inline=inline)

@mcp_tool("taskevtx")
async def download_task_evtx(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download the EVTX logs for a task."""
    return await _download_file(f"tasks/get/evtx/{task_id}/", destination, f"{task_id}_evtx.zip", token=token, inline=inline)

@mcp_tool("taskdropped")
async def download_task_dropped(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download dropped files for a task."""
    return await _download_file(f"tasks/get/dropped/{task_id}/", destination, f"{task_id}_dropped.zip", token=token, inline=inline)

@mcp_tool("taskselfextracted")
async def download_self_extracted_files(task_id: int, destination: str = "", tool: str = "all", inline: bool = False, token: str = "") -> str:
    """Download self-extracted files for a task."""
    return await _download_file(f"tasks/get/selfextracted/{task_id}/{tool}/", destination, f"{task_id}_selfextracted_{tool}.zip", token=token, inline=inline)

@mcp_tool("tasksurifile")
async def download_task_surifile(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download Suricata files for a task."""
    return await _download_file(f"tasks/get/surifile/{task_id}/", destination, f"{task_id}_surifiles.zip", token=token, inline=inline)

@mcp_tool("taskmitmdump")
async def download_task_mitmdump(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download mitmdump HAR file for a task."""
    return await _download_file(f"tasks/get/mitmdump/{task_id}/", destination, f"{task_id}_dump.har", token=token, inline=inline)

@mcp_tool("payloadfiles")
async def download_task_payloadfiles(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download CAPE payload files."""
    return await _download_file(f"tasks/get/payloadfiles/{task_id}/", destination, f"{task_id}_payloads.zip", token=token, inline=inline)

@mcp_tool("procdumpfiles")
async def download_task_procdumpfiles(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download CAPE procdump files."""
    return await _download_file(f"tasks/get/procdumpfiles/{task_id}/", destination, f"{task_id}_procdumps.zip", token=token, inline=inline)

@mcp_tool("taskprocmemory")
async def download_task_procmemory(task_id: int, destination: str = "", pid: str = "all", inline: bool = False, token: str = "") -> str:
    """Download process memory dumps."""
    return await _download_file(f"tasks/get/procmemory/{task_id}/{pid}/", destination, f"{task_id}_procmemory.zip", token=token, inline=inline)

@mcp_tool("taskfullmemory")
async def download_task_fullmemory(task_id: int, destination: str = "", inline: bool = False, token: str = "") -> str:
    """Download full VM memory dump."""
    return await _download_file(f"tasks/get/fullmemory/{task_id}/", destination, f"{task_id}_fullmemory.dmp", token=token, inline=inline)

# --- Files & Machines ---

@mcp_tool("fileview")
async def view_file(hash_value: str, hash_type: str = "sha256", token: str = "") -> str:
    """View information about a file in the database."""
    if not re.match(r"^[a-fA-F0-9]+$", hash_value):
        return json.dumps({"error": True, "message": "Invalid hash value provided. Only hexadecimal characters are allowed."}, indent=2)
    return await _request("GET", f"files/view/{hash_type}/{hash_value}/", token=token)

@mcp_tool("sampledl")
async def download_sample(hash_value: str, destination: str = "", hash_type: str = "sha256", inline: bool = False, token: str = "") -> str:
    """Download a sample from the database."""
    if not re.match(r"^[a-fA-F0-9]+$", hash_value):
        return json.dumps({"error": True, "message": "Invalid hash value provided. Only hexadecimal characters are allowed."}, indent=2)
    return await _download_file(f"files/get/{hash_type}/{hash_value}/", destination, f"{hash_value}.bin", token=token, inline=inline)

@mcp_tool("machinelist")
async def list_machines(token: str = "") -> str:
    """List available analysis machines."""
    result = await _request("GET", "machines/list/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("machineview")
async def view_machine(name: str, token: str = "") -> str:
    """View details of a specific machine."""
    result = await _request("GET", f"machines/view/{name}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("list_exitnodes")
async def list_exitnodes(token: str = "") -> str:
    """List available exit nodes."""
    result = await _request("GET", "exitnodes/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("capestatus")
async def get_cape_status(token: str = "") -> str:
    """Get the status of the CAPE host."""
    result = await _request("GET", "cape/status/", token=token)
    return json.dumps(result, indent=2)

@mcp.tool()
async def verify_auth(token: str = "") -> str:
    """
    Verify if the provided API token is valid.
    Useful for checking authentication status before performing other operations.
    """
    # We use a lightweight endpoint like cape status to check auth
    result = await _request("GET", "cape/status/", token=token)

    if isinstance(result, dict) and result.get("error"):
        return json.dumps({"authenticated": False, "message": "Invalid token or authentication failed.", "details": result}, indent=2)

    return json.dumps({"authenticated": True, "message": "Token is valid."}, indent=2)

# --- Resources (read-only views for MCP clients that support them) ---

@mcp_resource("taskreport", "cape://task/{task_id}/report")
async def resource_task_report(task_id: int) -> str:
    """Lean analysis report for a task."""
    return json.dumps(await _fetch_lean_report(task_id), indent=2)

@mcp_resource("taskiocs", "cape://task/{task_id}/iocs")
async def resource_task_iocs(task_id: int) -> str:
    """IOCs for a task."""
    result = await _request("GET", f"tasks/get/iocs/{task_id}/")
    return json.dumps(result, indent=2)

@mcp_resource("capeconfig", "cape://task/{task_id}/config")
async def resource_task_config(task_id: int) -> str:
    """Extracted malware configuration for a task."""
    result = await _request("GET", f"tasks/get/config/{task_id}/")
    return json.dumps(result, indent=2)

# --- Prompt ---

@mcp.prompt()
def triage_sample(file_path: str = "", task_id: str = "") -> str:
    """Guided workflow to triage a sample end-to-end and produce a verdict."""
    target = f"the file at {file_path}" if file_path else f"task {task_id}" if task_id else "the sample"
    return (
        f"Triage {target} using the CAPE sandbox tools. Steps:\n"
        "1. If given a file path, call submit_file_and_wait to submit and wait for the report. "
        "If given a task id, call get_task_report(format='lean').\n"
        "2. Review the lean report: score, family, extracted_configs, high_severity_signatures, network, indicators.\n"
        "3. Call get_task_iocs for the full indicator set, and get_genai_summary if GenAI enrichment is enabled.\n"
        "4. If a family or C2 is identified, call search_configs to find related samples in the corpus.\n"
        "5. Produce a verdict (malicious/suspicious/benign), the malware family if known, key IOCs "
        "(C2 domains/IPs, mutexes, dropped files), and recommended analyst next steps."
    )

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CAPE MCP Server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http", "http"], default=os.environ.get("CAPE_MCP_TRANSPORT", "stdio"), help="Transport protocol (default: stdio)")
    parser.add_argument("--host", default=os.environ.get("CAPE_MCP_HOST", "127.0.0.1"), help="Host to bind for HTTP/SSE (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("CAPE_MCP_PORT", "9004")), help="Port to bind for HTTP/SSE (default:  9004)")
    args = parser.parse_args()

    if args.transport in ["sse", "streamable-http", "http"]:
        print(f"Starting {args.transport} server on {args.host}:{args.port}", file=sys.stderr)
        mcp.run(transport=args.transport, host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
