import hashlib
import json
import re
from collections import Counter

try:
    import orjson

    HAVE_ORJSON = True
except ImportError:
    HAVE_ORJSON = False


# Per-section entry caps. Sized for verdict evidence, not completeness — the
# model doesn't need 500 domains to judge a sample, and every entry is tokens.
CAPS = {
    "signatures": 100,
    "dropped": 100,
    "domains": 200,
    "hosts": 200,
    "network_http": 200,
    "network_tls": 100,
    "processtree": 150,
    "behavior_processes": 150,
    "summary_run_keys": 50,
    "summary_service_events": 50,
    "summary_scheduled_tasks": 50,
    "ioc_mutexes": 100,
    "ioc_registry": 200,
    "ioc_files": 200,
    "ioc_emails": 50,
    "interesting_strings": 100,
}

SUSPICIOUS_KEYWORDS = (
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "wmic",
    "schtasks",
    "base64",
    "http",
    "hxxp",
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63}\b", re.I)
_RUNKEY_RE = re.compile(r"\\(run|runonce|runservices|runservicesonce)\\", re.I)
_SCHEDULED_TASK_RE = re.compile(r"\\tasks\\|schtasks", re.I)

_SECRET_PATTERNS = [
    (re.compile(r"(?i)\bbearer\s+[a-z0-9\-\._~\+\/]+=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key|token|password|passwd|secret)\s*[=:]\s*['\"]?[^'\"\s,;]+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(https?://)([^/\s:@]+):([^/\s@]+)@"), r"\1[REDACTED]@"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def _json_dumps(data):
    if HAVE_ORJSON:
        return orjson.dumps(data)
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def json_size_bytes(data):
    try:
        return len(_json_dumps(data))
    except Exception:
        return 0


def _as_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _cap_list(items, cap_key, stats):
    values = _as_list(items)
    limit = CAPS[cap_key]
    total = len(values)
    if total > limit:
        stats["capped"][cap_key] = {"before": total, "after": limit}
        return values[:limit]
    return values


def _collect_unique_strings(values):
    unique = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _extract_target(results):
    target = results.get("target", {}) or {}
    target_file = target.get("file", {}) or {}
    return {
        "category": results.get("info", {}).get("category"),
        "name": target_file.get("name") or target.get("name"),
        "path": target_file.get("path") or target.get("path"),
        "type": target_file.get("type"),
        "size": target_file.get("size"),
        "hashes": {
            "md5": target_file.get("md5"),
            "sha1": target_file.get("sha1"),
            "sha256": target_file.get("sha256"),
            "sha512": target_file.get("sha512"),
        },
        "submitted_url": target.get("url") or "",
    }


def _extract_signatures(results, stats):
    signatures = []
    for signature in _cap_list(results.get("signatures", []), "signatures", stats):
        signatures.append(
            {
                "name": signature.get("name"),
                "severity": signature.get("severity"),
                "confidence": signature.get("confidence"),
                "description": (signature.get("description") or "")[:300],
            }
        )
    return signatures


def _extract_dropped(results, stats):
    dropped_summary = []
    for item in _cap_list(results.get("dropped", []), "dropped", stats):
        dropped_summary.append(
            {
                "name": item.get("name"),
                "path": item.get("path"),
                "sha256": item.get("sha256"),
                "type": item.get("type"),
                "size": item.get("size"),
            }
        )
    return dropped_summary


def _extract_ports_and_protocols(network):
    tcp_ports = set()
    udp_ports = set()
    protocols = set()

    for conn in network.get("tcp", []) or []:
        if conn.get("dport") is not None:
            tcp_ports.add(conn.get("dport"))
        protocols.add("tcp")

    for conn in network.get("udp", []) or []:
        if conn.get("dport") is not None:
            udp_ports.add(conn.get("dport"))
        protocols.add("udp")

    return {
        "ports": {
            "tcp": sorted(list(tcp_ports))[:200],
            "udp": sorted(list(udp_ports))[:200],
        },
        "protocols": sorted(list(protocols)),
    }


def _extract_network(results, stats):
    network = results.get("network", {}) or {}

    summary = {
        "domains": _cap_list([d.get("domain") for d in network.get("domains", []) if d.get("domain")], "domains", stats),
        "hosts": _cap_list([h.get("ip") for h in network.get("hosts", []) if h.get("ip")], "hosts", stats),
        "http": [],
        "tls": [],
    }
    summary.update(_extract_ports_and_protocols(network))

    for item in _cap_list(network.get("http", []), "network_http", stats):
        summary["http"].append(
            {
                "host": item.get("host"),
                "uri": item.get("uri") or item.get("path"),
                "method": item.get("method"),
                "status": item.get("status"),
            }
        )

    for item in _cap_list(network.get("tls", []), "network_tls", stats):
        summary["tls"].append(
            {
                "sni": item.get("server_name") or item.get("sni"),
                "dst": item.get("dst"),
                "dport": item.get("dport"),
            }
        )

    return summary


def _extract_process_tree(behavior, stats):
    process_tree = []
    source = behavior.get("processtree", []) or []
    if source:
        for node in _cap_list(source, "processtree", stats):
            process_tree.append(
                {
                    "pid": node.get("pid"),
                    "ppid": node.get("parent_id"),
                    "name": node.get("name"),
                    "commandline": ((node.get("environ", {}) or {}).get("CommandLine") if isinstance(node.get("environ"), dict) else None),
                }
            )
        return process_tree

    for proc in _cap_list(behavior.get("processes", []), "behavior_processes", stats):
        process_tree.append(
            {
                "pid": proc.get("process_id"),
                "ppid": proc.get("parent_id"),
                "name": proc.get("process_name"),
                "commandline": ((proc.get("environ", {}) or {}).get("CommandLine") if isinstance(proc.get("environ"), dict) else None),
            }
        )
    return process_tree


def _extract_api_category_counts(behavior):
    api_total = 0
    cat_counter = Counter()
    for proc in behavior.get("processes", []) or []:
        calls = proc.get("calls", []) or []
        api_total += len(calls)
        for call in calls:
            category = call.get("category")
            if category:
                cat_counter[category] += 1
    return api_total, dict(cat_counter.most_common(25))


def _extract_key_events(behavior, stats):
    # Mutations only — read_keys/keys are mostly benign OS noise, and file
    # writes are already carried by iocs.files.
    summary = behavior.get("summary", {}) or {}
    registry_values = []
    for field in ("write_keys", "delete_keys"):
        registry_values.extend(_as_list(summary.get(field)))
    unique_registry = _collect_unique_strings(registry_values)

    scheduled = [value for value in unique_registry if _SCHEDULED_TASK_RE.search(value or "")]
    for command in _as_list(summary.get("executed_commands")):
        if _SCHEDULED_TASK_RE.search(str(command)):
            scheduled.append(command)

    return {
        "registry_run_keys": _cap_list([value for value in unique_registry if _RUNKEY_RE.search(value or "")], "summary_run_keys", stats),
        "service_events": _cap_list(
            _as_list(summary.get("created_services")) + _as_list(summary.get("started_services")),
            "summary_service_events",
            stats,
        ),
        "scheduled_tasks": _cap_list(scheduled, "summary_scheduled_tasks", stats),
    }


def _extract_behavior(results, stats):
    behavior = results.get("behavior", {}) or {}
    api_total, api_categories = _extract_api_category_counts(behavior)
    stats["dropped"]["behavior_processes_calls"] = api_total

    return {
        "process_tree": _extract_process_tree(behavior, stats),
        "api_categories": api_categories,
        "api_calls_total": api_total,
        "key_events": _extract_key_events(behavior, stats),
    }


def _extract_email_candidates(results, summary):
    candidates = []
    for source in (results.get("static", {}) or {}, results.get("target", {}) or {}, summary):
        if not isinstance(source, dict):
            continue
        for value in source.values():
            if isinstance(value, str):
                candidates.extend(_EMAIL_RE.findall(value))
    return sorted(list(set(candidates)))


def _extract_iocs(results, stats):
    behavior = results.get("behavior", {}) or {}
    summary = behavior.get("summary", {}) or {}
    network = results.get("network", {}) or {}

    # urls/domains/ips are not repeated here — the network section already
    # carries them. Registry/file lists are mutations only (reads are noise).
    iocs = {
        "mutexes": _cap_list(summary.get("mutexes", []), "ioc_mutexes", stats),
        "registry": _cap_list(
            _collect_unique_strings(_as_list(summary.get("write_keys")) + _as_list(summary.get("delete_keys"))),
            "ioc_registry",
            stats,
        ),
        "files": _cap_list(
            _collect_unique_strings(_as_list(summary.get("write_files")) + _as_list(summary.get("delete_files"))),
            "ioc_files",
            stats,
        ),
        "emails": _cap_list(_extract_email_candidates(results, summary), "ioc_emails", stats),
    }
    return iocs


def _extract_interesting_strings(results, stats):
    interesting = []
    for item in _as_list(results.get("strings")):
        if not isinstance(item, str):
            continue
        lower = item.lower()
        if _URL_RE.search(item) or _DOMAIN_RE.search(item) or any(keyword in lower for keyword in SUSPICIOUS_KEYWORDS):
            interesting.append(item[:300])

    return _cap_list(_collect_unique_strings(interesting), "interesting_strings", stats)


def _redact_string(value):
    redacted = value
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_secrets(data):
    if isinstance(data, dict):
        output = {}
        for key, value in data.items():
            output[key] = redact_secrets(value)
        return output
    if isinstance(data, list):
        return [redact_secrets(item) for item in data]
    if isinstance(data, str):
        return _redact_string(data)
    return data


def _prune_empty(value):
    """Drop None, empty strings, and empty containers recursively (0/False kept)."""
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            pruned = _prune_empty(item)
            if pruned or pruned == 0 or pruned is False:
                output[key] = pruned
        return output
    if isinstance(value, list):
        return [pruned for pruned in (_prune_empty(item) for item in value) if pruned or pruned == 0 or pruned is False]
    return value


def massage_report(results, opts=None):
    opts = opts or {}
    stats = {"dropped": {}, "capped": {}, "sizes": {}}

    curated = {
        "target": _extract_target(results),
        "signatures": _extract_signatures(results, stats),
        "dropped": _extract_dropped(results, stats),
        "network": _extract_network(results, stats),
        "behavior": _extract_behavior(results, stats),
        "iocs": _extract_iocs(results, stats),
        "strings": _extract_interesting_strings(results, stats),
    }
    curated = _prune_empty(curated)

    if opts.get("redact_enabled", True):
        curated = redact_secrets(curated)

    stats["sizes"]["curated_bytes"] = json_size_bytes(curated)
    stats["sizes"]["sha256"] = hashlib.sha256(_json_dumps(curated)).hexdigest()
    return curated, stats
