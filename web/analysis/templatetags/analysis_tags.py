import os
import json
from io import StringIO

try:
    import re2 as re
except ImportError:
    import re

from collections import OrderedDict
from uuid import NAMESPACE_DNS, uuid3

from django.template.defaultfilters import register
from django.utils.html import escape
from django.utils.safestring import mark_safe
from uuid import uuid3, NAMESPACE_DNS


@register.filter("is_string")
def is_string(value):
    return isinstance(value, str)


@register.filter("comma_join")
def comma_join(value):
    return ",".join(str(task) for task in value)


@register.filter("network_rn")
def network_rn_func(value):
    """get basename from path"""
    if isinstance(value, bytes):
        value = value.decode()
    return list(filter(None, value.split("\r\n")))


@register.filter("filename")
def filename(value):
    """get basename from path"""
    return os.path.basename(value)


@register.filter("mongo_id")
def mongo_id(value):
    """Retrieve _id value.
    @todo: it will be removed in future.
    """
    if isinstance(value, dict):
        if "_id" in value:
            return str(value.get("_id", ""))
        return ""

    # Return value
    return str(value)


@register.filter("is_dict")
def is_dict(value):
    """Checks if value is an instance of dict"""
    return isinstance(value, dict)


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key, "")


malware_name_url_pattern = """<a href="/analysis/search/detections:{malware_name}/"><span style="font-weight: bold;">{malware_name}</span></a>"""


@register.filter("get_detection_by_pid")
def get_detection_by_pid(dictionary, key):
    if not dictionary:
        return
    detections = dictionary.get(str(key), "")
    if detections:
        if len(detections) > 1:
            output = " -> ".join([malware_name_url_pattern.format(malware_name=name) for name in detections])
        else:
            output = malware_name_url_pattern.format(malware_name=detections[0])

        return mark_safe(output)


@register.filter(name="dehex")
def dehex(value):
    return re.sub(r"\\x[0-9a-f]{2}", "", value)


@register.filter(name="sort")
def sort(value):
    if isinstance(value, dict):
        sorteddict = OrderedDict()
        sortedkeys = sorted(value.keys())
        for key in sortedkeys:
            sorteddict[key] = value[key]
        return sorteddict
    return value


@register.filter(name="format_cli")
def format_cli(cli, length):
    if cli.startswith('"'):
        ret = " ".join(cli[cli[1:].index('"') + 2 :].split()).strip()
    else:
        ret = " ".join(cli.split()[1:]).strip()
    if len(ret) >= length + 15:
        ret = ret[:length] + " ...(truncated)"
    # Return blank string instead of 'None'
    if not ret:
        return ""
    return ret


@register.filter(name="flare_capa_capability")
def flare_capa_capabilities(obj, *args, **kwargs):
    result = StringIO()

    def _print(lvl, s):
        result.write((lvl * "  ") + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, "<thead>\n")
    _print(1, "<tr>\n")
    _print(1, '<th scope="col">Namespace</th>\n')
    _print(1, '<th scope="col">Capability</th>\n')
    _print(2, "</tr>\n")
    _print(3, "</thead>\n")
    _print(3, "<tbody>\n")
    for namespaces, capabilities in obj.get("CAPABILITY", {}).items():
        _print(4, "<tr>\n")
        _print(4, '<th width="25%" scope="row">' + namespaces + "</th>\n")
        _print(4, "<td>\n")
        for capability in capabilities:
            _print(5, "<li>" + capability + "</li>\n")
        _print(4, "</td>\n")
        _print(3, "</tr>\n")
    _print(2, "</tbody>\n")
    _print(1, "</table>\n")

    ret_result = result.getvalue()
    result.close()
    return mark_safe(ret_result)


@register.filter(name="flare_capa_attck")
def flare_capa_attck(obj, *args, **kwargs):
    result = StringIO()

    def _print(lvl, s):
        result.write((lvl * "  ") + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, "<thead>\n")
    _print(1, "<tr>\n")
    _print(1, '<th scope="col">ATT&CK Tactic</th>\n')
    _print(1, '<th scope="col">ATT&CK Technique</th>\n')
    _print(2, "</tr>\n")
    _print(3, "</thead>\n")
    _print(3, "<tbody>\n")
    for tactic, techniques in obj.get("ATTCK", {}).items():
        _print(4, "<tr>\n")
        _print(4, '<th width="25%" scope="row">' + tactic + "</th>\n")
        _print(4, "<td>\n")
        for technique in techniques:
            _print(5, "<li>" + technique + "</li>\n")

        _print(4, "</td>\n")
        _print(3, "</tr>\n")
    _print(2, "</tbody>\n")
    _print(1, "</table>\n")

    ret_result = result.getvalue()
    result.close()
    return mark_safe(ret_result)


@register.filter(name="flare_capa_mbc")
def flare_capa_mbc(obj, *args, **kwargs):
    result = StringIO()

    def _print(lvl, s):
        result.write((lvl * "  ") + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, "<thead>\n")
    _print(1, "<tr>\n")
    _print(1, '<th scope="col">MBC Objective</th>\n')
    _print(1, '<th scope="col">MBC Behavior</th>\n')
    _print(2, "</tr>\n")
    _print(3, "</thead>\n")
    _print(3, "<tbody>\n")
    for objective, behaviors in obj.get("MBC", {}).items():
        _print(4, "<tr>\n")
        _print(4, '<th width="25%" scope="row">' + objective + "</th>\n")
        _print(4, "<td>\n")
        for behavior in behaviors:
            _print(5, "<li>" + behavior + "</li>\n")

        _print(4, "</td>\n")
        _print(3, "</tr>\n")
    _print(2, "</tbody>\n")
    _print(1, "</table>\n")

    ret_result = result.getvalue()
    result.close()
    return mark_safe(ret_result)


# Thanks Sandor
@register.simple_tag
def malware_config(obj, *args, **kwargs):
    """Custom Django tag for improved malware config rendering.
    This tag will render Python dicts as tables, and Python lists as
    unordered lists. Empty dicts and lists are rendered as empty fields.
    Single element lists are expanded and rendered as regular values.
    """
    level = kwargs.get("level") or 0
    result = StringIO()

    def _print(lvl, s):
        result.write((lvl * "  ") + str(s))

    def _max_scalar_length(items):
        max_len = 0
        for item in items:
            if isinstance(item, (dict, list)):
                return None
            item_str = str(item)
            if "\n" in item_str:
                return None
            max_len = max(max_len, len(item_str))
        return max_len

    def _looks_like_url(value):
        if not isinstance(value, str):
            return False
        return value.startswith(("http://", "https://"))

    def _is_url_list(items):
        return bool(items) and all(_looks_like_url(item) for item in items)

    if isinstance(obj, dict):
        if obj:
            _print(0, "\n")
            _print(level + 0, "<table>\n")
            for key, val in obj.items():
                _print(level + 1, "<tr>\n")
                _print(level + 2, "<td>" + malware_config(key, level=level + 3) + "</td>\n")
                _print(level + 2, "<td>" + malware_config(val, level=level + 3) + "</td>\n")
                _print(level + 1, "</tr>\n")
            _print(level + 0, "</table>\n")
            _print(level - 1, "")
    elif isinstance(obj, list):
        if obj:
            if len(obj) > 1:
                _print(0, "\n")
                max_len = _max_scalar_length(obj)
                if _is_url_list(obj):
                    _print(
                        level + 0,
                        '<ul class="malware-config-list" data-force-single-col="1" style="margin: 0; --mc-cols: 1;">\n',
                    )
                elif max_len is None:
                    _print(level + 0, '<ul class="malware-config-list" style="margin: 0; --mc-cols: 1;">\n')
                else:
                    _print(
                        level + 0,
                        f'<ul class="malware-config-list" data-max-len="{max_len}" style="margin: 0; --mc-cols: 1;">\n',
                    )
                for item in obj:
                    _print(level + 1, "<li>" + malware_config(item, level=level + 2) + "</li>\n")
                _print(level + 0, "</ul>\n")
                _print(level - 1, "")
            else:
                result.write(malware_config(obj[0]))
    else:
        value = str(obj)
        escaped = escape(value)
        if isinstance(obj, str) and value.startswith(("http://", "https://")):
            result.write(f'<span class="malware-config-url">{escaped}</span>')
        else:
            result.write(escaped)

    ret_result = result.getvalue()
    result.close()
    return mark_safe(ret_result)


@register.filter(name="playback_url")
def playback_url(task_id):
    session_id = uuid3(NAMESPACE_DNS, str(task_id)).hex[:16]
    return f"{task_id}_{session_id}"


@register.filter(name="pretty_json")
def pretty_json(value):
    try:
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _parse_json_text(value):
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    if stripped[0] not in ("{", "["):
        return value
    try:
        return json.loads(stripped)
    except Exception:
        return value


def _format_headers(headers):
    if not headers:
        return ""
    if isinstance(headers, dict):
        return json.dumps(headers, indent=2, sort_keys=True, ensure_ascii=False)
    return str(headers)


def _format_body(body):
    if body is None:
        return ""
    if isinstance(body, dict):
        normalized = dict(body)
        if "text" in normalized:
            normalized["text"] = _parse_json_text(normalized["text"])
        return json.dumps(normalized, indent=2, sort_keys=True, ensure_ascii=False)
    parsed = _parse_json_text(body)
    if isinstance(parsed, (dict, list)):
        return json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=False)
    return str(parsed)


@register.filter(name="format_js_event")
def format_js_event(event):
    if not isinstance(event, dict):
        return str(event)

    ts = event.get("ts", "")
    source = event.get("source", "")
    event_type = event.get("event", "unknown")
    request_id = event.get("request_id")
    request_tag = f" req#{request_id}" if request_id is not None else ""
    source_tag = f" ({source})" if source else ""
    lines = [f"[{ts}] {event_type}{request_tag}{source_tag}"]

    if event_type == "http_request":
        lines.append(f"Method: {event.get('method', '')}")
        lines.append(f"URL: {event.get('url', '')}")
        headers = _format_headers(event.get("headers"))
        if headers:
            lines.append("Headers:")
            lines.append(headers)
        body = _format_body(event.get("body"))
        if body:
            lines.append("Body:")
            lines.append(body)
        return "\n".join(lines)

    if event_type == "http_response":
        lines.append(f"Status: {event.get('status', '')} {event.get('status_text', '')}".strip())
        lines.append(f"Elapsed: {event.get('elapsed_ms', '')} ms")
        headers = _format_headers(event.get("headers"))
        if headers:
            lines.append("Headers:")
            lines.append(headers)
        body = _format_body(event.get("body"))
        if body:
            lines.append("Body:")
            lines.append(body)
        return "\n".join(lines)

    if event_type == "http_error":
        lines.append(f"Elapsed: {event.get('elapsed_ms', '')} ms")
        lines.append(f"Error: {event.get('error', '')}")
        return "\n".join(lines)

    if event_type == "dns_query":
        lines.append(f"Type: {event.get('query_type', '')}")
        lines.append(f"Host: {event.get('host', '')}")
        return "\n".join(lines)

    if event_type == "dns_result":
        lines.append(f"Type: {event.get('query_type', '')}")
        lines.append(f"Host: {event.get('host', '')}")
        lines.append(f"Elapsed: {event.get('elapsed_ms', '')} ms")
        result = _format_body(event.get("result"))
        if result:
            lines.append("Result:")
            lines.append(result)
        return "\n".join(lines)

    if event_type == "dns_error":
        lines.append(f"Type: {event.get('query_type', '')}")
        lines.append(f"Host: {event.get('host', '')}")
        lines.append(f"Elapsed: {event.get('elapsed_ms', '')} ms")
        lines.append(f"Error: {event.get('error', '')}")
        return "\n".join(lines)

    if event_type == "tcp_connect":
        lines.append(f"Transport: {event.get('transport', '')}")
        lines.append(f"Protocol: {event.get('protocol', '')}")
        lines.append(f"Host: {event.get('host', '')}")
        lines.append(f"Port: {event.get('port', '')}")
        return "\n".join(lines)

    if event_type in ("tcp_send", "tcp_receive"):
        lines.append(f"Transport: {event.get('transport', '')}")
        body = _format_body(event.get("body"))
        if body:
            lines.append("Data:")
            lines.append(body)
        return "\n".join(lines)

    if event_type == "tcp_error":
        lines.append(f"Transport: {event.get('transport', '')}")
        lines.append(f"Error: {event.get('error', '')}")
        return "\n".join(lines)

    if event_type == "http_request_body":
        body = _format_body(event.get("body"))
        if body:
            lines.append("Body:")
            lines.append(body)
        return "\n".join(lines)

    if event_type == "console":
        lines.append(f"Level: {event.get('level', '')}")
        message = event.get("message", "")
        parsed_message = _parse_json_text(message)
        if isinstance(parsed_message, (dict, list)):
            lines.append("Message:")
            lines.append(json.dumps(parsed_message, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            lines.append(f"Message: {message}")
        return "\n".join(lines)

    if event_type == "warning":
        lines.append(f"Message: {event.get('message', '')}")
        return "\n".join(lines)

    if event_type == "eval":
        body = _format_body(event.get("body"))
        if body:
            lines.append("Code:")
            lines.append(body)
        return "\n".join(lines)

    if event_type in ("socket_emit", "socket_on_event"):
        lines.append(f"Socket Event: {event.get('socket_event', '')}")
        body = _format_body(event.get("args"))
        if body:
            lines.append("Args:")
            lines.append(body)
        return "\n".join(lines)

    if event_type == "init":
        lines.append(f"Log Path: {event.get('log_path', '')}")
        lines.append(f"PID: {event.get('pid', '')}  PPID: {event.get('ppid', '')}")
        lines.append(f"CWD: {event.get('cwd', '')}")
        lines.append(f"Exec: {event.get('exec_path', '')}")
        lines.append(f"Bun: {event.get('bun_version', '')}")
        lines.append(f"Fetch Available: {event.get('has_fetch', '')} ({event.get('fetch_type', '')})")
        argv = event.get("argv")
        if argv:
            lines.append("ARGV:")
            lines.append(json.dumps(argv, indent=2, ensure_ascii=False))
        return "\n".join(lines)

    lines.append(json.dumps(event, indent=2, sort_keys=True, ensure_ascii=False))
    return "\n".join(lines)

@register.filter
def split_csv(value):
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [t.strip() for t in str(value).split(",") if t.strip()]

@register.filter
def cert_chain_signers(signers):
    return [s for s in (signers or []) if "Certificate Chain" in s.get("name", "")]


@register.filter
def ts_chain_signers(signers):
    return [s for s in (signers or []) if "Timestamp Chain" in s.get("name", "")]