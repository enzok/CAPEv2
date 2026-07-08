import json
import logging
import os
import re
from hashlib import sha256

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_exists, path_mkdir, path_read_file, path_write_file

log = logging.getLogger(__name__)


def parse_js_log_file(log_path, max_entries=10000):
    events = []
    total_lines = 0
    parsed_lines = 0
    malformed_lines = 0
    truncated = False

    try:
        is_jsonl = True
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    is_jsonl = line_str.startswith("{")
                    break

        if is_jsonl:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    total_lines += 1
                    text = line.strip()
                    if not text:
                        continue

                    if parsed_lines >= max_entries:
                        truncated = True
                        break

                    try:
                        event = json.loads(text)
                        events.append(event)
                        parsed_lines += 1
                    except json.JSONDecodeError:
                        malformed_lines += 1
        else:
            header_re = re.compile(r"^\[([^\]]+)\]\s+(\w+)(?:\s+(req#\d+))?\s+\(([^)]+)\)")
            current_event = None
            current_key = None
            current_val_lines = []

            def finalize_key_val():
                nonlocal current_key, current_val_lines
                if current_event is None or current_key is None:
                    return

                val_str = "\n".join(current_val_lines).strip()
                if val_str.startswith("{") or val_str.startswith("["):
                    try:
                        current_event[current_key] = json.loads(val_str)
                    except Exception:
                        current_event[current_key] = val_str
                else:
                    current_event[current_key] = val_str

                current_key = None
                current_val_lines = []

            def finalize_event():
                nonlocal current_event, current_key, current_val_lines, parsed_lines
                if current_event:
                    finalize_key_val()
                    if current_val_lines:
                        val_str = "\n".join(current_val_lines).strip()
                        if val_str.startswith("{"):
                            try:
                                loaded = json.loads(val_str)
                                if isinstance(loaded, dict):
                                    current_event.update(loaded)
                            except Exception:
                                pass
                        current_val_lines = []
                    events.append(current_event)
                    parsed_lines += 1
                    current_event = None

            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    total_lines += 1
                    line_str = line.strip()
                    if not line_str:
                        continue

                    if parsed_lines >= max_entries and header_re.match(line_str):
                        truncated = True
                        break

                    m = header_re.match(line_str)
                    if m:
                        finalize_event()
                        ts, event_name, req_id, source = m.groups()
                        current_event = {
                            "ts": ts,
                            "event": event_name,
                            "source": source,
                        }
                        if req_id:
                            current_event["request_id"] = req_id
                        continue

                    if current_event is None:
                        continue

                    is_json_accumulating = current_key and len(current_val_lines) > 0 and (current_val_lines[0].startswith("{") or current_val_lines[0].startswith("["))
                    kv_match = None
                    if not is_json_accumulating:
                        kv_match = re.match(r"^([A-Za-z ]+):\s*(.*)$", line_str)

                    if kv_match:
                        finalize_key_val()
                        key_name, val_val = kv_match.groups()
                        norm_key = key_name.lower().replace(" ", "_")
                        if norm_key == "exec":
                            norm_key = "exec_path"

                        if norm_key == "pid" and "PPID" in val_val:
                            pid_match = re.search(r"(\d+)\s+PPID:\s+(\d+)", val_val)
                            if pid_match:
                                current_event["pid"] = int(pid_match.group(1))
                                current_event["ppid"] = int(pid_match.group(2))
                            current_key = None
                        else:
                            current_key = norm_key
                            if val_val:
                                current_val_lines.append(val_val)
                    else:
                        current_val_lines.append(line_str)

                finalize_event()

    except Exception as e:
        log.warning("Failed to parse JS log file %s: %s", log_path, e)

    return events, total_lines, parsed_lines, malformed_lines, truncated


class JSLogProcessing(Processing):
    """Parse JSONL logs generated by the Bun interceptor."""

    order = 0

    @staticmethod
    def _bytes_from_buffer_dict(value):
        if not isinstance(value, dict):
            return None

        if value.get("type") != "Buffer":
            return None

        data = value.get("data")
        if not isinstance(data, list) or not data:
            return None

        try:
            if not all(isinstance(item, int) and 0 <= item <= 255 for item in data):
                return None
            return bytes(data)
        except Exception:
            return None

    def _extract_drop_candidates(self, node):
        candidates = []
        if isinstance(node, dict):
            if node.get("truncated") is False:
                for value in node.values():
                    payload = self._bytes_from_buffer_dict(value)
                    if payload:
                        candidates.append(payload)

            for value in node.values():
                candidates.extend(self._extract_drop_candidates(value))
        elif isinstance(node, list):
            for value in node:
                candidates.extend(self._extract_drop_candidates(value))
        return candidates

    def run(self):
        self.key = "js_log"

        log_name = self.options.get("log_name", "js_console.log")
        max_entries = int(self.options.get("max_entries", 10000))
        log_path = os.path.join(self.aux_path, "js_console", log_name)
        if not path_exists(log_path):
            log_path = os.path.join(self.aux_path, log_name)
        dropped_created = 0
        dropped_errors = 0
        dropped_paths = []
        seen_hashes = set()

        output = {
            "path": log_path,
            "exists": False,
            "log": "",
            "total_lines": 0,
            "parsed_lines": 0,
            "malformed_lines": 0,
            "truncated": False,
            "events": [],
            "http_requests": [],
            "http_responses": [],
            "http_errors": [],
            "console": [],
            "warnings": [],
            "init": [],
            "dropped_from_js_log": [],
            "dropped_created": 0,
            "dropped_errors": 0,
        }

        if not path_exists(log_path):
            return output

        output["exists"] = True

        try:
            raw_log = path_read_file(log_path, mode="text")
            max_log_chars = 64 * 1024
            if len(raw_log) > max_log_chars:
                output["log"] = raw_log[:max_log_chars] + "\r\n... [TRUNCATED - LOG TOO LARGE] ..."
            else:
                output["log"] = raw_log
            events, total_lines, parsed_lines, malformed_lines, truncated = parse_js_log_file(log_path, max_entries)
            output["total_lines"] = total_lines
            output["parsed_lines"] = parsed_lines
            output["malformed_lines"] = malformed_lines
            output["truncated"] = truncated
            output["events"] = events

            for event in events:
                event_type = event.get("event")
                if event_type == "http_request":
                    output["http_requests"].append(event)
                elif event_type == "http_response":
                    output["http_responses"].append(event)
                elif event_type == "http_error":
                    output["http_errors"].append(event)
                elif event_type == "console":
                    output["console"].append(event)
                elif event_type == "warning":
                    output["warnings"].append(event)
                elif event_type == "init":
                    output["init"].append(event)

                    for payload in self._extract_drop_candidates(event):
                        digest = sha256(payload).hexdigest()
                        if digest in seen_hashes:
                            continue
                        seen_hashes.add(digest)

                        relative_path = os.path.join("files", digest)
                        abs_path = os.path.join(self.analysis_path, relative_path)

                        try:
                            if not path_exists(self.dropped_path):
                                path_mkdir(self.dropped_path, exist_ok=True)

                            if not path_exists(abs_path):
                                _ = path_write_file(abs_path, payload)

                            with open(self.files_metadata, "a", encoding="utf-8") as fh:
                                print(
                                    json.dumps(
                                        {
                                            "path": relative_path.replace("\\", "/"),
                                            "filepath": f"js_log/{event_type or 'event'}/{digest}",
                                            "pids": [],
                                            "ppids": [],
                                            "metadata": "",
                                            "category": "files",
                                        },
                                        ensure_ascii=False,
                                    ),
                                    file=fh,
                                )

                            dropped_created += 1
                            dropped_paths.append(relative_path.replace("\\", "/"))
                        except Exception as e:
                            dropped_errors += 1
                            log.warning("js_log_processing failed to drop extracted buffer for task %s: %s", self.task.get("id"), e)
        except Exception as e:
            log.warning("js_log_processing failed on %s: %s", log_path, e)

        output["dropped_from_js_log"] = dropped_paths
        output["dropped_created"] = dropped_created
        output["dropped_errors"] = dropped_errors
        return output
