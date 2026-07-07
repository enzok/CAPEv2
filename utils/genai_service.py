#!/usr/bin/env python3
"""Reference GenAI enrichment service for CAPEv2.

Implements the HTTP contract expected by lib/cuckoo/common/integrations/genai.py:
CAPE POSTs {"task_id", "sha256", "report": <curated report>, "context": {...}} to
/analyze and this service returns a JSON verdict produced by the Claude API.

Dependencies: pip install anthropic
Credentials:  ANTHROPIC_API_KEY (or any credential source the anthropic SDK resolves)

Usage:
    python3 utils/genai_service.py --host 127.0.0.1 --port 9055
    # then in custom/conf/reporting.conf: genai_endpoint = http://127.0.0.1:9055/analyze

Optional bearer auth: set GENAI_SERVICE_TOKEN here and auth_token in [genai_enrich].
"""
import argparse
import hmac
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import anthropic

log = logging.getLogger("genai_service")

DEFAULT_MODEL = "claude-opus-4-8"

SYSTEM_PROMPT = """You are a senior malware analyst reviewing curated CAPE Sandbox analysis reports.

You receive a JSON digest of one analysis: target file metadata, triggered signatures,
dropped files, network activity, behavior summary (process tree, API categories, key events),
extracted IOCs, and interesting strings. Some sections may be capped or redacted.

Assess the sample and respond with your verdict. Guidelines:
- Base every claim on evidence present in the report; do not invent indicators.
- "malicious" requires clear malicious behavior or strong signature/IOC corroboration.
- "suspicious" is for meaningful but inconclusive indicators.
- "benign" requires the observed behavior to be adequately explained by legitimate use.
- Use "unknown" when the report contains too little behavior to judge.
- key_behaviors: short, concrete, evidence-backed observations (not generic statements).
- family_hypothesis: only name families you can justify from the evidence; confidence 0.0-1.0.
- mitre: ATT&CK technique IDs (e.g. T1055) with names, only for behaviors actually observed.
- recommendations: actionable next steps for a SOC analyst triaging this sample."""

# Structured-output schema matching what CAPE's templates and genai.txt renderer read.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign", "unknown"]},
        "confidence": {"type": "number", "description": "0.0 to 1.0"},
        "summary": {"type": "string", "description": "3-6 sentence analyst summary"},
        "key_behaviors": {"type": "array", "items": {"type": "string"}},
        "family_hypothesis": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "confidence": {"type": "number", "description": "0.0 to 1.0"},
                },
                "required": ["name", "confidence"],
                "additionalProperties": False,
            },
        },
        "mitre": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string", "description": "ATT&CK ID, e.g. T1055"},
                    "name": {"type": "string"},
                },
                "required": ["technique", "name"],
                "additionalProperties": False,
            },
        },
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "errors": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "verdict",
        "confidence",
        "summary",
        "key_behaviors",
        "family_hypothesis",
        "mitre",
        "recommendations",
        "errors",
    ],
    "additionalProperties": False,
}

client = None  # initialized in main()
model_id = DEFAULT_MODEL
allowed_models = []  # empty = accept any requested model
auth_token = ""


def analyze(payload):
    """Run one enrichment request through the Claude API. Returns (status, body dict)."""
    report = payload.get("report")
    if not isinstance(report, (dict, list)):
        return 400, {"error": "payload must contain a JSON 'report' object"}

    model = str(payload.get("model") or model_id).strip()
    if allowed_models and model not in allowed_models:
        return 400, {"error": "model '{0}' not in allowed models: {1}".format(model, ", ".join(allowed_models))}

    user_content = "Analyze this CAPE Sandbox report (task_id={0}, sha256={1}):\n\n{2}".format(
        payload.get("task_id"),
        payload.get("sha256"),
        json.dumps(report, ensure_ascii=False, separators=(",", ":")),
    )

    response = client.messages.create(
        model=model,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        output_config={"format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
        messages=[{"role": "user", "content": user_content}],
    )

    if response.stop_reason == "refusal":
        return 200, {
            "verdict": "unknown",
            "confidence": 0.0,
            "summary": "The model declined to analyze this report.",
            "key_behaviors": [],
            "family_hypothesis": [],
            "mitre": [],
            "recommendations": ["Review the sample manually."],
            "errors": ["model_refusal"],
            "model": response.model,
        }
    if response.stop_reason == "max_tokens":
        return 200, {
            "verdict": "unknown",
            "confidence": 0.0,
            "summary": "Model output was truncated before a verdict could be produced.",
            "key_behaviors": [],
            "family_hypothesis": [],
            "mitre": [],
            "recommendations": [],
            "errors": ["output_truncated"],
            "model": response.model,
        }

    text = next(block.text for block in response.content if block.type == "text")
    result = json.loads(text)  # guaranteed valid JSON by output_config.format
    result["model"] = response.model
    return 200, result


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, extra_headers=None):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok", "model": model_id})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/analyze":
            self._send(404, {"error": "not found"})
            return

        if auth_token:
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, "Bearer {0}".format(auth_token)):
                self._send(401, {"error": "unauthorized"})
                return

        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))
        except Exception:
            self._send(400, {"error": "invalid JSON body"})
            return

        # Map SDK failures onto statuses CAPE's client treats correctly:
        # 429/503 are retried with backoff, 400 fails the job immediately.
        try:
            status, body = analyze(payload)
            self._send(status, body)
        except anthropic.RateLimitError as exc:
            retry_after = exc.response.headers.get("retry-after", "30")
            self._send(429, {"error": "rate_limited"}, {"Retry-After": retry_after})
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500:
                self._send(503, {"error": "upstream_error: {0}".format(exc.status_code)})
            else:
                log.error("Claude API rejected the request: %s", exc.message)
                self._send(400, {"error": "upstream_rejected: {0}".format(exc.message)[:400]})
        except anthropic.APIConnectionError:
            self._send(503, {"error": "upstream_unreachable"})
        except Exception as exc:
            log.exception("Unhandled error")
            self._send(400, {"error": "internal: {0}".format(exc)[:400]})

    def log_message(self, fmt, *args):
        log.info("%s - %s", self.address_string(), fmt % args)


def main():
    global client, model_id, allowed_models, auth_token

    parser = argparse.ArgumentParser(description="Reference GenAI enrichment service for CAPEv2")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9055)
    parser.add_argument("--model", default=os.environ.get("GENAI_MODEL", DEFAULT_MODEL),
                        help="default model when the request doesn't specify one")
    parser.add_argument("--allowed-models", default=os.environ.get("GENAI_ALLOWED_MODELS", ""),
                        help="comma-separated allowlist of models clients may request (empty = any)")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    model_id = args.model
    allowed_models = [m.strip() for m in args.allowed_models.split(",") if m.strip()]
    if allowed_models and model_id not in allowed_models:
        allowed_models.append(model_id)
    auth_token = os.environ.get("GENAI_SERVICE_TOKEN", "")
    client = anthropic.Anthropic()  # resolves ANTHROPIC_API_KEY / auth profile from env

    log.info(
        "Serving on http://%s:%s/analyze (default model=%s, allowed=%s, auth=%s)",
        args.host, args.port, model_id, allowed_models or "any", bool(auth_token),
    )
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
