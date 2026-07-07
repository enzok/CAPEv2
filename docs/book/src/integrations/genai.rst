==================================
GenAI post-analysis enrichment
==================================

CAPE can send a curated digest of a finished analysis to a GenAI HTTP service
and store the returned verdict alongside the report. The integration is
disabled by default and requires no extra services or dependencies on the CAPE
host: at the end of reporting (after ``report.json`` is written), the curated
report is POSTed to the configured endpoint, and the response is saved to:

* ``storage/analyses/<task_id>/reports/genai.json``
* ``storage/analyses/<task_id>/reports/genai.txt`` (if ``write_txt = yes``)
* MongoDB ``genai`` / ``genai_summary`` / ``genai_status`` fields, rendered on
  the WebGUI report overview card and the GenAI tab

The enrichment is fail-open: reporting always completes even if the GenAI
endpoint is down or misconfigured. Failures are recorded as
``genai_status = failed`` and shown in the WebGUI.

Configuration
=============

Enable and configure the ``[genai_enrich]`` section in
``custom/conf/reporting.conf``::

    [genai_enrich]
    enabled = yes
    # yes = only run from the "Generate GenAI" button in the WebGUI report page
    # no  = enrich every analysis automatically at the end of reporting
    on_demand = no
    genai_endpoint = http://127.0.0.1:9055/analyze
    # Model to request from the GenAI service; empty uses the service's default.
    model =
    timeout_secs = 30
    max_payload_bytes = 1500000
    # Scrub tokens/passwords/keys from the curated report before sending
    redact_enabled = yes
    write_txt = yes
    max_retries = 5
    # Optional, if your endpoint requires bearer auth
    auth_token =

Before sending, the report is curated (``lib/cuckoo/common/genai_report_curator.py``):
capped per-section evidence (signatures, network, behavior, IOCs, strings),
mutation-only registry/file events, deduplicated indicators, and optional
secret redaction — keeping token usage per analysis low.

Large reports can take a while to analyze; raise ``timeout_secs`` (e.g. 120)
if you see retries in the logs.

Reference service
=================

Any HTTP service that accepts the curated JSON payload on POST and returns a
JSON verdict can be used. A reference implementation backed by the Claude API
ships in ``utils/genai_service.py``::

    pip install anthropic
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 utils/genai_service.py --host 127.0.0.1 --port 9055

Options:

* ``--model`` (or ``GENAI_MODEL``) — default model when a request doesn't
  specify one; defaults to ``claude-opus-4-8``.
* ``--allowed-models`` (or ``GENAI_ALLOWED_MODELS``) — comma-separated
  allowlist of models clients may request, e.g.
  ``--allowed-models claude-opus-4-8,claude-haiku-4-5``. Empty accepts any.
* ``GENAI_SERVICE_TOKEN`` — enables bearer auth; set the same value as
  ``auth_token`` in ``[genai_enrich]``.

Model selection per CAPE instance: set ``model =`` in ``[genai_enrich]``
(e.g. ``claude-sonnet-5`` for cheaper triage); empty uses the service default.

API and MCP access
==================

The enrichment result can be retrieved programmatically:

* REST: ``GET /apiv2/tasks/get/genai/<task_id>/`` — returns
  ``genai_summary``, ``genai_status``, ``genai_error`` and
  ``genai_updated_ts``. Gated by the ``[taskgenai]`` section in ``api.conf``.
* MCP: the ``get_genai_summary`` tool in the CAPE MCP server
  (``mcp/server.py``), enabled with ``mcp = yes`` under ``[taskgenai]``.
