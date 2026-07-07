import datetime
import logging
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.integrations.genai import build_genai_options, genai_enrich_task

log = logging.getLogger(__name__)


class GenAIEnrich(Report):
    """Post-analysis GenAI enrichment."""

    # Ensure report.json from jsondump(order=10) already exists.
    order = 20

    def _extract_sha256(self, results):
        target = results.get("target", {}) or {}
        tfile = target.get("file", {}) or {}
        return tfile.get("sha256")

    def run(self, results):
        # Same convention as bingraph: on_demand means WebGUI button only.
        if self.options.get("on_demand"):
            return

        report_path = os.path.join(self.reports_path, "report.json")
        try:
            if not os.path.exists(report_path):
                log.warning("GenAI enrichment skipped for task %s: report.json not found", self.task["id"])
                return

            created_ts = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            genai_enrich_task(
                task_id=self.task["id"],
                report_path=report_path,
                sha256=self._extract_sha256(results),
                created_ts=created_ts,
                options=build_genai_options(self.options),
            )
        except Exception as exc:
            # fail-open: reporting flow must not fail because of GenAI errors
            log.warning("GenAI enrichment failed for task %s: %s", self.task.get("id"), exc)
