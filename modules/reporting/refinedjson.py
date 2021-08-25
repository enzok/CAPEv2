from __future__ import absolute_import
import os

try:
    import orjson
    HAVE_ORJSON = True
except ImportError:
    import json
    HAVE_ORJSON = False

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.core.database import Database, Task


class RefinedJson(Report):
    """Saves a subset of analysis results in JSON format."""

    order = 99999

    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf8')
        raise TypeError

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)

        host_filter = [
            "8.8.8.8",
            "8.8.4.4",
            "time.windows.com",
            "teredo.ipv6.microsoft.com",
            "ie9cvlist.ie.microsoft.com",
            "www.download.windowsupdate.com",
            "acroipm2.adobe.com",
            "acroipm.adobe.com",
            "files.acrobat.com",
            "ctldl.windowsupdate.com",
        ]

        try:
            db = Database()
            report = dict(results)

            miniresults = dict()
            if report["target"].get("file", False):
                miniresults["file"] = report["target"]["file"]
                del miniresults["file"]["yara"]
                del miniresults["file"]["path"]
                del miniresults["file"]["guest_paths"]
                miniresults["file"]["yara"] = []
                for rule in report["target"]["file"]["yara"]:
                    miniresults["file"]["yara"].append({"name": rule["name"]})
            if report.get("malfamily", False):
                miniresults["malfamily"] = report["malfamily"]
            if report.get("signatures", False):
                miniresults["signatures"] = []
                for sig in report["signatures"]:
                    miniresults["signatures"].append({"description": sig["description"]})
            if report.get("network", False):
                net = report["network"]
                mininet = dict()
                mininet["hosts"] = []
                for host in net["hosts"]:
                    if host["ip"] in host_filter or host["hostname"] in host_filter:
                        continue
                    mininet["hosts"].append(host)
                mininet["http"] = []
                for http in net["http"]:
                    if http["host"] in host_filter:
                        continue
                    httpdict = http
                    httpdict["uri"] = http["uri"]
                    httpdict["data"] = http["data"]
                    mininet["http"].append(httpdict)
                mininet["smtp"] = net["smtp"]
                mininet["irc"] = net["irc"]

                """
                if "suricata" in report and report["suricata"]:
                    if "alerts" in report["suricata"] and len(report["suricata"]["alerts"]) > 0:
                        mininet["alerts"] = report["suricata"]["alerts"]
                    if "http" in report["suricata"] and len(report["suricata"]["http"]) > 0:
                        mininet["suri_http"] = report["suricata"]["http"]
                """

                miniresults["network"] = mininet
            if report["behavior"]["summary"].get("executed_commands", False):
                miniresults["executed_commands"] = report["behavior"]["summary"]["executed_commands"]

            session = db.Session()
            task_id = report["info"]["id"]
            children = [c for c in session.query(Task.id, Task.package).filter(Task.parent_id == task_id)]

            if children:
                miniresults["cape"] = dict()
                cape = miniresults["cape"]
                cape["parent_id"] = task_id
                cape["children"] = []
                for kid in children:
                    child = dict()
                    child["task_id"], child["type"] = kid
                    cape["children"].append(child)

            path = os.path.join(self.reports_path, "refined-report.json")
            if HAVE_ORJSON:
                with open(path, "wb") as report:
                    report.write(orjson.dumps(miniresults, option=orjson.OPT_INDENT_2, default=self.default)) # orjson.OPT_SORT_KEYS |
            else:
                with open(path, "w") as report:
                    json.dump(miniresults, report, sort_keys=False, indent=int(indent), ensure_ascii=False)
        except (UnicodeError, TypeError, IOError, KeyError) as e:
            raise CuckooReportError("Failed to generate refined JSON report: %s" % e)