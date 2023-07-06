# Copyright (C) 2021 Intezer
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import os

from contextlib import suppress

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError


class TargetInfoReport(Report):
    """A target info report with only specific parts"""

    def format_json(self, report, indent=4):
        with suppress(KeyError):
            del report["pe"]["imports"]
            del report["pe"]["exports"]
            del report["pe"]["dirents"]
            del report["pe"]["sections"]
            del report["pe"]["resources"]

        with suppress(KeyError):
            del report["data"]

        formatted_text = json.dumps(report, indent=indent)

        formatted_text = formatted_text.replace('"', '')
        formatted_text = formatted_text.replace(',\n', '\n')

        return formatted_text

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        path = os.path.join(self.reports_path, "targetinfo.txt")

        try:
            report = dict(results["target"]["file"])
            formatted_text = self.format_json(report, indent=0)

            with open(path, "w") as hfile:
                hfile.write(formatted_text)
        except (KeyError):
            return
        except (IOError, TypeError, UnicodeError) as e:
            raise CuckooReportError(f"Failed to generate TargetInfo report: {e}")
