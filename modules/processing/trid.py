# This file is part of CAPE
# Tim Shelton
# tshelton@hawkdefense.com
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os.path
import subprocess

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooProcessingError

class TrID(Processing):
    """Extract TrID output from file."""

    def run(self):
        """Run extract of trid output.
        @return: list of trid output.
        """
        self.key = "trid"
        strings = []

        if self.task["category"] in ("file", "static"):
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: {}".format(self.file_path))

            trid_binary = os.path.join(CUCKOO_ROOT, self.options.get("identifier", "trid/trid"))
            definitions = os.path.join(CUCKOO_ROOT, self.options.get("definitions", "trid/triddefs.trd"))

            result = []
            output = subprocess.check_output([trid_binary, "-d:%s" % definitions, self.file_path],
                                             stderr=subprocess.STDOUT)
            result = output.split(b'\n')
            # trim data
            result = result[6:-1]
            for v in result:
                strings.append(v.decode("utf-8"))

        return strings
