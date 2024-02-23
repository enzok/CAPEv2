# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import xml.etree.ElementTree as ET

from lib.cuckoo.common.abstracts import Processing


class ProcmonLog:
    """Yield each API call event to the parent handler."""

    def __init__(self, filepath):
        self.filepath = filepath

    def __iter__(self):
        return self.parse_file()

    def parse_file(self):
        with open(self.filepath, "r") as file:
            iterator = ET.iterparse(file, events=["end"])
            for _, element in iterator:
                if element.tag != "event":
                    continue

                yield {child.tag: child.text for child in element}

    def __bool__(self):
        if not os.path.exists(self.filepath):
            return


class Procmon(Processing):
    """Extract events from procmon.exe output."""

    def run(self):
        self.key = "procmon"
        procmon_xml = os.path.join(self.analysis_path, "aux/procmon.xml")
        return list(ProcmonLog(procmon_xml))
