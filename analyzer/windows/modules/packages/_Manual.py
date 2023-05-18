# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package


class Manual(Package):
    """Manual analysis package.
    The sample is started manually from the temp directory with an interactive session.
    """

    PATHS = [
        ("SystemRoot", "explorer.exe"),
    ]

    def start(self, path):
        cmd_path = self.get_path("explorer.exe")
        return self.execute(cmd_path, os.path.dirname(path), cmd_path)
