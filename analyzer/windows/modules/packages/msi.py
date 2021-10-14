# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package


class Msi(Package):
    """MSI analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options
        self.options["exclude-apis"] = "NetUserGetInfo, NetGetJoinInformation, NetUserGetLocalGroups, DsEnumerateDomainTrustsW," \
                                       " CDocument_write, RegOpenKeyExA, RegOpenKeyExW, OpenSCManagerA, OpenSCManagerW," \
                                       " CreateServiceA," " CreateServiceW, OpenServiceA, OpenServiceW, StartServiceA," \
                                       " StartServiceW, ControlService, DeleteService"

    PATHS = [
        ("SystemRoot", "system32", "msiexec.exe"),
    ]

    def start(self, path):
        msi_path = self.get_path("msiexec.exe")
        msi_args = "/I \"{0}\" /qb ACCEPTEULA=1 LicenseAccepted=1".format(path)
        return self.execute(msi_path, msi_args, path)
