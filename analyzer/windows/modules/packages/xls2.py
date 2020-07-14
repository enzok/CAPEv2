# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import time
from lib.common.abstracts import Package
from lib.api.utils import Utils

util = Utils()


class XLS2(Package):
    """Excel analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
    ]

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options
        self.options["disable_hook_content"] = 4
        self.options["exclude-apis"] = "memcpy"

    def start(self, path):
        excel = self.get_path_glob("Microsoft Office Excel")
        if "." not in os.path.basename(path):
            new_path = path + ".xls"
            os.rename(path, new_path)
            path = new_path
        util.cmd_wrapper(
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "1808" /f'
        )
        util.cmd_wrapper(
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "LowRiskFileTypes" /t REG_SZ /d ".cmd;.bat;.vbs;.vbe;.js;.jse;.exe;.wsf;" /f'
        )
        util.cmd_wrapper(
            r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ef87b4cb-f2ce-4785-8658-4ca6c63e38c6}" /f'
        )
        util.cmd_wrapper(
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f'
        )
        time.sleep(5)
        return self.execute(excel, '"%s" /dde' % path, path)
