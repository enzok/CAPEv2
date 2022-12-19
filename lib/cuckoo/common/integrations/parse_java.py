# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
import os
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Any, Dict

from lib.cuckoo.common.utils import convert_to_printable, store_temp_file

log = logging.getLogger(__name__)


class Java:
    """Java Static Analysis"""

    def __init__(self, file_path: str, decomp_jar: str, deobfuscator_jar: str, deobfuscator_conf: str):
        self.file_path = file_path
        self.decomp_jar = decomp_jar
        self.deobfuscator_jar = deobfuscator_jar
        self.deobfuscator_conf = deobfuscator_conf

    def run(self) -> Dict[str, Any]:
        """Run analysis.
        @return: analysis results dict or None.
        """
        p = Path(self.file_path)
        if not p.exists():
            return None

        results = {"java": {}}
        ojar_file = ""
        jar_file = ""

        if self.deobfuscator_jar:
            f = Path(self.file_path)
            data = f.read_bytes()
            ijar_file = ""
            # TODO: run with detect: true, then apply from list of approved, discovered transformers
            try:
                ijar_file = store_temp_file(data, "obfuscated.jar")
                tmpdir = os.path.dirname(ijar_file)
                ojar_file = os.path.join(tmpdir, b"decompile.jar")
                tmp_conf = os.path.join(tmpdir, b"config.yml")
                cf = Path(self.deobfuscator_conf)
                confdata = cf.read_text()
                tf = Path(tmp_conf.decode())
                tf.write_text("input: " + ijar_file.decode() + "\n")
                tf.write_text("output: " + ojar_file.decode() + "\n")
                tf.write_text(confdata)

                p = Popen(["java", "-jar", self.deobfuscator_jar, "--config", tmp_conf], stdout=PIPE)
                log.info(convert_to_printable(p.stdout.read()))
                jar_file = ojar_file
            except Exception as e:
                ojar_file = ""
                log.error(e, exc_info=True)
                pass

            try:
                Path(ijar_file).unlink()
            except:
                pass

        if self.decomp_jar:
            if not jar_file:
                data = p.read_bytes()
                jar_file = store_temp_file(data, "decompile.jar")

            try:
                if self.decomp_jar.endswith(".jar"):
                    p = Popen(["java", "-jar", self.decomp_jar, jar_file], stdout=PIPE)
                else:
                    p = Popen([self.decomp_jar, jar_file], stdout=PIPE)
                results["decompiled"] = convert_to_printable(p.stdout.read())
            except Exception as e:
                log.error(e, exc_info=True)

            with contextlib.suppress(Exception):
                Path(jar_file).unlink()
        return results
