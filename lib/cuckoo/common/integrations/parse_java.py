# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
from subprocess import PIPE, Popen

from lib.cuckoo.common.utils import convert_to_printable, store_temp_file

log = logging.getLogger(__name__)


class Java(object):
    """Java Static Analysis"""

    def __init__(self, file_path, decomp_jar, deobfuscator_jar, deobfuscator_conf):
        self.file_path = file_path
        self.decomp_jar = decomp_jar
        self.deobfuscator_jar = deobfuscator_jar
        self.deobfuscator_conf = deobfuscator_conf

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None

        results = {}

        results["java"] = {}
        ojar_file = ""
        jar_file = ""

        if self.deobfuscator_jar:
            f = open(self.file_path, "rb")
            data = f.read()
            f.close()
            # TODO: run with detect: true, then apply from list of approved, discovered transformers
            try:
                ijar_file = store_temp_file(data, "obfuscated.jar")
                tmpdir = os.path.dirname(ijar_file)
                ojar_file = os.path.join(tmpdir, b"decompile.jar")
                tmp_conf = os.path.join(tmpdir, b"config.yml")
                with open (self.deobfuscator_conf, "r") as cf:
                    confdata = cf.read()
                with open (tmp_conf, "w") as tf:
                    tf.write("input: " + ijar_file.decode('utf8') + "\n")
                    tf.write("output: " + ojar_file.decode('utf8') + "\n")
                    tf.write(confdata)

                p = Popen(["java", "-jar", self.deobfuscator_jar, "--config", tmp_conf], stdout=PIPE)
                log.info(convert_to_printable(p.stdout.read()))
                jar_file = ojar_file
            except Exception as e:
                ojar_file = ""
                log.error(e, exc_info=True)
                pass

            try:
                os.unlink(ijar_file)
            except:
                pass

        if self.decomp_jar:
            if not jar_file:
                f = open(self.file_path, "rb")
                data = f.read()
                f.close()
                jar_file = store_temp_file(data, "decompile.jar")

            try:
                if self.decomp_jar.endswith(".jar"):
                    p = Popen(["java", "-jar", self.decomp_jar, jar_file], stdout=PIPE)
                else:
                    p = Popen([self.decomp_jar, jar_file], stdout=PIPE)
                results["decompiled"] = convert_to_printable(p.stdout.read())
            except Exception as e:
                log.error(e, exc_info=True)
                pass

            try:
                os.unlink(jar_file)
            except Exception:
                pass

        return results
