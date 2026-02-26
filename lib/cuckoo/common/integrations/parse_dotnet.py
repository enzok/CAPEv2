# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)

# Note universal_newlines should be False as some binaries fails to convert bytes to text


class DotNETExecutable:
    """.NET analysis"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._il_text = None

    @staticmethod
    def _read_compressed_uint(data: bytes, offset: int) -> Tuple[Optional[int], int]:
        if offset >= len(data):
            return None, 0
        first = data[offset]
        if first == 0xFF:
            return None, 1
        if first & 0x80 == 0:
            return first, 1
        if first & 0xC0 == 0x80:
            if offset + 1 >= len(data):
                return None, 0
            return ((first & 0x3F) << 8) | data[offset + 1], 2
        if first & 0xE0 == 0xC0:
            if offset + 3 >= len(data):
                return None, 0
            return ((first & 0x1F) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3], 4
        return None, 0

    @classmethod
    def _decode_custom_attr_string(cls, blob: bytes) -> Optional[str]:
        # Custom attribute blob starts with 0x0001 prolog.
        if len(blob) < 3 or blob[0] != 0x01 or blob[1] != 0x00:
            return None

        strlen, consumed = cls._read_compressed_uint(blob, 2)
        if consumed == 0 or strlen is None:
            return None

        str_off = 2 + consumed
        str_end = str_off + strlen
        if str_end > len(blob):
            return None

        try:
            return blob[str_off:str_end].decode("utf-8")
        except UnicodeDecodeError:
            return blob[str_off:str_end].decode("latin-1", errors="ignore")

    @staticmethod
    def _normalize_version(version: str) -> str:
        return version.replace(":", ".").strip()

    @staticmethod
    def _find_ildasm() -> Optional[str]:
        linux_candidates = (
            "/usr/local/bin/ildasm",
            "/usr/bin/ildasm",
        )
        for candidate in linux_candidates:
            if path_exists(candidate):
                return candidate

        for candidate in ("ildasm.exe", "ildasm"):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved

        windir = os.environ.get("WINDIR", r"C:\Windows")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        fixed_candidates = (
            os.path.join(windir, "Microsoft.NET", "Framework", "v4.0.30319", "ildasm.exe"),
            os.path.join(windir, "Microsoft.NET", "Framework64", "v4.0.30319", "ildasm.exe"),
            os.path.join(program_files_x86, "Microsoft SDKs", "Windows", "v10.0A", "bin", "NETFX 4.8 Tools", "ildasm.exe"),
        )
        for candidate in fixed_candidates:
            if path_exists(candidate):
                return candidate
        return None

    def _get_il_text(self) -> Optional[str]:
        if self._il_text is not None:
            return self._il_text

        ildasm = self._find_ildasm()
        if not ildasm:
            log.error("ildasm executable not found for .NET parsing: %s", self.file_path)
            self._il_text = None
            return None

        output_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="cape_ildasm_", suffix=".il", delete=False) as tmp:
                output_path = tmp.name

            # Keep Linux compatibility: some ildasm variants fail with /text+/out
            # and/or don't support /nobar. Try several CLI forms.
            cmd_variants = (
                [ildasm, f"-out:{output_path}", self.file_path],
                [ildasm, f"-out={output_path}", self.file_path],
                [ildasm, "-out", output_path, self.file_path],
            )
            last_exc = None
            for cmd in cmd_variants:
                try:
                    subprocess.check_output(cmd, universal_newlines=False, stderr=subprocess.STDOUT)
                    with open(output_path, "rb") as fp:
                        self._il_text = fp.read().decode("latin-1", errors="ignore")
                    if self._il_text:
                        return self._il_text
                except subprocess.CalledProcessError as e:
                    last_exc = e
                    continue

            # Fallback for ildasm variants that only emit IL to stdout.
            stdout_variants = (
                [ildasm, "-text", self.file_path],
                [ildasm, self.file_path],
            )
            for cmd in stdout_variants:
                try:
                    out = subprocess.check_output(cmd, universal_newlines=False, stderr=subprocess.STDOUT)
                    self._il_text = out.decode("latin-1", errors="ignore")
                    if self._il_text:
                        return self._il_text
                except subprocess.CalledProcessError as e:
                    last_exc = e

            if last_exc:
                errout = ""
                if getattr(last_exc, "output", None):
                    errout = last_exc.output.decode("latin-1", errors="ignore").strip()
                if errout:
                    log.error("ildasm failed (%s): %s", self.file_path, errout)
                else:
                    log.error("ildasm failed (%s): %s", self.file_path, str(last_exc))
        except subprocess.CalledProcessError as e:
            errout = ""
            if getattr(e, "output", None):
                errout = e.output.decode("latin-1", errors="ignore").strip()
            if errout:
                log.error("ildasm failed (%s): %s", self.file_path, errout)
            else:
                log.error("ildasm: %s", str(e))
        except Exception as e:
            log.exception(e)
        finally:
            if output_path and path_exists(output_path):
                try:
                    os.unlink(output_path)
                except OSError:
                    pass
        self._il_text = None
        return None

    def _get_custom_attrs(self) -> List[Dict[str, str]]:
        try:
            ret = []
            output = self._get_il_text()
            if not output:
                return ret

            matches = re.finditer(r"(?ms)^\s*\.custom\s+(?:/\*([0-9A-Fa-f]+)\*/\s+)?(.*?)=\s*\((.*?)\)\s*$", output)
            for idx, match in enumerate(matches):
                typeval = match.group(1) or str(idx + 1)
                signature = match.group(2).strip()
                blob_text = match.group(3)

                ctor_match = re.search(r"(\[[^\]]+\][^:\s]+)::'?\.ctor'?\(string\)", signature)
                if not ctor_match:
                    continue
                nameval = ctor_match.group(1)

                blob_hex = re.sub(r"[^0-9A-Fa-f]", "", blob_text)
                if not blob_hex:
                    continue
                try:
                    value_blob = bytes.fromhex(blob_hex)
                except ValueError:
                    continue

                valueval = self._decode_custom_attr_string(value_blob)
                if not valueval:
                    continue
                ret.append(
                    {
                        "type": convert_to_printable(typeval),
                        "name": convert_to_printable(nameval),
                        "value": convert_to_printable(valueval),
                    }
                )
            return ret
        except Exception as e:
            log.exception(e)
            return None

    def _get_assembly_refs(self) -> List[Dict[str, str]]:
        try:
            ret = []
            output = self._get_il_text()
            if not output:
                return ret

            matches = re.finditer(r"(?ms)^\s*\.assembly extern\s+([^\s{]+)\s*\{(.*?)^\s*\}", output)
            for match in matches:
                nameval = match.group(1).strip()
                block = match.group(2)
                ver_match = re.search(r"^\s*\.ver\s+([0-9:]+)", block, re.MULTILINE)
                if not ver_match:
                    continue
                verval = self._normalize_version(ver_match.group(1))
                item = {
                    "name": convert_to_printable(nameval),
                    "version": convert_to_printable(verval),
                }
                ret.append(item)
            return ret

        except Exception as e:
            log.exception(e)
            return None

    def _get_assembly_info(self) -> Dict[str, str]:
        try:
            ret = {}
            output = self._get_il_text()
            if not output:
                return ret

            asm_match = re.search(r"(?ms)^\s*\.assembly\s+(?!extern\b)([^\s{]+)\s*\{(.*?)^\s*\}", output)
            if asm_match:
                ret["name"] = convert_to_printable(asm_match.group(1).strip())
                ver_match = re.search(r"^\s*\.ver\s+([0-9:]+)", asm_match.group(2), re.MULTILINE)
                if ver_match:
                    ret["version"] = convert_to_printable(self._normalize_version(ver_match.group(1)))
            return ret
        except Exception as e:
            log.exception(e)
            return None

    def _get_type_refs(self) -> List[Dict[str, str]]:
        try:
            ret = []
            output = self._get_il_text()
            if not output:
                return ret

            seen = set()
            matches = re.finditer(r"\[([^\]\r\n]+)\]([A-Za-z_][A-Za-z0-9_.$`+/<>,-]*)", output)
            for match in matches:
                asmname = match.group(1).strip()
                typename = match.group(2).strip()
                key = (asmname, typename)
                if key in seen:
                    continue
                seen.add(key)
                if asmname and typename:
                    item = {
                        "assembly": convert_to_printable(asmname),
                        "typename": convert_to_printable(typename),
                    }
                    ret.append(item)
            return ret

        except Exception as e:
            log.exception(e)
            return None

    def run(self) -> Dict[str, Any]:
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not path_exists(self.file_path):
            return None

        try:
            results = {
                "typerefs": self._get_type_refs(),
                "assemblyrefs": self._get_assembly_refs(),
                "assemblyinfo": self._get_assembly_info(),
                "customattrs": self._get_custom_attrs(),
            }

            if all(results):
                return results
            else:
                return
        except Exception as e:
            log.exception(e)
            return None
