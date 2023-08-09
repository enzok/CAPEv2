import os
import logging
import subprocess

from lib.cuckoo.common.path_utils import path_write_file
from lib.cuckoo.common.integrations.file_extra_info_modules import time_tracker, ExtractorReturnType, extractor_ctx, collect_extracted_filenames

try:
    from sflock import unpack

    HAVE_SFLOCK = True
except ImportError:
    HAVE_SFLOCK = False

log = logging.getLogger()

# Enable/disable
enabled = True
# Module timeout
timeout = 60


@time_tracker
def jar_extract(file: str, *, data_dictionary: dict, **_) -> ExtractorReturnType:
    """Extract Java jar files"""

    if not any(_ in data_dictionary.get("type", "").lower() for _ in ("java jar", "java archive")):
        return

    with extractor_ctx(file, "JAR", prefix="jardump_") as ctx:
        tempdir = ctx["tempdir"]
        if HAVE_SFLOCK:
            unpacked = unpack(file.encode())
            for child in unpacked.children:
                _ = path_write_file(os.path.join(tempdir, child.filename.decode()), child.contents)
        else:
            _ = subprocess.check_output(
                [
                    "unzip",
                    file,
                    f"-d {tempdir}",
                ],
                universal_newlines=True,
                stderr=subprocess.PIPE,
            )
        ctx["extracted_files"] = collect_extracted_filenames(tempdir)
        ctx["data_dictionary"] = data_dictionary

    return ctx
