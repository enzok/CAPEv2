import logging
from contextlib import suppress

from lib.cuckoo.common.integrations.file_extra_info_modules import ExtractorReturnType, extractor_ctx, time_tracker

log = logging.getLogger(__name__)

# Enabled via [goresolver] in integrations.conf.
enabled = False
timeout = 180


def _has_go_static_markers(filepath: str) -> bool:
    # Keep memory usage bounded while still catching common Go runtime markers.
    markers = (b"Go buildinf:", b".gopclntab", b"runtime.main", b"runtime.gcenable")
    with suppress(Exception):
        with open(filepath, "rb") as f:
            data = f.read(8 * 1024 * 1024)
            return any(marker in data for marker in markers)
    return False


def _looks_like_go(filetype: str, data_dictionary: dict, filepath: str) -> bool:
    lowered_type = (filetype or "").lower()
    if "golang" in lowered_type or "go executable" in lowered_type:
        return True

    for candidate in data_dictionary.get("die", []) or []:
        text = str(candidate).lower()
        if "golang" in text or "go " in text:
            return True

    trid_value = data_dictionary.get("trid")
    if isinstance(trid_value, list):
        for item in trid_value:
            if "golang" in str(item).lower():
                return True
    elif "golang" in str(trid_value).lower():
        return True

    sections = data_dictionary.get("pe", {}).get("sections", []) or []
    for section in sections:
        section_name = str(section.get("name", "")).lower()
        if ".gopclntab" in section_name or ".go.buildinfo" in section_name:
            return True

    return _has_go_static_markers(filepath)


@time_tracker
def extract_details(file, *, data_dictionary, filetype="", **_) -> ExtractorReturnType:
    if "goresolver" in data_dictionary:
        return {}

    if not any(ftype in (filetype or "") for ftype in ("PE32", "MS-DOS executable", "ELF", "Mach-O")):
        return {}

    if not _looks_like_go(filetype, data_dictionary, file):
        return {}

    from lib.cuckoo.common.integrations.goresolver_engine import GoResolver, HAVE_GORESOLVER

    if not HAVE_GORESOLVER:
        return {}

    details = GoResolver(file, "files").run()
    if not details:
        return {}

    data_dictionary["goresolver"] = details
    with extractor_ctx(file, "goresolver", prefix="goresolver") as ctx:
        # Generic extractor flow merges this back into the current file dict.
        ctx["data_dictionary"] = data_dictionary
    return ctx
