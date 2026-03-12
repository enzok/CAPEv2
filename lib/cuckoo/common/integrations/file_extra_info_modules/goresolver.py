import logging
import os
from contextlib import suppress

from lib.cuckoo.common.integrations.file_extra_info_modules import ExtractorReturnType, extractor_ctx, time_tracker

log = logging.getLogger(__name__)

# Enabled via [goresolver] in integrations.conf.
enabled = False
timeout = 180


def _contains_go_metadata_hint(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    go_hints = (
        "golang",
        "go executable",
        "go buildid",
        "go build id",
        "go compiler",
        "go language",
    )
    return any(hint in lowered for hint in go_hints)


def _has_go_static_markers(filepath: str) -> bool:
    # Keep memory usage bounded while still catching common Go runtime markers.
    markers = (
        b"Go buildinf:",
        b".gopclntab",
        b".go.buildinfo",
        b".note.go.buildid",
        b"runtime.main",
        b"runtime.gcenable",
        b"runtime.schedinit",
        b"runtime.buildVersion",
        b"main.main",
    )
    with suppress(Exception):
        with open(filepath, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            if size <= 0:
                return False

            # Scan both head and tail so we still catch samples where marker-heavy
            # sections are near the end of larger binaries.
            scan_window = 24 * 1024 * 1024
            head = f.read(min(size, scan_window))
            if any(marker in head for marker in markers):
                return True

            if size > scan_window:
                f.seek(max(0, size - scan_window))
                tail = f.read(scan_window)
                if any(marker in tail for marker in markers):
                    return True
    return False


def _looks_like_go(filetype: str, data_dictionary: dict, filepath: str) -> bool:
    score = 0
    lowered_type = (filetype or "").lower()
    if _contains_go_metadata_hint(lowered_type):
        score += 2

    for candidate in data_dictionary.get("die", []) or []:
        text = str(candidate).lower()
        if _contains_go_metadata_hint(text):
            score += 2
            break

    trid_value = data_dictionary.get("trid")
    if isinstance(trid_value, list):
        for item in trid_value:
            if _contains_go_metadata_hint(str(item).lower()):
                score += 2
                break
    elif _contains_go_metadata_hint(str(trid_value).lower()):
        score += 2

    sections = data_dictionary.get("pe", {}).get("sections", []) or []
    for section in sections:
        section_name = str(section.get("name", "")).lower()
        if any(marker in section_name for marker in (".gopclntab", ".go.buildinfo", ".note.go.buildid", "__gosymtab", "__gopclntab")):
            score += 3
            break

    # Some packed/obfuscated samples lose type/section clues but still retain
    # runtime marker strings in bytes.
    if _has_go_static_markers(filepath):
        score += 3

    return score >= 3


@time_tracker
def extract_details(file, *, data_dictionary, filetype="", **_) -> ExtractorReturnType:
    if "goresolver" in data_dictionary:
        return {}

    if not any(ftype in (filetype or "") for ftype in ("PE32", "MS-DOS executable", "ELF", "Mach-O")):
        return {}

    heuristic_match = _looks_like_go(filetype, data_dictionary, file)

    from lib.cuckoo.common.integrations.goresolver_engine import GoResolver, HAVE_GORESOLVER

    if not HAVE_GORESOLVER:
        return {}

    if not heuristic_match:
        # False negatives happen on stripped/packed binaries; still probe resolver.
        log.debug("goresolver heuristic miss for %s; probing resolver anyway", file)

    details = GoResolver(file, "files").run()
    if not details:
        return {}

    details.setdefault("meta", {})
    details["meta"]["heuristic_match"] = heuristic_match
    data_dictionary["goresolver"] = details
    with extractor_ctx(file, "goresolver", prefix="goresolver") as ctx:
        # Generic extractor flow merges this back into the current file dict.
        ctx["data_dictionary"] = data_dictionary
    return ctx
