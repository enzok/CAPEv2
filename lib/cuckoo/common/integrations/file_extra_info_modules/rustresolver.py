import logging
import os
import re
import shutil
import subprocess
from contextlib import suppress
from typing import Dict, List, Set

from lib.cuckoo.common.integrations.file_extra_info_modules import ExtractorReturnType, extractor_ctx, time_tracker

log = logging.getLogger(__name__)

# Enabled via [rustresolver] in integrations.conf.
enabled = False
timeout = 180

_RUST_MARKERS = (
    b"rustc/",
    b".cargo/registry",
    b".cargo\\registry",
    b"rust_eh_personality",
    b"__rust_alloc",
    b"__rust_dealloc",
    b"__rust_realloc",
    b"__rust_no_alloc_shim_is_unstable",
    b"core::panicking",
    b"library/std/src",
)

_RUST_DIE_HINTS = ("rust", "librust", "cargo", "rustc")
_RUST_FILETYPE_HINTS = ("rust",)
_EXECUTABLE_TYPES = ("PE32", "MS-DOS executable", "ELF", "Mach-O")
_MAX_SYMBOLS = 300
_MAX_HEAD_TAIL = 24 * 1024 * 1024
_MAX_DEMANGLE = 120


def _read_head_tail(filepath: str, max_bytes: int = _MAX_HEAD_TAIL) -> bytes:
    with open(filepath, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size <= max_bytes:
            return f.read()
        head = f.read(max_bytes)
        f.seek(max(0, size - max_bytes))
        tail = f.read(max_bytes)
        return head + b"\n" + tail


def _match_markers(blob: bytes, markers: tuple) -> List[str]:
    return [marker.decode("latin-1", "ignore") for marker in markers if marker in blob]


def _extract_pe_symbols(data_dictionary: dict) -> Set[str]:
    out = set()
    pe_data = data_dictionary.get("pe", {}) or {}
    imports = pe_data.get("imports", {}) or {}
    for dll_data in imports.values():
        for imp in dll_data.get("imports", []) or []:
            name = imp.get("name")
            if isinstance(name, str) and name:
                out.add(name)
                if len(out) >= _MAX_SYMBOLS:
                    return out

    exports = pe_data.get("exports", []) or []
    for exp in exports:
        name = exp.get("name")
        if isinstance(name, str) and name:
            out.add(name)
            if len(out) >= _MAX_SYMBOLS:
                return out
    return out


def _extract_string_symbols(blob: bytes) -> Set[str]:
    out = set()
    patterns = (
        rb"_R[A-Za-z0-9_]{8,}",
        rb"_ZN[A-Za-z0-9_]{8,}E",
        rb"__rust_[A-Za-z0-9_]{4,}",
        rb"rust_eh_personality",
    )
    for pattern in patterns:
        with suppress(Exception):
            for m in re.findall(pattern, blob):
                out.add(m.decode("latin-1", "ignore"))
                if len(out) >= _MAX_SYMBOLS:
                    return out
    return out


def _maybe_demangle(symbols: List[str]) -> Dict[str, str]:
    rustfilt = shutil.which("rustfilt")
    if not rustfilt:
        return {}

    demangled = {}
    for symbol in symbols[:_MAX_DEMANGLE]:
        with suppress(Exception):
            proc = subprocess.run(
                [rustfilt, symbol],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            rendered = (proc.stdout or "").strip()
            if rendered and rendered != symbol:
                demangled[symbol] = rendered
    return demangled


def _contains_hint(strings: List[str], hints: tuple) -> bool:
    for value in strings:
        lowered = str(value).lower()
        if any(hint in lowered for hint in hints):
            return True
    return False


def _build_rust_report(filetype: str, data_dictionary: dict, filepath: str) -> Dict:
    score = 0
    signals = []
    die_values = [str(item) for item in (data_dictionary.get("die", []) or [])]
    trid_value = data_dictionary.get("trid")
    trid_values = [str(item) for item in trid_value] if isinstance(trid_value, list) else [str(trid_value or "")]
    lowered_type = (filetype or "").lower()

    if any(token in lowered_type for token in _RUST_FILETYPE_HINTS):
        score += 3
        signals.append("filetype")
    if _contains_hint(die_values, _RUST_DIE_HINTS):
        score += 3
        signals.append("die")
    if _contains_hint(trid_values, _RUST_DIE_HINTS):
        score += 2
        signals.append("trid")

    blob = b""
    with suppress(Exception):
        blob = _read_head_tail(filepath)
    markers = _match_markers(blob, _RUST_MARKERS) if blob else []
    if markers:
        score += min(4, len(markers))
        signals.append("markers")

    symbol_candidates = set()
    symbol_candidates.update(_extract_pe_symbols(data_dictionary))
    if blob:
        symbol_candidates.update(_extract_string_symbols(blob))

    rustish_symbols = [
        sym for sym in symbol_candidates if sym.startswith("_R") or sym.startswith("_ZN") or sym.startswith("__rust_")
    ]
    if rustish_symbols:
        score += 2
        signals.append("symbols")

    if score < 3:
        return {}

    selected_symbols = sorted(symbol_candidates)[:_MAX_SYMBOLS]
    demangled_map = _maybe_demangle(selected_symbols)
    crate_hints = sorted(
        {
            marker
            for marker in markers
            if "cargo" in marker.lower() or "rustc/" in marker.lower() or "library/std/src" in marker.lower()
        }
    )
    return {
        "meta": {
            "confidence_score": score,
            "signals": sorted(set(signals)),
            "symbol_count": len(selected_symbols),
            "demangled_count": len(demangled_map),
            "demangler": "rustfilt" if demangled_map else "",
        },
        "markers": markers,
        "crate_hints": crate_hints,
        "symbols": selected_symbols[:120],
        "demangled_symbols": demangled_map,
    }


@time_tracker
def extract_details(file, *, data_dictionary, filetype="", **_) -> ExtractorReturnType:
    if "rustresolver" in data_dictionary:
        return {}

    if not any(ftype in (filetype or "") for ftype in _EXECUTABLE_TYPES):
        return {}

    details = _build_rust_report(filetype, data_dictionary, file)
    if not details:
        return {}

    data_dictionary["rustresolver"] = details
    with extractor_ctx(file, "rustresolver", prefix="rustresolver") as ctx:
        # Generic extractor flow merges this back into the current file dict.
        ctx["data_dictionary"] = data_dictionary
    return ctx
