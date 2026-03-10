import logging
import os
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists

integrations_conf = Config("integrations")
log = logging.getLogger(__name__)

HAVE_GORESOLVER = False
try:
    from volexity.goresolver.models.symbol_report import SymbolReport
    from volexity.goresolver.models.symbol_source import SymbolSource
    from volexity.goresolver.models.symbol_tree import SymbolTree
    from volexity.goresolver.sym.binary import Binary
    from volexity.goresolver.sym.go_sym_parser import GoSymParser
    from volexity.goresolver.sym.go_type_parser import GoTypeParser

    HAVE_GORESOLVER = True
except ImportError:
    print("OPTIONAL! Missed dependency: poetry run pip install -U goresolver")


def _parse_csv_list(value: str) -> List[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _as_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off", ""):
            return False
    return bool(value)


def _safe_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_go_version(output: str) -> Optional[Tuple[int, int, int]]:
    # Example formats:
    # - go version go1.22.4 linux/amd64
    # - go version go1.23 windows/amd64
    match = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", output)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3) or 0)
    return (major, minor, patch)


def _has_min_go_version(minimum: Tuple[int, int, int]) -> bool:
    go_bin = shutil.which("go")
    if not go_bin:
        return False
    try:
        output = subprocess.check_output([go_bin, "version"], text=True, stderr=subprocess.STDOUT).strip()
    except Exception:
        return False
    parsed = _parse_go_version(output)
    if not parsed:
        return False
    return parsed >= minimum


def _check_graph_dependencies() -> Tuple[bool, str]:
    try:
        import gographer  # noqa: F401
        import volexity.gostrap.sample_generator  # noqa: F401
    except ImportError as e:
        return False, f"missing python dependency: {e}"

    # GoResolver README requires Go >= 1.20.6 for graph/sample generation workflows.
    if not _has_min_go_version((1, 20, 6)):
        return False, "Go toolchain >= 1.20.6 is required for graph mode"

    return True, ""


class GoResolver:
    """Resolve symbols and type information from Go binaries using GoResolver's Python API."""

    def __init__(self, filepath: str, category: str = "", on_demand: bool = False):
        self.file_path = filepath
        self.category = category
        self.on_demand = on_demand

    def run(
        self,
        *,
        extract: Optional[bool] = None,
        graph: Optional[bool] = None,
        types: Optional[bool] = None,
    ) -> Optional[Dict]:
        if not HAVE_GORESOLVER:
            return None

        if not integrations_conf.goresolver.enabled:
            return None

        if not path_exists(self.file_path):
            log.error("Sample file doesn't exist: %s", self.file_path)
            return None

        use_extract = _as_bool(extract, _as_bool(integrations_conf.goresolver.get("extract", True), default=True))
        use_graph = _as_bool(graph, _as_bool(integrations_conf.goresolver.get("graph", False), default=False))
        use_types = _as_bool(types, _as_bool(integrations_conf.goresolver.get("types", True), default=True))
        threshold = _safe_float(integrations_conf.goresolver.get("threshold", 0.9), default=0.9)

        if not any((use_extract, use_graph, use_types)):
            return None

        symbol_tree = SymbolTree()
        sample_bin = Binary(Path(self.file_path))
        sym_parser = GoSymParser()
        gotypes_address = None
        type_dict = None
        compare_report = None
        go_version = None
        graph_match_count = 0

        if use_extract:
            try:
                symbols = sym_parser.extract(sample_bin)
                for pc, symbol_name in symbols.items():
                    try:
                        symbol_tree.insert(pc, symbol_name, SymbolSource.EXTRACT)
                    except ValueError:
                        continue
            except Exception as e:
                log.debug("goresolver extract failed for %s: %s", self.file_path, e)

        if use_types:
            try:
                moduledata = sym_parser.extract_moduledata(sample_bin)
                if moduledata is not None:
                    type_parser = GoTypeParser(sample_bin, moduledata)
                    type_parser.parse_types()
                    type_dict = type_parser.to_dict()
                    gotypes_address = moduledata.types
            except Exception as e:
                log.debug("goresolver types failed for %s: %s", self.file_path, e)

        if use_graph:
            graph_ok, graph_reason = _check_graph_dependencies()
            if not graph_ok:
                log.warning("GoResolver graph mode disabled: %s", graph_reason)
                use_graph = False

        if use_graph:
            try:
                from gographer import UnsupportedBinaryFormat
                from volexity.goresolver.go_compare import GoCompare
                from volexity.gostrap.sample_generator import SampleGenerator

                storage_rel = integrations_conf.goresolver.get("storage_path", "storage/goresolver")
                storage_path = Path(os.path.join(CUCKOO_ROOT, storage_rel))
                generator = SampleGenerator(storage_path, display_progress=False)
                go_comparator = GoCompare(generator, sample_bin, display_progress=False)
                go_versions = _parse_csv_list(integrations_conf.goresolver.get("go_versions", ""))
                go_libs = _parse_csv_list(integrations_conf.goresolver.get("libs", ""))
                compare_report = go_comparator.compare(go_versions or None, go_libs or None)
                go_version = go_versions[0] if go_versions else None
            except ImportError:
                log.warning("GoResolver graph mode dependencies are unavailable")
            except UnsupportedBinaryFormat as e:
                log.warning("GoResolver graph mode skipped unsupported file: %s", e)
            except Exception as e:
                log.debug("goresolver graph failed for %s: %s", self.file_path, e)

        if compare_report is not None:
            try:
                for bin_matches in compare_report.matches:
                    for method_match in bin_matches.matches:
                        if len(method_match.resolved_name) > 0 and method_match.similarity >= threshold:
                            try:
                                symbol_tree.insert(method_match.malware_offset, method_match.resolved_name, SymbolSource.GRAPH)
                                graph_match_count += 1
                            except ValueError:
                                continue
            except Exception as e:
                log.debug("goresolver graph merge failed for %s: %s", self.file_path, e)

        if not symbol_tree.to_dict() and not type_dict:
            return None

        report = json.loads(SymbolReport(Path(self.file_path), symbol_tree, gotypes_address, type_dict).to_json())
        symbols = report.get("Symbols", {}) or {}
        return {
            "sample": report.get("Sample", {}),
            "symbols": symbols,
            "go_types_address": report.get("GoTypes Address"),
            "types": report.get("Types"),
            "meta": {
                "symbol_count": len(symbols),
                "type_count": len((report.get("Types") or {})),
                "go_version": go_version,
                "category": self.category,
                "graph_ran": use_graph,
                "graph_match_count": graph_match_count,
            },
        }
