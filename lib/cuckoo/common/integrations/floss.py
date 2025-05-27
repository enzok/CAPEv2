import contextlib
import logging
import mmap
import os.path
from pathlib import Path

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists

integrations_conf = Config("integrations")

HAVE_FLOSS = False
try:
    import floss.main as fm
    import floss.language.utils as fl_utils
    import floss.language.go.extract as go_extract
    import floss.language.rust.extract as rust_extract
    from floss.strings import extract_ascii_unicode_strings

    HAVE_FLOSS = True
except ImportError:
    print("Missed dependency flare-floss: poetry run pip install -U flare-floss")

log = logging.getLogger(__name__)


class Floss:
    """Extract strings from sample using FLOSS."""

    def __init__(self, filepath: str, package: str, on_demand: bool = False):
        self.file_path = filepath
        self.package = package
        self.on_demand = on_demand

    def run(self):
        """Run FLOSS to extract strings from sample.
        @return: dictionary of floss strings.
        """

        if not HAVE_FLOSS:
            return

        if integrations_conf.floss.on_demand and not self.on_demand:
            return

        results = {}

        if not path_exists(self.file_path):
            log.error("Sample file doesn't exist: %s", self.file_path)
            return

        try:
            file_path = Path(self.file_path)
            if not fm.is_supported_file_type(file_path):
                if self.package == "shellcode":
                    fileformat = "sc32"
                elif self.package == "shellcode_x64":
                    fileformat = "sc64"
                else:
                    return results
            else:
                fileformat = "pe"

            min_length = integrations_conf.floss.min_length
            fm.set_log_config(fm.DebugLevel.NONE, True)
            tmpres = {}
            results = {}

            if integrations_conf.floss.static_strings:
                with open(self.file_path, "rb") as f:
                    with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                        static_strings = list(extract_ascii_unicode_strings(buf, min_length))
                        tmpres["static_strings"] = static_strings

                lang_id, lang_version = fm.identify_language_and_version(file_path, static_strings)
                if lang_id.value == fm.Language.GO.value:
                    language_strings = go_extract.extract_go_strings(file_path, min_length)
                    string_blob_strings = go_extract.get_static_strings_from_blob_range(file_path, static_strings)
                    language_strings_missed = fl_utils.get_missed_strings(string_blob_strings, language_strings, min_length)
                    tmpres["go_strings"].append(language_strings)
                    tmpres["go_strings"].append(language_strings_missed)
                elif lang_id.value == fm.Language.RUST.value:
                    language_strings = rust_extract.extract_rust_strings(file_path, min_length)
                    rdata_strings = rust_extract.get_static_strings_from_rdata(file_path, static_strings)
                    language_strings_missed = fl_utils.get_missed_strings(rdata_strings, language_strings, min_length)
                    tmpres["rust_strings"].append(language_strings)
                    tmpres["rust_strings"].append(language_strings_missed)

            sigspath = fm.get_signatures(Path(os.path.join(CUCKOO_ROOT, integrations_conf.floss.sigs_path)))
            vw = fm.load_vw(file_path, fileformat, sigspath, False)
            selected_functions = fm.select_functions(vw, None)
            decoding_function_features, library_functions = fm.find_decoding_function_features(
                vw,
                selected_functions,
                True,
            )

            if integrations_conf.floss.stack_strings:
                selected_functions = fm.get_functions_without_tightloops(decoding_function_features)
                tmpres["stack_strings"] = fm.extract_stackstrings(
                    vw,
                    selected_functions,
                    min_length,
                    verbosity=False,
                    disable_progress=True,
                )

            if integrations_conf.floss.tight_strings:
                tightloop_functions = fm.get_functions_with_tightloops(decoding_function_features)
                tmpres["tight_strings"] = fm.extract_tightstrings(
                    vw,
                    tightloop_functions,
                    min_length=min_length,
                    verbosity=False,
                    disable_progress=True,
                )

            if integrations_conf.floss.decoded_strings:
                top_functions = fm.get_top_functions(decoding_function_features, 20)
                fvas_to_emulate = fm.get_function_fvas(top_functions)
                fvas_tight_functions = fm.get_tight_function_fvas(decoding_function_features)
                fvas_to_emulate = fm.append_unique(fvas_to_emulate, fvas_tight_functions)

                tmpres["decoded_strings"] = fm.decode_strings(
                    vw,
                    fvas_to_emulate,
                    min_length,
                    verbosity=False,
                    disable_progress=True,
                )

            for stype in tmpres.keys():
                if tmpres[stype]:
                    results[stype] = []
                for sval in tmpres[stype]:
                    results[stype].append(sval.string)

        except Exception as e:
            log.exception(e)

        fm.set_log_config(fm.DebugLevel.DEFAULT, False)

        return results
