import logging
import os
import zipfile

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS

log = logging.getLogger(__name__)

# CONFIGURATION - allow non installed bun
# Grab a copy of Bun for Windows and store it in extras as bun.zip
BUN_ZIP_NAME = "bun.zip"
BUN_DIR_NAME = "bun"
BUN_EXE_NAME = "bun.exe"


def setup_bun_environment():
    """
    Attempts to unzip a portable Bun environment.
    Returns: (path_to_bun_exe, None) on success (None, error_message) on failure
    """
    try:
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Admin")
        install_path = os.path.join(user_profile, "AppData", "Local", "app")
        bun_zip_path = os.path.abspath(os.path.join("extras", BUN_ZIP_NAME))
        bun_bin_path = os.path.join(install_path, BUN_DIR_NAME)

        if not os.path.exists(bun_zip_path):
            return None, f"Zip not found at {bun_zip_path}"

        with zipfile.ZipFile(bun_zip_path, "r") as z:
            file_list = z.namelist()
            bun_internal_path = next((f for f in file_list if f.lower().endswith(BUN_EXE_NAME)), None)
            if not bun_internal_path:
                return None, f"Archive does not contain {BUN_EXE_NAME}"

            bun_exe_path = os.path.normpath(os.path.join(bun_bin_path, bun_internal_path))
            if not os.path.exists(bun_exe_path):
                for member in z.infolist():
                    if member.filename.startswith("/") or ".." in member.filename:
                        return None, f"Aborting extraction. Zip contains potentially malicious path: {member.filename}"
                os.makedirs(bun_bin_path, exist_ok=True)
                log.info("Extracting Bun to %s...", bun_bin_path)
                z.extractall(bun_bin_path)

        if os.path.exists(bun_exe_path):
            bun_dir = os.path.dirname(bun_exe_path)
            current_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bun_dir};{current_path}"
            return bun_exe_path, None
        return None, f"Extraction finished but {BUN_EXE_NAME} not found on disk."

    except (zipfile.BadZipFile, OSError) as e:
        return None, f"Exception during Bun setup: {e}"


class Bun(Package):
    """Package for executing JavaScript files using Bun."""

    PATHS = [
        ("USERPROFILE", ".bun", "bin", "bun.exe"),
        ("ProgramFiles", "Bun", "bin", "bun.exe"),
        ("ProgramFiles(x86)", "Bun", "bin", "bun.exe"),
        ("SystemDrive", "bun", "bun.exe"),
    ]

    summary = "Executes a JS sample using Bun."
    description = "Uses bun.exe to execute JavaScript files."
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        path = check_file_extension(path, ".js")
        args = self.options.get(OPT_ARGUMENTS, "")
        bun_args = f'"{path}"'
        if args:
            bun_args += f" {args}"

        binary = None
        if os.path.exists(os.path.join("extras", BUN_ZIP_NAME)):
            custom_bin, error = setup_bun_environment()
            if custom_bin:
                binary = custom_bin
                log.info("Using Custom Bun: %s", binary)
            else:
                log.error("Failed to setup Custom Bun: %s", error)

        if not binary:
            log.info("Falling back to system installed Bun")
            binary = self.get_path("bun.exe")

        if not binary:
            raise Exception("Bun executable not found in custom bundle OR system paths.")

        return self.execute(binary, bun_args, path)
