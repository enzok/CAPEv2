import json
import logging
import subprocess
from pathlib import Path

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

class BinlexAnalysis(Processing):
    """Extract binary genetic traits and similarity hashes using Binlex in Docker."""

    key = "binlex"
    order = 2  # Run after file extraction & decompilation

    def run(self):
        try:
            binlex_cfg = Config("processing").binlex
        except Exception:
            log.warning("Binlex config section not found in processing.conf")
            return {}

        if not getattr(binlex_cfg, "enabled", False):
            return {}

        file_path = self.file_path
        if not Path(file_path).exists():
            return {}

        docker_bin = getattr(binlex_cfg, "docker_binary", "docker")
        container_name = getattr(binlex_cfg, "container_name", "binlex-server")
        host_prefix = getattr(binlex_cfg, "host_storage_prefix", "/opt/CAPEv2/storage")
        container_prefix = getattr(binlex_cfg, "container_storage_prefix", "/storage")

        # Translate path for container mount
        # Normalize paths to use forward slashes for container environment
        normalized_host_path = Path(file_path).as_posix()
        normalized_host_prefix = Path(host_prefix).as_posix()
        normalized_container_prefix = Path(container_prefix).as_posix()

        if normalized_host_path.startswith(normalized_host_prefix):
            container_file_path = normalized_host_path.replace(normalized_host_prefix, normalized_container_prefix, 1)
        else:
            # Fallback if path doesn't align with expected prefix
            container_file_path = normalized_host_path

        cmd = [
            docker_bin, "exec", container_name,
            "binlex", "-i", container_file_path
        ]

        results = {
            "traits": []
        }

        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if p.returncode != 0:
                log.warning("docker binlex exec failed with code %d: %s", p.returncode, stderr.decode())
                return results

            for line in stdout.decode().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    trait = json.loads(line)
                    results["traits"].append({
                        "pattern": trait.get("chromosome", {}).get("pattern"),
                        "type": trait.get("type"),
                        "size": trait.get("size"),
                        "offset": trait.get("offset")
                    })
                except Exception:
                    continue

        except Exception as e:
            log.error("Failed running binlex on %s: %s", file_path, e)

        return results
