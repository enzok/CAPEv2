from __future__ import absolute_import
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.thirdparty_detections import get_thirdparty_family
from lib.cuckoo.common.utils import add_family_detection

log = logging.getLogger(__name__)

processing_cfg = Config("processing")


class Detections(Processing):
    """Family detections from third party yara hits"""

    order = 4

    def run(self):
        self.key = "thirdpartydetections"
        maldata = []

        log.debug("Running Thirdparty family detections")
        if processing_cfg.detections.thirdparty_yara:
            result_types = ("target", "dropped", "procdump", "procmemory", "CAPE")
            for proctype in result_types:
                procres = self.results.get(proctype, None)
                if procres:
                    maldata = get_thirdparty_family(proctype, procres)
                for data in maldata:
                    for khash in data.keys():
                        for family in data[khash]:
                            print(f"Adding detection: {family} for {khash}")
                            add_family_detection(self.results, family, "CS Yara", khash)