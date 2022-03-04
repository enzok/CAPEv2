from __future__ import absolute_import
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.thirdparty_detections import get_crowdstrike_family, get_mandiant_family
from lib.cuckoo.common.utils import add_family_detection

log = logging.getLogger(__name__)

processing_cfg = Config("processing")


class Detections(Processing):
    """Family detections from third party yara hits"""

    order = 4

    def run(self):
        self.key = "detections"
        maldata = []

        log.debug("Running CrowdStrike family detections")
        if processing_cfg.detections.crowdstrike_yara:
            result_types = ("target", "dropped", "procdump", "procmemory", "CAPE")
            for proctype in result_types:
                procres = self.results.get(proctype, None)
                if procres:
                    maldata = get_crowdstrike_family(proctype, procres)
                for data in maldata:
                    for khash in data.keys():
                        for family in data[khash]:
                            add_family_detection(self.results, family, "CS Yara", khash)

        log.debug("Running Mandiant family detections")
        if processing_cfg.detections.mandiant_yara:
            result_types = ("target", "dropped", "procdump", "procmemory", "CAPE")
            for proctype in result_types:
                procres = self.results.get(proctype, None)
                if procres:
                    maldata = get_mandiant_family(proctype, procres)
                for data in maldata:
                    for khash in data.keys():
                        for family in data[khash]:
                            add_family_detection(self.results, family, "Mandiant Yara", khash)
