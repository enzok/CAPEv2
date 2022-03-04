from __future__ import absolute_import
import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.thirdparty_detections import get_crowdstrike_family, get_mandiant_family
from lib.cuckoo.common.utils import add_family_detection

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)


class Detections(Report):
    """Family detections from third party yara hits"""

    def __init__(self):
        self.reporting_cfg = Config("reporting")

    def run(self, results):
        """
        :param results: Cuckoo results dict.
        :type results: `dict`
        """

        maldata = []
        if self.reporting_cfg.detections.crowdstrike_yara:
            result_types = ("target", "dropped", "procdump", "procmemory", "CAPE")
            for proctype in result_types:
                procres = results.get(proctype, None)
                if procres:
                    maldata = get_crowdstrike_family(proctype, procres)
                for hash in maldata:
                    for family in maldata.get(hash, []):
                        add_family_detection(results, family, "CS Yara", hash)

        if self.reporting_cfg.detections.mandiant_yara:
            result_types = ("target", "dropped", "procdump", "procmemory", "CAPE")
            for proctype in result_types:
                procres = results.get(proctype, None)
                if procres:
                    maldata = get_mandiant_family(proctype, procres)
                for hash in maldata:
                    for family in maldata.get(hash, []):
                        add_family_detection(results, family, "Mandiant Yara", hash)
