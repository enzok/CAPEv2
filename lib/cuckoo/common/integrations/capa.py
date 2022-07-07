# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import logging
import os
from typing import Any, Dict, List

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)

processing_conf = Config("processing")

"""
from lib.cuckoo.common.integrations.capa import flare_capa_details, HAVE_FLARE_CAPA
path = "storage/binaries/8c4111e5ec6ec033ea32e7d40f3c36e16ad50146240dacfc3de6cf8df19e6531"
details = flare_capa_details(path, "static", on_demand=True)
"""

rules = False
HAVE_FLARE_CAPA = False

# ==== render dictionary helpers
def flare_capa_details(file_path: str, category: str = False, on_demand=False, disable_progress=True) -> Dict[str, Any]:
    capa_output = {}
    return capa_output
