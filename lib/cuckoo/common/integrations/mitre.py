# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger("mitre")


def mitre_generate_attck(results, mitre):
    attck = {}
    ttp_dict = {}
    for ttp in results["ttps"]:
        ttp_dict.setdefault(ttp["ttp"], set()).add(ttp["signature"])
    try:
        for ttp in ttp_dict:
            mitre = mitre.get_object_by_attack_id(ttp, "attack-pattern")
            if mitre:
                for phase in mitre.get("kill_chain_phases", []):
                    tactic = phase.phase_name
                    attck.setdefault(tactic, []).append(
                        {
                            "t_id": ttp,
                            "ttp_name": mitre.name,
                            "description": mitre.description,
                            "signature": list(ttp_dict[ttp]),
                        }
                    )
    except FileNotFoundError:
        print("MITRE Att&ck data missed, execute: 'python3 utils/community.py -waf --mitre'")
    except Exception as e:
        # simplejson.errors.JSONDecodeError
        log.error(("Mitre", e))

    return attck


def init_mitre_attck():
    mitre_attack_data = False

    try:
        from mitreattack.stix20 import MitreAttackData

    except ImportError:
        print("Missed dependency: install mitreattack-python library")
        return

    try:
        path = os.path.join(CUCKOO_ROOT, "data", "mitre", "enterprise_attck_json.json")
        mitre_attack_data = MitreAttackData(path)
    except Exception as e:
        log.error("Can't initialize MitreAttackData: %s", str(e))

    return mitre_attack_data


def mitre_load(enabled: bool = False):
    mitre = False
    HAVE_MITRE = False

    if not enabled:
        return mitre, HAVE_MITRE

    try:
        mitre = init_mitre_attck()
        HAVE_MITRE = True

    except ImportError:
        print("Missing mitreattack-python dependency")

    return mitre, HAVE_MITRE
