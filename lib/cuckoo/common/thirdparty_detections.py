from __future__ import absolute_import

def get_thirdparty_family(proctype, procres):
    """
    :param proctype: process results type
    :param procres: process results
    :return maldata: list of dicts of sha256 hash and yara based family, or empty list
    """
    maldata = []
    if proctype == "target":
        yarahits = procres.get("file", {}).get("yara", [])
        sha256 = procres.get("file", {}).get("sha256", "")
        families = []
        for yh in yarahits:
            mf = yh.get("meta",{}).get("malware_family", "")
            if mf:
                families.append(mf)
        maldata.append({sha256: families})
    elif proctype == "CAPE":
        payloads = procres.get("payloads", {})
        for payload in payloads:
            yarahits = payload.get("yara", [])
            sha256 = payload.get("sha256", "")
            families = []
            for yh in yarahits:
                mf = yh.get("meta",{}).get("malware_family", "")
                if mf:
                    families.append(mf)
            if families:
                maldata.append({sha256: families})
    elif proctype in ("dropped", "procdump", "procmemory"):
        for data in procres:
            yarahits = data.get("yara", [])
            sha256 = data.get("sha256", "")
            families = []
            for yh in yarahits:
                mf = yh.get("meta",{}).get("malware_family", "")
                if mf:
                    families.append(mf)
            if families:
                maldata.append({sha256: families})

    return maldata
