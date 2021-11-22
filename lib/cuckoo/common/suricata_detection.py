try:
    import re2 as re
except ImportError:
    import re

suricata_passlist = (
    "agenttesla",
    "medusahttp",
    "vjworm",
)

suricata_blocklist = (
    "abuse",
    "agent",
    "base64",
    "backdoor",
    "common",
    "custom",
    "dropper",
    "downloader",
    "evil",
    "executable",
    "f-av",
    "fake",
    "family",
    "fileless",
    "filename",
    "generic",
    "fireeye",
    "google",
    "hacking",
    "injector",
    "known",
    "likely",
    "magic",
    "malicious",
    "media",
    "msil",
    "multi",
    "observed",
    "owned",
    "perfect",
    "possible",
    "potential",
    "powershell",
    "probably",
    "python",
    "rogue",
    "self-signed",
    "shadowserver",
    "single",
    "suspect",
    "suspected",
    "supicious",
    "targeted",
    "team",
    "terse",
    "troj",
    "trojan",
    "unit42",
    "unknown",
    "user",
    "vbinject",
    "vbscript",
    "virus",
    "w2km",
    "w97m",
    "w32",
    "win32",
    "win64",
    "windows",
    "worm",
    "wscript",
    "http",
    "ptsecurity",
    "request",
    "suspicious",
)

et_categories = (
    "ET TROJAN",
    "ETPRO TROJAN",
    "ET MALWARE",
    "ETPRO MALWARE",
    "ET CNC",
    "ETPRO CNC"
)

def get_suricata_family(signature):
    """
    Args:
        signature: suricata alert string
    Return
        family: family name or False
    """
    # ToDo Trojan-Proxy
    family = False
    words = re.findall(r"[A-Za-z0-9/\-]+", signature)
    famcheck = words[2]
    if "/" in famcheck:
        famcheck_list = famcheck.split("/")  # [-1]
        for fam_name in famcheck_list:
            if not any([block in fam_name.lower() for block in suricata_blocklist]):
                famcheck = fam_name
                break
    famchecklower = famcheck.lower()
    if famchecklower.startswith("win.") and famchecklower.count(".") == 1:
        famchecklower = famchecklower.split(".")[-1]
        famcheck = famcheck.split(".")[-1]
    if famchecklower in ("win32", "w32", "ransomware"):
        famcheck = words[3]
        famchecklower = famcheck.lower()
    if famchecklower == "ptsecurity":
        famcheck = words[3]
        famchecklower = famcheck.lower()
    if famchecklower == "backdoor" and words[3].lower() == "family":
        famcheck = words[4]
        famchecklower = famcheck.lower()
    if "/" in famchecklower:
        famcheck_list = famchecklower.split("/")  # [-1]
        for fam_name in famcheck_list:
            if not any([block in fam_name.lower() for block in suricata_blocklist]):
                famcheck = fam_name
                break
    isbad = any([block in famchecklower for block in suricata_blocklist])
    if not isbad and len(famcheck) >= 4:
        family = famcheck.title()
    isgood = any([allow in famchecklower for allow in suricata_passlist])
    if isgood and len(famcheck) >= 4:
        family = famcheck.title()
    return family

def get_crowdstrike_family(proctype, procres):
    """
    :param proctype: process results type
    :param procres: process results
    :return maldata: list of dicts of yara based family name and actor, or empty list
    """
    maldata = list()
    if proctype == "target":
        yarahits = procres.get("file", {}).get("yara", [])
        malmeta = dict()
        for yh in yarahits:
            mf = yh.get("meta",{}).get("malware_family", "")
            if mf:
                malmeta["malware_family"] = mf
            ma = yh.get("meta",{}).get("actor", "")
            if ma:
                malmeta["actor"] = ma
            maldata.append(malmeta)
    elif proctype == "CAPE":
        payloads = procres.get("payload", {})
        for payload in payloads:
            yarahits = payload.get("yara", [])
            malmeta = dict()
            for yh in yarahits:
                mf = yh.get("meta",{}).get("malware_family", "")
                if mf:
                    malmeta["malware_family"] = mf
                ma = yh.get("meta",{}).get("actor", "")
                if ma:
                    malmeta["actor"] = ma
                maldata.append(malmeta)
    elif proctype in ("dropped", "procdump", "procmemory"):
        for data in procres:
            yarahits = data.get("yara", [])
            malmeta = dict()
            for yh in yarahits:
                mf = yh.get("meta",{}).get("malware_family", "")
                if mf:
                    malmeta["malware_family"] = mf
                ma = yh.get("meta",{}).get("actor", "")
                if ma:
                    malmeta["actor"] = ma
                maldata.append(malmeta)

    return maldata