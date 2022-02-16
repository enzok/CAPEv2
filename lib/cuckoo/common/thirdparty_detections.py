from __future__ import absolute_import

try:
    import re2 as re
except ImportError:
    import re


def get_crowdstrike_family(proctype, procres):
    """
    :param proctype: process results type
    :param procres: process results
    :return maldata: list of dicts of yara based family name and actor, or empty list
    """
    maldata = []
    if proctype == "target":
        yarahits = procres.get("file", {}).get("yara", [])
        malmeta = {}
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


def get_mandiant_name(identifier):
    """
    :param identifier: full mandiant yara rule identifier
    :return name: malware name
    """
    name_re1 = "^FE_(.*)$"
    ids = {}

    try:
        name = re.findall(name_re1, identifier)[0]
        ids[name] = 1
    except IndexError as e:
        return

    omitlist = [
        "1",
        "10",
        "11",
        "12",
        "13",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "A",
        "AG",
        "APT",
        "APTFIN",
        "ASHX",
        "ASP",
        "ASPX",
        "ATM",
        "Autopatt",
        "B",
        "BACKDOOR",
        "BAT",
        "Backdoor",
        "Builder",
        "C",
        "CFM",
        "CRIMEWARE",
        "Controller",
        "CredTheft",
        "Crimeware",
        "D",
        "Downloader",
        "Dropper",
        "Dropper2",
        "Dropper3",
        "ELF64",
        "EXE",
        "FE",
        "FIN",
        "HackTool",
        "Hacktool",
        "Heuristic",
        "Hunting",
        "InfoStealer",
        "Infostealer",
        "JAR",
        "JS",
        "JSP",
        "Jar",
        "Java",
        "Keylogger",
        "LNK",
        "Launcher",
        "Linux",
        "Linux32",
        "Linux64",
        "Loader",
        "MSIL",
        "MacOS",
        "Macro",
        "OLE",
        "PHP",
        "PL",
        "POS",
        "PS1",
        "PUP",
        "PY",
        "Ps1",
        "Python",
        "RAT",
        "RESX",
        "RTF",
        "Ransom",
        "Ransomware",
        "Raw",
        "Raw32",
        "Raw64",
        "Rootkit",
        "SH",
        "Stager",
        "Tool",
        "Trojan",
        "Tunneler",
        "VBS",
        "WIN",
        "Webshell",
        "Win",
        "Win32",
        "Win64",
        "Wiper",
        "Word",
        "Worm",
        "XLS",
    ]

    omitlist = set(omitlist)

    for key in ids.keys():
        parts = key.split("_")
        matches = omitlist.intersection(set(parts))
        if matches:
            finparts = [x for x in parts if x not in matches]
        else:
            finparts = parts
        if len(finparts) > 1:
            name = "_".join(finparts)
        else:
            name = finparts[0]
    return name


def get_mandiant_family(proctype, procres):
    """
    :param proctype: process results type
    :param procres: process results
    :return maldata: list of dicts of yara based family name, or empty list
    """
    maldata = []
    if proctype == "target":
        yarahits = procres.get("file", {}).get("yara", [])
        malmeta = {}
        for yh in yarahits:
            identifier = yh.get("name", "")
            if identifier:
                mf = get_mandiant_name(identifier)
                malmeta["malware_family"] = mf
            maldata.append(malmeta)
    elif proctype == "CAPE":
        payloads = procres.get("payload", {})
        for payload in payloads:
            yarahits = payload.get("yara", [])
            malmeta = dict()
            for yh in yarahits:
                identifier = yh.get("name", "")
                if identifier:
                    mf = get_mandiant_name(identifier)
                    malmeta["malware_family"] = mf
                maldata.append(malmeta)
    elif proctype in ("dropped", "procdump", "procmemory"):
        for data in procres:
            yarahits = data.get("yara", [])
            malmeta = dict()
            for yh in yarahits:
                identifier = yh.get("name", "")
                if identifier:
                    mf = get_mandiant_name(identifier)
                    malmeta["malware_family"] = mf
                maldata.append(malmeta)

    return maldata