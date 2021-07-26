# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import tempfile
import logging

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.common.utils import get_options


sf_version = ""
try:
    from sflock import unpack, __version__ as sf_version
    from sflock.unpack.office import OfficeFile
    from sflock.abstracts import File as sfFile
    from sflock.exception import UnpackException

    HAS_SFLOCK = True
except ImportError:
    print("You must install sflock\n" "sudo apt-get install p7zip-full lzip rar unace-nonfree cabextract\n" "pip3 install -U SFlock2")
    HAS_SFLOCK = False

if sf_version:
    sf_version_splited = sf_version.split(".")
    # Before 14 there is core changes that required by CAPE, since exit
    if int(sf_version_splited[-1]) < 14:
        print("You using old version of sflock! Upgrade: pip3 install -U SFlock2")
        sys.exit()
    # Latest release
    if int(sf_version_splited[-1]) < 23:
        print("You using old version of sflock! Upgrade: pip3 install -U SFlock2")

log = logging.getLogger(__name__)
cuckoo_conf = Config()
tmp_path = cuckoo_conf.cuckoo.get("tmppath", "/tmp").encode("utf8")

demux_extensions_list = [
    "",
    ".exe",
    ".dll",
    ".com",
    ".jar",
    ".pdf",
    ".msi",
    ".bin",
    ".scr",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".rar",
    ".htm",
    ".html",
    ".hta",
    ".doc",
    ".dot",
    ".docx",
    ".dotx",
    ".docm",
    ".dotm",
    ".docb",
    ".mht",
    ".mso",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".xls",
    ".xlt",
    ".xlm",
    ".xlsx",
    ".xltx",
    ".xlsm",
    ".xltm",
    ".xlsb",
    ".xla",
    ".xlam",
    ".xll",
    ".xlw",
    ".ppt",
    ".pot",
    ".pps",
    ".pptx",
    ".pptm",
    ".potx",
    ".potm",
    ".ppam",
    ".ppsx",
    ".ppsm",
    ".sldx",
    ".sldm",
    ".wsf",
    ".bat",
    ".ps1",
    ".sh",
    ".pl",
    ".lnk",
]

whitelist_extensions = ("doc", "xls", "ppt", "pub", "jar")

blacklist_extensions = ("apk", "dmg")

# list of valid file types to extract - TODO: add more types
VALID_TYPES = ["PE32", "Java Jar", "Outlook", "Message"]
VALID_LINUX_TYPES = ["Bourne-Again", "POSIX shell script", "ELF", "Python", "MS Windows shortcut"]
OFFICE_TYPES = ["Composite Document File",
                "CDFV2 Encrypted",
                "Excel 2007+",
                "Word 2007+",
                "Microsoft OOXML",
                ]


def options2passwd(options):
    password = False
    if "password=" in options:
        password = get_options(options).get("password")
        if password and isinstance(password, bytes):
            password = password.decode("utf8")

    return password


def demux_office(filename, password):
    retlist = []
    basename = os.path.basename(filename)
    target_path = os.path.join(tmp_path, b"cuckoo-tmp/msoffice-crypt-tmp")
    if not os.path.exists(target_path):
        os.makedirs(target_path)
    decrypted_name = os.path.join(target_path, basename)

    if HAS_SFLOCK:
        ofile = OfficeFile(sfFile.from_path(filename))
        d = ofile.decrypt(password)
        if hasattr(d, "contents"):
            with open(decrypted_name, "w") as outs:
                outs.write(d.contents)
            # TODO add decryption verification checks
            if "Encrypted" not in d.magic:
                retlist.append(decrypted_name)
    else:
        raise CuckooDemuxError("MS Office decryptor not available")

    if not retlist:
        retlist.append(filename)

    return retlist


def is_valid_type(magic):
    # check for valid file types and don't rely just on file extentsion
    VALID_TYPES.extend(VALID_LINUX_TYPES)
    for ftype in VALID_TYPES:
        if ftype in magic:
            return True
    return False


def get_filenames(retlist, tmp_dir, children):
    try:
        for child in children:
            if child.filesize == 0:
                continue
            at = child.astree()
            magic = child.magic
            if (
                "file" in at["type"]
                or child.package in whitelist_extensions
                or ("Microsoft" in magic and not ("Outlook" in magic or "Message" in magic))
            ):
                base, ext = os.path.splitext(at["filename"])
                ext = ext.lower().decode("utf8")
                if ext in demux_extensions_list or is_valid_type(magic):
                    retlist.append(os.path.join(tmp_dir, at["filename"]))
            elif "container" in at["type"] and child.package not in whitelist_extensions:
                get_filenames(retlist, tmp_dir, child.children)
    except Exception as err:
        log.error(err, exc_info=True)
        pass

    return retlist


def demux_sflock(filename, options):
    retlist = []
    try:
        password = ""
        tmp_pass = options2passwd(options)
        if tmp_pass:
            password = tmp_pass

        try:
            unpacked = unpack(filename, password=password)
        except UnpackException:
            unpacked = unpack(filename)

        if unpacked.package in blacklist_extensions:
            return retlist

        if unpacked.children:
            target_path = os.path.join(tmp_path, b"cuckoo-sflock")
            if not os.path.exists(target_path):
                os.mkdir(target_path)
            tmp_dir = tempfile.mkdtemp(dir=target_path)

            retlist = get_filenames([], tmp_dir, unpacked.children)

            if retlist:
                unpacked.extract(tmp_dir)

    except Exception as e:
        log.error(e, exc_info=True)

    return retlist


def demux_sample(filename, package, options, use_sflock=True):
    """
    If file is a ZIP, extract its included files and return their file paths
    If file is an email, extracts its attachments and return their file paths (later we'll also extract URLs)
    """
    # sflock requires filename to be bytes object for Py3
    if isinstance(filename, str) and use_sflock:
        filename = filename.encode("utf8")
    # if a package was specified, then don't do anything special
    if package:
        return [filename]

    # don't try to extract from office docs
    magic = File(filename).get_type()

    # if file is an Office doc and password is supplied, try to decrypt the doc
    if "Microsoft" in magic:
        ignore = ["Outlook", "Message", "Disk Image"]
        if any(x in magic for x in ignore):
            pass
        elif any(x in magic for x in OFFICE_TYPES):
            password = False
            tmp_pass = options2passwd(options)
            if tmp_pass:
                password = tmp_pass
            if password:
                return demux_office(filename, password)
            else:
                return [filename]

    # don't try to extract from Java archives or executables
    if "Java Jar" in magic or "Java archive data" in magic:
        return [filename]
    if "PE32" in magic or "MS-DOS executable" in magic:
        return [filename]
    if any(x in magic for x in VALID_LINUX_TYPES):
        return [filename]

    retlist = list()
    if HAS_SFLOCK:
        # all in one unarchiver
        retlist = demux_sflock(filename, options)

        if use_sflock:
            # all in one unarchiver
            retlist = demux_sflock(filename, options)
    # if it wasn't a ZIP or an email or we weren't able to obtain anything interesting from either, then just submit the
    # original file
    if not retlist:
        retlist.append(filename)
    else:
        if len(retlist) > 10:
            retlist = retlist[:10]

    return retlist
