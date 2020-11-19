# MIT License
#
# Copyright (c) 2017 Jason Reaves
# Copyright (c) 2019 Graham Austin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import
import pefile
import struct
import hashlib
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET
import yara

rule_source = """
rule TrickBot
{
    meta:
        author = "grahamaustin"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $snippet1 = {B8 ?? ?? 00 00 85 C9 74 32 BE ?? ?? ?? ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 03 F2 8B 2B 83 C3 04 33 2F 83 C7 04 89 29 83 C1 04 3B DE 0F 43 DA}
    condition:
        uint16(0) == 0x5A4D and ($snippet1)
}

rule TrickBot2
{
    meta:
        author = "enzok"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $transform = {8A 6C 24 ?? 8A 4C 24 ?? 8B BC 24 [4] 8A D5 8A F9 8A DD 80 E1 47 F6 D2 F6 D7 80 E3 47 8A F2 80 E7 B8 80 E6 B8 0A CF 0A DE 32 CB 88 4C 24 ?? 8A 5C 24 ?? 8A F3 22 DA F6 D6 22 F5 0A DE 88 5C 24 ?? 8A FB 88 5C 24 ?? 8A 74 24 ?? F6 D7 22 FE 22 D6 F6 D6 22 DE 22 F5 0A FB 0A D6 88 7C 24 ?? 88 54 24}

    condition:
        uint16(0) == 0x5A4D and ($transform)
}
"""


def yara_scan(raw_data, rule, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == rule:
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses


def xor_data(data, key, key_len):
    i = 0
    decrypted_blob = b""
    for x in range(0, len(data), 4):
        xor = struct.unpack("<L", data[x : x + 4])[0] ^ struct.unpack("<L", key[i % key_len])[0]
        decrypted_blob += struct.pack("<L", xor)
        i += 1
    return decrypted_blob


def derive_key(n_rounds, input_bf):
    intermediate = input_bf
    for i in range(0, n_rounds):
        sha = hashlib.sha256()
        sha.update(intermediate)
        current = sha.digest()
        intermediate += current
    return current


# expects a str of binary data open().read()
def trick_decrypt(data):
    key = derive_key(128, data[:32])
    iv = derive_key(128, data[16:48])[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    mod = len(data[48:]) % 16
    if mod != 0:
        data += "0" * (16 - mod)
    return aes.decrypt(data[48:])[: -(16 - mod)]


def get_rsrc(pe):
    ret = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = str(resource_type.name)
            else:
                name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
            if name == None:
                name = str(resource_type.struct.name)
            if hasattr(resource_type, "directory"):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, "directory"):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            ret.append((name, data, resource_lang.data.struct.Size, resource_type))
    return ret


def va_to_fileoffset(pe, va):
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if rva >= section.VirtualAddress and rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData


def decode_onboard_config(data):
    try:
        pe = pefile.PE(data=data)
        rsrcs = get_rsrc(pe)
    except:
        return

    if rsrcs != []:
        a = rsrcs[0][1]

        data = trick_decrypt(a[4:])
        length = struct.unpack_from("<I", data)[0]
        if length < 4000:
            return data[8 : length + 8]

        a = rsrcs[1][1]

        data = trick_decrypt(a[4:])
        length = struct.unpack_from("<I", data)[0]
        if length < 4000:
            return data[8 : length + 8]

    # Following code by grahamaustin
    snippet = yara_scan(data, "TrickBot", "$snippet1")
    if not snippet:
        return
    offset = int(snippet["$snippet1"])
    key_len = struct.unpack("<L", data[offset + 10 : offset + 14])[0]
    key_offset = struct.unpack("<L", data[offset + 15 : offset + 19])[0]
    key_offset = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset + 15 : offset + 19])[0]))
    data_offset = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset + 20 : offset + 24])[0]))
    size_offset = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset + 53 : offset + 57])[0]))
    size = size_offset - data_offset
    key = data[key_offset : key_offset + key_len]
    key = [key[i : i + 4] for i in range(0, len(key), 4)]
    key_len2 = len(key)
    a = data[data_offset : data_offset + size]
    a = xor_data(a, key, key_len2)

    data = trick_decrypt(a)
    length = struct.unpack_from("<I", data)[0]
    if length < 4000:
        return data[8 : length + 8]


def host_transform(data, server_list):
    if not yara_scan(data, "TrickBot2", "$transform"):
        return []
    new_list = []
    if server_list:
        for ip in server_list:
            host_ip, port = ip.split(":")
            o1, o2, o3, o4 = list(map(lambda  x: int(x), host_ip.split(".")))
            n1 = ((~o3 & 0xFF) & 0xB8 | o3 & 0x47) ^ ((~o1 & 0xFF) & 0xB8 | o1 & 0x47)
            n3 = o3 & (~o4 & 0xFF) | (~o3 & 0xFF) & o4
            n4 = o3 & (~o2 & 0xFF) | o2 & (~o3 & 0xFF)
            n2 = (~o2 & 0xFF) & n3 | o2 & (~n3 & 0xFF)

            # Concatenate new IP Address - Port is hardcoded in binary despite being transformed disabling for now
            #pt = ~(n4 << 8) & 0x67F6FF48 ^ (~o1 & 0x67F6FF48 | o1 & 0xB7)
            #nport = int(port) & (~pt & 0xFFFF) | pt & (~int(port) & 0xFFFF)

            nport = 443
            new_host = ".".join([str(n1), str(n2), str(n3), str(n4)]) + ":" + str(nport)
            new_list.append(new_host)

    return new_list

def config(data):
    xml = decode_onboard_config(data)
    try:
        root = ET.fromstring(xml)
    except:
        return
    raw_config = {}
    for child in root:

        if hasattr(child, "key"):
            tag = child.attrib["key"]
        else:
            tag = child.tag

        if tag == "autorun":
            val = list(map(lambda x: x.items(), child.getchildren()))
        elif tag == "servs":
            val = list(map(lambda x: x.text, child.getchildren()))
        else:
            val = child.text

        raw_config[tag] = val

    new_serves = host_transform(data, raw_config["servs"])
    if new_serves:
        raw_config["servs"] = new_serves

    return raw_config
