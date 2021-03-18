# Copyright (C) 2021 Kevin O'Reilly kevoreilly@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from mwcp.parser import Parser
import pefile
import struct
import yara

rule_source = '''
rule Carbanak
{
    meta:
        author = "enzok"
        description = "Carnbanak sbox init"
        cape_type = "Carbanak Payload"

    strings:
        $sboxinit = {4? 0F BE 02 4? 8D 05 [-] 4? 8D 4D ?? E8 [3] 00 33 F6 4? 8D 5D ?? 4? 63 F8 8B 45 ?? B? B1 E3 14 06} 
    condition:
        uint16(0) == 0x5A4D and any of them
}

'''

yara_rules = yara.compile(source=rule_source)

def decode_string(src, sbox):
    lenstr = len(src) - 4
    if lenstr < 0:
        lenstr = 0
    newstr = bytearray()
    lenblock = int(lenstr / 4)
    nb = 0
    rb = 0
    delta = 0
    n = 0
    i = 0

    while n < lenstr:
        if rb == 0 :
            nb += 1
            if nb <= 4:
                delta = src[i] - 97
                i += 1
                rb = lenblock
            else:
                rb = lenstr - n
        elif rb > 0:
            rb -= 1
            c = src[i]
            if c < 32:
                min = 1
                max = 31
            elif c < 128:
                min = 32
                max = 127
            else:
                min = 128
                max = 255
            c = sbox[c]
            c -= delta
            if c < min:
                c = max - min + c
            n += 1
            newstr.append(c)
            i += 1
    return newstr


class Carbanak(Parser):
    DESCRIPTION = "Carbanak string parser."
    AUTHOR = "enzok"
    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=filebuf, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        sbox_init_offset, sbox_rva = 0, 0
        dec = None

        matches = yara_rules.match(data=filebuf)
        if not matches:
            return

        for match in matches:
            if match.rule != "Carbanak":
                continue
            for item in match.strings:
                if '$sboxinit' in item[1]:
                    sbox_init_offset = int(item[0])

        if sbox_init_offset:
            sbox_rva = struct.unpack("i", filebuf[sbox_init_offset + 7: sbox_init_offset + 11])[0] - image_base
        else:
            return
        c2_offset = pe.get_offset_from_rva(sbox_rva)
        try:
            sbox = bytes(filebuf[c2_offset: c2_offset + 128])
        except:
            return

        data_sections = [s for s in pe.sections if s.Name.find(b'.rdata') != -1]
        if not data_sections or not sbox:
            return None
        data = data_sections[0].get_data()
        for item in data.split(b'\x00'):
            try:
                dec = decode_string(item, sbox)
            except Exception as err:
                pass
            if dec:
                self.reporter.add_metadata("string", dec)
        return