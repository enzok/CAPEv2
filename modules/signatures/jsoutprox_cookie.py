# Copyright (C) 2020 enzo
#
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature


class JSOutProxCookie(Signature):
    name = "jsoutprox_cookie"
    description = "JSOutProx Cookie"
    severity = 3
    categories = ["network", "http"]
    authors = ["enzo"]
    minimum = "1.3"
    families = ["JSOutProx"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cookieRex = "Cookie: [_\.]{0,1}\w+=(\w+)"

    filter_apinames = set(["WSASend"])

    def on_call(self, call, process):
        found_match = False
        cookie = dict()
        sysinfo = dict()
        buffer = self.get_argument(call, "Buffer")
        rex_cookie = re.findall(self.cookieRex, buffer)
        if rex_cookie:
            try:
                bufstr = bytes.fromhex(rex_cookie[0]).decode("utf8")
                info = bufstr.split("_|_")
                sysinfo["Volume_Serial_Number"] = info[0]
                sysinfo["UUID"] = info[1]
                sysinfo["Computer_Name"] = info[2]
                sysinfo["Username"] = info[3]
                sysinfo["OS_Caption"] = info[4]
                sysinfo["OS_Version"] = info[5]
                sysinfo["Tag"] = info[6]
                sysinfo["Receive_Method"] = info[7]
                self.data.append(sysinfo)
            except Exception as e:
                bufstr = rex_cookie[0]
                cookie["Raw_Cookie"] = bufstr
                self.data.append(cookie)
            found_match = True

        return found_match
