# Copyright (C) 2010-2015 Cuckoo Foundation.
# Copyright (C) 2012 JoseMi Holguin (@j0sm1)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""IRC Protocol"""

import logging
import re
from io import BytesIO

from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger("Processing.Pcap.irc.protocol")


class ircMessage:
    """IRC Protocol Request."""

    # Client commands
    __methods_client = dict.fromkeys(
        (
            "PASS",
            "JOIN",
            "USER",
            "OPER",
            "MODE",
            "SERVICE",
            "QUIT",
            "SQUIT",
            "PART",
            "TOPIC",
            "NAMES",
            "LIST",
            "INVITE",
            "KICK",
            "PRIVMSG",
            "NOTICE",
            "MOTD",
            "LUSERS",
            "VERSION",
            "STATS",
            "LINKS",
            "TIME",
            "CONNECT",
            "TRACE",
            "ADMIN",
            "INFO",
            "SERVLIST",
            "SQUERY",
            "WHO",
            "WHOIS",
            "WHOWAS",
            "KILL",
            "PING",
            "PONG",
            "ERROR",
            "AWAY",
            "REHASH",
            "DIE",
            "RESTART",
            "SUMMON",
            "USERS",
            "WALLOPS",
            "USERHOST",
            "NICK",
            "ISON",
        )
    )

    def __init__(self):
        self._messages = []
        # Server commandis : prefix - command - params
        self._sc = {}
        # Client commands : command - params
        self._cc = {}

    def _unpack(self, buf):
        """Extract into a list irc messages of a tcp streams.
        @buf: tcp stream data
        """
        try:
            with BytesIO(buf) as f:
                lines = f.readlines()
        except Exception:
            log.error("Failed reading tcp stream buffer")
            return False

        logirc = False
        for element in lines:
            if re.match(b"^:", element) is not None:
                command = "([a-zA-Z]+|[0-9]{3})"
                params = "(\x20.+)"
                irc_server_msg = re.findall(r"(^:[\w+.{}!@|()]+\x20)" + command + params, element)
                if irc_server_msg:
                    self._sc["prefix"] = convert_to_printable(irc_server_msg[0][0].strip())
                    self._sc["command"] = convert_to_printable(irc_server_msg[0][1].strip())
                    self._sc["params"] = convert_to_printable(irc_server_msg[0][2].strip())
                    self._sc["type"] = "server"
                    if logirc:
                        self._messages.append(dict(self._sc))
            else:
                irc_client_msg = re.findall(b"([a-zA-Z]+\x20)(.+[\x0a\0x0d])", element)
                if irc_client_msg and irc_client_msg[0][0].strip() in self.__methods_client:
                    self._cc["command"] = convert_to_printable(irc_client_msg[0][0].strip())
                    if self._cc["command"] in ("NICK", "USER"):
                        logirc = True
                    self._cc["params"] = convert_to_printable(irc_client_msg[0][1].strip())
                    self._cc["type"] = "client"
                    if logirc:
                        self._messages.append(dict(self._cc))

    def getClientMessages(self, buf):
        """Get irc client commands of tcp streams.
        @buf: list of messages
        @return: dictionary of the client messages
        """

        try:
            self._unpack(buf)
        except Exception:
            return None

        return [msg for msg in self._messages if msg["type"] == "client"]

    def getClientMessagesFilter(self, buf, filters):
        """Get irc client commands of tcp streams.
        @buf: list of messages
        @return: dictionary of the client messages filtered
        """
        try:
            self._unpack(buf)
        except Exception:
            return None

        return [msg for msg in self._messages if msg["type"] == "client" and msg["command"] not in filters]

    def getServerMessages(self, buf):
        """Get irc server commands of tcp streams.
        @buf: list of messages
        @return: dictionary of server messages
        """

        try:
            self._unpack(buf)
        except Exception:
            return None

        return [msg for msg in self._messages if msg["type"] == "server"]

    def getServerMessagesFilter(self, buf, filters):
        """Get irc server commands of tcp streams.
        @buf: list of messages
        @return: dictionary of server messages filtered
        """
        try:
            self._unpack(buf)
        except Exception:
            return None

        return [msg for msg in self._messages if msg["type"] == "server" and msg["command"] not in filters]

    def isthereIRC(self, buf):
        """Check if there is irc messages in a stream TCP.
        @buf: stream data
        @return: boolean result
        """

        try:
            self._unpack(buf)
            return bool(self._messages)
        except Exception:
            return False
