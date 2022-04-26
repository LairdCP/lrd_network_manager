#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2010 - 2012 Red Hat, Inc.
#

#
# This example adds a new ethernet connection via the AddConnection()
# D-Bus call, using backward-compatible settings, so it will work with
# both old and new versions of NetworkManager. Compare
# add-connection.py, which only supports NM 1.0 and later.
#
# Configuration settings are described at
# https://networkmanager.dev/docs/api/latest/ref-settings.html
#

import socket, struct, dbus, uuid


def ip_to_int(ip_string):
    return struct.unpack("=I", socket.inet_aton(ip_string))[0]


# full duplex
s_wired = dbus.Dictionary({"duplex": "full"})

s_con = dbus.Dictionary(
    {"type": "802-3-ethernet", "uuid": str(uuid.uuid4()), "id": "MyConnectionExample"}
)

addr1 = dbus.Array(
    [ip_to_int("10.1.2.3"), dbus.UInt32(8), ip_to_int("10.1.2.1")],
    signature=dbus.Signature("u"),
)
s_ip4 = dbus.Dictionary(
    {
        "addresses": dbus.Array([addr1], signature=dbus.Signature("au")),
        "method": "manual",
    }
)

s_ip6 = dbus.Dictionary({"method": "ignore"})

con = dbus.Dictionary(
    {"802-3-ethernet": s_wired, "connection": s_con, "ipv4": s_ip4, "ipv6": s_ip6}
)

print("Creating connection:", s_con["id"], "-", s_con["uuid"])

bus = dbus.SystemBus()
proxy = bus.get_object(
    "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings"
)
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")

settings.AddConnection(con)
