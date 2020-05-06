#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2011 Red Hat, Inc.
#

import dbus, uuid

def path_to_value(path):
    return dbus.ByteArray("file://".encode("utf-8") + path.encode("utf-8") + "\0".encode("utf-8"))

s_con = dbus.Dictionary({
    'type': '802-11-wireless',
    'uuid': str(uuid.uuid4()),
    'id': 'My Wifi'})

s_wifi = dbus.Dictionary({
    'ssid': dbus.ByteArray("homewifi".encode("utf-8")),
    'security': '802-11-wireless-security'})

s_wsec = dbus.Dictionary({'key-mgmt': 'wpa-eap'})

s_8021x = dbus.Dictionary({
    'eap': ['tls'],
    'identity': 'Bill Smith',
    'client-cert': path_to_value("/some/place/client.pem"),
    'ca-cert': path_to_value("/some/place/ca-cert.pem"),
    'private-key': path_to_value("/some/place/privkey.pem"),
    'private-key-password': "12345testing"})

s_ip4 = dbus.Dictionary({'method': 'auto'})
s_ip6 = dbus.Dictionary({'method': 'ignore'})

con = dbus.Dictionary({
    'connection': s_con,
    '802-11-wireless': s_wifi,
    '802-11-wireless-security': s_wsec,
    '802-1x': s_8021x,
    'ipv4': s_ip4,
    'ipv6': s_ip6
     })


bus = dbus.SystemBus()

proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")

settings.AddConnection(con)

