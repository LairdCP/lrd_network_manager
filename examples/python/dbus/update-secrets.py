#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2011 - 2012 Red Hat, Inc.
#

#
# The example shows how to update secrets in a connection by means of D-Bus
# Update() method. The method replaces all previous settings with new ones
# including possible secrets.
# So, we get all settings using GetSettings() and then find out what secrets
# are associated with the connection using GetSecrets(), ask for new secret
# values, and add them to the settings that we pass to Update().
#

import dbus
import sys

bus = dbus.SystemBus()

def change_secrets_in_one_setting(proxy, config, setting_name):
    # Add new secret values to the connection config
    try:
        # returns a dict of dicts mapping name::setting, where setting is a dict
        # mapping key::value.  Each member of the 'setting' dict is a secret
        secrets = proxy.GetSecrets(setting_name)
        print("Current secrets:" + secrets)

        # Ask user for new secrets and put them into our connection config
        for setting in secrets:
            for key in secrets[setting]:
                new_secret = raw_input ("Enter new secret for '%s' in '%s': " % (key, setting))
                config[setting_name][key] = new_secret
    except Exception as e:
        #code = str(e).split(':')[0]
        #print("Exception:" + str(e))
        pass

def change_secrets(con_path, config):
    # Get existing secrets; we grab the secrets for each type of connection
    # (since there isn't a "get all secrets" call because most of the time
    # you only need 'wifi' secrets or '802.1x' secrets, not everything) and
    # set new values into the connection settings (config)
    con_proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
    connection_secrets = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
    change_secrets_in_one_setting(connection_secrets, config, '802-11-wireless')
    change_secrets_in_one_setting(connection_secrets, config, '802-11-wireless-security')
    change_secrets_in_one_setting(connection_secrets, config, '802-1x')
    change_secrets_in_one_setting(connection_secrets, config, 'gsm')
    change_secrets_in_one_setting(connection_secrets, config, 'cdma')
    change_secrets_in_one_setting(connection_secrets, config, 'ppp')

def find_connection(name):
    # Ask the settings service for the list of connections it provides
    global con_path
    proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
    settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")
    connection_paths = settings.ListConnections()

    # Get the settings and look for connection's name
    for path in connection_paths:
        con_proxy = bus.get_object("org.freedesktop.NetworkManager", path)
        connection = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
        try:
            config = connection.GetSettings()
        except Exception as e:
            pass

        # Find connection by the id
        s_con = config['connection']
        if name == s_con['id']:
            con_path = path
            return config
        # Find connection by the uuid
        if name == s_con['uuid']:
            con_path = path
            return config

    return None


# Main part
con_path = None

if len(sys.argv) != 2:
    sys.exit("Usage: %s <connection name/uuid>" % sys.argv[0])

# Find the connection
con = find_connection(sys.argv[1])

print("Connection found: " + con_path)

if con:
    # Obtain new secrets and put then into connection dict
    change_secrets(con_path, con)

    # Change the connection with Update()
    proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
    settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings.Connection")
    settings.Update(con)
else:
    sys.exit("No connection '%s' found" % sys.argv[1])

