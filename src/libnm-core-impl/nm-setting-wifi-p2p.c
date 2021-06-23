/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-wifi-p2p.h"

#include <net/ethernet.h>

#include "nm-utils.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-wifi-p2p
 * @short_description: Describes connection properties for 802.11 Wi-Fi P2P networks
 *
 * The #NMSettingWifiP2P object is a #NMSetting subclass that describes properties
 * necessary for connection to 802.11 Wi-Fi P2P networks (aka Wi-Fi Direct).
 **/

/**
 * NMSettingWifiP2P:
 *
 * Wi-Fi P2P Settings
 *
 * Since: 1.16
 */

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PEER, PROP_WPS_METHOD, PROP_WFD_IES,
    PROP_DEVICE_NAME,
    PROP_PEER_DEVICE_NAME,
    PROP_FREQUENCY,
);

typedef struct {
    char *  peer_mac_address;
    GBytes *wfd_ies;

    NMSettingWirelessSecurityWpsMethod wps_method;

    char *device_name;
    char *peer_device_name;
    int frequency;

} NMSettingWifiP2PPrivate;

struct _NMSettingWifiP2P {
    NMSetting               parent;
    NMSettingWifiP2PPrivate _priv;
};

struct _NMSettingWifiP2PClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingWifiP2P, nm_setting_wifi_p2p, NM_TYPE_SETTING)

#define NM_SETTING_WIFI_P2P_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSettingWifiP2P, NM_IS_SETTING_WIFI_P2P, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_wifi_p2p_get_peer:
 * @setting: the #NMSettingWifiP2P
 *
 * Returns: the #NMSettingWifiP2P:peer property of the setting
 *
 * Since: 1.16
 **/
const char *
nm_setting_wifi_p2p_get_peer(NMSettingWifiP2P *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIFI_P2P(setting), NULL);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE(setting)->peer_mac_address;
}

/**
 * nm_setting_wifi_p2p_get_device_name:
 * @setting: the #NMSettingWifiP2P
 *
 * Returns: the #NMSettingWifiP2P:device-name property of the setting
 *
 * Since: 1.18
 **/
const char *
nm_setting_wifi_p2p_get_device_name (NMSettingWifiP2P *setting)
{
    g_return_val_if_fail (NM_IS_SETTING_WIFI_P2P (setting), NULL);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE (setting)->device_name;
}

/**
 * nm_setting_wifi_p2p_get_peer_device_name:
 * @setting: the #NMSettingWifiP2P
 *
 * Returns: the #NMSettingWifiP2P:peer-device-name property of the setting
 *
 * Since: 1.18
 **/
const char *
nm_setting_wifi_p2p_get_peer_device_name (NMSettingWifiP2P *setting)
{
    g_return_val_if_fail (NM_IS_SETTING_WIFI_P2P (setting), NULL);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE (setting)->peer_device_name;
}

/**
 * nm_setting_wifi_p2p_get_frequency:
 * @setting: the #NMSettingWifiP2P
 *
 * Returns: the #NMSettingWifiP2P:frequency property of the setting
 *
 * Since: 1.18
 **/
int
nm_setting_wifi_p2p_get_frequency (NMSettingWifiP2P *setting)
{
    g_return_val_if_fail (NM_IS_SETTING_WIFI_P2P (setting), (int) NULL);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE (setting)->frequency;
}

/**
 * nm_setting_wifi_p2p_get_wps_method:
 * @setting: the #NMSettingWifiP2P
 *
 * Returns: the #NMSettingWifiP2P:wps-method property of the setting
 *
 * Since: 1.16
 **/
NMSettingWirelessSecurityWpsMethod
nm_setting_wifi_p2p_get_wps_method(NMSettingWifiP2P *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIFI_P2P(setting),
                         NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE(setting)->wps_method;
}

/**
 * nm_setting_wifi_p2p_get_wfd_ies:
 * @setting: the #NMSettingWiFiP2P
 *
 * Returns: (transfer none): the #NMSettingWiFiP2P:wfd-ies property of the setting
 *
 * Since: 1.16
 **/
GBytes *
nm_setting_wifi_p2p_get_wfd_ies(NMSettingWifiP2P *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIFI_P2P(setting), NULL);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE(setting)->wfd_ies;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingWifiP2PPrivate *priv = NM_SETTING_WIFI_P2P_GET_PRIVATE(setting);

    // need at least one of the 'peer' properties to be set to identify the peer
    if (!priv->peer_mac_address &&
        !priv->peer_device_name)
    {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("missing peer, or peer-device-name"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIFI_P2P_SETTING_NAME,
                       NM_SETTING_WIFI_P2P_PEER);
        return FALSE;
    }

    if (priv->peer_mac_address) {
        if (!nm_utils_hwaddr_valid (priv->peer_mac_address, ETH_ALEN)) {
            g_set_error_literal (error,
                                 NM_CONNECTION_ERROR,
                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                 _("property is invalid"));
            g_prefix_error (error, "%s.%s: ", NM_SETTING_WIFI_P2P_SETTING_NAME, NM_SETTING_WIFI_P2P_PEER);
            return FALSE;
        }
    }

    if (priv->device_name) {
        int len = strlen(priv->device_name);
        if (len < 1 || len > 32) {
            g_set_error_literal (error,
                                 NM_CONNECTION_ERROR,
                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                 _("property is invalid"));
            g_prefix_error (error, "%s.%s: ", NM_SETTING_WIFI_P2P_SETTING_NAME, NM_SETTING_WIFI_P2P_DEVICE_NAME);
            return FALSE;
        }
    }

    if (priv->peer_device_name) {
        int len = strlen(priv->peer_device_name);
        if (len < 1 || len > 32) {
            g_set_error_literal (error,
                                 NM_CONNECTION_ERROR,
                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                 _("property is invalid"));
            g_prefix_error (error, "%s.%s: ", NM_SETTING_WIFI_P2P_SETTING_NAME, NM_SETTING_WIFI_P2P_PEER_DEVICE_NAME);
            return FALSE;
        }
    }

    if (!_nm_utils_wps_method_validate(priv->wps_method,
                                       NM_SETTING_WIFI_P2P_SETTING_NAME,
                                       NM_SETTING_WIFI_P2P_WPS_METHOD,
                                       TRUE,
                                       error))
        return FALSE;

    return TRUE;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingWifiP2P *setting = NM_SETTING_WIFI_P2P(object);

    switch (prop_id) {
    case PROP_PEER:
        g_value_set_string(value, nm_setting_wifi_p2p_get_peer(setting));
        break;
    case PROP_WPS_METHOD:
        g_value_set_uint(value, nm_setting_wifi_p2p_get_wps_method(setting));
        break;
    case PROP_WFD_IES:
        g_value_set_boxed(value, nm_setting_wifi_p2p_get_wfd_ies(setting));
        break;
    case PROP_DEVICE_NAME:
        g_value_set_string(value, nm_setting_wifi_p2p_get_device_name(setting));
        break;
    case PROP_PEER_DEVICE_NAME:
        g_value_set_string(value, nm_setting_wifi_p2p_get_peer_device_name(setting));
        break;
    case PROP_FREQUENCY:
        g_value_set_uint(value, nm_setting_wifi_p2p_get_frequency(setting));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingWifiP2PPrivate *priv = NM_SETTING_WIFI_P2P_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_PEER:
        g_free(priv->peer_mac_address);
        priv->peer_mac_address =
            _nm_utils_hwaddr_canonical_or_invalid(g_value_get_string(value), ETH_ALEN);
        break;
    case PROP_WPS_METHOD:
        priv->wps_method = g_value_get_uint(value);
        break;
    case PROP_WFD_IES:
        nm_clear_pointer(&priv->wfd_ies, g_bytes_unref);
        priv->wfd_ies = g_value_dup_boxed(value);
        break;
    case PROP_DEVICE_NAME:
        g_free(priv->device_name);
        priv->device_name = g_value_dup_string(value);
        break;
    case PROP_PEER_DEVICE_NAME:
        g_free(priv->peer_device_name);
        priv->peer_device_name = g_value_dup_string(value);
        break;
    case PROP_FREQUENCY:
        priv->frequency = g_value_get_uint(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_wifi_p2p_init(NMSettingWifiP2P *setting)
{}

/**
 * nm_setting_wifi_p2p_new:
 *
 * Creates a new #NMSettingWifiP2P object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWifiP2P object
 *
 * Since: 1.16
 **/
NMSetting *
nm_setting_wifi_p2p_new(void)
{
    return g_object_new(NM_TYPE_SETTING_WIFI_P2P, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingWifiP2PPrivate *priv = NM_SETTING_WIFI_P2P_GET_PRIVATE(object);

    g_free(priv->peer_mac_address);
    g_free(priv->device_name);
    g_free(priv->peer_device_name);
    g_bytes_unref(priv->wfd_ies);

    G_OBJECT_CLASS(nm_setting_wifi_p2p_parent_class)->finalize(object);
}

static void
nm_setting_wifi_p2p_class_init(NMSettingWifiP2PClass *setting_wifi_p2p_class)
{
    GObjectClass *  object_class  = G_OBJECT_CLASS(setting_wifi_p2p_class);
    NMSettingClass *setting_class = NM_SETTING_CLASS(setting_wifi_p2p_class);

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingWifiP2P:peer:
     *
     * The P2P device that should be connected to. Currently, this is the only
     * way to create or join a group.
     *
     * Since: 1.16
     */
    /* ---keyfile---
     * property: peer
     * format: usual hex-digits-and-colons notation
     * description: MAC address in traditional hex-digits-and-colons notation
     *   (e.g. 00:22:68:12:79:A2), or semicolon separated list of 6 bytes (obsolete)
     *   (e.g. 0;34;104;18;121;162).
     * ---end---
     */
    obj_properties[PROP_PEER] = g_param_spec_string(NM_SETTING_WIFI_P2P_PEER,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWifiP2P:wps-method:
     *
     * Flags indicating which mode of WPS is to be used.
     *
     * There's little point in changing the default setting as NetworkManager will
     * automatically determine the best method to use.
     *
     * Since: 1.16
     */
    obj_properties[PROP_WPS_METHOD] = g_param_spec_uint(
        NM_SETTING_WIFI_P2P_WPS_METHOD,
        "",
        "",
        0,
        G_MAXUINT32,
        NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT,
        G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWifiP2P:wfd-ies:
     *
     * The Wi-Fi Display (WFD) Information Elements (IEs) to set.
     *
     * Wi-Fi Display requires a protocol specific information element to be
     * set in certain Wi-Fi frames. These can be specified here for the
     * purpose of establishing a connection.
     * This setting is only useful when implementing a Wi-Fi Display client.
     *
     * Since: 1.16
     */
    obj_properties[PROP_WFD_IES] = g_param_spec_boxed(
        NM_SETTING_WIFI_P2P_WFD_IES,
        "",
        "",
        G_TYPE_BYTES,
        G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE | G_PARAM_STATIC_STRINGS);
    /**
     * NMSettingWifiP2P:device-name:
     *
     * The P2P device name to be used for this device.
     *
     * Since: 1.18
     */
    /* ---keyfile---
     * property: device-name
     * format: string
     * description: P2P device name to be used for this device.
     * ---end---
     */
    obj_properties[PROP_DEVICE_NAME] =
        g_param_spec_string (NM_SETTING_WIFI_P2P_DEVICE_NAME, "", "",
                             NULL,
                             G_PARAM_READWRITE |
                             G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWifiP2P:peer-device-name:
     *
     * The P2P device name that should be connected to.
     *
     * Since: 1.18
     */
    /* ---keyfile---
     * property: peer-device-name
     * format: string
     * description: P2P device name of the peer.
     * ---end---
     */
    obj_properties[PROP_PEER_DEVICE_NAME] =
        g_param_spec_string (NM_SETTING_WIFI_P2P_PEER_DEVICE_NAME, "", "",
                             NULL,
                             G_PARAM_READWRITE |
                             G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWifiP2P:frequency:
     *
     * Frequency (MHz).
     *
     * Since: 1.18
     */
    obj_properties[PROP_FREQUENCY] =
        g_param_spec_uint (NM_SETTING_WIFI_P2P_FREQUENCY, "", "",
                           0,
                           G_MAXUINT32,
                           0,
                           G_PARAM_READWRITE |
                           G_PARAM_CONSTRUCT |
                           NM_SETTING_PARAM_FUZZY_IGNORE |
                           G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class, NM_META_SETTING_TYPE_WIFI_P2P);
}
