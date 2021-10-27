/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-supplicant-config.h"

#include <stdlib.h>

#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-supplicant-settings-verify.h"
#include "nm-setting.h"
#include "libnm-core-aux-intern/nm-auth-subject.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-setting-ip4-config.h"

typedef struct {
    char *         value;
    guint32        len;
    NMSupplOptType type;
} ConfigOption;

/*****************************************************************************/

typedef struct {
    GHashTable *   config;
    GHashTable *   blobs;

    guint32    ccx;
    guint32    scan_delay;
    guint32    scan_dwell;
    guint32    scan_passive_dwell;
    guint32    scan_suspend_time;
    guint32    scan_roam_delta;
    guint32    frequency_dfs;

    struct {
        gboolean suiteb;
        gboolean ca_cert_check;
    } flags1x;

    NMSupplCapMask capabilities;
    guint32        ap_scan;
    bool           fast_required : 1;
    bool           dispose_has_run : 1;
    bool           ap_isolation : 1;
} NMSupplicantConfigPrivate;

struct _NMSupplicantConfig {
    GObject                   parent;
    NMSupplicantConfigPrivate _priv;
};

struct _NMSupplicantConfigClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMSupplicantConfig, nm_supplicant_config, G_TYPE_OBJECT)

#define NM_SUPPLICANT_CONFIG_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSupplicantConfig, NM_IS_SUPPLICANT_CONFIG)

/*****************************************************************************/

static gboolean
_get_capability(NMSupplicantConfigPrivate *priv, NMSupplCapType type)
{
    return NM_SUPPL_CAP_MASK_GET(priv->capabilities, type) == NM_TERNARY_TRUE;
}

static gboolean
_get_capability_laird (NMSupplicantConfigPrivate *priv)
{
    return NM_SUPPL_CAP_MASK_GET (priv->capabilities, NM_SUPPL_CAP_TYPE_LAIRD) == NM_TERNARY_TRUE;
}

NMSupplicantConfig *
nm_supplicant_config_new(NMSupplCapMask capabilities)
{
    NMSupplicantConfigPrivate *priv;
    NMSupplicantConfig *       self;

    self = g_object_new(NM_TYPE_SUPPLICANT_CONFIG, NULL);
    priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE(self);

    priv->capabilities = capabilities;

    return self;
}

static void
config_option_free(ConfigOption *opt)
{
    g_free(opt->value);
    g_slice_free(ConfigOption, opt);
}

static void
nm_supplicant_config_init(NMSupplicantConfig *self)
{
    NMSupplicantConfigPrivate *priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE(self);

    priv->config = g_hash_table_new_full(nm_str_hash,
                                         g_str_equal,
                                         g_free,
                                         (GDestroyNotify) config_option_free);

    priv->ap_scan         = 1;
    priv->dispose_has_run = FALSE;
}

static gboolean
nm_supplicant_config_add_option_with_type(NMSupplicantConfig *self,
                                          const char *        key,
                                          const char *        value,
                                          gint32              len,
                                          NMSupplOptType      opt_type,
                                          const char *        display_value,
                                          GError **           error)
{
    NMSupplicantConfigPrivate *priv;
    ConfigOption *             old_opt;
    ConfigOption *             opt;
    NMSupplOptType             type;

    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), FALSE);
    g_return_val_if_fail(key != NULL, FALSE);
    g_return_val_if_fail(value != NULL, FALSE);
    nm_assert(!error || !*error);

    priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE(self);

    if (len < 0)
        len = strlen(value);

    if (opt_type != NM_SUPPL_OPT_TYPE_INVALID)
        type = opt_type;
    else {
        type = nm_supplicant_settings_verify_setting(key, value, len);
        if (type == NM_SUPPL_OPT_TYPE_INVALID) {
            gs_free char *str_free = NULL;
            const char *  str;

            str = nm_utils_buf_utf8safe_escape(value,
                                               len,
                                               NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                               &str_free);

            str = nm_strquote_a(255, str);

            g_set_error(error,
                        NM_SUPPLICANT_ERROR,
                        NM_SUPPLICANT_ERROR_CONFIG,
                        "key '%s' and/or value %s invalid",
                        key,
                        display_value ?: str);
            return FALSE;
        }
    }

    old_opt = (ConfigOption *) g_hash_table_lookup(priv->config, key);
    if (old_opt) {
        g_set_error(error,
                    NM_SUPPLICANT_ERROR,
                    NM_SUPPLICANT_ERROR_CONFIG,
                    "key '%s' already configured",
                    key);
        return FALSE;
    }

    opt        = g_slice_new0(ConfigOption);
    opt->value = g_malloc(len + 1);
    memcpy(opt->value, value, len);
    opt->value[len] = '\0';

    opt->len  = len;
    opt->type = type;

    {
        char buf[255];
        memset(&buf[0], 0, sizeof(buf));
        memcpy(&buf[0], opt->value, opt->len > 254 ? 254 : opt->len);
        nm_log_info(LOGD_SUPPLICANT,
                    "Config: added '%s' value '%s'",
                    key,
                    display_value ?: &buf[0]);
    }

    g_hash_table_insert(priv->config, g_strdup(key), opt);

    return TRUE;
}

static gboolean
nm_supplicant_config_add_option(NMSupplicantConfig *self,
                                const char *        key,
                                const char *        value,
                                gint32              len,
                                const char *        display_value,
                                GError **           error)
{
    return nm_supplicant_config_add_option_with_type(self,
                                                     key,
                                                     value,
                                                     len,
                                                     NM_SUPPL_OPT_TYPE_INVALID,
                                                     display_value,
                                                     error);
}

static gboolean
nm_supplicant_config_add_blob(NMSupplicantConfig *self,
                              const char *        key,
                              GBytes *            value,
                              const char *        blobid,
                              GError **           error)
{
    NMSupplicantConfigPrivate *priv;
    ConfigOption *             old_opt;
    ConfigOption *             opt;
    NMSupplOptType             type;
    const guint8 *             data;
    gsize                      data_len;

    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), FALSE);
    g_return_val_if_fail(key != NULL, FALSE);
    g_return_val_if_fail(value != NULL, FALSE);
    g_return_val_if_fail(blobid != NULL, FALSE);

    data = g_bytes_get_data(value, &data_len);
    g_return_val_if_fail(data_len > 0, FALSE);

    priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE(self);

    type = nm_supplicant_settings_verify_setting(key, (const char *) data, data_len);
    if (type == NM_SUPPL_OPT_TYPE_INVALID) {
        g_set_error(error,
                    NM_SUPPLICANT_ERROR,
                    NM_SUPPLICANT_ERROR_CONFIG,
                    "key '%s' and/or its contained value is invalid",
                    key);
        return FALSE;
    }

    old_opt = (ConfigOption *) g_hash_table_lookup(priv->config, key);
    if (old_opt) {
        g_set_error(error,
                    NM_SUPPLICANT_ERROR,
                    NM_SUPPLICANT_ERROR_CONFIG,
                    "key '%s' already configured",
                    key);
        return FALSE;
    }

    opt        = g_slice_new0(ConfigOption);
    opt->value = g_strdup_printf("blob://%s", blobid);
    opt->len   = strlen(opt->value);
    opt->type  = type;

    nm_log_info(LOGD_SUPPLICANT, "Config: added '%s' value '%s'", key, opt->value);

    g_hash_table_insert(priv->config, g_strdup(key), opt);
    if (!priv->blobs) {
        priv->blobs =
            g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, (GDestroyNotify) g_bytes_unref);
    }
    g_hash_table_insert(priv->blobs, g_strdup(blobid), g_bytes_ref(value));

    return TRUE;
}

static gboolean
nm_supplicant_config_add_blob_for_connection(NMSupplicantConfig *self,
                                             GBytes *            field,
                                             const char *        name,
                                             const char *        con_uid,
                                             GError **           error)
{
    if (field && g_bytes_get_size(field)) {
        gs_free char *uid = NULL;
        char *        p;

        uid = g_strdup_printf("%s-%s", con_uid, name);
        for (p = uid; *p; p++) {
            if (*p == '/')
                *p = '-';
        }
        if (!nm_supplicant_config_add_blob(self, name, field, uid, error))
            return FALSE;
    }
    return TRUE;
}

static void
nm_supplicant_config_finalize(GObject *object)
{
    NMSupplicantConfigPrivate *priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE(object);

    g_hash_table_destroy(priv->config);
    nm_clear_pointer(&priv->blobs, g_hash_table_destroy);

    G_OBJECT_CLASS(nm_supplicant_config_parent_class)->finalize(object);
}

static void
nm_supplicant_config_class_init(NMSupplicantConfigClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->finalize = nm_supplicant_config_finalize;
}

guint32
nm_supplicant_config_get_ap_scan(NMSupplicantConfig *self)
{
    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), 1);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE(self)->ap_scan;
}

guint32
nm_supplicant_config_get_ccx (NMSupplicantConfig * self)
{
    g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), NM_SETTING_WIRELESS_CCX_DISABLE);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->ccx;
}

guint32
nm_supplicant_config_get_scan_delay (NMSupplicantConfig * self)
{
    g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 0);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->scan_delay;
}

guint32
nm_supplicant_config_get_scan_dwell (NMSupplicantConfig * self)
{
    g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 0);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->scan_dwell;
}

guint32
nm_supplicant_config_get_scan_passive_dwell (NMSupplicantConfig * self)
{
    g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 0);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->scan_passive_dwell;
}

guint32
nm_supplicant_config_get_scan_suspend_time (NMSupplicantConfig * self)
{
    g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 0);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->scan_suspend_time;
}

guint32
nm_supplicant_config_get_scan_roam_delta (NMSupplicantConfig * self)
{
    g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 0);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->scan_roam_delta;
}

guint32
nm_supplicant_config_get_frequency_dfs (NMSupplicantConfig * self)
{
    g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 0);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->frequency_dfs;
}

gboolean
nm_supplicant_config_fast_required(NMSupplicantConfig *self)
{
    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), FALSE);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE(self)->fast_required;
}

GVariant *
nm_supplicant_config_to_variant(NMSupplicantConfig *self)
{
    NMSupplicantConfigPrivate *priv;
    GVariantBuilder            builder;
    GHashTableIter             iter;
    ConfigOption *             option;
    const char *               key;

    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), NULL);

    priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE(self);

    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    g_hash_table_iter_init(&iter, priv->config);
    while (g_hash_table_iter_next(&iter, (gpointer) &key, (gpointer) &option)) {
        switch (option->type) {
        case NM_SUPPL_OPT_TYPE_INT:
            g_variant_builder_add(&builder, "{sv}", key, g_variant_new_int32(atoi(option->value)));
            break;
        case NM_SUPPL_OPT_TYPE_BYTES:
        case NM_SUPPL_OPT_TYPE_UTF8:
            g_variant_builder_add(&builder,
                                  "{sv}",
                                  key,
                                  nm_g_variant_new_ay((const guint8 *) option->value, option->len));
            break;
        case NM_SUPPL_OPT_TYPE_KEYWORD:
        case NM_SUPPL_OPT_TYPE_STRING:
            g_variant_builder_add(&builder, "{sv}", key, g_variant_new_string(option->value));
            break;
        default:
            break;
        }
    }

    return g_variant_builder_end(&builder);
}

GHashTable *
nm_supplicant_config_get_blobs(NMSupplicantConfig *self)
{
    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), NULL);

    return NM_SUPPLICANT_CONFIG_GET_PRIVATE(self)->blobs;
}

static const char *
wifi_freqs_to_string(gboolean bg_band)
{
    static const char *str_2ghz = NULL;
    static const char *str_5ghz = NULL;
    const char **      f_p;
    const char *       f;

    f_p = bg_band ? &str_2ghz : &str_5ghz;

again:
    f = g_atomic_pointer_get(f_p);

    if (G_UNLIKELY(!f)) {
        nm_auto_str_buf NMStrBuf strbuf = NM_STR_BUF_INIT(400, FALSE);
        const guint *            freqs;
        int                      i;

        freqs = bg_band ? nm_utils_wifi_2ghz_freqs() : nm_utils_wifi_5ghz_freqs();
        for (i = 0; freqs[i]; i++) {
            if (i > 0)
                nm_str_buf_append_c(&strbuf, ' ');
            nm_str_buf_append_printf(&strbuf, "%u", freqs[i]);
        }

        f = g_strdup(nm_str_buf_get_str(&strbuf));

        if (!g_atomic_pointer_compare_and_exchange(f_p, NULL, f)) {
            g_free((char *) f);
            goto again;
        }
    }

    return f;
}

static void
wifi_channel_width_24g(guint32 channel, int width, int *ht40)
{
    if (width == 80) {
        *ht40 = 0;
        return; // 80MHz is not supported, fallback to 20MHz
    }
    if (channel < 1 || channel > 11) {
        *ht40 = 0;
        return; // channel only supports 20MHz
    }
    if (channel < 5) {
        *ht40 = 1; // secondary channel is always above
    } else if (channel > 7) {
        *ht40 = -1; // secondary channel is always below
    } else {
        if (*ht40 == 0)
            *ht40 = 1; // default to secondary channel is above
    }
}

typedef struct {
    int chan;
    int ht40; // ht40 -- secondary channel: 1=above, -1=below
    int vht80_cfreq; // vht 80-MHz center frequency
} vhtchan_t;

static vhtchan_t vht_table[] =
{
    { 36, 1, 5210 },
    { 40, -1, 5210 },
    { 44, 1, 5210 },
    { 48, -1, 5210 },

    { 52, 1, 5290 },
    { 56, -1, 5290 },
    { 60, 1, 5290 },
    { 64, -1, 5290 },

    { 100, 1, 5530 },
    { 104, -1, 5530 },
    { 108, 1, 5530 },
    { 112, -1, 5530 },

    { 116, 1, 5610 },
    { 120, -1, 5610 },
    { 124, 1, 5610 },
    { 128, -1, 5610 },

    { 132, 1, 5690 },
    { 136, -1, 5690 },
    { 140, 1, 5690 },
    { 144, -1, 5690 },

    { 149, 1, 5775 },
    { 153, -1, 5775 },
    { 157, 1, 5775 },
    { 161, -1, 5775 },

    { 0, 0, 0 }
};

static void
wifi_channel_width_5g(guint32 channel, int width, int *ht40, int *vht80_cfreq)
{
    vhtchan_t *pt = vht_table;
    while (pt->chan) {
        if (pt->chan == channel) break;
        pt++;
    }
    if (pt->chan) {
        *ht40 = pt->ht40;
        if (width == 80)
            *vht80_cfreq = pt->vht80_cfreq;
        return;
    }
    *ht40 = 0;
    *vht80_cfreq = 0;
}

/*
 * settings for 40 and 80 MHz channels
 */
static gboolean
nm_supplicant_config_add_channel_width(NMSupplicantConfig * self,
                                       const char *band, guint32 channel,
                                       const char *width_str,
                                       GError **error)
{
    int ht40 = 0; // secondary channel is above(+1), or below(-1)
    int vht80_cfreq = 0;
    int width;

    if (!width_str) {
        return TRUE; // default to 20MHz
    } else if (!strcmp(width_str, "80")) {
        width = 80;
    } else if (!strcmp(width_str, "40")) {
        width = 40;
    } else if (!strcmp(width_str, "40+")) {
        width = 40;
        ht40 = 1;
    } else if (!strcmp(width_str, "40-")) {
        width = 40;
        ht40 = -1;
    } else {
        return TRUE; // unsupported channel width, or 20MHz
    }
    if (!strcmp (band, "bg")) {
        wifi_channel_width_24g(channel, width, &ht40);
    } else if (!strcmp (band, "a")) {
        wifi_channel_width_5g(channel, width, &ht40, &vht80_cfreq);
    } else {
        return TRUE; // unsupported band
    }
    if (ht40) {
        char buf[32];
        snprintf (buf, sizeof (buf), "%d", ht40);
        if (!nm_supplicant_config_add_option (self, "ht40", buf, -1, NULL, error))
            return FALSE;
        if (vht80_cfreq) {
            snprintf (buf, sizeof (buf), "%d", vht80_cfreq);
            if (!nm_supplicant_config_add_option (self, "vht_center_freq1", buf, -1, NULL, error))
                return FALSE;
            if (!nm_supplicant_config_add_option (self, "vht", "1", -1, NULL, error))
                return FALSE;
            if (!nm_supplicant_config_add_option (self, "max_oper_chwidth", "1", -1, NULL, error))
                return FALSE;
        }
    }

    return TRUE;
}

gboolean
nm_supplicant_config_add_setting_macsec(NMSupplicantConfig *self,
                                        NMSettingMacsec *   setting,
                                        GError **           error)
{
    const char *value;
    char        buf[32];
    int         port;

    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), FALSE);
    g_return_val_if_fail(setting != NULL, FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);

    if (!nm_supplicant_config_add_option(self, "macsec_policy", "1", -1, NULL, error))
        return FALSE;

    value = nm_setting_macsec_get_encrypt(setting) ? "0" : "1";
    if (!nm_supplicant_config_add_option(self, "macsec_integ_only", value, -1, NULL, error))
        return FALSE;

    port = nm_setting_macsec_get_port(setting);
    if (port > 0 && port < 65534) {
        snprintf(buf, sizeof(buf), "%d", port);
        if (!nm_supplicant_config_add_option(self, "macsec_port", buf, -1, NULL, error))
            return FALSE;
    }

    if (nm_setting_macsec_get_mode(setting) == NM_SETTING_MACSEC_MODE_PSK) {
        guint8 buffer_cak[NM_SETTING_MACSEC_MKA_CAK_LENGTH / 2];
        guint8 buffer_ckn[NM_SETTING_MACSEC_MKA_CKN_LENGTH / 2];

        if (!nm_supplicant_config_add_option(self, "key_mgmt", "NONE", -1, NULL, error))
            return FALSE;

        value = nm_setting_macsec_get_mka_cak(setting);
        if (!value || !nm_utils_hexstr2bin_buf(value, FALSE, FALSE, NULL, buffer_cak)) {
            g_set_error_literal(error,
                                NM_SUPPLICANT_ERROR,
                                NM_SUPPLICANT_ERROR_CONFIG,
                                value ? "invalid MKA CAK" : "missing MKA CAK");
            return FALSE;
        }
        if (!nm_supplicant_config_add_option(self,
                                             "mka_cak",
                                             (char *) buffer_cak,
                                             sizeof(buffer_cak),
                                             "<hidden>",
                                             error))
            return FALSE;

        value = nm_setting_macsec_get_mka_ckn(setting);
        if (!value || !nm_utils_hexstr2bin_buf(value, FALSE, FALSE, NULL, buffer_ckn)) {
            g_set_error_literal(error,
                                NM_SUPPLICANT_ERROR,
                                NM_SUPPLICANT_ERROR_CONFIG,
                                value ? "invalid MKA CKN" : "missing MKA CKN");
            return FALSE;
        }
        if (!nm_supplicant_config_add_option(self,
                                             "mka_ckn",
                                             (char *) buffer_ckn,
                                             sizeof(buffer_ckn),
                                             value,
                                             error))
            return FALSE;
    }

    return TRUE;
}

static const char scan_a_freq_str[] = {
    "5180 5200 5220 5240 "
    "5260 5280 5300 5320 "
    "5500 5520 5540 5560 "
    "5580 5600 5620 5640 "
    "5660 5680 5700 5720 "
    "5745 5765 5785 5805 5825"
};

static const char scan_bg_freq_str[] = {
    "2412 2417 2422 2427 2432 2437 2442 2447 2452 2457 2462 2467 "
    "2472 "
    "2484"
};

gboolean
nm_supplicant_config_add_setting_wireless(NMSupplicantConfig *self,
                                          NMSettingWireless * setting,
                                          guint32             fixed_freq,
                                          GError **           error)
{
    NMSupplicantConfigPrivate *priv;
    gboolean                   is_adhoc, is_ap, is_mesh;
    const char *               mode, *band;
    guint32                    channel;
    const char *frequency_list;
    GBytes *                   ssid;
    const char *               bssid;
    const char *client_name;

    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), FALSE);
    g_return_val_if_fail(setting != NULL, FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);

    priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE(self);

    mode     = nm_setting_wireless_get_mode(setting);
    is_adhoc = nm_streq0(mode, "adhoc");
    is_ap    = nm_streq0(mode, "ap");
    is_mesh  = nm_streq0(mode, "mesh");
    if (is_adhoc || is_ap)
        priv->ap_scan = 2;
    else
        priv->ap_scan = 1;

    if (_get_capability_laird(priv)) {
        priv->ccx = nm_setting_wireless_get_ccx (setting);
        priv->scan_delay = nm_setting_wireless_get_scan_delay (setting);
        priv->scan_dwell = nm_setting_wireless_get_scan_dwell (setting);
        priv->scan_passive_dwell = nm_setting_wireless_get_scan_passive_dwell (setting);
        priv->scan_suspend_time = nm_setting_wireless_get_scan_suspend_time (setting);
        priv->scan_roam_delta = nm_setting_wireless_get_scan_roam_delta (setting);
        priv->frequency_dfs = nm_setting_wireless_get_frequency_dfs (setting);
    }

    ssid = nm_setting_wireless_get_ssid(setting);
    if (!nm_supplicant_config_add_option(self,
                                         "ssid",
                                         (char *) g_bytes_get_data(ssid, NULL),
                                         g_bytes_get_size(ssid),
                                         NULL,
                                         error))
        return FALSE;

    if (is_adhoc) {
        if (!nm_supplicant_config_add_option(self, "mode", "1", -1, NULL, error))
            return FALSE;
    }

    if (is_ap) {
        if (!nm_supplicant_config_add_option(self, "mode", "2", -1, NULL, error))
            return FALSE;

        // LAIRD: disable wps for ap mode
        if (!nm_supplicant_config_add_option (self, "wps_disabled", "1", -1, NULL, error))
            return FALSE;

        if (nm_setting_wireless_get_hidden(setting)
            && !nm_supplicant_config_add_option(self,
                                                "ignore_broadcast_ssid",
                                                "1",
                                                -1,
                                                NULL,
                                                error))
            return FALSE;

        if (_get_capability_laird(priv)) {
            const char *ap_config_file;
            ap_config_file = nm_setting_wireless_get_ap_config_file(setting);
            if (ap_config_file) {
                if (!nm_supplicant_config_add_option (self,
                                                 "ap_config_file", ap_config_file,
                                                 -1, NULL, error))
                    return FALSE;
            }
        }
    }

    if (is_mesh) {
        if (!nm_supplicant_config_add_option(self, "mode", "5", -1, NULL, error))
            return FALSE;
    }

    if ((is_adhoc || is_ap || is_mesh) && fixed_freq) {
        gs_free char *str_freq = NULL;

        str_freq = g_strdup_printf("%u", fixed_freq);
        if (!nm_supplicant_config_add_option(self, "frequency", str_freq, -1, NULL, error))
            return FALSE;
    }

    /* Except for Ad-Hoc, Hotspot and Mesh, request that the driver probe for the
     * specific SSID we want to associate with.
     */
    if (!(is_adhoc || is_ap || is_mesh)) {
        if (!nm_supplicant_config_add_option(self, "scan_ssid", "1", -1, NULL, error))
            return FALSE;
    }

    bssid = nm_setting_wireless_get_bssid(setting);
    if (bssid) {
        if (!nm_supplicant_config_add_option(self, "bssid", bssid, strlen(bssid), NULL, error))
            return FALSE;
    }

    band    = nm_setting_wireless_get_band(setting);
    channel = nm_setting_wireless_get_channel(setting);
    frequency_list = nm_setting_wireless_get_frequency_list (setting);
    if (frequency_list) {
        if (!nm_supplicant_config_add_option (self, "freq_list", frequency_list, -1, NULL, error))
                return FALSE;
        if (_get_capability_laird(priv)) {
            // only summit; sterling may reject scan if unsupported frequencies
            if (!nm_supplicant_config_add_option (self, "scan_freq", frequency_list, -1, NULL, error))
                return FALSE;
        }
    } else
    if (band) {
        if (channel) {
            const char *width;
            guint32       freq;
            gs_free char *str_freq = NULL;

            freq     = nm_utils_wifi_channel_to_freq(channel, band);
            str_freq = g_strdup_printf("%u", freq);
            if (!nm_supplicant_config_add_option(self, "freq_list", str_freq, -1, NULL, error))
                return FALSE;
            if (_get_capability_laird(priv)) {
                // only summit; sterling may reject scan if invalid frequencies
                if (!nm_supplicant_config_add_option (self, "scan_freq", str_freq, -1, NULL, error))
                    return FALSE;
            }
            width = nm_setting_wireless_get_channel_width (setting);
            if (!nm_supplicant_config_add_channel_width(self, band, channel, width, error))
                return FALSE;
        } else {
            const char *freqs = NULL;
            const char *scan_freqs = NULL;
            if (nm_streq(band, "a"))
            {
                freqs = wifi_freqs_to_string(FALSE);
                scan_freqs = scan_a_freq_str;
            }
            else if (nm_streq(band, "bg"))
            {
                freqs = wifi_freqs_to_string(TRUE);
                scan_freqs = scan_bg_freq_str;
            }

            if (freqs
                && !nm_supplicant_config_add_option(self,
                                                    "freq_list",
                                                    freqs,
                                                    strlen(freqs),
                                                    NULL,
                                                    error))
                return FALSE;
            if (_get_capability_laird(priv)) {
                // only summit; sterling may reject scan if invalid frequencies
                if (scan_freqs && !nm_supplicant_config_add_option (self, "scan_freq", scan_freqs, strlen (scan_freqs), NULL, error))
                    return FALSE;
            }
        }
    }

    if (priv->ccx) {
        client_name = nm_setting_wireless_get_client_name (setting);
        if (client_name)
            if (!nm_supplicant_config_add_option (self, "laird_ccx_client_name", client_name, strlen (client_name), NULL, error))
                return FALSE;
    }

    if (_get_capability_laird(priv)) {
        guint32 auth_timeout;
        auth_timeout = nm_setting_wireless_get_auth_timeout (setting);
        if (auth_timeout) {
            char buf[32];
            snprintf (buf, sizeof (buf), "%d", auth_timeout);
            if (!nm_supplicant_config_add_option (self, "laird_auth_timeout", buf, -1, NULL, error))
                return FALSE;
        }
    }

    if (_get_capability_laird(priv)) {
        guint32 dms;
        dms = nm_setting_wireless_get_dms (setting);
        if (dms) {
            char buf[32];
            snprintf (buf, sizeof (buf), "%d", dms);
            if (!nm_supplicant_config_add_option (self, "dms", buf, -1, NULL, error))
                return FALSE;
        }
    }

    if (_get_capability_laird(priv)) {
        guint32 acs;
        acs = nm_setting_wireless_get_acs (setting);
        if (acs) {
            char buf[32];
            snprintf (buf, sizeof (buf), "%d", acs);
            if (!nm_supplicant_config_add_option (self, "acs", buf, -1, NULL, error))
                return FALSE;
        }
    }

    return TRUE;
}

gboolean
nm_supplicant_config_add_bgscan(NMSupplicantConfig *self, NMConnection *connection, GError **error)
{
    NMSettingWireless *        s_wifi;
    NMSettingWirelessSecurity *s_wsec;
    const char *               bgscan;

    s_wifi = nm_connection_get_setting_wireless(connection);
    g_assert(s_wifi);

    /* Don't scan when a shared connection (either AP or Ad-Hoc) is active;
     * it will disrupt connected clients.
     */
    if (NM_IN_STRSET(nm_setting_wireless_get_mode(s_wifi),
                     NM_SETTING_WIRELESS_MODE_AP,
                     NM_SETTING_WIRELESS_MODE_ADHOC))
        return TRUE;

    /* Don't scan when the connection is locked to a specific AP, since
     * intra-ESS roaming (which requires periodic scanning) isn't being
     * used due to the specific AP lock. (bgo #513820)
     */
    if (nm_setting_wireless_get_bssid(s_wifi))
        return TRUE;

    /* Laird: bgscan from configuration */
    {
        bgscan = nm_setting_wireless_get_bgscan (s_wifi);
        if (bgscan) {
            return nm_supplicant_config_add_option (self, "bgscan", bgscan, -1, FALSE, error);
        }
    }

    /* Default to a very long bgscan interval when signal is OK on the assumption
     * that either (a) there aren't multiple APs and we don't need roaming, or
     * (b) since EAP/802.1x isn't used and thus there are fewer steps to fail
     * during a roam, we can wait longer before scanning for roam candidates.
     */
    bgscan = "simple:30:-70:86400";

    /* If using WPA Enterprise, Dynamic WEP or we have seen more than one AP use
     * a shorter bgscan interval on the assumption that this is a multi-AP ESS
     * in which we want more reliable roaming between APs. Thus trigger scans
     * when the signal is still somewhat OK so we have an up-to-date roam
     * candidate list when the signal gets bad.
     */
    if (nm_setting_wireless_get_num_seen_bssids(s_wifi) > 1
        || ((s_wsec = nm_connection_get_setting_wireless_security(connection))
            && NM_IN_STRSET(nm_setting_wireless_security_get_key_mgmt(s_wsec),
                            "ieee8021x",
                            "cckm",
                            "wpa-eap-suite-b",
                            "wpa-eap",
                            "wpa-eap-suite-b-192")))
        bgscan = "simple:30:-65:300";

    return nm_supplicant_config_add_option(self, "bgscan", bgscan, -1, FALSE, error);
}

static gboolean
add_string_val(NMSupplicantConfig *self,
               const char *        field,
               const char *        name,
               gboolean            ucase,
               const char *        display_value,
               GError **           error)
{
    if (field) {
        gs_free char *value = NULL;

        if (ucase) {
            value = g_ascii_strup(field, -1);
            field = value;
        }
        return nm_supplicant_config_add_option(self,
                                               name,
                                               field,
                                               strlen(field),
                                               display_value,
                                               error);
    }
    return TRUE;
}

// Laird: Upstream 1.32.0 moved _NMSetting8021x from nm-setting-8021x.h to nm-setting-8021x.c, making it inaccessible.
// src/core/supplicant/nm-supplicant-config.c:1023:17: error: dereferencing pointer to incomplete type ‘NMSetting8021x {aka struct _NMSetting8021x}’
struct _NMSetting8021x {
    struct parent;
};

#define ADD_STRING_LIST_VAL(self,                                                         \
                            setting,                                                      \
                            setting_name,                                                 \
                            field,                                                        \
                            field_plural,                                                 \
                            name,                                                         \
                            separator,                                                    \
                            ucase,                                                        \
                            display_value,                                                \
                            error)                                                        \
    ({                                                                                    \
        typeof(setting) _setting = (setting);                                             \
        gboolean        _success = TRUE;                                                  \
                                                                                          \
        if (nm_setting_##setting_name##_get_num_##field_plural(_setting)) {               \
            const char _separator = (separator);                                          \
            GString *  _str       = g_string_new(NULL);                                   \
            guint      _k, _n;                                                            \
                                                                                          \
            _n = nm_setting_##setting_name##_get_num_##field_plural(_setting);            \
            for (_k = 0; _k < _n; _k++) {                                                 \
                const char *item = nm_setting_##setting_name##_get_##field(_setting, _k); \
                                                                                          \
                if (!_str->len) {                                                         \
                    g_string_append(_str, item);                                          \
                } else {                                                                  \
                    g_string_append_c(_str, _separator);                                  \
                    g_string_append(_str, item);                                          \
                }                                                                         \
            }                                                                             \
            if ((ucase))                                                                  \
                g_string_ascii_up(_str);                                                  \
            if (_str->len) {                                                              \
                if (!nm_supplicant_config_add_option((self),                              \
                                                     (name),                              \
                                                     _str->str,                           \
                                                     -1,                                  \
                                                     (display_value),                     \
                                                     (error)))                            \
                    _success = FALSE;                                                     \
            }                                                                             \
            g_string_free(_str, TRUE);                                                    \
        }                                                                                 \
        _success;                                                                         \
    })


#define ADD_STRING_LIST_VAL_TO_STRING(_str, setting, setting_name, field, field_plural, name, separator, ucase, secret, error) \
    ({ \
        typeof (*(setting)) *_setting = (setting); \
        gboolean _success = TRUE; \
        \
        if (nm_setting_##setting_name##_get_num_##field_plural (_setting)) { \
            const char _separator = (separator); \
            guint _k, _n; \
            \
            _n = nm_setting_##setting_name##_get_num_##field_plural (_setting); \
            for (_k = 0; _k < _n; _k++) { \
                const char *item = nm_setting_##setting_name##_get_##field (_setting, _k); \
                GString *temp = g_string_new (NULL); \
                g_string_append_printf(temp,"%s",item); \
                \
                if ((ucase)) \
                    g_string_ascii_up (temp); \
                \
                if (!_str->len) { \
                    g_string_append_printf (_str, "%s=%s",name,temp->str); \
                } else { \
                    g_string_append_c (_str, _separator); \
                    g_string_append_printf (_str, "%s=%s",name,temp->str); \
                } \
                g_string_free (temp, TRUE); \
            } \
        } \
        _success; \
    })


static void
wep128_passphrase_hash(const char *input, gsize input_len, guint8 *digest /* 13 bytes */)
{
    nm_auto_free_checksum GChecksum *sum = NULL;
    guint8                           md5[NM_UTILS_CHECKSUM_LENGTH_MD5];
    guint8                           data[64];
    int                              i;

    nm_assert(input);
    nm_assert(input_len);
    nm_assert(digest);

    /* Get at least 64 bytes by repeating the passphrase into the buffer */
    for (i = 0; i < sizeof(data); i++)
        data[i] = input[i % input_len];

    sum = g_checksum_new(G_CHECKSUM_MD5);
    g_checksum_update(sum, data, sizeof(data));
    nm_utils_checksum_get_digest(sum, md5);

    /* WEP104 keys are 13 bytes in length (26 hex characters) */
    memcpy(digest, md5, 13);
}

static gboolean
add_wep_key(NMSupplicantConfig *self,
            const char *        key,
            const char *        name,
            NMWepKeyType        wep_type,
            GError **           error)
{
    gsize key_len;

    if (!key || (key_len = strlen(key)) == 0)
        return TRUE;

    if (wep_type == NM_WEP_KEY_TYPE_UNKNOWN) {
        if (nm_utils_wep_key_valid(key, NM_WEP_KEY_TYPE_KEY))
            wep_type = NM_WEP_KEY_TYPE_KEY;
        else if (nm_utils_wep_key_valid(key, NM_WEP_KEY_TYPE_PASSPHRASE))
            wep_type = NM_WEP_KEY_TYPE_PASSPHRASE;
    }

    if ((wep_type == NM_WEP_KEY_TYPE_UNKNOWN) || (wep_type == NM_WEP_KEY_TYPE_KEY)) {
        if ((key_len == 10) || (key_len == 26)) {
            guint8 buffer[26 / 2];

            if (!nm_utils_hexstr2bin_full(key,
                                          FALSE,
                                          FALSE,
                                          FALSE,
                                          NULL,
                                          key_len / 2,
                                          buffer,
                                          sizeof(buffer),
                                          NULL)) {
                g_set_error(error,
                            NM_SUPPLICANT_ERROR,
                            NM_SUPPLICANT_ERROR_CONFIG,
                            "cannot add wep-key %s to supplicant config because key is not hex",
                            name);
                return FALSE;
            }
            if (!nm_supplicant_config_add_option(self,
                                                 name,
                                                 (char *) buffer,
                                                 key_len / 2,
                                                 "<hidden>",
                                                 error))
                return FALSE;
        } else if ((key_len == 5) || (key_len == 13)) {
            if (!nm_supplicant_config_add_option(self, name, key, key_len, "<hidden>", error))
                return FALSE;
        } else {
            g_set_error(
                error,
                NM_SUPPLICANT_ERROR,
                NM_SUPPLICANT_ERROR_CONFIG,
                "Cannot add wep-key %s to supplicant config because key-length %u is invalid",
                name,
                (guint) key_len);
            return FALSE;
        }
    } else if (wep_type == NM_WEP_KEY_TYPE_PASSPHRASE) {
        guint8 digest[13];

        wep128_passphrase_hash(key, key_len, digest);
        if (!nm_supplicant_config_add_option(self,
                                             name,
                                             (const char *) digest,
                                             sizeof(digest),
                                             "<hidden>",
                                             error))
            return FALSE;
    }

    return TRUE;
}

static gboolean
has_proto (NMSettingWirelessSecurity *s_wsec, const char *proto)
{
    int i;

    for (i = 0; i < nm_setting_wireless_security_get_num_protos (s_wsec); i++) {
        if (g_strcmp0 (proto, nm_setting_wireless_security_get_proto (s_wsec, i)) == 0)
            return TRUE;
    }
    return FALSE;
}

static gboolean
has_proto_only (NMSettingWirelessSecurity *s_wsec, const char *proto)
{
    if (1 != nm_setting_wireless_security_get_num_protos (s_wsec))
        return FALSE;
    return has_proto (s_wsec, proto);
}

gboolean
nm_supplicant_config_add_setting_wireless_security(NMSupplicantConfig *          self,
                                                   NMSettingWireless *           setting_wireless,
                                                   NMSettingWirelessSecurity *   setting,
                                                   NMSetting8021x *              setting_8021x,
                                                   const char *                  con_uuid,
                                                   guint32                       mtu,
                                                   NMSettingWirelessSecurityPmf  pmf,
                                                   NMSettingWirelessSecurityFils fils,
                                                   NMSettingWirelessSecurityFt   ft,
                                                   GError **                     error)
{
    NMSupplicantConfigPrivate *priv             = NM_SUPPLICANT_CONFIG_GET_PRIVATE(self);
    nm_auto_free_gstring GString *key_mgmt_conf = NULL;
    const char *                  key_mgmt, *auth_alg;
    const char *                  psk;
    gboolean                      set_pmf, wps_disabled;
    gboolean                      wpa3_only;
    const char *mode;
    gboolean is_ap;

    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), FALSE);
	g_return_val_if_fail (setting_wireless != NULL, FALSE);
    g_return_val_if_fail(setting != NULL, FALSE);
    g_return_val_if_fail(con_uuid != NULL, FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);

    mode = nm_setting_wireless_get_mode (setting_wireless);
    is_ap = (mode && !strcmp (mode, "ap")) ? TRUE : FALSE;

    wpa3_only = has_proto_only(setting, "wpa3");

    /* Check if we actually support FILS */
    if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT)
        fils = NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE;
    if (!_get_capability(priv, NM_SUPPL_CAP_TYPE_FILS)) {
        if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED) {
            g_set_error_literal(error,
                                NM_SUPPLICANT_ERROR,
                                NM_SUPPLICANT_ERROR_CONFIG,
                                "Supplicant does not support FILS");
            return FALSE;
        } else if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_OPTIONAL)
            fils = NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE;
    }

    /* Check if we actually support FT */
    if (ft == NM_SETTING_WIRELESS_SECURITY_FT_DEFAULT)
        ft = NM_SETTING_WIRELESS_SECURITY_FT_OPTIONAL;
    if (!_get_capability (priv, NM_SUPPL_CAP_TYPE_FT)) {
        if (ft == NM_SETTING_WIRELESS_SECURITY_FT_REQUIRED) {
            g_set_error_literal (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
                                 "Supplicant does not support FT");
            return FALSE;
        } else if (ft == NM_SETTING_WIRELESS_SECURITY_FT_OPTIONAL)
            ft = NM_SETTING_WIRELESS_SECURITY_FT_DISABLE;
    }

    key_mgmt      = nm_setting_wireless_security_get_key_mgmt(setting);

    // override pmf setting if necessary
    if (pmf == NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT)
        pmf = NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL;
    if (NM_IN_STRSET (key_mgmt, "sae", "wpa-eap-suite-b", "wpa-eap-suite-b-192"))
    {
        // pmf required for suite-b and sae
        pmf = NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED;
    }
    else if (wpa3_only) {

        /* wpa3/wpa-psk (wpa3-sae transition): default to pmf optional */
        /* wpa3/other: pmf required */
        if (NM_IN_STRSET (key_mgmt, "wpa-psk")) {
            // wpa3-sae transition mode: default to pmf optional
            if (pmf != NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED)
                pmf = NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL;
        } else {
            // wpa3: pmf required
            pmf = NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED;
        }
    }
    else
    /* Don't try to enable PMF on non-WPA/SAE networks */
    if (!NM_IN_STRSET (key_mgmt, "wpa-eap", "wpa-psk", "sae", "owe", "owe-only"))
        pmf = NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE;

    /* Check if we actually support PMF */
    set_pmf = TRUE;
    if (!_get_capability (priv, NM_SUPPL_CAP_TYPE_PMF)) {
        if (pmf == NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED) {
            g_set_error_literal (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
                                 "Supplicant does not support PMF");
            return FALSE;
        }
        if (wpa3_only) {
            g_set_error_literal (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
                                 "Supplicant does not support PMF.  Required for wpa3.");
            return FALSE;
        }
        if (fils != NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE) {
            g_set_error_literal (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
                                 "Supplicant does not support PMF.  Required for fils.");
            return FALSE;
        }

        pmf = NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE;
        set_pmf = FALSE;
    }

    key_mgmt_conf = g_string_new("");

    if (nm_streq(key_mgmt, "none")) {
        g_string_append(key_mgmt_conf, "NONE");

    } else if (nm_streq(key_mgmt, "ieee8021x")) {
        g_string_append(key_mgmt_conf, "IEEE8021X");

    } else if (NM_IN_STRSET (key_mgmt, "owe", "owe-only")) {
        pmf = NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED;

        g_string_append(key_mgmt_conf, "OWE");

    } else if (nm_streq(key_mgmt, "wpa-psk")) {
        // if (pmf != NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED)
            g_string_append(key_mgmt_conf, "WPA-PSK");
        if (pmf != NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE)
            g_string_append(key_mgmt_conf, " WPA-PSK-SHA256");

#if 1
        // BZ19892 -- do not enable SAE for wpa-psk (except wpa3 sae-transition)
        // makes behavior consistent with previous release
        // use wifi-sec.key-mgmt "sae" if needed
#else
        if (_get_capability(priv, NM_SUPPL_CAP_TYPE_SAE) &&
            pmf != NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE) {
            g_string_append(key_mgmt_conf, " SAE");
            if (ft != NM_SETTING_WIRELESS_SECURITY_FT_DISABLE)
                g_string_append(key_mgmt_conf, " FT-SAE");
        }
#endif

        // wpa3-psk: must also enable sae
        if (wpa3_only)
            g_string_append (key_mgmt_conf, " SAE");
        if (ft != NM_SETTING_WIRELESS_SECURITY_FT_DISABLE) {
            // Only FT modes should present when in required state
            if (ft == NM_SETTING_WIRELESS_SECURITY_FT_REQUIRED)
                g_string_truncate (key_mgmt_conf, 0);

            g_string_append(key_mgmt_conf, " FT-PSK");

            // wpa3-psk: must also enable sae
            if (wpa3_only)
                g_string_append (key_mgmt_conf, " FT-SAE");
        }
    /* LAIRD: use the ft variable instead of checking capability, to allow disabling ft via configuration */
    } else if (nm_streq(key_mgmt, "sae")) {
        pmf = NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED;

        g_string_append(key_mgmt_conf, "SAE");
        if (ft != NM_SETTING_WIRELESS_SECURITY_FT_DISABLE)
            g_string_append(key_mgmt_conf, " FT-SAE");
    } else if (nm_streq(key_mgmt, "wpa-eap")) {
        // if (pmf != NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED)
            g_string_append(key_mgmt_conf, "WPA-EAP");
        bool add_ft = true, add_fils = true, add_fils_ft = true;
        if (pmf != NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE) {
            g_string_append(key_mgmt_conf, " WPA-EAP-SHA256");
            if (_get_capability(priv, NM_SUPPL_CAP_TYPE_SUITEB192)
                && pmf == NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED)
                g_string_append(key_mgmt_conf, " WPA-EAP-SUITE-B-192");
        }
        if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE ||
            pmf == NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE) {
            add_fils = add_fils_ft = false;
        }
        if (ft == NM_SETTING_WIRELESS_SECURITY_FT_DISABLE) {
            add_ft = add_fils_ft = false;
        }
        if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED &&
            ft == NM_SETTING_WIRELESS_SECURITY_FT_REQUIRED)
        {
            add_fils = add_ft = false;
        }
        if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED ||
            ft == NM_SETTING_WIRELESS_SECURITY_FT_REQUIRED)
        {
            g_string_truncate (key_mgmt_conf, 0); 
        }
        if (add_ft) {
            g_string_append(key_mgmt_conf, " ft-eap"); 
            if (_get_capability (priv, NM_SUPPL_CAP_TYPE_SHA384))
                g_string_append(key_mgmt_conf, " ft-eap-sha384");
        }
        if (add_fils) {
            g_string_append (key_mgmt_conf, " FILS-SHA256");
            if (_get_capability (priv, NM_SUPPL_CAP_TYPE_SHA384))
                g_string_append(key_mgmt_conf, " FILS-SHA256 FILS-SHA384");
        }
        if (add_fils_ft) {
                    g_string_append(key_mgmt_conf, " FT-FILS-SHA256");
            if (_get_capability (priv, NM_SUPPL_CAP_TYPE_SHA384))
                        g_string_append(key_mgmt_conf, " FT-FILS-SHA384");

        }
    } else if (nm_streq(key_mgmt, "wpa-eap-suite-b-192")) {
        pmf = NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED;

        g_string_append(key_mgmt_conf, "WPA-EAP-SUITE-B-192");
        if (ft != NM_SETTING_WIRELESS_SECURITY_FT_DISABLE
            && _get_capability(priv, NM_SUPPL_CAP_TYPE_SHA384))
            g_string_append(key_mgmt_conf, " FT-EAP-SHA384");
#if 1
        // BZ19994 -- pairwise/group are set below -- do not set here
#else
        if (!nm_supplicant_config_add_option(self, "pairwise", "GCMP-256", -1, NULL, error)
            || !nm_supplicant_config_add_option(self, "group", "GCMP-256", -1, NULL, error))
            return FALSE;
#endif
    } else if (nm_streq(key_mgmt, "wpa-eap-suite-b")) {
        g_string_append(key_mgmt_conf, "WPA-EAP-SUITE-B");
    } else if (nm_streq(key_mgmt, "cckm")) {
        g_string_append(key_mgmt_conf, "CCKM");
    } else if (nm_streq (key_mgmt, "open")) {
        g_string_append(key_mgmt_conf, "OPEN");
        // wpa3-open: must use owe
        if (wpa3_only) {
            g_string_truncate (key_mgmt_conf, 0);
            g_string_append (key_mgmt_conf, "OWE");
        }
    }

    if (!add_string_val(self, key_mgmt_conf->str, "key_mgmt", TRUE, NULL, error))
        return FALSE;

    if (nm_streq (key_mgmt, "owe-only")) {
        if (!add_string_val (self, "1", "owe_only", TRUE, NULL, error))
            return FALSE;
    }

    auth_alg = nm_setting_wireless_security_get_auth_alg(setting);
    if (!add_string_val(self, auth_alg, "auth_alg", TRUE, NULL, error))
        return FALSE;

    psk = nm_setting_wireless_security_get_psk(setting);
    if (psk) {
        size_t psk_len = strlen(psk);

        if (psk_len >= 8 && psk_len <= 63) {
            /* Use NM_SUPPL_OPT_TYPE_STRING here so that it gets pushed to the
             * supplicant as a string, and therefore gets quoted,
             * and therefore the supplicant will interpret it as a
             * passphrase and not a hex key.
             */
            if (!nm_supplicant_config_add_option_with_type(self,
                                                           "psk",
                                                           psk,
                                                           -1,
                                                           NM_SUPPL_OPT_TYPE_STRING,
                                                           "<hidden>",
                                                           error))
                return FALSE;
        } else if (nm_streq(key_mgmt, "sae")) {
            /* If the SAE password doesn't comply with WPA-PSK limitation,
             * we need to call it "sae_password" instead of "psk".
             */
            if (!nm_supplicant_config_add_option_with_type(self,
                                                           "sae_password",
                                                           psk,
                                                           -1,
                                                           NM_SUPPL_OPT_TYPE_STRING,
                                                           "<hidden>",
                                                           error))
                return FALSE;
        } else if (psk_len == 64) {
            guint8 buffer[32];

            /* Hex PSK */
            if (!nm_utils_hexstr2bin_buf(psk, FALSE, FALSE, NULL, buffer)) {
                g_set_error(error,
                            NM_SUPPLICANT_ERROR,
                            NM_SUPPLICANT_ERROR_CONFIG,
                            "Cannot add psk to supplicant config due to invalid hex");
                return FALSE;
            }
            if (!nm_supplicant_config_add_option(self,
                                                 "psk",
                                                 (char *) buffer,
                                                 sizeof(buffer),
                                                 "<hidden>",
                                                 error))
                return FALSE;
        } else {
            g_set_error(error,
                        NM_SUPPLICANT_ERROR,
                        NM_SUPPLICANT_ERROR_CONFIG,
                        "Cannot add psk to supplicant config due to invalid PSK length %u (not "
                        "between 8 and 63 characters)",
                        (guint) psk_len);
            return FALSE;
        }
    }

    /* Don't try to enable PMF on non-WPA/SAE/OWE networks */
    if (NM_IN_STRSET(key_mgmt, "wpa-psk", "wpa-eap", "wpa-eap-suite-b", "wpa-eap-suite-b-192", "cckm",
        "sae", "owe", "owe-only") || wpa3_only)
    {
        const char *_pairwise = NULL;
        const char *_group = NULL;
        const char *_group_mgmt = NULL;

        if (wpa3_only) {
            if (!strcmp (key_mgmt, "wpa-eap-suite-b")) {
                // suite-b: GCMP/BIP-GMAC (same as wpa2 mode)
                _pairwise = "GCMP";
                _group = "GCMP";
                _group_mgmt = "BIP-GMAC-128";
            } else if (!strcmp (key_mgmt, "wpa-eap-suite-b-192")) {
                // wpa3-enterprise-192: GCMP-256/BIP-GMAC-256, PMF required
                _pairwise = "GCMP-256";
                _group = "GCMP-256";
                _group_mgmt = "BIP-GMAC-256";
            } else {
                // wpa3: no wep/tkip
                _pairwise = "CCMP CCMP-256 GCMP GCMP-256";
                _group = "CCMP CCMP-256 GCMP GCMP-256";
                _group_mgmt = "AES-128-CMAC BIP-CMAC-256 BIP-GMAC-128 BIP-GMAC-256";
            }
            // use "WPA3" so sae-transition will use pmf for sae
            if (!nm_supplicant_config_add_option (self, "proto", "WPA3", -1, NULL, error))
                return FALSE;
        } else {
            if (!strcmp (key_mgmt, "wpa-eap-suite-b")) {
                // suite-b: GCMP/BIP-GMAC
                _pairwise = "GCMP";
                _group = "GCMP";
                _group_mgmt = "BIP-GMAC-128";
            } else if (!strcmp (key_mgmt, "wpa-eap-suite-b-192")) {
                // suite-b-192: CCMP-256/GCMP-256/BIP-CMAC-256/BIP-GMAC-256, PMF required
                _pairwise = "CCMP-256 GCMP-256";
                _group = "CCMP-256 GCMP-256";
                _group_mgmt = "BIP-CMAC-256 BIP-GMAC-256";
            }
            if (!ADD_STRING_LIST_VAL (self, setting, wireless_security, proto, protos, "proto", ' ', TRUE, NULL, error))
                return FALSE;
        } 

        if (nm_setting_wireless_security_get_num_pairwise (setting) == 0) {
            if (_pairwise && !nm_supplicant_config_add_option (self, "pairwise", _pairwise, -1, NULL, error))
                return FALSE;
        } else
            if (!ADD_STRING_LIST_VAL(self,
                                     setting,
                                     wireless_security,
                                     pairwise,
                                     pairwise,
                                     "pairwise",
                                     ' ',
                                     TRUE,
                                     NULL,
                                     error))
                return FALSE;

        if (nm_setting_wireless_security_get_num_groups (setting) == 0) {
            if (_group && !nm_supplicant_config_add_option (self, "group", _group, -1, NULL, error))
                return FALSE;
        } else
            if (!ADD_STRING_LIST_VAL(self,
                                     setting,
                                     wireless_security,
                                     group,
                                     groups,
                                     "group",
                                     ' ',
                                     TRUE,
                                     NULL,
                                     error))
                return FALSE;

        if (_group_mgmt && !nm_supplicant_config_add_option (self, "group_mgmt", _group_mgmt, -1, NULL, error))
            return FALSE;

        if (wpa3_only) {
            // pmf: was set to required, or optional above
            if (!nm_supplicant_config_add_option (self,
                                                  "ieee80211w",
                                                  pmf == NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL ? "1" : "2",
                                                  -1,
                                                  NULL,
                                                  error))
                return FALSE;
        } else
        if (set_pmf
            && NM_IN_SET(pmf,
                         NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE,
                         NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED)) {
            if (!nm_supplicant_config_add_option(
                    self,
                    "ieee80211w",
                    pmf == NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE ? "0" : "2",
                    -1,
                    NULL,
                    error))
                return FALSE;
        }
    }

    /* WEP keys if required */
    if (nm_streq(key_mgmt, "none")) {
        NMWepKeyType wep_type = nm_setting_wireless_security_get_wep_key_type(setting);
        const char * wep0     = nm_setting_wireless_security_get_wep_key(setting, 0);
        const char * wep1     = nm_setting_wireless_security_get_wep_key(setting, 1);
        const char * wep2     = nm_setting_wireless_security_get_wep_key(setting, 2);
        const char * wep3     = nm_setting_wireless_security_get_wep_key(setting, 3);

        if (!add_wep_key(self, wep0, "wep_key0", wep_type, error))
            return FALSE;
        if (!add_wep_key(self, wep1, "wep_key1", wep_type, error))
            return FALSE;
        if (!add_wep_key(self, wep2, "wep_key2", wep_type, error))
            return FALSE;
        if (!add_wep_key(self, wep3, "wep_key3", wep_type, error))
            return FALSE;

        if (wep0 || wep1 || wep2 || wep3) {
            gs_free char *value = NULL;

            value = g_strdup_printf("%d", nm_setting_wireless_security_get_wep_tx_keyidx(setting));
            if (!nm_supplicant_config_add_option(self, "wep_tx_keyidx", value, -1, NULL, error))
                return FALSE;
        }
    }

    if (nm_streq0(auth_alg, "leap")) {
        /* LEAP */
        if (nm_streq(key_mgmt, "ieee8021x")) {
            const char *tmp;

            tmp = nm_setting_wireless_security_get_leap_username(setting);
            if (!add_string_val(self, tmp, "identity", FALSE, NULL, error))
                return FALSE;

            tmp = nm_setting_wireless_security_get_leap_password(setting);
            if (!add_string_val(self, tmp, "password", FALSE, "<hidden>", error))
                return FALSE;

            if (!add_string_val(self, "leap", "eap", TRUE, NULL, error))
                return FALSE;
        } else {
            g_set_error(error,
                        NM_SUPPLICANT_ERROR,
                        NM_SUPPLICANT_ERROR_CONFIG,
                        "Invalid key-mgmt \"%s\" for leap",
                        key_mgmt);
            return FALSE;
        }
    } else {
        /* 802.1x for Dynamic WEP and WPA-Enterprise */
        if (NM_IN_STRSET(key_mgmt, "ieee8021x", "wpa-eap", "cckm", "wpa-eap-suite-b", "wpa-eap-suite-b-192")) {
            if (is_ap && _get_capability_laird(priv)) {
                ; // ap mode: summit supplicant support with ap-config-file
                if (!strcmp (key_mgmt, "cckm"))
                {
                    // ap mode: cckm is not allowed
                    g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
                                 "Invalid key-mgmt \"%s\" for AP mode", key_mgmt);
                    return FALSE;
                }
            } else
            if (!setting_8021x) {
                g_set_error(error,
                            NM_SUPPLICANT_ERROR,
                            NM_SUPPLICANT_ERROR_CONFIG,
                            "Cannot set key-mgmt %s with missing 8021x setting",
                            key_mgmt);
                return FALSE;
            }
            if (NM_IN_STRSET(key_mgmt, "wpa-eap-suite-b", "wpa-eap-suite-b-192"))
            {
                priv->flags1x.suiteb = TRUE;
            } else {
                priv->flags1x.suiteb = FALSE;
            }
            if (wpa3_only) {
                priv->flags1x.ca_cert_check = TRUE;
            } else {
                priv->flags1x.ca_cert_check = FALSE;
            }
            if (is_ap && _get_capability_laird(priv)) {
                ; // ap mode: summit supplicant support with ap-config-file
            } else
            if (!nm_supplicant_config_add_setting_8021x(self,
                                                        setting_8021x,
                                                        con_uuid,
                                                        mtu,
                                                        FALSE,
                                                        error))
                return FALSE;
        }

        if (NM_IN_STRSET(key_mgmt, "wpa-eap", "cckm", "wpa-eap-suite-b", "wpa-eap-suite-b-192")) {
            /* When using WPA-Enterprise, we want to use Proactive Key Caching (also
             * called Opportunistic Key Caching) to avoid full EAP exchanges when
             * roaming between access points in the same mobility group.
             */
            const char* proactive_key_caching = nm_setting_wireless_security_get_proactive_key_caching (setting);
            if (!add_string_val (self, proactive_key_caching, "proactive_key_caching", TRUE, FALSE, error)) {
                if (!nm_supplicant_config_add_option(self,
                                                     "proactive_key_caching",
                                                     "1",
                                                     -1,
                                                     NULL,
                                                     error))
                    return FALSE;
            }
        }
    }

    wps_disabled = (nm_setting_wireless_security_get_wps_method(setting)
                    == NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED);
    if (wps_disabled) {
        if (!nm_supplicant_config_add_option(self, "wps_disabled", "1", 1, NULL, error))
            return FALSE;
    }

    return TRUE;
}

static gboolean
add_pkcs11_uri_with_pin(NMSupplicantConfig *       self,
                        const char *               name,
                        const char *               uri,
                        const char *               pin,
                        const NMSettingSecretFlags pin_flags,
                        GError **                  error)
{
    gs_strfreev char **split     = NULL;
    gs_free char *     tmp       = NULL;
    gs_free char *     tmp_log   = NULL;
    gs_free char *     pin_qattr = NULL;
    char *             escaped   = NULL;

    if (uri == NULL)
        return TRUE;

    /* We ignore the attributes -- RFC 7512 suggests that some of them
     * might be unsafe and we want to be on the safe side. Also, we're
     * installing our attributes, so this makes things a bit easier for us. */
    split = g_strsplit(uri, "&", 2);
    if (split[1])
        nm_log_info(LOGD_SUPPLICANT, "URI attributes ignored");

    /* Fill in the PIN if required. */
    if (pin) {
        escaped   = g_uri_escape_string(pin, NULL, TRUE);
        pin_qattr = g_strdup_printf("pin-value=%s", escaped);
        g_free(escaped);
    } else if (!(pin_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
        /* Include an empty PIN to indicate the login is still needed.
         * Probably a token that has a PIN path and the actual PIN will
         * be entered using a protected path. */
        pin_qattr = g_strdup("pin-value=");
    }

    tmp = g_strdup_printf("%s%s%s", split[0], (pin_qattr ? "?" : ""), (pin_qattr ?: ""));

    tmp_log = g_strdup_printf("%s%s%s",
                              split[0],
                              (pin_qattr ? "?" : ""),
                              (pin_qattr ? "pin-value=<hidden>" : ""));

    return add_string_val(self, tmp, name, FALSE, tmp_log, error);
}

gboolean
nm_supplicant_config_add_setting_8021x(NMSupplicantConfig *self,
                                       NMSetting8021x *    setting,
                                       const char *        con_uuid,
                                       guint32             mtu,
                                       gboolean            wired,
                                       GError **           error)
{
    NMSupplicantConfigPrivate *priv;
    char *                     tmp;
    const char *               peapver, *value, *path;
    gboolean                   added;
    GString *                  phase1, *phase2;
    GBytes *                   bytes;
    gboolean                   fast = FALSE;
    guint32                    i, num_eap;
    gboolean                   fast_provisoning_allowed = FALSE;
    const char *               ca_path_override = NULL, *ca_cert_override = NULL;
    guint32                    frag, hdrs;
    gs_free char *             frag_str = NULL;
    NMSetting8021xAuthFlags    phase1_auth_flags;
    nm_auto_free_gstring GString *eap_str = NULL;
    char const *tls_disable = NULL;
    int ca_cert_needed = 0;
    int ca_cert_configured = 0;

    g_return_val_if_fail(NM_IS_SUPPLICANT_CONFIG(self), FALSE);
    g_return_val_if_fail(setting != NULL, FALSE);
    g_return_val_if_fail(con_uuid != NULL, FALSE);

    priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE(self);

    value = nm_setting_802_1x_get_password(setting);
    if (value) {
        if (!add_string_val(self, value, "password", FALSE, "<hidden>", error))
            return FALSE;
    } else {
        bytes = nm_setting_802_1x_get_password_raw(setting);
        if (bytes) {
            if (!nm_supplicant_config_add_option(self,
                                                 "password",
                                                 (const char *) g_bytes_get_data(bytes, NULL),
                                                 g_bytes_get_size(bytes),
                                                 "<hidden>",
                                                 error))
                return FALSE;
        }
    }
    value = nm_setting_802_1x_get_pin(setting);
    if (!add_string_val(self, value, "pin", FALSE, "<hidden>", error))
        return FALSE;

    if (wired) {
        if (!add_string_val(self, "IEEE8021X", "key_mgmt", FALSE, NULL, error))
            return FALSE;
        /* Wired 802.1x must always use eapol_flags=0 */
        if (!add_string_val(self, "0", "eapol_flags", FALSE, NULL, error))
            return FALSE;
        priv->ap_scan = 0;
    }

    /* Build the "eap" option string while we check for EAP methods needing
     * special handling: PEAP + GTC, FAST, external */
    eap_str = g_string_new(NULL);
    num_eap = nm_setting_802_1x_get_num_eap_methods(setting);

    for (i = 0; i < num_eap; i++) {
        const char *method = nm_setting_802_1x_get_eap_method(setting, i);

        if (priv->flags1x.suiteb) {
            // suiteb, 802-1x.eap must be only tls
            if (!nm_streq (method, "tls")) {
                g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
                             "suite-b must use 802-1x.eap tls");
                return FALSE;
            }
        }

        if (nm_streq(method, "fast")) {
            fast                = TRUE;
            priv->fast_required = TRUE;
        }

        if (nm_streq(method, "external")) {
            if (num_eap == 1) {
                g_set_error(error,
                            NM_SUPPLICANT_ERROR,
                            NM_SUPPLICANT_ERROR_CONFIG,
                            "Connection settings managed externally to NM, connection"
                            " cannot be used with wpa_supplicant");
                return FALSE;
            }
            continue;
        }

        if (nm_streq (method, "tls") ||
            nm_streq (method, "peap") ||
            nm_streq (method, "ttls")) {
            ca_cert_needed = 1;
        }

        if (eap_str->len)
            g_string_append_c(eap_str, ' ');
        g_string_append(eap_str, method);
    }

    if (priv->flags1x.suiteb && num_eap != 1) {
        // suiteb, 802-1x.eap must be only tls
        g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
                     "suite-b must use 802-1x.eap tls");
        return FALSE;
    }

    g_string_ascii_up(eap_str);
    if (eap_str->len
        && !nm_supplicant_config_add_option(self, "eap", eap_str->str, -1, NULL, error))
        return FALSE;

    /* Adjust the fragment size according to MTU, but do not set it higher than 1280-14
     * for better compatibility */
    hdrs = 14; /* EAPOL + EAP-TLS */
    frag = 1280 - hdrs;
    if (mtu > hdrs)
        frag = CLAMP(mtu - hdrs, 100, frag);
    frag_str = g_strdup_printf("%u", frag);

    if (!nm_supplicant_config_add_option(self, "fragment_size", frag_str, -1, NULL, error))
        return FALSE;

    phase1  = g_string_new(NULL);
    peapver = nm_setting_802_1x_get_phase1_peapver(setting);
    if (peapver) {
        if (nm_streq(peapver, "0"))
            g_string_append(phase1, "peapver=0");
        else if (nm_streq(peapver, "1"))
            g_string_append(phase1, "peapver=1");
    }

    if (nm_setting_802_1x_get_phase1_peaplabel(setting)) {
        if (phase1->len)
            g_string_append_c(phase1, ' ');
        g_string_append_printf(phase1,
                               "peaplabel=%s",
                               nm_setting_802_1x_get_phase1_peaplabel(setting));
    }

    value = nm_setting_802_1x_get_phase1_fast_provisioning(setting);
    if (value) {
        if (phase1->len)
            g_string_append_c(phase1, ' ');
        g_string_append_printf(phase1, "fast_provisioning=%s", value);

        if (!nm_streq(value, "0"))
            fast_provisoning_allowed = TRUE;
    }

    phase1_auth_flags = nm_setting_802_1x_get_phase1_auth_flags(setting);
    if (NM_FLAGS_HAS(phase1_auth_flags, NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_0_DISABLE))
        g_string_append_printf(phase1, "%stls_disable_tlsv1_0=1", (phase1->len ? " " : ""));
    if (NM_FLAGS_HAS(phase1_auth_flags, NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_1_DISABLE))
        g_string_append_printf(phase1, "%stls_disable_tlsv1_1=1", (phase1->len ? " " : ""));
    if (NM_FLAGS_HAS(phase1_auth_flags, NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_2_DISABLE))
        g_string_append_printf(phase1, "%stls_disable_tlsv1_2=1", (phase1->len ? " " : ""));

    tls_disable = nm_setting_802_1x_get_tls_disable_time_checks (setting);
    if (tls_disable) {
        g_string_append_printf (phase1, "%stls_disable_time_checks=%s", (phase1->len ? " " : ""), tls_disable);
    }

    if (priv->flags1x.suiteb) {
        g_string_append_printf (phase1, "%stls_suiteb=1", (phase1->len ? " " : ""));
    }

    if (phase1->len) {
        if (!add_string_val(self, phase1->str, "phase1", FALSE, NULL, error)) {
            g_string_free(phase1, TRUE);
            return FALSE;
        }
    }
    g_string_free(phase1, TRUE);

    phase2 = g_string_new(NULL);
    if (nm_setting_802_1x_get_num_phase2_auths (setting) && !fast_provisoning_allowed) {
            if(!ADD_STRING_LIST_VAL_TO_STRING(phase2,setting,802_1x,phase2_auth,phase2_auths,"auth",' ', TRUE, FALSE, error)){
            g_string_free(phase2, TRUE);
            return FALSE;
        }
    }

    if (nm_setting_802_1x_get_num_phase2_autheaps (setting)) {
            if(!ADD_STRING_LIST_VAL_TO_STRING(phase2,setting,802_1x,phase2_autheap,phase2_autheaps,"autheap",' ', TRUE, FALSE, error)){
            g_string_free(phase2, TRUE);
            return FALSE;
        }
    }

    if (tls_disable) {
        g_string_append_printf (phase2, "%stls_disable_time_checks=%s", (phase2->len ? " " : ""), tls_disable);
    }

    if (phase2->len) {
        if (!add_string_val(self, phase2->str, "phase2", FALSE, NULL, error)) {
            g_string_free(phase2, TRUE);
            return FALSE;
        }
    }
    g_string_free(phase2, TRUE);

    /* PAC file */
    path = nm_setting_802_1x_get_pac_file(setting);
    if (path) {
        if (!add_string_val(self, path, "pac_file", FALSE, NULL, error))
            return FALSE;

        if (_get_capability_laird(priv)) {
            /* PAC file password for manually provisioned PAC files */
            const char *pwd = nm_setting_802_1x_get_pac_file_password (setting);
            if (pwd && !add_string_val (self, pwd, "pac_file_password", FALSE, "<hidden>", error))
                return FALSE;
        }

    } else {
        /* PAC file is not specified.
         * If provisioning is allowed, use an blob format.
         */
        if (fast_provisoning_allowed) {
            gs_free char *blob_name = NULL;

            blob_name = g_strdup_printf("blob://pac-blob-%s", con_uuid);
            if (!add_string_val(self, blob_name, "pac_file", FALSE, NULL, error))
                return FALSE;
        } else {
            /* This is only error for EAP-FAST; don't disturb other methods. */
            if (fast) {
                g_set_error(error,
                            NM_SUPPLICANT_ERROR,
                            NM_SUPPLICANT_ERROR_CONFIG,
                            "EAP-FAST error: no PAC file provided and "
                            "automatic PAC provisioning is disabled");
                return FALSE;
            }
        }
    }

    /* If user wants to use system CA certs, either populate ca_path (if the path
     * is a directory) or ca_cert (the path is a file name) */
    if (nm_setting_802_1x_get_system_ca_certs(setting)) {
        if (g_file_test(SYSTEM_CA_PATH, G_FILE_TEST_IS_DIR))
            ca_path_override = SYSTEM_CA_PATH;
        else
            ca_cert_override = SYSTEM_CA_PATH;
    }

    /* CA path */
    path = nm_setting_802_1x_get_ca_path(setting);
    path = ca_path_override ?: path;
    if (path) {
        if (!add_string_val(self, path, "ca_path", FALSE, NULL, error))
            return FALSE;
    }

    /* Phase2 CA path */
    path = nm_setting_802_1x_get_phase2_ca_path(setting);
    path = ca_path_override ?: path;
    if (path) {
        if (!add_string_val(self, path, "ca_path2", FALSE, NULL, error))
            return FALSE;
    }

    /* CA certificate */
    if (ca_cert_override) {
        if (!add_string_val(self, ca_cert_override, "ca_cert", FALSE, NULL, error))
            return FALSE;
        ca_cert_configured = 1;
    } else {
        switch (nm_setting_802_1x_get_ca_cert_scheme(setting)) {
        case NM_SETTING_802_1X_CK_SCHEME_BLOB:
            bytes = nm_setting_802_1x_get_ca_cert_blob(setting);
            if (!nm_supplicant_config_add_blob_for_connection(self,
                                                              bytes,
                                                              "ca_cert",
                                                              con_uuid,
                                                              error))
                return FALSE;
            ca_cert_configured = 1;
            break;
        case NM_SETTING_802_1X_CK_SCHEME_PATH:
            path = nm_setting_802_1x_get_ca_cert_path(setting);
            if (!add_string_val(self, path, "ca_cert", FALSE, NULL, error))
                return FALSE;
            ca_cert_configured = 1;
            break;
        case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
            if (!add_pkcs11_uri_with_pin(self,
                                         "ca_cert",
                                         nm_setting_802_1x_get_ca_cert_uri(setting),
                                         nm_setting_802_1x_get_ca_cert_password(setting),
                                         nm_setting_802_1x_get_ca_cert_password_flags(setting),
                                         error)) {
                return FALSE;
            }
            ca_cert_configured = 1;
            break;
        default:
            break;
        }
    }

    if (priv->flags1x.ca_cert_check &&
        ca_cert_needed && !ca_cert_configured)
    {
        // wpa3 must have ca cert if required for eap
        g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
                     "wpa3 missing ca certificate");
        return FALSE;
    }

    /* Phase 2 CA certificate */
    if (ca_cert_override) {
        if (!add_string_val(self, ca_cert_override, "ca_cert2", FALSE, NULL, error))
            return FALSE;
    } else {
        switch (nm_setting_802_1x_get_phase2_ca_cert_scheme(setting)) {
        case NM_SETTING_802_1X_CK_SCHEME_BLOB:
            bytes = nm_setting_802_1x_get_phase2_ca_cert_blob(setting);
            if (!nm_supplicant_config_add_blob_for_connection(self,
                                                              bytes,
                                                              "ca_cert2",
                                                              con_uuid,
                                                              error))
                return FALSE;
            break;
        case NM_SETTING_802_1X_CK_SCHEME_PATH:
            path = nm_setting_802_1x_get_phase2_ca_cert_path(setting);
            if (!add_string_val(self, path, "ca_cert2", FALSE, NULL, error))
                return FALSE;
            break;
        case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
            if (!add_pkcs11_uri_with_pin(
                    self,
                    "ca_cert2",
                    nm_setting_802_1x_get_phase2_ca_cert_uri(setting),
                    nm_setting_802_1x_get_phase2_ca_cert_password(setting),
                    nm_setting_802_1x_get_phase2_ca_cert_password_flags(setting),
                    error)) {
                return FALSE;
            }
            break;
        default:
            break;
        }
    }

    /* Subject match */
    value = nm_setting_802_1x_get_subject_match(setting);
    if (!add_string_val(self, value, "subject_match", FALSE, NULL, error))
        return FALSE;
    value = nm_setting_802_1x_get_phase2_subject_match(setting);
    if (!add_string_val(self, value, "subject_match2", FALSE, NULL, error))
        return FALSE;

    /* altSubjectName match */
    if (!ADD_STRING_LIST_VAL(self,
                             setting,
                             802_1x,
                             altsubject_match,
                             altsubject_matches,
                             "altsubject_match",
                             ';',
                             FALSE,
                             NULL,
                             error))
        return FALSE;
    if (!ADD_STRING_LIST_VAL(self,
                             setting,
                             802_1x,
                             phase2_altsubject_match,
                             phase2_altsubject_matches,
                             "altsubject_match2",
                             ';',
                             FALSE,
                             NULL,
                             error))
        return FALSE;

    /* Domain suffix match */
    value = nm_setting_802_1x_get_domain_suffix_match(setting);
    if (!add_string_val(self, value, "domain_suffix_match", FALSE, NULL, error))
        return FALSE;
    value = nm_setting_802_1x_get_phase2_domain_suffix_match(setting);
    if (!add_string_val(self, value, "domain_suffix_match2", FALSE, NULL, error))
        return FALSE;

    /* domain match */
    value = nm_setting_802_1x_get_domain_match(setting);
    if (!add_string_val(self, value, "domain_match", FALSE, NULL, error))
        return FALSE;
    value = nm_setting_802_1x_get_phase2_domain_match(setting);
    if (!add_string_val(self, value, "domain_match2", FALSE, NULL, error))
        return FALSE;

    /* Private key */
    added = FALSE;
    switch (nm_setting_802_1x_get_private_key_scheme(setting)) {
    case NM_SETTING_802_1X_CK_SCHEME_BLOB:
        bytes = nm_setting_802_1x_get_private_key_blob(setting);
        if (!nm_supplicant_config_add_blob_for_connection(self,
                                                          bytes,
                                                          "private_key",
                                                          con_uuid,
                                                          error))
            return FALSE;
        added = TRUE;
        break;
    case NM_SETTING_802_1X_CK_SCHEME_PATH:
        path = nm_setting_802_1x_get_private_key_path(setting);
        if (!add_string_val(self, path, "private_key", FALSE, NULL, error))
            return FALSE;
        added = TRUE;
        break;
    case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
        if (!add_pkcs11_uri_with_pin(self,
                                     "private_key",
                                     nm_setting_802_1x_get_private_key_uri(setting),
                                     nm_setting_802_1x_get_private_key_password(setting),
                                     nm_setting_802_1x_get_private_key_password_flags(setting),
                                     error)) {
            return FALSE;
        }
        added = TRUE;
        break;
    default:
        break;
    }

    if (added) {
        NMSetting8021xCKFormat format;
        NMSetting8021xCKScheme scheme;

        format = nm_setting_802_1x_get_private_key_format(setting);
        scheme = nm_setting_802_1x_get_private_key_scheme(setting);

        if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH
            || format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
            /* Only add the private key password for PKCS#12 blobs and
             * all path schemes, since in both of these cases the private key
             * isn't decrypted at all.
             */
            value = nm_setting_802_1x_get_private_key_password(setting);
            if (!add_string_val(self, value, "private_key_passwd", FALSE, "<hidden>", error))
                return FALSE;
        }

        if (format != NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
            /* Only add the client cert if the private key is not PKCS#12, as
             * wpa_supplicant configuration directs us to do.
             */
            switch (nm_setting_802_1x_get_client_cert_scheme(setting)) {
            case NM_SETTING_802_1X_CK_SCHEME_BLOB:
                bytes = nm_setting_802_1x_get_client_cert_blob(setting);
                if (!nm_supplicant_config_add_blob_for_connection(self,
                                                                  bytes,
                                                                  "client_cert",
                                                                  con_uuid,
                                                                  error))
                    return FALSE;
                break;
            case NM_SETTING_802_1X_CK_SCHEME_PATH:
                path = nm_setting_802_1x_get_client_cert_path(setting);
                if (!add_string_val(self, path, "client_cert", FALSE, NULL, error))
                    return FALSE;
                break;
            case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
                if (!add_pkcs11_uri_with_pin(
                        self,
                        "client_cert",
                        nm_setting_802_1x_get_client_cert_uri(setting),
                        nm_setting_802_1x_get_client_cert_password(setting),
                        nm_setting_802_1x_get_client_cert_password_flags(setting),
                        error)) {
                    return FALSE;
                }
                break;
            default:
                break;
            }
        }
    }

    /* Phase 2 private key */
    added = FALSE;
    switch (nm_setting_802_1x_get_phase2_private_key_scheme(setting)) {
    case NM_SETTING_802_1X_CK_SCHEME_BLOB:
        bytes = nm_setting_802_1x_get_phase2_private_key_blob(setting);
        if (!nm_supplicant_config_add_blob_for_connection(self,
                                                          bytes,
                                                          "private_key2",
                                                          con_uuid,
                                                          error))
            return FALSE;
        added = TRUE;
        break;
    case NM_SETTING_802_1X_CK_SCHEME_PATH:
        path = nm_setting_802_1x_get_phase2_private_key_path(setting);
        if (!add_string_val(self, path, "private_key2", FALSE, NULL, error))
            return FALSE;
        added = TRUE;
        break;
    case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
        if (!add_pkcs11_uri_with_pin(
                self,
                "private_key2",
                nm_setting_802_1x_get_phase2_private_key_uri(setting),
                nm_setting_802_1x_get_phase2_private_key_password(setting),
                nm_setting_802_1x_get_phase2_private_key_password_flags(setting),
                error)) {
            return FALSE;
        }
        added = TRUE;
        break;
    default:
        break;
    }

    if (added) {
        NMSetting8021xCKFormat format;
        NMSetting8021xCKScheme scheme;

        format = nm_setting_802_1x_get_phase2_private_key_format(setting);
        scheme = nm_setting_802_1x_get_phase2_private_key_scheme(setting);

        if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH
            || format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
            /* Only add the private key password for PKCS#12 blobs and
             * all path schemes, since in both of these cases the private key
             * isn't decrypted at all.
             */
            value = nm_setting_802_1x_get_phase2_private_key_password(setting);
            if (!add_string_val(self, value, "private_key2_passwd", FALSE, "<hidden>", error))
                return FALSE;
        }

        if (format != NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
            /* Only add the client cert if the private key is not PKCS#12, as
             * wpa_supplicant configuration directs us to do.
             */
            switch (nm_setting_802_1x_get_phase2_client_cert_scheme(setting)) {
            case NM_SETTING_802_1X_CK_SCHEME_BLOB:
                bytes = nm_setting_802_1x_get_phase2_client_cert_blob(setting);
                if (!nm_supplicant_config_add_blob_for_connection(self,
                                                                  bytes,
                                                                  "client_cert2",
                                                                  con_uuid,
                                                                  error))
                    return FALSE;
                break;
            case NM_SETTING_802_1X_CK_SCHEME_PATH:
                path = nm_setting_802_1x_get_phase2_client_cert_path(setting);
                if (!add_string_val(self, path, "client_cert2", FALSE, NULL, error))
                    return FALSE;
                break;
            case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
                if (!add_pkcs11_uri_with_pin(
                        self,
                        "client_cert2",
                        nm_setting_802_1x_get_phase2_client_cert_uri(setting),
                        nm_setting_802_1x_get_phase2_client_cert_password(setting),
                        nm_setting_802_1x_get_phase2_client_cert_password_flags(setting),
                        error)) {
                    return FALSE;
                }
                break;
            default:
                break;
            }
        }
    }

    value = nm_setting_802_1x_get_identity(setting);
    if (!add_string_val(self, value, "identity", FALSE, NULL, error))
        return FALSE;
    value = nm_setting_802_1x_get_anonymous_identity(setting);
    if (!add_string_val(self, value, "anonymous_identity", FALSE, NULL, error))
        return FALSE;

    return TRUE;
}

gboolean
nm_supplicant_config_add_no_security(NMSupplicantConfig *self, GError **error)
{
    return nm_supplicant_config_add_option(self, "key_mgmt", "NONE", -1, NULL, error);
}

gboolean
nm_supplicant_config_get_ap_isolation(NMSupplicantConfig *self)
{
    return self->_priv.ap_isolation;
}

void
nm_supplicant_config_set_ap_isolation(NMSupplicantConfig *self, gboolean ap_isolation)
{
    self->_priv.ap_isolation = ap_isolation;
}
