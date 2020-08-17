// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2011 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-bond.h"

#include <stdlib.h>

#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"
#include "nm-ip4-config.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceBond);

/*****************************************************************************/

struct _NMDeviceBond {
	NMDevice parent;
};

struct _NMDeviceBondClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceBond, nm_device_bond, NM_TYPE_DEVICE)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingBond *s_bond;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_BOND_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("Bond connection"),
	                           "bond",
	                           NULL,
	                           TRUE);

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond) {
		s_bond = (NMSettingBond *) nm_setting_bond_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bond));
	}

	return TRUE;
}

/*****************************************************************************/

static gboolean
_set_bond_attr (NMDevice *device, const char *attr, const char *value)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	int ifindex = nm_device_get_ifindex (device);
	gboolean ret;

	ret = nm_platform_sysctl_master_set_option (nm_device_get_platform (device),
	                                            ifindex,
	                                            attr,
	                                            value);
	if (!ret)
		_LOGW (LOGD_PLATFORM, "failed to set bonding attribute '%s' to '%s'", attr, value);
	return ret;
}

#define _set_bond_attr_take(device, attr, value) \
	G_STMT_START { \
		gs_free char *_tmp = (value); \
		\
		_set_bond_attr (device, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, _tmp); \
	} G_STMT_END

#define _set_bond_attr_printf(device, attr, fmt, ...) \
	_set_bond_attr_take ((device), (attr), g_strdup_printf (fmt, __VA_ARGS__))

static gboolean
ignore_option (NMSettingBond *s_bond, const char *option, const char *value)
{
	const char *defvalue;

	if (nm_streq0 (option, NM_SETTING_BOND_OPTION_MIIMON)) {
		/* The default value for miimon, when missing in the setting, is
		 * 0 if arp_interval is != 0, and 100 otherwise. So, let's ignore
		 * miimon=0 (which means that miimon is disabled) and accept any
		 * other value. Adding miimon=100 does not cause any harm.
		 */
		defvalue = "0";
	} else
		defvalue = nm_setting_bond_get_option_default (s_bond, option);

	return nm_streq0 (value, defvalue);
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingBond *s_bond = nm_connection_get_setting_bond (connection);
	int ifindex = nm_device_get_ifindex (device);
	NMBondMode mode = NM_BOND_MODE_UNKNOWN;
	const char **options;

	if (!s_bond) {
		s_bond = (NMSettingBond *) nm_setting_bond_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_bond);
	}

	/* Read bond options from sysfs and update the Bond setting to match */
	options = nm_setting_bond_get_valid_options (s_bond);
	for (; *options; options++) {
		char *p;
		gs_free char *value = nm_platform_sysctl_master_get_option (nm_device_get_platform (device),
		                                                            ifindex,
		                                                            *options);

		if (   value
		    && _nm_setting_bond_get_option_type (s_bond, *options) == NM_BOND_OPTION_TYPE_BOTH) {
			p = strchr (value, ' ');
			if (p)
				*p = '\0';
		}

		if (mode == NM_BOND_MODE_UNKNOWN) {
			if (value && nm_streq (*options, NM_SETTING_BOND_OPTION_MODE))
				mode = _nm_setting_bond_mode_from_string (value);
			if (mode == NM_BOND_MODE_UNKNOWN)
				continue;
		}

		if (!_nm_setting_bond_option_supported (*options, mode))
			continue;

		if (   value
		    && value[0]
		    && !ignore_option (s_bond, *options, value)) {
			/* Replace " " with "," for arp_ip_targets from the kernel */
			if (strcmp (*options, NM_SETTING_BOND_OPTION_ARP_IP_TARGET) == 0) {
				for (p = value; *p; p++) {
					if (*p == ' ')
						*p = ',';
				}
			}

			nm_setting_bond_add_option (s_bond, *options, value);
		}
	}
}

static gboolean
master_update_slave_connection (NMDevice *self,
                                NMDevice *slave,
                                NMConnection *connection,
                                GError **error)
{
	g_object_set (nm_connection_get_setting_connection (connection),
	              NM_SETTING_CONNECTION_MASTER, nm_device_get_iface (self),
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);
	return TRUE;
}

static void
set_arp_targets (NMDevice *device,
                 NMBondMode mode,
                 const char *cur_arp_ip_target,
                 const char *new_arp_ip_target)
{
	gs_unref_ptrarray GPtrArray *free_list = NULL;
	gs_free const char **cur_strv = NULL;
	gs_free const char **new_strv = NULL;
	gsize cur_len;
	gsize new_len;
	gsize i;
	gsize j;

	cur_strv = nm_utils_strsplit_set_full (cur_arp_ip_target, NM_ASCII_SPACES, NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP);
	new_strv = nm_utils_bond_option_arp_ip_targets_split (new_arp_ip_target);

	cur_len = NM_PTRARRAY_LEN (cur_strv);
	new_len = NM_PTRARRAY_LEN (new_strv);

	if (new_len > 0) {
		for (j = 0, i = 0; i < new_len; i++) {
			const char *s;
			in_addr_t a4;

			s = new_strv[i];
			if (nm_utils_parse_inaddr_bin (AF_INET, s, NULL, &a4)) {
				char sbuf[INET_ADDRSTRLEN];

				_nm_utils_inet4_ntop (a4, sbuf);
				if (!nm_streq (s, sbuf)) {
					if (!free_list)
						free_list = g_ptr_array_new_with_free_func (g_free);
					s = g_strdup (sbuf);
					g_ptr_array_add (free_list, (gpointer) s);
				}
			}

			if (nm_utils_strv_find_first ((char **) new_strv, i, s) < 0)
				new_strv[j++] = s;
		}
		new_strv[j] = NULL;
		new_len = j;
	}

	if (   cur_len == 0
	    && new_len == 0)
		return;

	if (_nm_utils_strv_equal ((char **) cur_strv, (char **) new_strv))
		return;

	for (i = 0; i < cur_len; i++)
		_set_bond_attr_printf (device, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, "-%s", cur_strv[i]);
	for (i = 0; i < new_len; i++)
		_set_bond_attr_printf (device, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, "+%s", new_strv[i]);
}

/*
 * Sets bond attribute stored in the option hashtable or
 * the default value if no value was set.
 */
static void
set_bond_attr_or_default (NMDevice *device,
                          NMSettingBond *s_bond,
                          const char *opt)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	const char *value;

	value = nm_setting_bond_get_option_or_default (s_bond, opt);
	if (!value) {
		if (   _LOGT_ENABLED (LOGD_BOND)
		    && nm_setting_bond_get_option_by_name (s_bond, opt))
			_LOGT (LOGD_BOND, "bond option '%s' not set as it conflicts with other options", opt);
		return;
	}

	_set_bond_attr (device, opt, value);
}

static gboolean
apply_bonding_config (NMDeviceBond *self)
{
	NMDevice *device = NM_DEVICE (self);
	int ifindex = nm_device_get_ifindex (device);
	NMSettingBond *s_bond;
	NMBondMode mode;
	const char *mode_str;
	gs_free char *cur_arp_ip_target = NULL;

	s_bond = nm_device_get_applied_setting (device, NM_TYPE_SETTING_BOND);
	g_return_val_if_fail (s_bond, FALSE);

	mode_str = nm_setting_bond_get_option_or_default (s_bond, NM_SETTING_BOND_OPTION_MODE);
	mode = _nm_setting_bond_mode_from_string (mode_str);
	g_return_val_if_fail (mode != NM_BOND_MODE_UNKNOWN, FALSE);

	/* Set mode first, as some other options (e.g. arp_interval) are valid
	 * only for certain modes.
	 */
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_MODE);

	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_MIIMON);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_UPDELAY);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_ARP_VALIDATE);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_PRIMARY);

	/* ARP targets: clear and initialize the list */
	cur_arp_ip_target = nm_platform_sysctl_master_get_option (nm_device_get_platform (device),
	                                                          ifindex,
	                                                          NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
	set_arp_targets (device,
	                 mode,
	                 cur_arp_ip_target,
	                 nm_setting_bond_get_option_or_default (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET));

	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_AD_SELECT);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_FAIL_OVER_MAC);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_LACP_RATE);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_LP_INTERVAL);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_MIN_LINKS);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_PRIMARY_RESELECT);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_RESEND_IGMP);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_USE_CARRIER);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY);
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP);
	return TRUE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;

	/* Interface must be down to set bond options */
	nm_device_take_down (device, TRUE);
	if (!apply_bonding_config (self))
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	else {
		if (!nm_device_hw_addr_set_cloned (device,
		                                   nm_device_get_applied_connection (device),
		                                   FALSE))
			ret = NM_ACT_STAGE_RETURN_FAILURE;
	}
	nm_device_bring_up (device, TRUE, NULL);

	return ret;
}

static gboolean
enslave_slave (NMDevice *device,
               NMDevice *slave,
               NMConnection *connection,
               gboolean configure)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	gboolean success = TRUE;
	const char *slave_iface = nm_device_get_ip_iface (slave);
	NMConnection *master_con;

	nm_device_master_check_slave_physical_port (device, slave, LOGD_BOND);

	if (configure) {
		nm_device_take_down (slave, TRUE);
		success = nm_platform_link_enslave (nm_device_get_platform (device),
		                                    nm_device_get_ip_ifindex (device),
		                                    nm_device_get_ip_ifindex (slave));
		nm_device_bring_up (slave, TRUE, NULL);

		if (!success)
			return FALSE;

		_LOGI (LOGD_BOND, "enslaved bond slave %s", slave_iface);

		/* The active_slave option can be set only after the interface is enslaved */
		master_con = nm_device_get_applied_connection (device);
		if (master_con) {
			NMSettingBond *s_bond = nm_connection_get_setting_bond (master_con);
			const char *active;

			if (s_bond) {
				active = nm_setting_bond_get_option_or_default (s_bond,
				                                                NM_SETTING_BOND_OPTION_ACTIVE_SLAVE);
				if (nm_streq0 (active, nm_device_get_iface (slave))) {
					nm_platform_sysctl_master_set_option (nm_device_get_platform (device),
					                                      nm_device_get_ifindex (device),
					                                      "active_slave",
					                                      active);
					_LOGD (LOGD_BOND, "setting slave %s as active one for master %s",
					       active, nm_device_get_iface (device));
				}
			}
		}
	} else
		_LOGI (LOGD_BOND, "bond slave %s was enslaved", slave_iface);

	return TRUE;
}

static void
release_slave (NMDevice *device,
               NMDevice *slave,
               gboolean configure)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	gboolean success;
	gs_free char *address = NULL;
	int ifindex_slave;
	int ifindex;

	if (configure) {
		ifindex = nm_device_get_ifindex (device);
		if (   ifindex <= 0
		    || !nm_platform_link_get (nm_device_get_platform (device), ifindex))
			configure = FALSE;
	}

	ifindex_slave = nm_device_get_ip_ifindex (slave);

	if (ifindex_slave <= 0)
		_LOGD (LOGD_BOND, "bond slave %s is already released", nm_device_get_ip_iface (slave));

	if (configure) {
		/* When the last slave is released the bond MAC will be set to a random
		 * value by kernel; remember the current one and restore it afterwards.
		 */
		address = g_strdup (nm_device_get_hw_address (device));

		if (ifindex_slave > 0) {
			success = nm_platform_link_release (nm_device_get_platform (device),
			                                    nm_device_get_ip_ifindex (device),
			                                    ifindex_slave);

			if (success) {
				_LOGI (LOGD_BOND, "released bond slave %s",
				       nm_device_get_ip_iface (slave));
			} else {
				_LOGW (LOGD_BOND, "failed to release bond slave %s",
				       nm_device_get_ip_iface (slave));
			}
		}

		nm_platform_process_events (nm_device_get_platform (device));
		if (nm_device_update_hw_address (device))
			nm_device_hw_addr_set (device, address, "restore", FALSE);

		/* Kernel bonding code "closes" the slave when releasing it, (which clears
		 * IFF_UP), so we must bring it back up here to ensure carrier changes and
		 * other state is noticed by the now-released slave.
		 */
		if (ifindex_slave > 0) {
			if (!nm_device_bring_up (slave, TRUE, NULL))
				_LOGW (LOGD_BOND, "released bond slave could not be brought up.");
		}
	} else {
		if (ifindex_slave > 0) {
			_LOGI (LOGD_BOND, "bond slave %s was released",
			       nm_device_get_ip_iface (slave));
		}
	}
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	int r;

	g_assert (iface);

	r = nm_platform_link_bond_add (nm_device_get_platform (device), iface, out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create bond interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}
	return TRUE;
}

static gboolean
check_changed_options (NMSettingBond *s_a, NMSettingBond *s_b, GError **error)
{
	guint i, num;
	const char *name = NULL, *value_a = NULL, *value_b = NULL;

	/* Check that options in @s_a have compatible changes in @s_b */

	num = nm_setting_bond_get_num_options (s_a);
	for (i = 0; i < num; i++) {
		nm_setting_bond_get_option (s_a, i, &name, &value_a);

		/* We support changes to these */
		if (NM_IN_STRSET (name,
		                  NM_SETTING_BOND_OPTION_ACTIVE_SLAVE,
		                  NM_SETTING_BOND_OPTION_PRIMARY)) {
			continue;
		}

		/* Missing in @s_b, but has a default value in @s_a */
		value_b = nm_setting_bond_get_option_by_name (s_b, name);
		if (   !value_b
		    && nm_streq0 (value_a, nm_setting_bond_get_option_default (s_a, name))) {
			continue;
		}

		/* Reject any other changes */
		if (!nm_streq0 (value_a, value_b)) {
			g_set_error (error,
			             NM_DEVICE_ERROR,
			             NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			             "Can't reapply '%s' bond option",
			             name);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
can_reapply_change (NMDevice *device,
                    const char *setting_name,
                    NMSetting *s_old,
                    NMSetting *s_new,
                    GHashTable *diffs,
                    GError **error)
{
	NMDeviceClass *device_class;
	NMSettingBond *s_bond_old, *s_bond_new;

	/* Only handle bond setting here, delegate other settings to parent class */
	if (nm_streq (setting_name, NM_SETTING_BOND_SETTING_NAME)) {
		if (!nm_device_hash_check_invalid_keys (diffs,
		                                        NM_SETTING_BOND_SETTING_NAME,
		                                        error,
		                                        NM_SETTING_BOND_OPTIONS))
			return FALSE;

		s_bond_old = NM_SETTING_BOND (s_old);
		s_bond_new = NM_SETTING_BOND (s_new);

		if (   !check_changed_options (s_bond_old, s_bond_new, error)
		    || !check_changed_options (s_bond_new, s_bond_old, error)) {
			return FALSE;
		}

		return TRUE;
	}

	device_class = NM_DEVICE_CLASS (nm_device_bond_parent_class);
	return device_class->can_reapply_change (device,
	                                         setting_name,
	                                         s_old,
	                                         s_new,
	                                         diffs,
	                                         error);
}

static void
reapply_connection (NMDevice *device, NMConnection *con_old, NMConnection *con_new)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	const char *value;
	NMSettingBond *s_bond;
	NMBondMode mode;

	NM_DEVICE_CLASS (nm_device_bond_parent_class)->reapply_connection (device,
	                                                                   con_old,
	                                                                   con_new);

	_LOGD (LOGD_BOND, "reapplying bond settings");
	s_bond = nm_connection_get_setting_bond (con_new);
	g_return_if_fail (s_bond);

	value = nm_setting_bond_get_option_or_default (s_bond, NM_SETTING_BOND_OPTION_MODE);
	mode = _nm_setting_bond_mode_from_string (value);
	g_return_if_fail (mode != NM_BOND_MODE_UNKNOWN);

	/* Primary */
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_PRIMARY);
	/* Active slave */
	set_bond_attr_or_default (device, s_bond, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE);
}

/*****************************************************************************/

static void
nm_device_bond_init (NMDeviceBond * self)
{
	nm_assert (nm_device_is_master (NM_DEVICE (self)));
}

static const NMDBusInterfaceInfoExtended interface_info_device_bond = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_BOND,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress", "s",  NM_DEVICE_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Carrier",   "b",  NM_DEVICE_CARRIER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Slaves",    "ao", NM_DEVICE_SLAVES),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_bond_class_init (NMDeviceBondClass *klass)
{
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_bond);

	device_class->connection_type_supported = NM_SETTING_BOND_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_BOND_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_BOND);

	device_class->is_master = TRUE;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->complete_connection = complete_connection;

	device_class->update_connection = update_connection;
	device_class->master_update_slave_connection = master_update_slave_connection;

	device_class->create_and_realize = create_and_realize;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
	device_class->enslave_slave = enslave_slave;
	device_class->release_slave = release_slave;
	device_class->can_reapply_change = can_reapply_change;
	device_class->reapply_connection = reapply_connection;
}

/*****************************************************************************/

#define NM_TYPE_BOND_DEVICE_FACTORY (nm_bond_device_factory_get_type ())
#define NM_BOND_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BOND_DEVICE_FACTORY, NMBondDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_BOND,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, "bonding",
	                                  NM_DEVICE_TYPE_DESC, "Bond",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BOND,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_BOND,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (BOND, Bond, bond,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_BOND)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_BOND_SETTING_NAME),
	factory_class->create_device = create_device;
);
