/* Laird additions to generated clients/common/settings-docs.c */

#define DESCRIBE_DOC_NM_SETTING_802_1X_TLS_DISABLE_TIME_CHECKS \
	N_("Disable checking of the server certificates date.")
#define DESCRIBE_DOC_NM_SETTING_802_1X_PAC_FILE_PASSWORD \
	N_("Password for decrypting manually generated PAC files.")

#define DESCRIBE_DOC_NM_SETTING_WIRELESS_CCX	\
	N_("Enable CCX features.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_CLIENT_NAME \
	N_("CCX client name.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_SCAN_DELAY \
	N_("Scanning delay before sending probe request after tuning to a new channel.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_SCAN_DWELL \
	N_("Time to wait for responses to a probe request.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_SCAN_PASSIVE_DWELL \
	N_("Time to wait for beacons on passive scan channels.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_SCAN_SUSPEND_TIME \
	N_("Time to service an active connection between background scans.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_SCAN_ROAM_DELTA \
	N_("Limits signal difference required for roaming.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_BGSCAN \
	N_("Background scanning algorithm to be used.  See supplicant documentation for details.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_AUTH_TIMEOUT \
	N_("Timeout to complete connection from association start.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_FREQUENCY_LIST \
	N_("A string listing the allowed frequencies.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_FREQUENCY_DFS \
	N_("Used to enable/disable DFS/Radar channels.")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_MAX_SCAN_INTERVAL \
	N_("Maximum scan interval while disconnected.")

#define DESCRIBE_DOC_NM_SETTING_WIRELESS_SECURITY_PROACTIVE_KEY_CACHING \
	N_("Selects PMK caching method (OPMK/OKC versus SPMK/SKC).")
#define DESCRIBE_DOC_NM_SETTING_WIRELESS_DMS \
	N_("Directed multicast service.")

#define DESCRIBE_DOC_NM_SETTING_WIRELESS_SECURITY_FT N_("Indicates whether Fast BSS Transition (FT/802.11r) must be enabled for the connection.  One of NM_SETTING_WIRELESS_SECURITY_FT_DEFAULT (0) (use global default value), NM_SETTING_WIRELESS_SECURITY_FT_DISABLE (1) (disable FT), NM_SETTING_WIRELESS_SECURITY_FT_OPTIONAL (2) (enable FT if the supplicant and the access point support it) or NM_SETTING_WIRELESS_SECURITY_FT_REQUIRED (3) (enable FT and fail if not supported).  When set to NM_SETTING_WIRELESS_SECURITY_FT_DEFAULT (0) and no global default is set, FT will be optionally enabled.")

#define DESCRIBE_DOC_NM_SETTING_WIRELESS_CHANNEL_WIDTH	\
	N_("Selects channel width used when creating a network (AP/Ahoc).  Valid values are 20, 40, 40-, 40+, and 80.")


#define DESCRIBE_DOC_NM_SETTING_WIFI_P2P_DEVICE_NAME \
	N_("P2P device name used for this device.")
#define DESCRIBE_DOC_NM_SETTING_WIFI_P2P_PEER_DEVICE_NAME \
	N_("P2P device name that should be connected to.")
#define DESCRIBE_DOC_NM_SETTING_WIFI_P2P_FREQUENCY \
	N_("P2P frequency (MHz).")
