#include <linux/if_link.h>

/* LAIRD: Detect older linux/if_link.h header, and define
 * necessary missing enum values.
 */
#if IFLA_BR_MAX < 8
#define IFLA_BR_VLAN_PROTOCOL              8
#define IFLA_BR_GROUP_FWD_MASK             9
#define IFLA_BR_GROUP_ADDR                 20
#define IFLA_BR_MCAST_SNOOPING             23
#define IFLA_BR_MCAST_ROUTER               22
#define IFLA_BR_MCAST_QUERY_USE_IFADDR     24
#define IFLA_BR_MCAST_QUERIER              25
#define IFLA_BR_MCAST_HASH_MAX             27
#define IFLA_BR_MCAST_LAST_MEMBER_CNT      28
#define IFLA_BR_MCAST_STARTUP_QUERY_CNT    29
#define IFLA_BR_MCAST_LAST_MEMBER_INTVL    30
#define IFLA_BR_MCAST_MEMBERSHIP_INTVL     31
#define IFLA_BR_MCAST_QUERIER_INTVL        32
#define IFLA_BR_MCAST_QUERY_INTVL          33
#define IFLA_BR_MCAST_QUERY_RESPONSE_INTVL 34
#define IFLA_BR_MCAST_STARTUP_QUERY_INTVL  35
#endif

#if IFLA_BOND_MAX < 24
#define IFLA_BOND_AD_ACTOR_SYS_PRIO 24
#define IFLA_BOND_AD_USER_PORT_KEY 25
#define IFLA_BOND_AD_ACTOR_SYSTEM 26
#define IFLA_BOND_TLB_DYNAMIC_LB 27
#endif