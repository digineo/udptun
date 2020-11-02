#pragma once

#include <linux/if_vlan.h>
#include <net/udp_tunnel.h>
#include <net/dst_metadata.h>


enum {
	UDPTUN_ATTR_UNSPEC,
	UDPTUN_ATTR_FD,			/* u32 */
	UDPTUN_ATTR_AF,			/* u8 */
	UDPTUN_ATTR_LOCAL_ADDR,		/* u32/in6_addr */
	UDPTUN_ATTR_LOCAL_PORT,		/* u16 */
	UDPTUN_ATTR_PEER_ADDR,		/* u32/in6_addr */
	UDPTUN_ATTR_PEER_PORT,		/* u16 */

	__UDPTUN_ATTR_LAST
};

#define UDPTUN_ATTR_MAX (__UDPTUN_ATTR_LAST - 1)

// fou in einem network namespace
struct udptun_net {
  struct list_head udptun_dev_list; // Liste der Devices
  struct mutex     udptun_lock;
};

// ein fou device
struct udptun_dev {
  struct list_head   list; // Liste der Devices im namespace
  struct net        *net;
  struct net_device *dev;
  struct socket     *sock;
  struct flowi       flowinfo;
  struct dst_cache   routing_cache;
  struct gro_cells   gro_cells;
};

// Zusätzliche Daten für die Device-Konfiguration
struct udptun_dev_cfg {
  int sockfd;
};
