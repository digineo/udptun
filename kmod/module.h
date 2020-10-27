#pragma once

#include <linux/if_vlan.h>
#include <net/udp_tunnel.h>
#include <net/dst_metadata.h>


enum {
	UDPTUN_ATTR_UNSPEC,
	UDPTUN_ATTR_FD,
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
