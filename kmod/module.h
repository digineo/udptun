#pragma once

#include <linux/if_vlan.h>
#include <net/udp_tunnel.h>
#include <net/dst_metadata.h>


enum {
	FASTD_SETFD_A_UNSPEC,
	FASTD_SETFD_A_FD,
	__FASTD_SETFD_A_LAST
};
#define FASTD_SETFD_A_MAX (__FASTD_SETFD_A_LAST - 1)

// fou in einem network namespace
struct fou_net {
  struct list_head fou_dev_list; // Liste der Devices
  struct mutex     fou_lock;
};

// ein fou device
struct fou_dev {
  struct list_head   list; // Liste der Devices im namespace
  struct net        *net;
  struct net_device *dev;
  struct socket     *sock;
  struct flowi       flowinfo;
  struct dst_cache   routing_cache;
  struct gro_cells   gro_cells;
};

// Zusätzliche Daten für die Device-Konfiguration
struct fou_dev_cfg {
  int sockfd;
};
