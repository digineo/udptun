#include <linux/if_vlan.h>
#include <net/udp_tunnel.h>
#include <net/dst_metadata.h>
#include <net/rtnetlink.h>

// fou in einem network namespace
struct fou_net {
  struct list_head fou_dev_list;
  struct mutex     fou_lock;
};

struct fou_dev {
  struct list_head   list; // Liste der Devices im namespace
  struct gro_cells   gro_cells;
  struct net        *net;
  struct net_device *dev;
  struct socket     *sock;
  struct flowi       flowinfo;
  struct rtable     *rt;
  struct dst_cache   routing_cache;
};

struct fou_dev_cfg {
  int sockfd;
};


struct fou_cfg {
  struct udp_port_cfg udp_config;
};
