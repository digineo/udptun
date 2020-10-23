#include <linux/if_vlan.h>
#include <net/udp_tunnel.h>
#include <net/dst_metadata.h>
#include <net/rtnetlink.h>

struct my_net {
  struct list_head my_list;
  struct list_head my_dev_list;
  struct mutex my_lock;
};

struct my_dev {
  struct list_head next;
  struct gro_cells gro_cells;
  struct net *net;
  struct net_device *dev;
  int id;
};

struct my_dev_cfg {
  int id;
};


struct my_cfg {
  struct udp_port_cfg udp_config;
};

struct my {
  struct list_head list;
  int protocol;
  struct socket *sock;
};
