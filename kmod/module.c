#include <linux/kernel.h>   /* We're doing Kernel work */
#include <linux/module.h>   /* Specifically a Kernel Module */
#include <linux/init.h>     /* Needed for the module_init/exit() macros */
#include <linux/errno.h>
#include <linux/version.h>
#include <net/protocol.h>
#include <net/ip_tunnels.h>
#include <net/udp_tunnel.h>
#include "module.h"
#include "recv.h"
#include "xmit.h"



static unsigned int udptun_net_id __read_mostly;


static int udptun_err_lookup(struct sock *sk, struct sk_buff *skb);


/* Setup stats when device is created */
static int udptun_init(struct net_device *dev)
{
	struct udptun_dev *foudev = netdev_priv(dev);
	int err;
	netdev_dbg(dev, "udptun_init");

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	err = gro_cells_init(&foudev->gro_cells, dev);
	if (err) {
		free_percpu(dev->tstats);
		return err;
	}
	return 0;
}

static void udptun_uninit(struct net_device *dev)
{
	struct udptun_dev *foudev = netdev_priv(dev);
	netdev_dbg(dev, "udptun_uninit");

	gro_cells_destroy(&foudev->gro_cells);
	free_percpu(dev->tstats);
}

static int udptun_open(struct net_device *dev)
{
	netdev_dbg(dev, "udptun_open");
	netif_start_queue(dev);
	return 0;
}

static int udptun_stop(struct net_device *dev)
{
	pr_debug("udptun_stop");
	netif_stop_queue(dev);
	return 0;
}




static int udptun_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	netdev_dbg(dev, "udptun_fill_metadata_dst");
	return 0;
}

static const struct net_device_ops udptun_netdev_ops = {
	.ndo_init               = udptun_init,
	.ndo_uninit             = udptun_uninit,
	.ndo_open               = udptun_open,
	.ndo_stop               = udptun_stop,
	.ndo_start_xmit         = udptun_xmit,
	.ndo_get_stats64        = ip_tunnel_get_stats64,
	.ndo_fill_metadata_dst  = udptun_fill_metadata_dst,
};

static const struct nla_policy udptun_policy[UDPTUN_ATTR_MAX + 1] = {
	[UDPTUN_ATTR_FD] = { .type = NLA_U32 },
};


/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type udptun_type = {
	.name = "udptun",
};

/* Initialize the device structure. */
static void udptun_setup(struct net_device *dev)
{
	struct udptun_dev *foudev = netdev_priv(dev);

	netdev_dbg(dev, "udptun_setup");

	dev->netdev_ops        = &udptun_netdev_ops;
	dev->needs_free_netdev = true;
	SET_NETDEV_DEVTYPE(dev, &udptun_type);
	dev->features         |= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features         |= NETIF_F_RXCSUM;
	dev->features         |= NETIF_F_GSO_SOFTWARE;
	dev->hw_features      |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features      |= NETIF_F_GSO_SOFTWARE;
	dev->hard_header_len   = 0;
	dev->addr_len          = 0;
	dev->mtu               = ETH_DATA_LEN;
	dev->min_mtu           = IPV4_MIN_MTU;
	dev->max_mtu           = IP_MAX_MTU;
	dev->type              = ARPHRD_NONE;
	netif_keep_dst(dev);
	dev->priv_flags       |= IFF_NO_QUEUE;
	dev->flags             = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;

	INIT_LIST_HEAD(&foudev->list);
	foudev->dev = dev;
}

static int udptun_validate(struct nlattr *tb[], struct nlattr *data[],
                struct netlink_ext_ack *extack)
{
	pr_debug("udptun_validate");

	if (!data[UDPTUN_ATTR_FD]) {
		pr_debug("udptun: filedescriptor is missing");
		return -EINVAL;
	}

	return 0;
}

static int fou2info(struct nlattr *data[], struct udptun_dev_cfg *conf,
            struct netlink_ext_ack *extack)
{
	memset(conf, 0, sizeof(*conf));
	conf->sockfd = nla_get_u32(data[UDPTUN_ATTR_FD]);
	return 0;
}

// Überprüft, ob der übergebene Socket unterstützt wird
static int udptun_check_sock_type(struct socket *skt) {
    struct ipv6_pinfo *np;
	int addrtype;

	switch (skt->sk->sk_family) {
	case AF_INET:
		if (inet_sk(skt->sk)->inet_saddr == htonl(INADDR_ANY))
			return -ESOCKTNOSUPPORT;
		break;

	case AF_INET6:
		np = inet6_sk(skt->sk);
		if (np->saddr_cache == NULL) {
			return -ESOCKTNOSUPPORT;
		}

		addrtype = ipv6_addr_type(np->saddr_cache);
		if (addrtype == IPV6_ADDR_ANY || !(addrtype & IPV6_ADDR_UNICAST))
			return -ESOCKTNOSUPPORT;

		break;

	default:
		return -ESOCKTNOSUPPORT;
	}

	return 0;
}


static void _update_flowi4(const struct udptun_dev *foudev)
{
	const struct inet_sock *inet = inet_sk(foudev->sock->sk);
	struct flowi4 *fl = (struct flowi4*)&foudev->flowinfo.u.ip4;

	memset(fl, 0, sizeof(*fl));
	fl->flowi4_proto = IPPROTO_UDP;
	fl->saddr = inet->inet_saddr;
	fl->daddr = inet->inet_daddr;
	fl->fl4_sport = inet->inet_sport;
	fl->fl4_dport = inet->inet_dport;
}

static void _update_flowi6(const struct udptun_dev *foudev)
{
	struct inet_sock *inet = inet_sk(foudev->sock->sk);
	struct ipv6_pinfo *np = inet6_sk(foudev->sock->sk);
	struct flowi6 *fl = (struct flowi6*)&foudev->flowinfo.u.ip6;

	memset(fl, 0, sizeof(*fl));
	fl->flowi6_proto = IPPROTO_UDP;
	fl->saddr = *np->saddr_cache;
	fl->daddr = *np->daddr_cache;
	fl->fl6_sport = inet->inet_sport;
	fl->fl6_dport = inet->inet_dport;
}


inline static int getsockname(struct socket *sock, struct sockaddr_storage *addr){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
	return kernel_getsockname(sock, (struct sockaddr *)addr);
#else
	int addrlen = sizeof(struct sockaddr_storage);
	return kernel_getsockname(sock, (struct sockaddr *)addr, &addrlen);
#endif
}

inline static int getpeername(struct socket *sock, struct sockaddr_storage *addr){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
	return kernel_getpeername(sock, (struct sockaddr *)addr);
#else
	int addrlen = sizeof(struct sockaddr_storage);
	return kernel_getpeername(sock, (struct sockaddr *)addr, &addrlen);
#endif
}

static int udptun_configure(struct net *net, struct net_device *dev,
                 struct udptun_dev_cfg *conf)
{
	struct udptun_net *fn = net_generic(net, udptun_net_id);
	struct udptun_dev *foudev = netdev_priv(dev);
	struct udp_tunnel_sock_cfg tunnel_cfg;
	struct socket *skt;
	struct sockaddr_storage local, peer;
	int err;

	netdev_dbg(dev, "udptun_configure");

	if (!foudev)
		return -EBUSY;


	/* This also takes a new reference on the fd, keeping it open. */
	skt = sockfd_lookup(conf->sockfd, &err);
	if (skt == NULL) {
		return err == 0 ? -EINVAL : err;
	}

	err = udptun_check_sock_type(skt);
	if (err) {
		return err;
	}

	getsockname(skt, &local);
	getpeername(skt, &peer);
	netdev_dbg(dev, "new socket %pISpfc -> %pISpfc", &local, &peer);

	foudev->sock = skt;
	foudev->net = net;
	foudev->dev = dev;

	memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
	tunnel_cfg.sk_user_data     = foudev;
	tunnel_cfg.encap_type       = 1;
	tunnel_cfg.encap_destroy    = NULL;
	tunnel_cfg.encap_rcv        = udptun_udp_recv;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
	tunnel_cfg.encap_err_lookup = udptun_err_lookup;
#endif
	tunnel_cfg.gro_receive      = udptun_gro_receive;
	tunnel_cfg.gro_complete     = udptun_gro_complete;
	setup_udp_tunnel_sock(net, skt, &tunnel_cfg);

	/* As the setup_udp_tunnel_sock does not call udp_encap_enable if the
	* socket type is v6 an explicit call to udp_encap_enable is needed.
	*/
	if (skt->sk->sk_family == AF_INET6)
		udp_encap_enable();


	// Update flow info
	// see https://elixir.bootlin.com/linux/latest/source/drivers/net/geneve.c#L1568
		if (skt->sk->sk_family == AF_INET){
	_update_flowi4(foudev);
	} else {
		_update_flowi6(foudev);
	}
	dst_cache_init(&foudev->routing_cache, GFP_KERNEL);


	err = register_netdevice(dev);
	if (err)
		return err;


	mutex_lock(&fn->udptun_lock);
	list_add(&foudev->list, &fn->udptun_dev_list);
	mutex_unlock(&fn->udptun_lock);

	return 0;
}


static int udptun_newlink(struct net *src_net, struct net_device *dev,
               struct nlattr *tb[], struct nlattr *data[],
               struct netlink_ext_ack *extack)
{
	struct udptun_dev_cfg conf;
	int err;

	netdev_dbg(dev, "udptun_newlink");

	err = fou2info(data, &conf, extack);
	if (err)
		return err;

	err = udptun_configure(src_net, dev, &conf);
	if (err)
		return err;

	return 0;
}

static void udptun_release(struct udptun_dev *foudev)
{
	list_del(&foudev->list);
	udp_tunnel_sock_release(foudev->sock);
	dst_cache_destroy(&foudev->routing_cache);
}

static void udptun_dellink(struct net_device *dev, struct list_head *head)
{
	struct udptun_dev *foudev = netdev_priv(dev);
	netdev_dbg(dev, "udptun_dellink");

	udptun_release(foudev);
	unregister_netdevice_queue(dev, head);
}

static size_t udptun_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(__u32)) +			/* UDPTUN_ATTR_FD */
		nla_total_size(sizeof(__u8)) +			/* UDPTUN_ATTR_AF */
		nla_total_size(sizeof(struct in6_addr)) +	/* UDPTUN_ATTR_LOCAL_ADDR */
		nla_total_size(sizeof(__u16)) +			/* UDPTUN_ATTR_LOCAL_PORT */
		nla_total_size(sizeof(struct in6_addr)) +	/* UDPTUN_ATTR_PEER_ADDR */
		nla_total_size(sizeof(__u16)) +			/* UDPTUN_ATTR_PEER_PORT */
		0;
}

// returns the device specific link data for netlink
static int udptun_link_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct sock *sk;
	struct inet_sock *inet;
	struct udptun_dev *foudev = netdev_priv(dev);

	netdev_dbg(dev, "udptun_link_fill_info");

	sk = foudev->sock->sk;
	if (sk == NULL) {
		// Socket has been closed
		return 0;
	}

	inet = inet_sk(sk);

	if (nla_put_u8(skb, UDPTUN_ATTR_AF, sk->sk_family) ||
	    nla_put_be16(skb, UDPTUN_ATTR_LOCAL_PORT, inet->inet_sport) ||
	    nla_put_be16(skb, UDPTUN_ATTR_PEER_PORT, inet->inet_dport)
	)
		return -1;

	if (sk->sk_family == AF_INET) {
		if (nla_put_in_addr(skb, UDPTUN_ATTR_LOCAL_ADDR, sk->sk_rcv_saddr))
			return -1;

		if (nla_put_in_addr(skb, UDPTUN_ATTR_PEER_ADDR, sk->sk_daddr))
			return -1;
	} else {
		if (nla_put_in6_addr(skb, UDPTUN_ATTR_LOCAL_ADDR, &sk->sk_v6_rcv_saddr))
			return -1;

		if (nla_put_in6_addr(skb, UDPTUN_ATTR_PEER_ADDR, &sk->sk_v6_daddr))
			return -1;
	}

	return 0;
}



static struct rtnl_link_ops udptun_link_ops __read_mostly = {
	.kind       = "udptun",
	.maxtype    = UDPTUN_ATTR_MAX,
	.policy     = udptun_policy,
	.priv_size  = sizeof(struct udptun_dev),
	.setup      = udptun_setup,
	.validate   = udptun_validate,
	.newlink    = udptun_newlink,
	.dellink    = udptun_dellink,
	.get_size   = udptun_get_size,
	.fill_info  = udptun_link_fill_info,
};



static int udptun_err_lookup(struct sock *sk, struct sk_buff *skb)
{
	pr_debug("udptun_err_lookup");
	return 0;
}


// Registrierung eines network namespaces
static __net_init int udptun_init_net(struct net *net)
{
	struct udptun_net *fn = net_generic(net, udptun_net_id);
	pr_debug("udptun_init_net net_id=%d", udptun_net_id);


	INIT_LIST_HEAD(&fn->udptun_dev_list);
	mutex_init(&fn->udptun_lock);
	return 0;
}


// Entfernung eines network namespaces
static __net_exit void udptun_exit_net(struct net *net)
{
	struct udptun_net *fn = net_generic(net, udptun_net_id);
	struct udptun_dev *fou, *next;

	pr_debug("udptun_exit_net net_id=%d", udptun_net_id);

	/* Close all the FOU sockets */
	mutex_lock(&fn->udptun_lock);
	list_for_each_entry_safe(fou, next, &fn->udptun_dev_list, list)
	udptun_release(fou);
	mutex_unlock(&fn->udptun_lock);
}


/* Struct containing pointers to the above functions */
static struct pernet_operations udptun_net_ops = {
	.init = udptun_init_net,
	.exit = udptun_exit_net,
	.id   = &udptun_net_id,
	.size = sizeof(struct udptun_net),
};



// Kernelmodul wird initialisiert (modprobe/insmod)
static int __init udptun_init_module(void)
{
	int rc;
	pr_debug("udptun_init_module");

	rc = register_pernet_subsys(&udptun_net_ops);
	if (rc)
		goto out;

	rc = rtnl_link_register(&udptun_link_ops);

out:
	pr_debug("udptun_init_module finished rc=%d", rc);
	return rc;
}


// Kernelmodul wird aufgeräumt (rmmod)
static void __exit udptun_cleanup_module(void)
{
	pr_debug("udptun_cleanup_module");
	rtnl_link_unregister(&udptun_link_ops);
	unregister_pernet_subsys(&udptun_net_ops);
}



module_init(udptun_init_module);
module_exit(udptun_cleanup_module);
MODULE_AUTHOR("Julian Kornberger <jk@digineo.de>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UDP Tunnel");
