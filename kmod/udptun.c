#include <linux/kernel.h>   /* We're doing Kernel work */
#include <linux/module.h>   /* Specifically a Kernel Module */
#include <linux/moduleparam.h>
#include <linux/init.h>     /* Needed for the module_init/exit() macros */
#include <linux/errno.h>
#include <linux/inetdevice.h>
#include <net/protocol.h>
#include <net/ip_tunnels.h>
#include <net/udp_tunnel.h>
#include "udptun.h"
#include "uapi/fastd.h"



static unsigned int fou_net_id __read_mostly;


static int fou_udp_recv(struct sock *sk, struct sk_buff *skb);
static int fou_err_lookup(struct sock *sk, struct sk_buff *skb);
static struct sk_buff *fou_gro_receive(struct sock *sk,
                       struct list_head *head,
                       struct sk_buff *skb);
static int fou_gro_complete(struct sock *sk, struct sk_buff *skb,
                int nhoff);


static inline struct fou_dev *fou_from_sock(struct sock *sk)
{
    return sk->sk_user_data;
}


/* Setup stats when device is created */
static int fou_init(struct net_device *dev)
{
    struct fou_dev *foudev = netdev_priv(dev);
    int err;
    pr_info("fou_init");

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

static void fou_uninit(struct net_device *dev)
{
    struct fou_dev *foudev = netdev_priv(dev);
    pr_info("fou_uninit");

    gro_cells_destroy(&foudev->gro_cells);
    free_percpu(dev->tstats);
}

static int fou_open(struct net_device *dev)
{
    pr_info("fou_open");
    netif_start_queue(dev);
    return 0;
}

static int fou_stop(struct net_device *dev)
{
    pr_info("fou_stop");
    netif_stop_queue(dev);
    return 0;
}











static int _push_fastd_header(
	struct sk_buff *skb,
	unsigned int needed_headroom)
{
	int rc;

	needed_headroom += sizeof(struct udphdr);

	if (needed_headroom > skb_headroom(skb)) {
		pr_debug_ratelimited(
			"head space: %d, needed: %d",
			skb_headroom(skb), needed_headroom);

		rc = skb_cow_head(skb, needed_headroom);
		if (unlikely(rc))
			return -ENOBUFS;
	}

	return 0;
}




static struct rtable * _get_rtable4(
	struct fou_dev *foudev,
	const struct sk_buff *skb)
{
    struct sock *sk = foudev->sock->sk;
    struct flowi4 *flowinfo = &foudev->flowinfo.u.ip4;
	struct rtable *rt;

	rt = dst_cache_get_ip4(&foudev->routing_cache, &flowinfo->saddr);
	if (likely(rt))
		return rt;

	pr_debug("dst_cache_get_ip4 miss");

	/* Check whenever the cached source IP is gone. */
	if (unlikely(!inet_confirm_addr(sock_net(sk), NULL, 0,
	                                flowinfo->saddr,
	                                RT_SCOPE_HOST))) {
		dst_cache_reset(&foudev->routing_cache);

		return ERR_PTR(-EHOSTUNREACH);
	}

	rt = ip_route_output_flow(sock_net(sk), flowinfo, sk);
	if (unlikely(IS_ERR(rt)))
		return rt;

	/* Avoid looping packages coming from the tunnel netdev back into
	 * the same netdev again.
	 */
	if (unlikely(rt->dst.dev == skb->dev)) {
		ip_rt_put(rt);
		return ERR_PTR(-ELOOP);
	}

	dst_cache_set_ip4(&foudev->routing_cache, &rt->dst, flowinfo->saddr);

	return rt;
}


static int _send4(struct fou_dev *foudev, struct sk_buff *skb)
{
    struct flowi4 *flowinfo = &foudev->flowinfo.u.ip4;
	struct rtable *rt;
	int rc;

	rt = _get_rtable4(foudev, skb);
	if (unlikely(IS_ERR(rt))) {
		rc = PTR_ERR(rt);
		pr_warn_ratelimited("no route, error %d", rc);
		goto err_no_route;
	}

	rc = _push_fastd_header(skb, sizeof(struct iphdr));
	if (unlikely(rc))
		goto err_no_buffer_space;

	udp_tunnel_xmit_skb(
		rt, foudev->sock->sk, skb, flowinfo->saddr, flowinfo->daddr, 0,
		ip4_dst_hoplimit(&rt->dst), 0, flowinfo->fl4_sport,
		flowinfo->fl4_dport, false, false);
	return 0;

err_no_buffer_space:
	ip_rt_put(rt);

err_no_route:
	dev_kfree_skb(skb);

	return rc;
}


static struct dst_entry * _get_dst_entry(
	struct fou_dev *foudev,
    const struct sk_buff *skb)
{
    struct sock *sk = foudev->sock->sk;
    struct flowi6 *flowinfo = &foudev->flowinfo.u.ip6;
	struct dst_entry *dst;
	int rc = 0;

	dst = dst_cache_get_ip6(&foudev->routing_cache, &flowinfo->saddr);
	if (likely(dst))
		return dst;

	pr_debug("dst_cache_get_ip6 miss.");

	if (!ipv6_chk_addr(sock_net(sk), &flowinfo->saddr, NULL, 0)) {
		dst_cache_reset(&foudev->routing_cache);

		return ERR_PTR(-EHOSTUNREACH);
	}

	rc = ip6_dst_lookup(sock_net(sk), sk, &dst, flowinfo);
	if (unlikely(rc))
		return ERR_PTR(rc);

	/* Avoid looping packages coming from the tunnel netdev back into
	 * the same netdev again.
	 */
	if (unlikely(dst->dev == skb->dev)) {
		dst_release(dst);
		return ERR_PTR(-ELOOP);
	}

	dst_cache_set_ip6(&foudev->routing_cache, dst, &flowinfo->saddr);

	return dst;
}


static int _send6(struct fou_dev *foudev, struct sk_buff *skb)
{
    struct flowi6 *flowinfo = &foudev->flowinfo.u.ip6;
	struct dst_entry *dst;
	int rc = 0;

	dst = _get_dst_entry(foudev, skb);
	if (unlikely(IS_ERR(dst))) {
		rc = PTR_ERR(dst);
		pr_debug_ratelimited("no route, error %d", rc);
		goto err_no_route;
	}

	rc = _push_fastd_header(skb, sizeof(struct ipv6hdr));
	if (unlikely(rc))
		goto err_no_buffer_space;

	udp_tunnel6_xmit_skb(
		dst, foudev->sock->sk, skb, skb->dev, &flowinfo->saddr,
		&flowinfo->daddr, 0, ip6_dst_hoplimit(dst), 0,
		flowinfo->fl6_sport, flowinfo->fl6_dport, false);
	return 0;

err_no_buffer_space:
	dst_release(dst);

err_no_route:
	dev_kfree_skb(skb);

	return rc;
}










static netdev_tx_t fou_xmit(struct sk_buff *skb, struct net_device *dev)
{
    /* This is where the magic happens */
    pr_info("fou_xmit");

    struct rtable *rt;
    struct fou_dev *foudev = netdev_priv(dev);
    int err;

	skb_scrub_packet(skb, true);

	if (foudev->sock->sk->sk_family == AF_INET) {
		err = _send4(foudev, skb);

	} else if (foudev->sock->sk->sk_family == AF_INET6) {
		err = _send6(foudev, skb);

	} else {
		dev_kfree_skb(skb);
		err = -EAFNOSUPPORT;
	}

    if (err)
        return err;

    dev->stats.tx_dropped++;
    return NETDEV_TX_OK;
}

static int fou_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
    pr_info("fou_fill_metadata_dst");
    return 0;
}

static const struct net_device_ops fou_netdev_ops = {
    .ndo_init               = fou_init,
    .ndo_uninit             = fou_uninit,
    .ndo_open               = fou_open,
    .ndo_stop               = fou_stop,
    .ndo_start_xmit         = fou_xmit,
    .ndo_get_stats64        = ip_tunnel_get_stats64,
    .ndo_fill_metadata_dst  = fou_fill_metadata_dst,
};

static const struct nla_policy fou_policy[FASTD_SETFD_A_MAX + 1] = {
    [FASTD_SETFD_A_FD] = { .type = NLA_U32 },
};


/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type fou_type = {
    .name = "myfou",
};

/* Initialize the device structure. */
static void fou_setup(struct net_device *dev)
{
    struct fou_dev *foudev = netdev_priv(dev);

    pr_info("fou_setup");

    dev->netdev_ops        = &fou_netdev_ops;
    dev->needs_free_netdev = true;
    SET_NETDEV_DEVTYPE(dev, &fou_type);
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

static int fou_validate(struct nlattr *tb[], struct nlattr *data[],
                struct netlink_ext_ack *extack)
{
    pr_info("fou_validate");

    if (!data[FASTD_SETFD_A_FD]) {
        pr_info("udptun: filedescriptor is missing");
        return -EINVAL;
    }

    return 0;
}

static int fou2info(struct nlattr *data[], struct fou_dev_cfg *conf,
            struct netlink_ext_ack *extack)
{
    pr_info("fou2info");


    memset(conf, 0, sizeof(*conf));
    conf->sockfd = nla_get_u32(data[FASTD_SETFD_A_FD]);
    return 0;
}

// Überprüft, ob der übergebene Socket unterstützt wird
static int fou_check_sock_type(struct socket *skt) {
	struct sock *sk = skt->sk;
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
			pr_debug("saddr_cache missing");
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


static void _update_flowi4(const struct fou_dev *foudev)
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

static void _update_flowi6(const struct fou_dev *foudev)
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

static int fou_configure(struct net *net, struct net_device *dev,
                 struct fou_dev_cfg *conf)
{
    struct fou_net *fn = net_generic(net, fou_net_id);
    struct fou_dev *t, *foudev = netdev_priv(dev);
    struct udp_tunnel_sock_cfg tunnel_cfg;
	struct ipv6_pinfo *np;
    struct socket *skt;
    int err;

    pr_info("fou_configure");

    if(!foudev)
        return -EBUSY;


    /* This also takes a new reference on the fd, keeping it open. */
    skt = sockfd_lookup(conf->sockfd, &err);
    if (skt == NULL) {
        return err == 0 ? -EINVAL : err;
    }

    err = fou_check_sock_type(skt);
    if (err)
        return;

    struct sockaddr_storage local, peer;
	kernel_getsockname(skt, (struct sockaddr *)&local);
	kernel_getpeername(skt, (struct sockaddr *)&peer);
	pr_info("new socket %pISpfc -> %pISpfc", &local, &peer);

    foudev->sock = skt;
    foudev->net = net;
    foudev->dev = dev;

    tunnel_cfg = (struct udp_tunnel_sock_cfg){
        .sk_user_data     = foudev,
        .encap_type       = 1,
        .encap_destroy    = NULL,
        .encap_rcv        = fou_udp_recv,
        .encap_err_lookup = fou_err_lookup,
        .gro_receive      = fou_gro_receive,
        .gro_complete     = fou_gro_complete,
    };
    pr_info("fou: setup_udp_tunnel_sock()");
    setup_udp_tunnel_sock(NULL, skt, &tunnel_cfg);

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

    list_add(&foudev->list, &fn->fou_dev_list);
    return 0;
}


static int fou_newlink(struct net *src_net, struct net_device *dev,
               struct nlattr *tb[], struct nlattr *data[],
               struct netlink_ext_ack *extack)
{
    struct fou_dev_cfg conf;
    int err;

    pr_info("fou_newlink");

    err = fou2info(data, &conf, extack);
    if (err)
        return err;

    err = fou_configure(src_net, dev, &conf);
    if (err)
        return err;

    return 0;
}

static void fou_dellink(struct net_device *dev, struct list_head *head)
{
    struct fou_dev *foudev = netdev_priv(dev);

    pr_info("fou_dellink");

    list_del(&foudev->list);
    unregister_netdevice_queue(dev, head);
}

static size_t fou_get_size(const struct net_device *dev)
{

    return
        /* FASTD_SETFD_A_FD */
        nla_total_size(4) +
        0;
}

static int fou_link_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
    return 0;
}



static struct rtnl_link_ops fou_link_ops __read_mostly = {
    .kind           = "fou",
    .maxtype        = FASTD_SETFD_A_MAX,
    .policy         = fou_policy,
    .priv_size      = sizeof(struct fou_dev),
    .setup          = fou_setup,
    .validate       = fou_validate,
    .newlink        = fou_newlink,
    .dellink        = fou_dellink,
    .get_size       = fou_get_size,
    .fill_info      = fou_link_fill_info,
};






static int fou_udp_recv(struct sock *sk, struct sk_buff *skb)
{
    int err;
    struct net *net = sock_net(sk);
    struct fou_dev *fou = rcu_dereference_sk_user_data(sk);
//    ...
    /* This is where your magic goes. */
//    ...
    err = netif_receive_skb(skb);
    return 0;
drop:
    kfree_skb(skb);
    return 0;
}

static struct sk_buff *fou_gro_receive(struct sock *sk,
                       struct list_head *head,
                       struct sk_buff *skb)
{
    u8 proto = 0; // fou_from_sock(sk)->protocol;
    const struct net_offload **offloads;
    const struct net_offload *ops;
    struct sk_buff *pp = NULL;

    pr_info("fou_gro_receive");

    NAPI_GRO_CB(skb)->encap_mark = 0;

    /* Flag this frame as already having an outer encap header */
    NAPI_GRO_CB(skb)->is_fou = 1;

    rcu_read_lock();
    offloads = NAPI_GRO_CB(skb)->is_ipv6 ? inet6_offloads : inet_offloads;
    ops = rcu_dereference(offloads[proto]);
    if (!ops || !ops->callbacks.gro_receive)
        goto out_unlock;
    pp = call_gro_receive(ops->callbacks.gro_receive, head, skb);

out_unlock:
    rcu_read_unlock();
    return pp;
}

static int fou_gro_complete(struct sock *sk, struct sk_buff *skb,
                int nhoff)
{
    const struct net_offload *ops;
    u8 proto = 0; // fou_from_sock(sk)->protocol;
    int err = -ENOSYS;
    const struct net_offload **offloads;

    pr_info("fou_gro_complete");

    rcu_read_lock();
    offloads = NAPI_GRO_CB(skb)->is_ipv6 ? inet6_offloads : inet_offloads;
    ops = rcu_dereference(offloads[proto]);
    if (WARN_ON(!ops || !ops->callbacks.gro_complete))
        goto out_unlock;

    err = ops->callbacks.gro_complete(skb, nhoff);
    skb_set_inner_mac_header(skb, nhoff);

out_unlock:
    rcu_read_unlock();
    return err;
}

static int fou_err_lookup(struct sock *sk, struct sk_buff *skb)
{
    return 0;
}


static void fou_release(struct fou_dev *foudev)
{
    struct socket *sock = foudev->sock;

    list_del(&foudev->list);
    if (sock) {
        udp_tunnel_sock_release(sock);
        dst_cache_destroy(&foudev->routing_cache);
    }
}


// Registrierung eines network namespaces
static __net_init int fou_init_net(struct net *net)
{
    struct fou_net *fn = net_generic(net, fou_net_id);
    pr_info("fou_init_net net_id=%d", fou_net_id);


    INIT_LIST_HEAD(&fn->fou_dev_list);
    mutex_init(&fn->fou_lock);
    return 0;
}


// Entfernung eines network namespaces
static __net_exit void fou_exit_net(struct net *net)
{
    struct fou_net *fn = net_generic(net, fou_net_id);
    struct fou_dev *fou, *next;

    pr_info("fou_exit_net net_id=%d", fou_net_id);

    /* Close all the FOU sockets */
    mutex_lock(&fn->fou_lock);
    list_for_each_entry_safe(fou, next, &fn->fou_dev_list, list)
        fou_release(fou);
    mutex_unlock(&fn->fou_lock);
}


/* Struct containing pointers to the above functions */
static struct pernet_operations fou_net_ops = {
    .init = fou_init_net,
    .exit = fou_exit_net,
    .id   = &fou_net_id,
    .size = sizeof(struct fou_net),
};



// Kernelmodul wird initialisiert (modprobe/insmod)
static int __init fou_init_module(void)
{
    int rc;
    pr_info("fou_init_module");

    rc = register_pernet_subsys(&fou_net_ops);
    if (rc)
        goto out;

    rc = rtnl_link_register(&fou_link_ops);

out:
    pr_info("fou_init_module finished rc=%d", rc);
    return rc;
}


// Kernelmodul wird aufgeräumt (rmmod)
static void __exit fou_cleanup_module(void)
{
    pr_info("fou_cleanup_module");
    rtnl_link_unregister(&fou_link_ops);
    unregister_pernet_subsys(&fou_net_ops);
}



module_init(fou_init_module);
module_exit(fou_cleanup_module);
MODULE_AUTHOR("Rob Hartzenberg <rob@craftypenguins.ca>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UDP Tunnel");
