#include <linux/kernel.h>   /* We're doing Kernel work */
#include <linux/module.h>   /* Specifically a Kernel Module */
#include <linux/moduleparam.h>
#include <linux/init.h>     /* Needed for the module_init/exit() macros */
#include <linux/errno.h>
#include <net/protocol.h>
#include <net/ip_tunnels.h>
#include <net/ip6_tunnel.h>
#include <net/udp_tunnel.h>
#include "udptun.h"
#include "uapi/fastd.h"



static unsigned int my_net_id __read_mostly;


static __net_init int my_init_net(struct net *net)
{
    struct my_net *mn = net_generic(net, my_net_id);

    INIT_LIST_HEAD(&mn->my_list);
    mutex_init(&mn->my_lock);
    return 0;
}

static __net_exit void my_exit_net(struct net *net)
{
    /* Close any sockets and free any netns specific stuff */
}





static inline struct my *my_from_sock(struct sock *sk)
{
    return sk->sk_user_data;
}



static int my_init(struct net_device *dev)
{
    struct my_dev *mydev = netdev_priv(dev);
    int err;

    dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
    if (!dev->tstats)
        return -ENOMEM;

    err = gro_cells_init(&mydev->gro_cells, dev);
    if (err) {
        free_percpu(dev->tstats);
        return err;
    }
    return 0;
}

static void my_uninit(struct net_device *dev)
{
    struct my_dev *mydev = netdev_priv(dev);

    gro_cells_destroy(&mydev->gro_cells);
    free_percpu(dev->tstats);
}

static int my_open(struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

static int my_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}

static netdev_tx_t my_xmit(struct sk_buff *skb, struct net_device *dev)
{
    /* This is where the magic happens */
    //...
    return NETDEV_TX_OK;
}

static int my_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
    return 0;
}

static const struct net_device_ops my_netdev_ops = {
    .ndo_init               = my_init,
    .ndo_uninit             = my_uninit,
    .ndo_open               = my_open,
    .ndo_stop               = my_stop,
    .ndo_start_xmit         = my_xmit,
    .ndo_get_stats64        = ip_tunnel_get_stats64,
    .ndo_fill_metadata_dst  = my_fill_metadata_dst,
};

static const struct nla_policy my_policy[FASTD_SETFD_A_MAX + 1] = {
    [FASTD_SETFD_A_FD] = { .type = NLA_U32 },
};


/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type my_type = {
    .name = "my",
};

/* Initialize the device structure. */
static void my_setup(struct net_device *dev)
{
    dev->netdev_ops = &my_netdev_ops;
    dev->needs_free_netdev = true;
    SET_NETDEV_DEVTYPE(dev, &my_type);
    dev->features    |= NETIF_F_SG | NETIF_F_HW_CSUM;
    dev->features    |= NETIF_F_RXCSUM;
    dev->features    |= NETIF_F_GSO_SOFTWARE;
    dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
    dev->hw_features |= NETIF_F_GSO_SOFTWARE;
    dev->hard_header_len = 0;
    dev->addr_len = 0;
    dev->mtu = ETH_DATA_LEN;
    dev->min_mtu = IPV4_MIN_MTU;
    dev->max_mtu = IP_MAX_MTU;
    dev->type = ARPHRD_NONE;
    netif_keep_dst(dev);
    dev->priv_flags |= IFF_NO_QUEUE;
    dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
}

static int my_validate(struct nlattr *tb[], struct nlattr *data[],
                struct netlink_ext_ack *extack)
{
    return 0;
}

static int my2info(struct nlattr *data[], struct my_dev_cfg *conf,
            struct netlink_ext_ack *extack)
{
    memset(conf, 0, sizeof(*conf));
    conf->id = 0;

    return 0;
}

static struct my_dev *my_find_dev(struct my_net *mn,
                        const struct my_dev_cfg *conf)
{
    struct my_dev *mydev, *t = NULL;

    if(! list_empty(&mn->my_dev_list))
        list_for_each_entry(mydev, &mn->my_dev_list, next) {
            if (conf->id == mydev->id)
                t = mydev;
        }
    return t;
}

static int my_configure(struct net *net, struct net_device *dev,
                 struct my_dev_cfg *conf)
{
    struct my_net *mn = net_generic(net, my_net_id);
    struct my_dev *t, *mydev = netdev_priv(dev);
    int err;

    if(!mydev)
        return -EBUSY;

    mydev->net = net;
    mydev->dev = dev;
    t = my_find_dev(mn, conf);
    if (t)
        return -EBUSY;

    mydev->id = conf->id;
    err = register_netdevice(dev);
    if (err)
        return err;

    list_add(&mydev->next, &mn->my_dev_list);
    return 0;
}

static int my_link_config(struct net_device *dev, struct nlattr *tb[])
{
    int err;

    if (tb[IFLA_MTU]) {
        err = dev_set_mtu(dev, nla_get_u32(tb[IFLA_MTU]));
        if (err)
            return err;
    }
    return 0;
}

static int my_newlink(struct net *net, struct net_device *dev,
               struct nlattr *tb[], struct nlattr *data[],
               struct netlink_ext_ack *extack)
{
    struct my_dev_cfg conf;
    int err;

    err = my2info(data, &conf, extack);
    if (err)
        return err;

    err = my_configure(net, dev, &conf);
    if (err)
        return err;

    err = my_link_config(dev, tb);
    if (err)
        return err;

    return 0;
}

static void my_dellink(struct net_device *dev, struct list_head *head)
{
    struct my_dev *mydev = netdev_priv(dev);

    list_del(&mydev->next);
    unregister_netdevice_queue(dev, head);
}

static size_t my_get_size(const struct net_device *dev)
{
    return 0;
}

static int my_link_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
    return 0;
}



static struct rtnl_link_ops my_link_ops __read_mostly = {
    .kind           = "my",
    .maxtype        = FASTD_SETFD_A_MAX,
    .policy         = my_policy,
    .priv_size      = sizeof(struct my_dev),
    .setup          = my_setup,
    .validate       = my_validate,
    .newlink        = my_newlink,
    .dellink        = my_dellink,
    .get_size       = my_get_size,
    .fill_info      = my_link_fill_info,
};






static int my_udp_recv(struct sock *sk, struct sk_buff *skb)
{
    int err;
    struct net *net = sock_net(sk);
    struct my *my = rcu_dereference_sk_user_data(sk);
//    ...
    /* This is where your magic goes. */
//    ...
    err = netif_receive_skb(skb);
    return 0;
drop:
    kfree_skb(skb);
    return 0;
}

static struct sk_buff *my_gro_receive(struct sock *sk,
                       struct list_head *head,
                       struct sk_buff *skb)
{
    u8 proto = my_from_sock(sk)->protocol;
    const struct net_offload **offloads;
    const struct net_offload *ops;
    struct sk_buff *pp = NULL;

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

static int my_gro_complete(struct sock *sk, struct sk_buff *skb,
                int nhoff)
{
    const struct net_offload *ops;
    u8 proto = my_from_sock(sk)->protocol;
    int err = -ENOSYS;
    const struct net_offload **offloads;

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

static int my_err_lookup(struct sock *sk, struct sk_buff *skb)
{
    return 0;
}

static int my_create(struct net *net, struct my_cfg *cfg, struct socket **sockp)
{
    struct socket *sock = NULL;
    struct my *my;
    struct sock *sk;
    struct udp_tunnel_sock_cfg tunnel_cfg;
    int err;

    /* Open UDP socket */
    err = udp_sock_create(net, &cfg->udp_config, &sock);
    if (err < 0) {
        goto error;
    }

    /* Allocate MY port structure */
    my = kzalloc(sizeof(*my), GFP_KERNEL);
    if (!my) {
        err = -ENOMEM;
        goto error;
    }

    memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
    tunnel_cfg.encap_type = 1;
    tunnel_cfg.sk_user_data = my;
    tunnel_cfg.encap_destroy = NULL;
    tunnel_cfg.encap_rcv = my_udp_recv;
    tunnel_cfg.encap_err_lookup = my_err_lookup;
    tunnel_cfg.gro_receive = my_gro_receive;
    tunnel_cfg.gro_complete = my_gro_complete;

    setup_udp_tunnel_sock(net, sock, &tunnel_cfg);
// ...
    error:
    return err;
}


static void my_release(struct my *my)
{
    struct socket *sock = my->sock;

    list_del(&my->list);
    if (sock)
        udp_tunnel_sock_release(sock);
}





/* Struct containing pointers to the above functions */
static struct pernet_operations my_net_ops = {
    .init = my_init_net,
    .exit = my_exit_net,
    .id   = &my_net_id,
    .size = sizeof(struct my_net),
};


static int __init my_init_module(void)
{
    int rc;

    rc = register_pernet_subsys(&my_net_ops);
    if (rc)
        goto out;

    rc = rtnl_link_register(&my_link_ops);

out:
    return rc;
}


static void __exit my_cleanup_module(void)
{
    rtnl_link_unregister(&my_link_ops);
    unregister_pernet_subsys(&my_net_ops);
}



module_init(my_init_module);
module_exit(my_cleanup_module);
MODULE_AUTHOR("Rob Hartzenberg <rob@craftypenguins.ca>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UDP Tunnel");
