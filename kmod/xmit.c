#include <linux/inetdevice.h>
#include "module.h"


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

	netdev_dbg(foudev->dev, "dst_cache_get_ip4 miss");

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
		rt, foudev->sock->sk, skb,
		flowinfo->saddr,
		flowinfo->daddr,
		0, ip4_dst_hoplimit(&rt->dst), 0,
		flowinfo->fl4_sport,
		flowinfo->fl4_dport,
		false, false);
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

	netdev_dbg(foudev->dev, "dst_cache_get_ip6 miss");

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
		dst, foudev->sock->sk,
		skb, skb->dev,
		&flowinfo->saddr,
		&flowinfo->daddr,
		0, ip6_dst_hoplimit(dst), 0,
		flowinfo->fl6_sport,
		flowinfo->fl6_dport,
		false);

	return 0;

err_no_buffer_space:
	dst_release(dst);

err_no_route:
	dev_kfree_skb(skb);

	return rc;
}




netdev_tx_t fou_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct fou_dev *foudev = netdev_priv(dev);
	int err;

	/* This is where the magic happens */
	netdev_dbg(dev, "fou_xmit");

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
