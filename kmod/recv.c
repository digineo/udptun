
#include <net/protocol.h>
#include <linux/version.h>
#include "module.h"


inline static int _fou_inner_proto(struct iphdr *hdr, int *out_inner_proto)
{
	switch (hdr->version) {
	case 4:
		*out_inner_proto = IPPROTO_IPIP;
		break;
	case 6:
		*out_inner_proto = IPPROTO_IPV6;
		break;
	default:
		return 1;
	}

	return 0;
}


// UDP packet received
int fou_udp_recv(struct sock *sk, struct sk_buff *skb)
{
	struct fou_dev *foudev = sk->sk_user_data;
	struct iphdr *iphdr;
	size_t len;
	int proto;

	netdev_dbg(foudev->dev, "fou_udp_recv");

	// UDP-header + IP-Header müssen vorhanden sein
	len = sizeof(struct udphdr) + sizeof(struct iphdr);
	if (unlikely(!pskb_may_pull(skb, len)))
		goto drop;

	// Pointer to IP header behind the UDP header
	iphdr = (struct iphdr *)&udp_hdr(skb)[1];

	// Get ethernet protocol number
	switch (iphdr->version) {
	case 4:
		proto = htons(ETH_P_IP);
		break;
	case 6:
		proto = htons(ETH_P_IPV6);
		break;
	default:
		goto drop;
	}

	// Pull UDP header
	if (iptunnel_pull_header(skb, sizeof(struct udphdr), proto, false))
		goto drop;

	// set incoming device
	skb->dev = foudev->dev;

	if(gro_cells_receive(&foudev->gro_cells, skb)) {
		netdev_dbg(foudev->dev, "fou_udp_recv: gro_cells_receive failed");
	}

	return 0;

drop:
	netdev_dbg(foudev->dev, "fou_udp_recv: dropped");
	kfree_skb(skb);
	return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
struct sk_buff *fou_gro_receive(struct sock *sk, struct list_head *head, struct sk_buff *skb) {
	struct sk_buff *pp = NULL;
#else
struct sk_buff **fou_gro_receive(struct sock *sk, struct sk_buff **head, struct sk_buff *skb) {
	struct sk_buff **pp = NULL;
#endif
	const struct net_offload **offloads;
	const struct net_offload *ops;
	struct iphdr *iphdr;
	size_t len, off;
	int flush = 1;
	struct gro_remcsum grc;
	int proto;

	netdev_dbg(skb->dev, "fou_gro_receive");
	skb_gro_remcsum_init(&grc);

	off = skb_gro_offset(skb);
	len = off + 1;  // im ersten byte steht die IP-Version

	// Referenz auf IP-Header
	iphdr = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, len)) {
		iphdr = skb_gro_header_slow(skb, len, off);
		if (unlikely(!iphdr))
			goto out;
	}

	if(_fou_inner_proto(iphdr, &proto)){
		goto out;
	}

	/* We can clear the encap_mark for GUE as we are essentially doing
	 * one of two possible things.  We are either adding an L4 tunnel
	 * header to the outer L3 tunnel header, or we are are simply
	 * treating the GRE tunnel header as though it is a UDP protocol
	 * specific header such as VXLAN or GENEVE.
	 */
	NAPI_GRO_CB(skb)->encap_mark = 0;

	/* Flag this frame as already having an outer encap header */
	NAPI_GRO_CB(skb)->is_fou = 1;

	rcu_read_lock();
	offloads = NAPI_GRO_CB(skb)->is_ipv6 ? inet6_offloads : inet_offloads;
	ops = rcu_dereference(offloads[proto]);
	if (WARN_ON_ONCE(!ops || !ops->callbacks.gro_receive))
		goto out_unlock;

	pp = call_gro_receive(ops->callbacks.gro_receive, head, skb);
	flush = 0;

out_unlock:
	rcu_read_unlock();
out:
	skb_gro_flush_final_remcsum(skb, pp, flush, &grc);

	return pp;
}


int fou_gro_complete(struct sock *sk, struct sk_buff *skb,
                int nhoff)
{
	const struct net_offload **offloads;
	struct iphdr *iphdr = (struct iphdr *)(skb->data + nhoff);
	const struct net_offload *ops;
	int proto;
	int err = -ENOENT;

	netdev_dbg(skb->dev, "fou_gro_complete");

	if(_fou_inner_proto(iphdr, &proto)){
		return err;
	}

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
