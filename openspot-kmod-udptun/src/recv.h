#pragma once

#include <linux/inetdevice.h>
#include <linux/version.h>
#include "module.h"


int udptun_udp_recv(struct sock *sk, struct sk_buff *skb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
struct sk_buff *udptun_gro_receive(struct sock *sk, struct list_head *head, struct sk_buff *skb);
#else
struct sk_buff **udptun_gro_receive(struct sock *sk, struct sk_buff **head, struct sk_buff *skb);
#endif

int udptun_gro_complete(struct sock *sk, struct sk_buff *skb,
                int nhoff);
