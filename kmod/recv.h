#pragma once
#include <linux/inetdevice.h>
#include "module.h"


int fou_udp_recv(struct sock *sk, struct sk_buff *skb);


struct sk_buff *fou_gro_receive(struct sock *sk,
                       struct list_head *head,
                       struct sk_buff *skb);

int fou_gro_complete(struct sock *sk, struct sk_buff *skb,
                int nhoff);
