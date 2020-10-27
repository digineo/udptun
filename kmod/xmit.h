#pragma once

#include <linux/inetdevice.h>

netdev_tx_t udptun_xmit(struct sk_buff *skb, struct net_device *dev);
