package main

import (
	"log"
	"net"

	"github.com/vishvananda/netlink"
)

func configureDevice(ifname string, mtu int, ip *net.IPNet) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	log.Println("adding IP address", ip)
	if err := netlink.AddrAdd(link, &netlink.Addr{
		IPNet: ip,
	}); err != nil {
		return err
	}

	return netlink.LinkSetMTU(link, mtu)
}
