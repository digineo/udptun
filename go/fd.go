package main

import (
	"fmt"
	"log"
	"net"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// passFd passes the file descriptor via netlink to the kernel module
func passFd(fd uintptr, ifname string) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		panicf("failed to dial: %v", err)
	}
	defer conn.Close()

	attr := rtnetlink.LinkAttributes{
		Name: ifname,
		MTU:  mtu,
		Info: &rtnetlink.LinkInfo{
			Kind: "udptun",
		},
	}

	// Driver specific configuration
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(1, uint32(fd)) // file descriptor
	attr.Info.Data, err = ae.Encode()
	if err != nil {
		panic(err)
	}

	err = conn.Link.New(&rtnetlink.LinkMessage{
		Attributes: &attr,
	})

	if err != nil {
		panic(err)
	}
}

func addAddr(ifname string, addr net.IPNet) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}

	// Dial a connection to the rtnetlink socket
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Test for the right address family for addr
	family := unix.AF_INET6
	to4 := addr.IP.To4()
	if to4 != nil {
		family = unix.AF_INET
	}
	// Calculate the prefix length
	ones, _ := addr.Mask.Size()

	// Send the message using the rtnetlink.Conn
	err = conn.Address.New(&rtnetlink.AddressMessage{
		Family:       uint8(family),
		PrefixLength: uint8(ones),
		Index:        uint32(iface.Index),
		Attributes: rtnetlink.AddressAttributes{
			Address: addr.IP,
		},
	})

	if err != nil {
		panic(err)
	}
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
