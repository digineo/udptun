package main

import (
	"log"
	"net"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
)

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
