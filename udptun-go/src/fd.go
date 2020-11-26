package main

import (
	"fmt"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
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

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
