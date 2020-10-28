package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
)

func info() {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		panicf("failed to dial: %v", err)
	}
	defer conn.Close()

	msgs, err := conn.Link.ListByKind("udptun")
	if err != nil {
		panicf("failed to list links: %v", err)
	}

	for i := range msgs {
		msg := &msgs[i]
		data, err := decodeLinkData(msg.Attributes.Info.Data)
		if err != nil {
			log.Println(err)
			continue
		}

		fmt.Printf("iface=%v local=%+v remote=%+v\n", msg.Attributes.Name, udpAddrToString(data.local), udpAddrToString(data.remote))
	}
}

func udpAddrToString(addr net.UDPAddr) string {
	port := strconv.Itoa(addr.Port)

	return net.JoinHostPort(addr.IP.String(), port)
}

const (
	UDPTUN_ATTR_UNSPEC     = iota
	UDPTUN_ATTR_FD         /* u32 */
	UDPTUN_ATTR_AF         /* u8 */
	UDPTUN_ATTR_LOCAL_ADDR /* u32/in6_addr */
	UDPTUN_ATTR_LOCAL_PORT /* u16 */
	UDPTUN_ATTR_PEER_ADDR  /* u32/in6_addr */
	UDPTUN_ATTR_PEER_PORT  /* u16 */
)

type linkData struct {
	local  net.UDPAddr
	remote net.UDPAddr
}

func decodeLinkData(data []byte) (result linkData, err error) {
	var ad *netlink.AttributeDecoder
	ad, err = netlink.NewAttributeDecoder(data)
	if err != nil {
		return
	}

	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case UDPTUN_ATTR_LOCAL_ADDR:
			result.local.IP = net.IP(ad.Bytes())
		case UDPTUN_ATTR_PEER_ADDR:
			result.remote.IP = net.IP(ad.Bytes())
		case UDPTUN_ATTR_LOCAL_PORT:
			result.local.Port = int(ad.Uint16())
		case UDPTUN_ATTR_PEER_PORT:
			result.remote.Port = int(ad.Uint16())
		}
	}

	return
}
