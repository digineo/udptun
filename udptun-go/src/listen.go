package main

import (
	"errors"
	"log"
	"net"
	"os"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

var (
	peerAddr *net.UDPAddr
	tun      *water.Interface
	udpConn  *net.UDPConn
)

const mtu = 1450

func listen() {
	addr := net.UDPAddr{
		Port: *listenPort,
	}

	var err error

	log.Println("creating interface", *devName)
	tun, err = CreateTun(*devName)
	if err != nil {
		panic(err)
	}

	log.Println("listening on", addr)
	udpConn, err = net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}

	ip, ipnet, err := net.ParseCIDR(*devAddr)
	if err != nil {
		panic(err)
	}

	err = SetupTun(*devName, mtu, &net.IPNet{
		IP:   ip,
		Mask: ipnet.Mask,
	})
	if err != nil {
		panic(err)
	}

	go udpWorker()
	tunWorker()
}

func CreateTun(ifname string) (*water.Interface, error) {
	return water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: ifname,
		},
	})
}

func SetupTun(ifname string, mtu int, ip *net.IPNet) error {
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

func udpWorker() {
	buf := make([]byte, mtu)

	for {
		n, addr, err := udpConn.ReadFrom(buf)
		if err != nil {
			log.Println(err)
			break
		}

		log.Printf("received %d bytes", n)
		peerAddr = addr.(*net.UDPAddr)

		// forward to tun interface
		tun.Write(buf[:n])
	}
}

// Reads packets from the TUN device and sends them via UDP
func tunWorker() {
	buf := make([]byte, mtu)

	for {
		n, err := tun.Read(buf)
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				log.Printf("unable to read from tun interface: %v", err)
			}
			break
		}

		if addr := peerAddr; addr != nil {
			written, _ := udpConn.WriteToUDP(buf[:n], peerAddr)
			log.Printf("sent %d bytes", written)
		}
	}
}
