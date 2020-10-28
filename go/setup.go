package main

import (
	"log"
	"net"
)

func setup() {
	raddr, err := net.ResolveUDPAddr("udp", *remoteEndpoint)
	if err != nil {
		panic(err)
	}

	laddr, err := net.ResolveUDPAddr("udp", *localEndpoint)
	if err != nil {
		panic(err)
	}

	log.Println("connecting from", laddr, "to", raddr)

	// UDP-Socket aufbauen
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		panic(err)
	}

	conn.Write([]byte("hello world"))

	log.Printf("local=%v remote=%v", conn.LocalAddr(), conn.RemoteAddr())

	// get raw connection
	rawConn, err := conn.SyscallConn()
	if err != nil {
		panic(err)
	}

	// Store rawConn.Control err in nestedErr so that it doesn't
	// overwrite any error from the passed callback.
	err = rawConn.Control(func(fd uintptr) {
		log.Printf("fd=%v", fd)
		passFd(fd, *ifname)
	})
	if err != nil {
		panic(err)
	}
	conn.Close()

	// IP-Adresse hinzufügen
	ip, ipnet, err := net.ParseCIDR(*local)
	if err != nil {
		panic(err)
	}

	addAddr(*ifname, net.IPNet{
		IP:   ip,
		Mask: ipnet.Mask,
	})
}
