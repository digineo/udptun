package main

import (
	"flag"
	"log"
	"net"
	"os"
)

var (
	ifname         = flag.String("ifname", "test", "interface name")
	remoteEndpoint = flag.String("remote", "192.168.180.38:8500", "tunnel remote endpoint")
	localEndpoint  = flag.String("local", ":0", "tunnel local endpoint")
	local          = flag.String("ip", "fe80::1/64", "ip address of the interface")
	listenPort     = flag.Uint("port", 8500, "listening port for the server")
)

func main() {
	flag.Parse()
	cmd := flag.Arg(0)

	switch cmd {
	case "setup":
		setup()
	case "listen":
		listen()
	case "info":
		info()
	default:
		log.Panicln("invalid command:", cmd)
		os.Exit(1)
	}
}

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
