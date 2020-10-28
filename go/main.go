package main

import (
	"flag"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	cmdSetup       = kingpin.Command("setup", "setup a tunnel")
	localEndpoint  = cmdSetup.Flag("local", "tunnel local endpoint").Default(":0").String()
	remoteEndpoint = cmdSetup.Flag("remote", "tunnel remote endpoint").Default("192.168.180.38:8500").String()

	cmdInfo   = kingpin.Command("info", "list all tunnels")
	cmdListen = kingpin.Command("listen", "create a TUN interface and listen")

	ifname     = kingpin.Flag("ifname", "interface name").Default("test").String()
	local      = flag.String("ip", "fe80::1/64", "ip address of the interface")
	listenPort = flag.Uint("port", 8500, "listening port for the server")
)

func main() {
	switch kingpin.Parse() {
	// Register user
	case cmdSetup.FullCommand():
		setup()
	case cmdInfo.FullCommand():
		info()
	case cmdListen.FullCommand():
		listen()
	}
}
