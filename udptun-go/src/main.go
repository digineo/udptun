package main

import (
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	cmdSetup       = kingpin.Command("setup", "setup a tunnel")
	localEndpoint  = cmdSetup.Flag("local", "tunnel local endpoint").Default(":0").String()
	remoteEndpoint = cmdSetup.Flag("remote", "tunnel remote endpoint").Default("192.168.180.38:8500").String()

	cmdInfo   = kingpin.Command("info", "list all tunnels")
	cmdListen = kingpin.Command("listen", "create a TUN interface and listen")

	devName    = kingpin.Flag("dev", "interface name").Default("test").String()
	devAddr    = kingpin.Flag("ip", "ip address to add to the interface").Default("fe80::1/64").String()
	listenPort = kingpin.Flag("port", "listening port for the server").Default("8500").Int()
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
