package main

import (
	"log"
	"net"

	"github.com/spf13/cobra"
)

func init() {
	addTunnelFlags(setupCmd.Flags())
	setupCmd.MarkFlagRequired("peer")
	rootCmd.AddCommand(setupCmd)
}

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up the UDP tunnel interface in the kernel via netlink",
	Run: func(cmd *cobra.Command, args []string) {
		raddr, err := net.ResolveUDPAddr("udp", peerEndpoint)
		if err != nil {
			panic(err)
		}

		laddr := &net.UDPAddr{
			Port: localPort,
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
			passFd(fd, devName)
		})
		if err != nil {
			panic(err)
		}
		conn.Close()

		// Add IP address

		ip, ipnet, err := net.ParseCIDR(ipAddr)
		if err != nil {
			panic(err)
		}

		err = configureDevice(devName, 1450, &net.IPNet{
			IP:   ip,
			Mask: ipnet.Mask,
		})
		if err != nil {
			panic(err)
		}
	},
}
