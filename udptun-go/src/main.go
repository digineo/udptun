package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   os.Args[0],
		Short: "udptun helper tool",
		Long:  `https://github.com/digineo/udptun`,
	}

	devName      string
	ipAddr       string
	localPort    int
	peerEndpoint string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func addTunnelFlags(flagSet *pflag.FlagSet) {
	flagSet.StringVar(&devName, "dev", "test", "tunnel device name")
	flagSet.StringVar(&ipAddr, "ip", "192.168.2.2/24", "local IP address for the tunnel interface")
	flagSet.IntVar(&localPort, "localPort", 5000, "local port")
	flagSet.StringVar(&peerEndpoint, "peer", "", "peer endpoint (ip:port)")
}
