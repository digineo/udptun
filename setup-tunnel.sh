#!/bin/sh
# Script to set up a tunnel from VM node1 to the host machine

# get local IPv4 address
local=$(ip -4 addr list scope global |grep inet | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | head -n1)

echo "Using local IP address $local"

# Prepare ssh config for faster ssh invocation.
ssh_config="$(mktemp --tmpdir vagrant_ssh_cfg.XXXXXXX)"
trap "{ rm '$ssh_config'; }" EXIT

# echo "Include ~/.ssh/config" > "$ssh_config"
vagrant ssh-config node1  > "$ssh_config"

# 1. build and install kernel module
# 2. build and install setup tool
# 3. set up tunnel
ssh -F "$ssh_config" -t root@node1 <<SHELL
  set -x
  cd /vagrant/openspot-kmod-udptun/src/
  make clean
  make
  rmmod udptun
  insmod udptun.ko

  cd /vagrant/udptun-go/src
  go install .

  ~/go/bin/main setup --localPort 8500 --peer "$local:8500"
  ip addr add 192.168.2.1/24 dev test
  ip link set up dev test
  ~/go/bin/main info
SHELL
