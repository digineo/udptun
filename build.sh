
cd go && go build -o ../output/config . && cd ..
cd kmod && make && rsync udptun.ko ../output/ || exit 1

host=default

# Prepare ssh config for faster ssh invocation.
ssh_config="$(mktemp --tmpdir vagrant_ssh_cfg.XXXXXXX)"
trap "{ rm '$ssh_config'; }" EXIT

# echo "Include ~/.ssh/config" > "$ssh_config"
vagrant ssh-config "$host"  > "$ssh_config"


ssh -F "$ssh_config" -t root@"$host" <<SHELL
    set -x
    cd /vagrant/output

    rmmod udptun
    modprobe udp_tunnel
    modprobe ip_tunnel
    modprobe ip6_tunnel
    insmod udptun.ko
SHELL
