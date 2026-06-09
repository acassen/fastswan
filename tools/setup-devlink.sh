#
#	Setup to properly run ipsec_packet oflload on a VF
#
# This has been used to debug IPsec packet offload tunnel mode on a VF

DEVLINK="/opt/mellanox/iproute2/sbin/devlink"

echo 0000:31:00.0 > /sys/bus/pci/drivers/mlx5_core/unbind
echo 0000:31:00.0 > /sys/bus/pci/drivers/mlx5_core/bind
echo 1 > /sys/class/net/p0/device/sriov_numvfs
$DEVLINK dev param set pci/0000:31:00.0 name flow_steering_mode value dmfs cmode runtime
$DEVLINK dev eswitch set pci/0000:31:00.0 encap-mode none
$DEVLINK dev eswitch set pci/0000:31:00.0 mode switchdev
echo 0000:31:00.2 > /sys/bus/pci/drivers/mlx5_core/unbind
$DEVLINK port function set pci/0000:31:00.0/1 ipsec_packet enable
$DEVLINK port function set pci/0000:31:00.0/1 hw_addr 16:9c:33:44:55:66
echo 0000:31:00.2 > /sys/bus/pci/drivers/mlx5_core/bind

# Network
ip link set p0 up
ip link set ens1f0r0 up
ip link add link p0 name p0.502 type vlan id 502
ip link set dev p0.502 up
ip a a 10.0.0.254/24 dev p0.502
ip r a 16.0.0.0/8 via 10.0.0.1

# Qdisc
tc qdisc add dev p0 ingress
tc qdisc add dev ens1f0r0 ingress
tc filter add dev p0 parent ffff: protocol all chain 0 flower \
	action mirred egress redirect dev ens1f0r0
tc filter add dev ens1f0r0 parent ffff: protocol all chain 0 flower \
	action mirred egress redirect dev p0

# strongSwan must run on the VF in its own netns or a VM so IKE
# binds to the isolated VF netdev
ip netns del vf0 2>/dev/null
ip netns add vf0
ip link set ens1f0v0 netns vf0
ip -n vf0 link set lo up
ip -n vf0 link set ens1f0v0 up
ip -n vf0 a a 123.0.0.1/16 dev ens1f0v0
ip -n vf0 r a 123.2.0.0/16 via 123.0.0.254
ip -n vf0 r a 48.0.0.0/8 via 123.0.0.254

ip netns exec vf0 ipsec start
sleep 2
ip netns exec vf0 swanctl --load-all
ip netns exec vf0 swanctl -i --child gw
