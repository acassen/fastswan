#!/usr/bin/env bash
# CPU layout, NUMA 0 only (Package 0, CPUs 0-23):
#   0-1		housekeeping (kernel, generic IRQs, services)
#   2-3		fastSwan daemon + monitor pthread
#   4-13	p0 (mlx5_0, PCI 0000:31:00.0) rx queues 0..9
#   14-23	p1 (mlx5_1, PCI 0000:31:00.1) rx queues 0..9

P0_IFACE=p0
P1_IFACE=p1
RXQ_COUNT=10
P0_PCI=0000:31:00.0
P1_PCI=0000:31:00.1
P0_RXQ_CPUS=4-13
P1_RXQ_CPUS=14-23

log() {
	printf '[setup-host] %s\n' "$*"
}

expand_cpulist() {
	local IFS=,
	for part in $1; do
		if [[ $part == *-* ]]; then
			seq "${part%-*}" "${part#*-}"
		else
			echo "$part"
		fi
	done
}

disable_thp() {
	log "disable transparent hugepages"
	local f
	for f in /sys/kernel/mm/transparent_hugepage/enabled \
		 /sys/kernel/mm/transparent_hugepage/defrag; do
		[ -w "$f" ] && echo never > "$f"
	done
}

sysctl_tune() {
	log "apply sysctl tuning"
	sysctl -qw kernel.nmi_watchdog=0
	sysctl -qw net.core.bpf_jit_enable=1
	sysctl -qw net.core.bpf_jit_harden=0
	sysctl -qw net.ipv4.ip_forward=1
	sysctl -qw net.ipv6.conf.all.forwarding=1
	sysctl -qw net.ipv4.conf.all.rp_filter=0
	sysctl -qw net.ipv4.conf.default.rp_filter=0
	sysctl -qw net.core.busy_poll=50
	sysctl -qw net.core.busy_read=50
	sysctl -qw net.core.netdev_budget=600
	sysctl -qw net.core.netdev_budget_usecs=8000
}

tune_nic() {
	local dev=$1

	log "tune $dev"

	ethtool -K "$dev" gro off lro off gso off tso off
	ethtool -K "$dev" hw-tc-offload on ntuple on

	ethtool -G "$dev" rx 8192 tx 8192
	ethtool -C "$dev" adaptive-rx off adaptive-tx off
	ethtool -C "$dev" rx-usecs 8 rx-frames 64 tx-usecs 8

	ethtool -A "$dev" rx off tx off 2>/dev/null || true

	ethtool --set-priv-flags "$dev" rx_striding_rq on
	ethtool --set-priv-flags "$dev" rx_cqe_compress on

	ethtool -L "$dev" combined "$RXQ_COUNT"
	ethtool -X "$dev" equal "$RXQ_COUNT"

	ip link set "$dev" up
}

# Pin mlx5_compN IRQs by name from /proc/interrupts in queue order
pin_mlx_rxqs() {
	local pci=$1
	local cpulist=$2
	local cpus
	cpus=( $(expand_cpulist "$cpulist") )

	local q irq cpu pat
	for ((q = 0; q < RXQ_COUNT; q++)); do
		pat="mlx5_comp${q}@pci:${pci}"
		irq=$(awk -v p="$pat" \
			'$NF == p { sub(":","",$1); print $1 }' \
			/proc/interrupts)
		if [ -z "$irq" ]; then
			log "pin: $pci comp$q IRQ not found"
			continue
		fi
		cpu=${cpus[$q]}
		log "pin: $pci comp$q (IRQ $irq) -> CPU $cpu"
		echo "$cpu" > "/proc/irq/$irq/smp_affinity_list"
	done
}

# Bump PCIe MaxReadReq to 2048B
set_pcie_mrrs() {
	local pci=$1
	local cur new
	cur=$(setpci -s "$pci" CAP_EXP+8.w)
	new=$(printf '%04x' $(( (0x$cur & 0x8fff) | 0x4000 )))
	setpci -s "$pci" CAP_EXP+8.w=$new
	log "pcie: $pci DevCtl 0x$cur -> 0x$new (MRRS=2048B)"
}

disable_thp
sysctl_tune
tune_nic "$P0_IFACE"
tune_nic "$P1_IFACE"
set_pcie_mrrs "$P0_PCI"
set_pcie_mrrs "$P1_PCI"
pin_mlx_rxqs "$P0_PCI" "$P0_RXQ_CPUS"
pin_mlx_rxqs "$P1_PCI" "$P1_RXQ_CPUS"
log "done"
