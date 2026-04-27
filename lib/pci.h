/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of this project is to provide a fast data-path
 *              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
 *              acceleration via a Crypto mode or a Packet mode. In Packet
 *              mode, all IPSEC ESP operations are done by the hardware to
 *              offload the kernel for crypto and packet handling. To further
 *              increase perfs we implement kernel routing offload via XDP.
 *              A XFRM kernel netlink reflector is dynamically and
 *              transparently mirroring kernel XFRM policies to the XDP layer
 *              for kernel netstack bypass. fastSwan is an XFRM offload feature.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _PCI_H
#define _PCI_H

#include "vty.h"

#define PCI_MAX_ETH_DEVS	16

struct pci_eth_dev {
	char bdf[16];
	int numa_node;
	unsigned long vendor_id;
	unsigned long device_id;
	char vendor_name[64];
	char device_name[96];
	char driver[32];
	char netifs[64];
};

/* Prototypes */
int pci_eth_dev_fetch(struct pci_eth_dev *devs, int max_devs);
void pci_eth_dev_vty(struct vty *vty, struct pci_eth_dev *devs, int ndevs);

#endif
