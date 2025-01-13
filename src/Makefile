# SPDX-License-Identifier: AGPL-3.0-or-later 
#
# Soft:        The main goal of this project is to provide a fast data-path
#              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
#              acceleration via a Crypto mode or a Packet mode. In Packet
#              mode, all IPSEC ESP operations are done by the hardware to
#              offload the kernel for crypto and packet handling. To further
#              increase perfs we implement kernel routing offload via XDP.
#              A XFRM kernel netlink reflector is dynamically andi
#              transparently mirroring kernel XFRM policies to the XDP layer
#              for kernel netstack bypass. fastSwan is an XFRM offload feature.
#
# Authors:     Alexandre Cassen, <acassen@gmail.com>
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU Affero General Public
#              License Version 3.0 as published by the Free Software Foundation;
#              either version 3.0 of the License, or (at your option) any later
#              version.
#
# Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
#

CC	 ?= gcc
INCLUDES = -Iinclude -I../lib -I../libbpf/src -I../libbpf/src/uapi
CFLAGS	 = -g -O2 -ggdb $(INCLUDES) -Werror -Wall -Wunused -Wstrict-prototypes -D_GNU_SOURCE
#DEFS	 = -D_DEBUG_
DEFS	 =
COMPILE	 = $(CC) $(CFLAGS) $(DEFS)

OBJS = 	main.o fswan_data.o fswan_vty.o fswan_if.o fswan_bpf.o fswan_bpf_vty.o \
	fswan_bpf_xfrm.o fswan_netlink.o

HEADERS = $(OBJS:.o=.h)

.c.o:
	@echo "  CC" $@
	@$(COMPILE) -c $<

all:	$(OBJS)

clean:
	rm -f *.a *.o *~
