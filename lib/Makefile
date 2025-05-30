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
INCLUDES = -I.
CFLAGS	 = -g -O2 $(INCLUDES) -Werror -Wall -Wunused -Wstrict-prototypes
#DEFS	 = -D_DEBUG_
DEFS	 = -D_GNU_SOURCE
COMPILE	 = $(CC) $(CFLAGS) $(DEFS)

OBJS = 	memory.o utils.o timer.o vector.o rbtree.o daemon.o \
	scheduler.o md5.o list_head.o pidfile.o prefix.o rt_table.o \
	signals.o process.o logger.o buffer.o command.o vty.o \
	pkt_buffer.o json_reader.o json_writer.o
HEADERS = $(OBJS:.o=.h)

.c.o:
	@echo "  CC" $@
	@$(COMPILE) -c $<

all:	$(OBJS)

clean:
	rm -f *.a *.o *~

distclean: clean
	rm -f Makefile

memory.o: memory.c memory.h
utils.o: utils.c utils.h
timer.o: timer.c timer.h
vector.o: vector.c vector.h memory.h
daemon.o: daemon.c daemon.h utils.h
pidfile.o: pidfile.c pidfile.h
md5.o: md5.h md5.c
list_head.o: list_head.h list_head.c
prefix.o: prefix.c prefix.h
rt_table.o: rt_table.c rt_table.h prefix.h
logger.o: logger.c logger.h
buffer.o: buffer.c buffer.h memory.h
command.o: command.c command.h vector.h memory.h vty.h timer.h \
	config.h logger.h
vty.o: vty.c vty.h scheduler.h timer.h utils.h command.h logger.h \
	memory.h
