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

EXEC = fastswan
BIN  = bin
VERSION := $(shell cat VERSION)
TARBALL = $(EXEC)-$(VERSION).tar.xz
TARFILES = AUTHOR VERSION LICENSE README.md bin src lib Makefile libbpf

prefix = /usr/local
exec_prefix = ${prefix}
sbindir     = ${exec_prefix}/sbin
sysconfdir  = ${prefix}/etc

CC        ?= gcc
LDFLAGS   = -lpthread -lcrypt -ggdb -lm -lz -lelf
SUBDIRS   = lib src src/bpf
LIBBPF    = libbpf
OBJDIR    = $(LIBBPF)/src

all: $(OBJDIR)/libbpf.a
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i || exit 1; done && \
	echo "Building $(BIN)/$(EXEC)" && \
	$(CC) -o $(BIN)/$(EXEC) `find $(SUBDIRS) -name '*.[oa]'` $(OBJDIR)/libbpf.a $(LDFLAGS)
#	strip $(BIN)/$(EXEC)
	@echo ""
	@echo "Make complete"

$(OBJDIR)/libbpf.a:
	@$(MAKE) -C $(LIBBPF)/src BUILD_STATIC_ONLY=y NO_PKG_CONFIG=y
	@ln -sf ../include/uapi $(OBJDIR)

clean:
	@$(MAKE) -C $(LIBBPF)/src clean
	rm -f $(OBJDIR)/uapi
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i clean; done
	rm -f $(BIN)/$(EXEC)
	@echo ""
	@echo "Make complete"

uninstall:
	rm -f $(sbindir)/$(EXEC)

install:
	install -d $(prefix)
	install -m 700 $(BIN)/$(EXEC) $(sbindir)/$(EXEC)-$(VERSION)
	ln -sf $(sbindir)/$(EXEC)-$(VERSION) $(sbindir)/$(EXEC)

tarball: clean
	@mkdir $(EXEC)-$(VERSION)
	@cp -a $(TARFILES) $(EXEC)-$(VERSION)
	@tar -cJf $(TARBALL) $(EXEC)-$(VERSION)
	@rm -rf $(EXEC)-$(VERSION)
	@echo $(TARBALL)
