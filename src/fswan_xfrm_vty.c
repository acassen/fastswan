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
 * Copyright (C) 2026 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/xfrm.h>

/* local includes */
#include "vty.h"
#include "command.h"
#include "table.h"
#include "utils.h"
#include "memory.h"
#include "fswan_netlink.h"
#include "fswan_bpf_xfrm.h"
#include "fswan_if.h"
#include "fswan_flower.h"

#ifndef XFRM_OFFLOAD_PACKET
#define XFRM_OFFLOAD_PACKET	4
#endif


/*
 *	Type declarations
 */
struct xfrm_state_flag_name {
	uint8_t		bit;
	const char	*name;
};

struct sa_scan_ctx {
	struct table	*tbl;
	int		family;		/* 0 = no addr filter */
	xfrm_address_t	addr1;		/* peer (single) or src (pair) */
	xfrm_address_t	addr2;		/* dst (pair only) */
	bool		has_pair;
	bool		has_spi;
	__be32		spi;		/* network byte order */
	int		filter_ifindex;	/* 0 = no ifindex filter */
};

struct sa_detail_ctx {
	struct vty	*vty;
	bool		show_keys;
	bool		has_spi;
	__be32		spi;		/* network byte order */
	int		family;		/* 0 = no addr filter */
	bool		has_pair;
	xfrm_address_t	addr1;		/* src */
	xfrm_address_t	addr2;		/* dst */
};

struct policy_scan_ctx {
	struct table	*tbl;
	bool		has_selector;
	xfrm_address_t	saddr;
	xfrm_address_t	daddr;
	__u8		prefixlen_s;
	__u8		prefixlen_d;
	int		filter_ifindex;	/* 0 = no ifindex filter */
};

struct sa_array {
	struct xfrm_sa	*items;
	size_t		n;
	size_t		cap;
};

struct policy_array {
	struct xfrm_policy	*items;
	size_t			n;
	size_t			cap;
};

struct xfrm_stat_section {
	const char	*prefix;
	const char	*section;
};

/* Fast-path mirrors carrying the policy */
enum xfrm_policy_backend {
	XFRM_BACKEND_XDP	= 1 << 0,
	XFRM_BACKEND_FLOWER	= 1 << 1,
	XFRM_BACKEND_FLOWER_HW	= 1 << 2,
};


/*
 *	Cell formatters
 */
static const char *
xfrm_sa_proto_str(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_ESP:	return "esp";
	case IPPROTO_AH:	return "ah";
	case IPPROTO_COMP:	return "comp";
	}
	return "?";
}

static const char *
xfrm_mode_str(uint8_t mode)
{
	switch (mode) {
	case XFRM_MODE_TRANSPORT:	return "transport";
	case XFRM_MODE_TUNNEL:		return "tunnel";
	case XFRM_MODE_ROUTEOPTIMIZATION: return "ro";
	case XFRM_MODE_IN_TRIGGER:	return "in_trigger";
	case XFRM_MODE_BEET:		return "beet";
	}
	return "?";
}

static const char *
xfrm_offload_dir_str(uint8_t offload_flags)
{
	return (offload_flags & XFRM_OFFLOAD_INBOUND) ? "in" : "out";
}

static void
xfrm_addr_str(const xfrm_address_t *a, uint16_t family, char *buf, size_t len)
{
	int af = (family == AF_INET6) ? AF_INET6 : AF_INET;

	if (!inet_ntop(af, a, buf, len))
		bsd_strlcpy(buf, "?", len);
}

static void
xfrm_bytes_str(uint64_t bytes, char *buf, size_t len)
{
	if (bytes < 1024)
		snprintf(buf, len, "%lu", (unsigned long) bytes);
	else if (bytes < 1024UL * 1024)
		snprintf(buf, len, "%.1fK", bytes / 1024.0);
	else if (bytes < 1024UL * 1024 * 1024)
		snprintf(buf, len, "%.1fM", bytes / (1024.0 * 1024));
	else
		snprintf(buf, len, "%.1fG", bytes / (1024.0 * 1024 * 1024));
}

static void
xfrm_dev_str(int ifindex, char *buf, size_t len)
{
	char ifname[IF_NAMESIZE];

	if (ifindex > 0 && if_indextoname(ifindex, ifname))
		bsd_strlcpy(buf, ifname, len);
	else
		bsd_strlcpy(buf, "-", len);
}


/*
 *	show ipsec sa [filter]  -  one-line scan, optionally filtered
 */
static void
sa_scan_row_add(struct table *tbl, const struct xfrm_sa *sa)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	char spi[16], reqid[16], dev[IF_NAMESIZE];
	char pkts[24], bytes[24];

	xfrm_addr_str(&sa->saddr, sa->family, src, sizeof(src));
	xfrm_addr_str(&sa->daddr, sa->family, dst, sizeof(dst));
	snprintf(spi, sizeof(spi), "0x%08x", ntohl(sa->spi));
	snprintf(reqid, sizeof(reqid), "%u", sa->reqid);
	xfrm_dev_str(sa->offload_ifindex, dev, sizeof(dev));
	snprintf(pkts, sizeof(pkts), "%lu", (unsigned long) sa->curlft.packets);
	xfrm_bytes_str(sa->curlft.bytes, bytes, sizeof(bytes));

	table_add_row(tbl, src, dst,
		      xfrm_sa_proto_str(sa->proto), spi, reqid,
		      xfrm_mode_str(sa->mode), dev,
		      xfrm_offload_dir_str(sa->offload_flags),
		      pkts, bytes);
}

static bool
sa_matches_filter(const struct xfrm_sa *sa, const struct sa_scan_ctx *f)
{
	if (f->has_spi && sa->spi != f->spi)
		return false;

	if (f->filter_ifindex && sa->offload_ifindex != f->filter_ifindex)
		return false;

	if (f->family && sa->family != f->family)
		return false;

	if (f->has_pair) {
		if (memcmp(&sa->saddr, &f->addr1, sizeof(xfrm_address_t)) ||
		    memcmp(&sa->daddr, &f->addr2, sizeof(xfrm_address_t)))
			return false;
	} else if (f->family) {
		if (memcmp(&sa->saddr, &f->addr1, sizeof(xfrm_address_t)) &&
		    memcmp(&sa->daddr, &f->addr1, sizeof(xfrm_address_t)))
			return false;
	}

	return true;
}

static int
sa_scan_cb(struct xfrm_sa *sa, void *ctx)
{
	struct sa_scan_ctx *c = ctx;

	if (!sa_matches_filter(sa, c))
		return 0;

	sa_scan_row_add(c->tbl, sa);
	return 0;
}

static struct table *
sa_scan_table_alloc(struct vty *vty)
{
	struct table *tbl;

	tbl = table_init(10, STYLE_BOLD_TITLE_LIGHT);
	if (!tbl) {
		vty_out(vty, "%% Cant allocate table%s", VTY_NEWLINE);
		return NULL;
	}

	table_set_column(tbl, "SRC", "DST", "PROTO", "SPI", "REQID",
			      "MODE", "DEV", "DIR", "PKTS", "BYTES");
	table_set_header_align(tbl, ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
			            ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
			            ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
			            ALIGN_CENTER);
	table_set_column_align(tbl, ALIGN_LEFT, ALIGN_LEFT, ALIGN_CENTER,
				    ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
				    ALIGN_CENTER, ALIGN_CENTER, ALIGN_RIGHT,
				    ALIGN_RIGHT);
	return tbl;
}

static int
do_show_ipsec_sa_scan(struct vty *vty, struct sa_scan_ctx *ctx)
{
	ctx->tbl = sa_scan_table_alloc(vty);
	if (!ctx->tbl)
		return CMD_WARNING;

	if (fswan_netlink_xfrm_sa_walk(sa_scan_cb, ctx, 0) < 0) {
		table_destroy(ctx->tbl);
		vty_out(vty, "%% Error dumping XFRM SAs%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	table_vty_out(ctx->tbl, vty);
	table_destroy(ctx->tbl);
	return CMD_SUCCESS;
}

DEFUN(show_ipsec_sa,
      show_ipsec_sa_cmd,
      "show ipsec sa",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth via XFRM_MSG_GETSA,"
      " packet-offload only)\n")
{
	struct sa_scan_ctx ctx = { 0 };
	return do_show_ipsec_sa_scan(vty, &ctx);
}


/*
 *	Filter parsers for the SA scan
 */
static int
sa_filter_parse_addr(struct vty *vty, int family, const char *str,
		     xfrm_address_t *out)
{
	int rc = inet_pton(family, str, out);

	if (rc != 1) {
		vty_out(vty, "%% Invalid %s address '%s'%s",
			     family == AF_INET ? "IPv4" : "IPv6", str, VTY_NEWLINE);
		return -1;
	}
	return 0;
}

static int
sa_filter_parse_spi(struct vty *vty, const char *str, __be32 *out)
{
	char *end;
	unsigned long v;

	v = strtoul(str, &end, 0);
	if (*str == '\0' || *end != '\0' || v > 0xFFFFFFFFUL) {
		vty_out(vty, "%% Invalid SPI '%s'%s", str, VTY_NEWLINE);
		return -1;
	}
	*out = htonl((uint32_t) v);
	return 0;
}

DEFUN(show_ipsec_sa_peer4,
      show_ipsec_sa_peer4_cmd,
      "show ipsec sa A.B.C.D",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth, packet-offload only)\n"
      "Filter by peer IPv4 (matches src or dst)\n")
{
	struct sa_scan_ctx ctx = { .family = AF_INET };

	if (sa_filter_parse_addr(vty, AF_INET, argv[0], &ctx.addr1))
		return CMD_WARNING;

	return do_show_ipsec_sa_scan(vty, &ctx);
}

DEFUN(show_ipsec_sa_peer6,
      show_ipsec_sa_peer6_cmd,
      "show ipsec sa X:X::X:X",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth, packet-offload only)\n"
      "Filter by peer IPv6 (matches src or dst)\n")
{
	struct sa_scan_ctx ctx = { .family = AF_INET6 };

	if (sa_filter_parse_addr(vty, AF_INET6, argv[0], &ctx.addr1))
		return CMD_WARNING;

	return do_show_ipsec_sa_scan(vty, &ctx);
}

DEFUN(show_ipsec_sa_pair6,
      show_ipsec_sa_pair6_cmd,
      "show ipsec sa X:X::X:X X:X::X:X",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth, packet-offload only)\n"
      "Source IPv6\n"
      "Destination IPv6\n")
{
	struct sa_scan_ctx ctx = { .family = AF_INET6, .has_pair = true };

	if (sa_filter_parse_addr(vty, AF_INET6, argv[0], &ctx.addr1) ||
	    sa_filter_parse_addr(vty, AF_INET6, argv[1], &ctx.addr2))
		return CMD_WARNING;

	return do_show_ipsec_sa_scan(vty, &ctx);
}

/*
 *	show ipsec sa detail [keys]  -  iproute2-style multi-line
 */
static const struct xfrm_state_flag_name xfrm_state_flag_names[] = {
	{ XFRM_STATE_NOECN,		"noecn" },
	{ XFRM_STATE_DECAP_DSCP,	"decap-dscp" },
	{ XFRM_STATE_NOPMTUDISC,	"nopmtudisc" },
	{ XFRM_STATE_WILDRECV,		"wildrecv" },
	{ XFRM_STATE_ICMP,		"icmp" },
	{ XFRM_STATE_AF_UNSPEC,		"af-unspec" },
	{ XFRM_STATE_ALIGN4,		"align4" },
	{ XFRM_STATE_ESN,		"esn" },
};

static void
sa_detail_flag_str(uint8_t flags, char *buf, size_t len)
{
	size_t off = 0;
	size_t i;

	if (!len)
		return;
	buf[0] = 0;

	for (i = 0; i < ARRAY_SIZE(xfrm_state_flag_names); i++) {
		if (!(flags & xfrm_state_flag_names[i].bit))
			continue;
		if (off >= len)
			break;
		off += snprintf(buf + off, len - off, "%s%s",
				off ? "," : "", xfrm_state_flag_names[i].name);
	}

	if (!off)
		bsd_strlcpy(buf, "none", len);
}

static void
sa_detail_lastused_str(uint64_t use_time, char *buf, size_t len)
{
	struct tm tm;
	time_t t = (time_t) use_time;

	if (use_time == 0) {
		bsd_strlcpy(buf, "never", len);
		return;
	}

	if (!localtime_r(&t, &tm)) {
		snprintf(buf, len, "%lu", (unsigned long) use_time);
		return;
	}

	strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
}

static void
sa_detail_print_aead_keys(struct vty *vty, const struct xfrm_sa *sa)
{
	size_t klen = (sa->aead_key_bits + 7) / 8;
	size_t i;

	vty_out(vty, "\taead %s 0x", sa->aead_name);
	for (i = 0; i < klen; i++)
		vty_out(vty, "%02x", sa->aead_key[i]);
	vty_out(vty, " %u%s", sa->aead_key_bits, VTY_NEWLINE);
}

static int
sa_detail_cb(struct xfrm_sa *sa, void *ctx)
{
	struct sa_detail_ctx *c = ctx;
	struct vty *vty = c->vty;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	char dev[IF_NAMESIZE], flagstr[64], lastused[32];

	if (c->has_spi && sa->spi != c->spi)
		return 0;

	if (c->has_pair &&
	    (sa->family != c->family ||
	     memcmp(&sa->saddr, &c->addr1, sizeof(xfrm_address_t)) ||
	     memcmp(&sa->daddr, &c->addr2, sizeof(xfrm_address_t))))
		return 0;

	xfrm_addr_str(&sa->saddr, sa->family, src, sizeof(src));
	xfrm_addr_str(&sa->daddr, sa->family, dst, sizeof(dst));
	xfrm_dev_str(sa->offload_ifindex, dev, sizeof(dev));
	sa_detail_flag_str(sa->flags, flagstr, sizeof(flagstr));
	sa_detail_lastused_str(sa->curlft.use_time, lastused, sizeof(lastused));

	vty_out(vty, "src %s dst %s%s", src, dst, VTY_NEWLINE);
	vty_out(vty, "\tproto %s spi 0x%08x reqid %u mode %s%s",
		     xfrm_sa_proto_str(sa->proto), ntohl(sa->spi),
		     sa->reqid, xfrm_mode_str(sa->mode), VTY_NEWLINE);
	vty_out(vty, "\treplay-window %u flag %s%s",
		     sa->replay_window, flagstr, VTY_NEWLINE);

	if (sa->aead_name[0]) {
		if (c->show_keys && sa->aead_key_valid)
			sa_detail_print_aead_keys(vty, sa);
		else
			vty_out(vty, "\taead %s <%u bits>%s",
				     sa->aead_name, sa->aead_key_bits,
				     VTY_NEWLINE);
	}

	vty_out(vty, "\tlifetime current: %lu (packets), %lu (bytes)%s",
		     (unsigned long) sa->curlft.packets,
		     (unsigned long) sa->curlft.bytes, VTY_NEWLINE);
	vty_out(vty, "\tlastused %s%s", lastused, VTY_NEWLINE);
	vty_out(vty, "\thw stats: integrity-failed %u, replay-drop %u%s",
		     sa->stats.integrity_failed, sa->stats.replay,
		     VTY_NEWLINE);
	vty_out(vty, "\tcrypto offload parameters: dev %s dir %s mode %s%s",
		     dev, xfrm_offload_dir_str(sa->offload_flags),
		     (sa->offload_flags & XFRM_OFFLOAD_PACKET) ? "packet" : "crypto",
		     VTY_NEWLINE);
	return 0;
}

static int
do_show_ipsec_sa_detail(struct vty *vty, struct sa_detail_ctx *ctx)
{
	uint32_t flags = ctx->show_keys ? XFRM_SA_WALK_F_KEYS : 0;

	ctx->vty = vty;
	if (fswan_netlink_xfrm_sa_walk(sa_detail_cb, ctx, flags) < 0) {
		vty_out(vty, "%% Error dumping XFRM SAs%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(show_ipsec_sa_spi,
      show_ipsec_sa_spi_cmd,
      "show ipsec sa spi WORD",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth, packet-offload only)\n"
      "Filter by SPI (multi-line iproute2-style detail)\n"
      "SPI (0xHEX, hex, or decimal)\n")
{
	struct sa_detail_ctx ctx = { .has_spi = true };

	if (sa_filter_parse_spi(vty, argv[0], &ctx.spi))
		return CMD_WARNING;

	return do_show_ipsec_sa_detail(vty, &ctx);
}

DEFUN(show_ipsec_sa_spi_keys,
      show_ipsec_sa_spi_keys_cmd,
      "show ipsec sa spi WORD keys",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth, packet-offload only)\n"
      "Filter by SPI (multi-line iproute2-style detail)\n"
      "SPI (0xHEX, hex, or decimal)\n"
      "Reveal AEAD key bytes in hex (sensitive — avoid logging this output)\n")
{
	struct sa_detail_ctx ctx = { .has_spi = true, .show_keys = true };

	if (sa_filter_parse_spi(vty, argv[0], &ctx.spi))
		return CMD_WARNING;

	return do_show_ipsec_sa_detail(vty, &ctx);
}

DEFUN(show_ipsec_sa_pair4,
      show_ipsec_sa_pair4_cmd,
      "show ipsec sa A.B.C.D A.B.C.D",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth, packet-offload only)\n"
      "Source IPv4 (multi-line iproute2-style detail)\n"
      "Destination IPv4\n")
{
	struct sa_detail_ctx ctx = { .family = AF_INET, .has_pair = true };

	if (sa_filter_parse_addr(vty, AF_INET, argv[0], &ctx.addr1) ||
	    sa_filter_parse_addr(vty, AF_INET, argv[1], &ctx.addr2))
		return CMD_WARNING;

	return do_show_ipsec_sa_detail(vty, &ctx);
}

DEFUN(show_ipsec_sa_pair4_keys,
      show_ipsec_sa_pair4_keys_cmd,
      "show ipsec sa A.B.C.D A.B.C.D keys",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth, packet-offload only)\n"
      "Source IPv4 (multi-line iproute2-style detail)\n"
      "Destination IPv4\n"
      "Reveal AEAD key bytes in hex (sensitive — avoid logging this output)\n")
{
	struct sa_detail_ctx ctx = {
		.family		= AF_INET,
		.has_pair	= true,
		.show_keys	= true,
	};

	if (sa_filter_parse_addr(vty, AF_INET, argv[0], &ctx.addr1) ||
	    sa_filter_parse_addr(vty, AF_INET, argv[1], &ctx.addr2))
		return CMD_WARNING;

	return do_show_ipsec_sa_detail(vty, &ctx);
}


/*
 *	Policy helpers
 */
static const char *
xfrm_policy_dir_str(uint8_t dir)
{
	switch (dir) {
	case XFRM_POLICY_IN:	return "in";
	case XFRM_POLICY_OUT:	return "out";
	case XFRM_POLICY_FWD:	return "fwd";
	}
	return "?";
}

static const char *
xfrm_policy_ptype_str(uint8_t ptype)
{
	switch (ptype) {
	case XFRM_POLICY_TYPE_MAIN:	return "main";
	case XFRM_POLICY_TYPE_SUB:	return "sub";
	case XFRM_POLICY_TYPE_ANY:	return "any";
	}
	return "?";
}

static const char *
xfrm_policy_offload_str(uint32_t backends)
{
	if (backends & XFRM_BACKEND_XDP)
		return "xdp-packet";
	if (backends & XFRM_BACKEND_FLOWER_HW)
		return "flower-packet (hw)";
	if (backends & XFRM_BACKEND_FLOWER)
		return "flower-packet";
	return "xfrm";
}

static uint32_t
xfrm_policy_probe_backends(const struct xfrm_policy *p,
			   uint64_t *pkts_out, uint64_t *bytes_out)
{
	uint32_t backends = 0;
	uint64_t flower_pkts = 0, flower_bytes = 0;
	struct interface *iface;

	*pkts_out = 0;
	*bytes_out = 0;

	if (p->family == AF_INET &&
	    fswan_bpf_xfrm_policy_counters_by_selector_sum(
			p->saddr.a4, p->prefixlen_s,
			p->daddr.a4, p->prefixlen_d,
			pkts_out, bytes_out))
		backends |= XFRM_BACKEND_XDP;

	iface = fswan_if_get_by_ifindex(p->ifindex, false);
	if (iface && iface->flower &&
	    fswan_flower_policy_counters(iface, p, &flower_pkts, &flower_bytes)) {
		backends |= XFRM_BACKEND_FLOWER_HW;
		*pkts_out += flower_pkts;
		*bytes_out += flower_bytes;
	}

	return backends;
}

static int
parse_prefix4(const char *str, xfrm_address_t *out, __u8 *plen_out)
{
	char buf[24], *slash, *end;
	long plen;

	bsd_strlcpy(buf, str, sizeof(buf));
	slash = strchr(buf, '/');
	if (!slash)
		return -1;
	*slash++ = '\0';

	plen = strtol(slash, &end, 10);
	if (*end != '\0' || plen < 0 || plen > 32)
		return -1;
	if (inet_pton(AF_INET, buf, &out->a4) != 1)
		return -1;

	*plen_out = (__u8) plen;
	return 0;
}


/*
 *	show ipsec policy [filter]  -  one-line scan
 */
static bool
policy_matches_filter(const struct xfrm_policy *p, const struct policy_scan_ctx *f)
{
	if (f->filter_ifindex && p->ifindex != f->filter_ifindex)
		return false;

	if (!f->has_selector)
		return true;

	return p->prefixlen_s == f->prefixlen_s &&
	       p->prefixlen_d == f->prefixlen_d &&
	       memcmp(&p->saddr, &f->saddr, sizeof(xfrm_address_t)) == 0 &&
	       memcmp(&p->daddr, &f->daddr, sizeof(xfrm_address_t)) == 0;
}

static void
policy_scan_row_add(struct table *tbl, const struct xfrm_policy *p)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	char src_pfx[INET6_ADDRSTRLEN + 4], dst_pfx[INET6_ADDRSTRLEN + 4];
	char prio[16], dev[IF_NAMESIZE], reqid[16];
	char pkts[24], bytes[24];
	uint64_t pkts_v, bytes_v;
	uint32_t backends;

	xfrm_addr_str(&p->saddr, p->family, src, sizeof(src));
	xfrm_addr_str(&p->daddr, p->family, dst, sizeof(dst));

	snprintf(src_pfx, sizeof(src_pfx), "%s/%u", src, p->prefixlen_s);
	snprintf(dst_pfx, sizeof(dst_pfx), "%s/%u", dst, p->prefixlen_d);
	snprintf(prio, sizeof(prio), "%u", p->priority);
	xfrm_dev_str(p->ifindex, dev, sizeof(dev));
	snprintf(reqid, sizeof(reqid), "%u", p->tmpl_reqid);

	backends = xfrm_policy_probe_backends(p, &pkts_v, &bytes_v);
	if (backends) {
		snprintf(pkts, sizeof(pkts), "%lu", (unsigned long) pkts_v);
		xfrm_bytes_str(bytes_v, bytes, sizeof(bytes));
	} else {
		bsd_strlcpy(pkts, "-", sizeof(pkts));
		bsd_strlcpy(bytes, "-", sizeof(bytes));
	}

	table_add_row(tbl, src_pfx, dst_pfx,
		      xfrm_policy_dir_str(p->dir), prio, dev,
		      xfrm_policy_offload_str(backends),
		      reqid, pkts, bytes);
}

static int
policy_scan_cb(struct xfrm_policy *p, void *ctx)
{
	struct policy_scan_ctx *c = ctx;

	if (!policy_matches_filter(p, c))
		return 0;

	policy_scan_row_add(c->tbl, p);
	return 0;
}

static struct table *
policy_scan_table_alloc(struct vty *vty)
{
	struct table *tbl;

	tbl = table_init(9, STYLE_BOLD_TITLE_LIGHT);
	if (!tbl) {
		vty_out(vty, "%% Cant allocate table%s", VTY_NEWLINE);
		return NULL;
	}

	table_set_column(tbl, "SRC", "DST", "DIR", "PRIO", "DEV",
			      "OFFLOAD", "REQID", "PKTS", "BYTES");
	table_set_header_align(tbl, ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
				    ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
				    ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER);
	table_set_column_align(tbl, ALIGN_LEFT, ALIGN_LEFT, ALIGN_CENTER,
				    ALIGN_RIGHT, ALIGN_CENTER, ALIGN_CENTER,
				    ALIGN_CENTER, ALIGN_RIGHT, ALIGN_RIGHT);
	return tbl;
}

static int
do_show_ipsec_policy_scan(struct vty *vty, struct policy_scan_ctx *ctx)
{
	int rc = CMD_SUCCESS;

	ctx->tbl = policy_scan_table_alloc(vty);
	if (!ctx->tbl)
		return CMD_WARNING;

	fswan_flower_counter_cache_begin();
	if (fswan_netlink_xfrm_policy_walk(policy_scan_cb, ctx) < 0) {
		vty_out(vty, "%% Error dumping XFRM policies%s", VTY_NEWLINE);
		rc = CMD_WARNING;
	} else {
		table_vty_out(ctx->tbl, vty);
	}
	fswan_flower_counter_cache_end();

	table_destroy(ctx->tbl);
	return rc;
}

DEFUN(show_ipsec_policy,
      show_ipsec_policy_cmd,
      "show ipsec policy",
      SHOW_STR
      "IPsec\n"
      "Policies (kernel ground truth via XFRM_MSG_GETPOLICY,"
      " packet-offload only)\n")
{
	struct policy_scan_ctx ctx = { 0 };
	return do_show_ipsec_policy_scan(vty, &ctx);
}

DEFUN(show_ipsec_policy_filter4,
      show_ipsec_policy_filter4_cmd,
      "show ipsec policy A.B.C.D/M A.B.C.D/M",
      SHOW_STR
      "IPsec\n"
      "Policies (kernel ground truth, packet-offload only)\n"
      "Source IPv4 prefix\n"
      "Destination IPv4 prefix\n")
{
	struct policy_scan_ctx ctx = { .has_selector = true };

	if (parse_prefix4(argv[0], &ctx.saddr, &ctx.prefixlen_s) ||
	    parse_prefix4(argv[1], &ctx.daddr, &ctx.prefixlen_d)) {
		vty_out(vty, "%% Invalid prefix syntax%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return do_show_ipsec_policy_scan(vty, &ctx);
}


/*
 *	show ipsec policy detail  -  iproute2-style multi-line
 */
static int
policy_detail_cb(struct xfrm_policy *p, void *ctx)
{
	struct vty *vty = ctx;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	char tsrc[INET6_ADDRSTRLEN], tdst[INET6_ADDRSTRLEN];
	char dev[IF_NAMESIZE];

	xfrm_addr_str(&p->saddr, p->family, src, sizeof(src));
	xfrm_addr_str(&p->daddr, p->family, dst, sizeof(dst));

	vty_out(vty, "src %s/%u dst %s/%u%s", src, p->prefixlen_s,
		     dst, p->prefixlen_d, VTY_NEWLINE);
	vty_out(vty, "\tdir %s priority %u ptype %s%s",
		     xfrm_policy_dir_str(p->dir), p->priority,
		     xfrm_policy_ptype_str(p->ptype), VTY_NEWLINE);

	if (p->tmpl_reqid) {
		xfrm_addr_str(&p->tmpl_saddr, p->family, tsrc, sizeof(tsrc));
		xfrm_addr_str(&p->tmpl_daddr, p->family, tdst, sizeof(tdst));

		vty_out(vty, "\ttmpl src %s dst %s%s", tsrc, tdst, VTY_NEWLINE);
		vty_out(vty, "\t\tproto esp reqid %u mode %s%s",
			     p->tmpl_reqid, xfrm_mode_str(p->tmpl_mode),
			     VTY_NEWLINE);
	}

	xfrm_dev_str(p->ifindex, dev, sizeof(dev));
	vty_out(vty, "\tcrypto offload parameters: dev %s mode packet%s",
		     dev, VTY_NEWLINE);
	return 0;
}

DEFUN(show_ipsec_policy_detail,
      show_ipsec_policy_detail_cmd,
      "show ipsec policy detail",
      SHOW_STR
      "IPsec\n"
      "Policies (kernel ground truth, packet-offload only)\n"
      "Multi-line iproute2-style detail\n")
{
	if (fswan_netlink_xfrm_policy_walk(policy_detail_cb, vty) < 0) {
		vty_out(vty, "%% Error dumping XFRM policies%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}


/*
 *	show ipsec  -  combined SA + policy operator view
 */

static int
array_grow(void **items, size_t *cap, size_t need, size_t elem_size)
{
	size_t new_cap;
	void *p;

	if (need <= *cap)
		return 0;

	new_cap = *cap ? *cap * 2 : 16;
	while (new_cap < need)
		new_cap *= 2;

	p = REALLOC(*items, new_cap * elem_size);
	if (!p)
		return -1;

	*items = p;
	*cap = new_cap;
	return 0;
}

static int
sa_collect_cb(struct xfrm_sa *sa, void *ctx)
{
	struct sa_array *a = ctx;

	if (array_grow((void **) &a->items, &a->cap, a->n + 1, sizeof(*a->items)))
		return -1;

	a->items[a->n++] = *sa;
	return 0;
}

static void
combined_render_sa_header(struct vty *vty, const struct xfrm_sa *sa)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	char dev[IF_NAMESIZE], lastused[32];

	xfrm_addr_str(&sa->saddr, sa->family, src, sizeof(src));
	xfrm_addr_str(&sa->daddr, sa->family, dst, sizeof(dst));
	xfrm_dev_str(sa->offload_ifindex, dev, sizeof(dev));
	sa_detail_lastused_str(sa->curlft.use_time, lastused, sizeof(lastused));

	vty_out(vty, "[SA]  src %s -> dst %s   %s spi 0x%08x reqid %u mode %s%s",
		     src, dst, xfrm_sa_proto_str(sa->proto), ntohl(sa->spi),
		     sa->reqid, xfrm_mode_str(sa->mode), VTY_NEWLINE);
	vty_out(vty, "      offload packet dev %s dir %s    aead %s %u bits%s",
		     dev, xfrm_offload_dir_str(sa->offload_flags),
		     sa->aead_name[0] ? sa->aead_name : "?",
		     sa->aead_key_bits, VTY_NEWLINE);
	vty_out(vty, "      ESP    pkts:%lu     bytes:%lu    lastused %s%s",
		     (unsigned long) sa->curlft.packets,
		     (unsigned long) sa->curlft.bytes, lastused, VTY_NEWLINE);
}

static void
combined_render_policy(struct vty *vty, const struct xfrm_policy *p)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	uint64_t pkts_v, bytes_v;
	uint32_t backends;

	xfrm_addr_str(&p->saddr, p->family, src, sizeof(src));
	xfrm_addr_str(&p->daddr, p->family, dst, sizeof(dst));

	backends = xfrm_policy_probe_backends(p, &pkts_v, &bytes_v);

	vty_out(vty, "        dir %s   %s/%u -> %s/%u   prio %u ptype %s   %s%s",
		     xfrm_policy_dir_str(p->dir),
		     src, p->prefixlen_s, dst, p->prefixlen_d,
		     p->priority, xfrm_policy_ptype_str(p->ptype),
		     xfrm_policy_offload_str(backends), VTY_NEWLINE);

	/* Per-program XDP counter breakdown for diagnostic. */
	if (backends & XFRM_BACKEND_XDP)
		fswan_bpf_xfrm_policy_counters_by_selector_vty(vty,
			p->saddr.a4, p->prefixlen_s,
			p->daddr.a4, p->prefixlen_d);

	if (backends & XFRM_BACKEND_FLOWER_HW) {
		struct interface *iface = fswan_if_get_by_ifindex(p->ifindex, false);
		uint64_t fp = 0, fb = 0;

		if (iface &&
		    fswan_flower_policy_counters(iface, p, &fp, &fb))
			vty_out(vty, "            CLEAR (flower):"
				     " pkts:%lu bytes:%lu%s",
				     (unsigned long) fp, (unsigned long) fb,
				     VTY_NEWLINE);
	}
}

static int
policy_collect_cb(struct xfrm_policy *p, void *ctx)
{
	struct policy_array *a = ctx;

	if (array_grow((void **) &a->items, &a->cap, a->n + 1, sizeof(*a->items)))
		return -1;

	a->items[a->n++] = *p;
	return 0;
}

static bool
policy_attaches_to_sa(const struct xfrm_policy *p, const struct xfrm_sa *sa)
{
	return p->tmpl_reqid == sa->reqid &&
	       memcmp(&p->tmpl_saddr, &sa->saddr, sizeof(sa->saddr)) == 0 &&
	       memcmp(&p->tmpl_daddr, &sa->daddr, sizeof(sa->daddr)) == 0;
}

static void
combined_render_sa_block(struct vty *vty, const struct xfrm_sa *sa,
			 const struct policy_array *policies)
{
	bool emitted = false;
	size_t i;

	combined_render_sa_header(vty, sa);

	for (i = 0; i < policies->n; i++) {
		const struct xfrm_policy *p = &policies->items[i];

		if (!policy_attaches_to_sa(p, sa))
			continue;

		if (!emitted) {
			vty_out(vty, "      policies:%s", VTY_NEWLINE);
			emitted = true;
		}
		combined_render_policy(vty, p);
	}
}

/*
 *	Interface filters
 */
static int
resolve_iface(struct vty *vty, const char *name, int *out)
{
	int idx = if_nametoindex(name);

	if (!idx) {
		vty_out(vty, "%% Unknown interface '%s'%s", name, VTY_NEWLINE);
		return -1;
	}
	*out = idx;
	return 0;
}

DEFUN(show_ipsec_sa_iface,
      show_ipsec_sa_iface_cmd,
      "show ipsec sa interface WORD",
      SHOW_STR
      "IPsec\n"
      "Security Associations (kernel ground truth, packet-offload only)\n"
      "Filter by offload interface\n"
      "Interface name (resolved via if_nametoindex; not limited to fastswan-managed interfaces)\n")
{
	struct sa_scan_ctx ctx = { 0 };

	if (resolve_iface(vty, argv[0], &ctx.filter_ifindex))
		return CMD_WARNING;

	return do_show_ipsec_sa_scan(vty, &ctx);
}

DEFUN(show_ipsec_policy_iface,
      show_ipsec_policy_iface_cmd,
      "show ipsec policy interface WORD",
      SHOW_STR
      "IPsec\n"
      "Policies (kernel ground truth, packet-offload only)\n"
      "Filter by offload interface\n"
      "Interface name (resolved via if_nametoindex; not limited to fastswan-managed interfaces)\n")
{
	struct policy_scan_ctx ctx = { 0 };

	if (resolve_iface(vty, argv[0], &ctx.filter_ifindex))
		return CMD_WARNING;

	return do_show_ipsec_policy_scan(vty, &ctx);
}

DEFUN(show_ipsec,
      show_ipsec_cmd,
      "show ipsec",
      SHOW_STR
      "IPsec combined SA + attached-policy operator view"
      " (kernel ground truth, packet-offload only)\n")
{
	struct sa_array sas = { 0 };
	struct policy_array policies = { 0 };
	size_t i;

	if (fswan_netlink_xfrm_sa_walk(sa_collect_cb, &sas, 0) < 0) {
		vty_out(vty, "%% Error dumping XFRM SAs%s", VTY_NEWLINE);
		goto err;
	}

	if (fswan_netlink_xfrm_policy_walk(policy_collect_cb, &policies) < 0) {
		vty_out(vty, "%% Error dumping XFRM policies%s", VTY_NEWLINE);
		goto err;
	}

	fswan_flower_counter_cache_begin();
	for (i = 0; i < sas.n; i++) {
		if (i)
			vty_out(vty, "%s", VTY_NEWLINE);
		combined_render_sa_block(vty, &sas.items[i], &policies);
	}
	fswan_flower_counter_cache_end();

	FREE_PTR(sas.items);
	FREE_PTR(policies.items);
	return CMD_SUCCESS;

err:
	FREE_PTR(sas.items);
	FREE_PTR(policies.items);
	return CMD_WARNING;
}


/*
 *	show ipsec stats  -  /proc/net/xfrm_stat snapshot
 */
static const struct xfrm_stat_section xfrm_stat_sections[] = {
	{ "XfrmIn",	"IN" },
	{ "XfrmOut",	"OUT" },
	{ "XfrmFwd",	"FWD" },
	{ "XfrmAcquire","ACQUIRE" },
};

static const char *
xfrm_stat_section_split(const char *key, const char **metric_out)
{
	size_t i, plen;

	for (i = 0; i < ARRAY_SIZE(xfrm_stat_sections); i++) {
		plen = strlen(xfrm_stat_sections[i].prefix);
		if (strncmp(key, xfrm_stat_sections[i].prefix, plen) == 0) {
			*metric_out = key + plen;
			return xfrm_stat_sections[i].section;
		}
	}

	*metric_out = key;
	return "?";
}

DEFUN(show_ipsec_stats,
      show_ipsec_stats_cmd,
      "show ipsec stats",
      SHOW_STR
      "IPsec\n"
      "Global SNMP counters from /proc/net/xfrm_stat (kernel-wide)\n")
{
	struct table *tbl;
	FILE *fp;
	char line[256];

	fp = fopen("/proc/net/xfrm_stat", "r");
	if (!fp) {
		vty_out(vty, "%% Cant open /proc/net/xfrm_stat: %m%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	tbl = table_init(3, STYLE_BOLD_TITLE_LIGHT);
	if (!tbl) {
		fclose(fp);
		vty_out(vty, "%% Cant allocate table%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	table_set_column(tbl, "SECTION", "METRIC", "COUNT");
	table_set_header_align(tbl, ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER);
	table_set_column_align(tbl, ALIGN_CENTER, ALIGN_LEFT, ALIGN_RIGHT);

	while (fgets(line, sizeof(line), fp)) {
		char key[128], value[32];
		const char *metric, *section;

		if (sscanf(line, "%127s %31s", key, value) != 2)
			continue;

		section = xfrm_stat_section_split(key, &metric);
		table_add_row(tbl, section, metric, value);
	}

	fclose(fp);
	table_vty_out(tbl, vty);
	table_destroy(tbl);
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static struct cmd_element *const show_cmds[] = {
	&show_ipsec_cmd,
	&show_ipsec_stats_cmd,
	&show_ipsec_sa_cmd,
	&show_ipsec_sa_peer4_cmd,
	&show_ipsec_sa_pair4_cmd,
	&show_ipsec_sa_pair4_keys_cmd,
	&show_ipsec_sa_peer6_cmd,
	&show_ipsec_sa_pair6_cmd,
	&show_ipsec_sa_spi_cmd,
	&show_ipsec_sa_spi_keys_cmd,
	&show_ipsec_sa_iface_cmd,
	&show_ipsec_policy_cmd,
	&show_ipsec_policy_filter4_cmd,
	&show_ipsec_policy_detail_cmd,
	&show_ipsec_policy_iface_cmd,
};

static int
cmd_ext_fswan_xfrm_install(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(show_cmds); i++) {
		install_element(VIEW_NODE, show_cmds[i]);
		install_element(ENABLE_NODE, show_cmds[i]);
	}
	return 0;
}

static struct cmd_ext cmd_ext_fswan_xfrm = {
	.install	= cmd_ext_fswan_xfrm_install,
};

static void __attribute__((constructor))
fswan_xfrm_vty_init(void)
{
	cmd_ext_register(&cmd_ext_fswan_xfrm);
}
