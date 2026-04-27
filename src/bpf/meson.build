# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Soft:        The main goal of this project is to provide a fast data-path
#              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
#              acceleration via a Crypto mode or a Packet mode. In Packet
#              mode, all IPSEC ESP operations are done by the hardware to
#              offload the kernel for crypto and packet handling. To further
#              increase perfs we implement kernel routing offload via XDP.
#              A XFRM kernel netlink reflector is dynamically and
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
# Copyright (C) 2025-2026 Alexandre Cassen, <acassen@gmail.com>
#

fs = import('fs')

bpf_sources = files(
  'xfrm_offload.c',
)

clang_bpf_flags = [
  clang_includes,
  '-DEBPF_SRC',
  '-D__x86_64__',
  libbpf_uapi_inc != '' ? '-I' + libbpf_uapi_inc : '',
  '-I' + meson.current_source_dir(),
  '-I' + libbpf_inc,
  '-Wno-unused-value',
  '-Wno-pointer-sign',
  '-Wno-compare-distinct-pointer-types',
  '-Wno-gnu-variable-sized-type-not-at-end',
  '-Wno-tautological-compare',
  '-Wno-unknown-warning-option',
  '-Wno-address-of-packed-member',
  '-fno-asynchronous-unwind-tables',
]

foreach bsrc : bpf_sources
  name = fs.replace_suffix(fs.name(bsrc), '')
  bpf_obj = custom_target('bpf-' + name,
			  input : bsrc,
			  output : name + '.ll',
			  depfile : name + '.d',
			  build_by_default: true,
			  command : [clang, '-c', '-g', '-O2', '-emit-llvm',
				     '-target', 'bpf', '-mcpu=v3',
				     clang_bpf_flags,
				     '-MD', '-MF', '@DEPFILE@',
				     '-o', '@OUTPUT@', '@INPUT@'
				    ],
  )

  bpf_prog = custom_target('bpf-' + name + '-bin',
			   input : bpf_obj,
			   output : name + '.bpf',
			   command : [llc, '-march=bpf', '-filetype=obj',
				      '-o', '@OUTPUT@', '@INPUT@'],
			   install_dir: get_option('sharedstatedir') + '/fastswan',
			   install: true
  )
endforeach
