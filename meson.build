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

project('fastswan', 'c',
	version : files('VERSION'),
	meson_version: '>= 0.61.2',
	license: 'AGPL-3.0-or-later',
	default_options : [
	  'buildtype=debugoptimized',
	  'werror=false',
	  'warning_level=2',
	  'c_std=gnu99'
	]
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-Wstrict-prototypes', language: 'c')
add_project_arguments('-Wno-extra', language: 'c')
add_project_arguments('-ggdb', language: 'c')

# config.h header
build_date = run_command('date', '+%Y/%m/%d', check: true).stdout().strip()
conf_data = configuration_data()
conf_data.set('VERSION', meson.project_version())
conf_data.set('BUILD_DATE', build_date)
configure_file(input : 'lib/config.h.in',
               output : 'config.h',
               configuration : conf_data)

# get programs to compile ebpf
clang = find_program('clang', required: true)
llc = find_program('llc', required: true)

# libraries this project is using
libelf_dep = dependency('libelf')

# check for system's libbpf
# if not found or version too old, fetch and compile libbpf from git
libbpf_dep = dependency('libbpf', version : '>=1.5.0', fallback: ['libbpf', 'libbpf_dep'])
libbpf_inc = libbpf_dep.get_variable('includedir') + '/bpf'
add_project_arguments('-I' + libbpf_inc, language: 'c')

# if using our own compiled libbpf, also use provided include/uapi/linux
# instead of /usr/include/linux
libbpf_uapi_inc = libbpf_dep.get_variable('includeuapidir', default_value: '')
if libbpf_uapi_inc != ''
  add_project_arguments('-I' + libbpf_uapi_inc, language: 'c')
endif

# get Clang's default include paths, to compile bpf
clang_includes = []
search_start = false
foreach line : run_command(clang, '-v', '-E', '-', check: false, capture: true).stderr().split('\n')
	if search_start
		if line.strip() == 'End of search list.'
			break
		endif
		if line.strip().startswith('/')
			clang_includes += ['-idirafter', line.strip()]
		endif
	elif line.strip() == '#include <...> search starts here:'
		search_start = true
	endif
endforeach


src = []
inc = []

subdir('lib')
subdir('src')

fastswan_exe = executable(
  'fastswan', src,
  include_directories: inc,
  dependencies: [libbpf_dep, libelf_dep],
  link_args: [ '-lpthread', '-lz' ],
  install_dir: get_option('sbindir'),
  install: true,
)
