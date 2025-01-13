/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of this project is to provide a fast data-path
 *              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
 *              acceleration via a Crypto mode or a Packet mode. In Packet
 *              mode, all IPSEC ESP operations are done by the hardware to
 *              offload the kernel for crypto and packet handling. To further
 *              increase perfs we implement kernel routing offload via XDP.
 *              A XFRM kernel netlink reflector is dynamically andi
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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
 */

/* global includes */
#include <getopt.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <libbpf.h>

/* local includes */
#include "fastswan.h"
#include "config.h"
#include "main.h"


/* Log facility table */
struct {
	int facility;
} LOG_FACILITY[LOG_FACILITY_MAX + 1] = {
	{LOG_LOCAL0}, {LOG_LOCAL1}, {LOG_LOCAL2}, {LOG_LOCAL3},
	{LOG_LOCAL4}, {LOG_LOCAL5}, {LOG_LOCAL6}, {LOG_LOCAL7}
};

static char * __prog_pid_file = PROG_PID_FILE;

/* Daemon stop sequence */
static void
stop_fswan(void)
{
	syslog(LOG_INFO, "Stopping " VERSION_STRING "\n");

	/* Just cleanup memory & exit */
	vty_terminate();
	cmd_terminate();
	free_daemon_data();
	thread_destroy_master(master);

#ifdef _DEBUG_
	memory_free_final("fastswan process");
#endif
	closelog();
	pidfile_rm(__prog_pid_file);
	exit(EXIT_SUCCESS);
}

/* Daemon init sequence */
static void
start_fswan(void)
{
	int ret;

	/* Configuration file parsing */
	daemon_data = alloc_daemon_data();

	cmd_init();
	vty_init();
	fswan_vty_init();
	sort_node();
	fswan_netlink_init();

	ret = vty_read_config(conf_file, default_conf_file);
	if (ret < 0) {
		stop_fswan();
	}
}

/* Terminate handler */
static void
sigend(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	__set_bit(FSWAN_FL_STOP_BIT, &daemon_data->flags);
	thread_add_terminate_event(master);
}

/* Initialize signal handler */
void
signal_init(void)
{
	signal_set(SIGHUP, sigend, NULL);
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
	signal_set(SIGKILL, sigend, NULL);
	signal_noignore_sigchld();
	signal_ignore(SIGPIPE);
}

/* Usage function */
static void
usage(const char *prog)
{
	fprintf(stderr, VERSION_STRING "\n");
	fprintf(stderr, COPYRIGHT_STRING "\n");
	fprintf(stderr, "libbpf %s\n", libbpf_version_string());
	fprintf(stderr,
		"\nUsage:\n"
		"  %s\n"
		"  %s -n\n"
		"  %s -f fastswan.conf\n"
		"  %s -d\n"
		"  %s -h\n" "  %s -v\n\n", prog, prog, prog, prog, prog, prog);
	fprintf(stderr,
		"Commands:\n"
		"Either long or short options are allowed.\n"
		"  %s --dont-fork          -n    Dont fork the daemon process.\n"
		"  %s --use-file           -f    Use the specified configuration file.\n"
		"                                Default is /etc/fastswan/fastswan.conf.\n"
		"  %s --enable-bpf-debug   -b    Enable verbose libbpf log debug.\n"
		"  %s --dump-conf          -d    Dump the configuration data.\n"
		"  %s --log-console        -l    Log message to stderr.\n"
		"  %s --log-detail         -D    Detailed log messages.\n"
		"  %s --log-facility       -S    0-7 Set syslog facility to LOG_LOCAL[0-7]. (default=LOG_DAEMON)\n"
		"  %s --help               -h    Display this short inlined help screen.\n"
		"  %s --version            -v    Display the version number\n",
		prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

/* Command line parser */
static void
parse_cmdline(int argc, char **argv)
{
	int c, longindex, curind;
	bool bad_option = false;

	struct option long_options[] = {
		{"log-console",		no_argument,		NULL, 'l'},
		{"log-detail",		no_argument,		NULL, 'D'},
		{"log-facility",	required_argument,	NULL, 'S'},
		{"dont-fork",		no_argument,		NULL, 'n'},
		{"dump-conf",		no_argument,		NULL, 'd'},
		{"enable-bpf-debug",	no_argument,		NULL, 'b'},
		{"use-file",		required_argument,	NULL, 'f'},
		{"version",		no_argument,		NULL, 'v'},
		{"help",		no_argument,		NULL, 'h'},
		{NULL,			0,			NULL,  0 }
	};

	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":vhlndDbf:S:"
						, long_options, &longindex)) != -1) {
		if (longindex >= 0 && long_options[longindex].has_arg == required_argument &&
		    optarg && !optarg[0]) {
			c = ':';
			optarg = NULL;
		}

		switch (c) {
		case 'v':
			fprintf(stderr, VERSION_STRING "\n");
			fprintf(stderr, COPYRIGHT_STRING "\n");
			fprintf(stderr, "libbpf %s\n", libbpf_version_string());
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'l':
			enable_console_log();
			debug |= 1;
			break;
		case 'n':
			debug |= 2;
			break;
		case 'd':
			debug |= 4;
			break;
		case 'D':
			debug |= 8;
			break;
		case 'b':
			debug |= 16;
			break;
		case 'S':
			log_facility = LOG_FACILITY[atoi(optarg)].facility;
			break;
		case 'f':
			conf_file = optarg;
			break;
		case '?':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Unknown option -%c\n", optopt);
			else
				fprintf(stderr, "Unknown option --%s\n", argv[curind]);
			bad_option = true;
			break;
		case ':':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Missing parameter for option -%c\n", optopt);
			else
				fprintf(stderr, "Missing parameter for option --%s\n", long_options[longindex].name);
			bad_option = true;
			break;
		default:
			exit(EXIT_FAILURE);
			break;
		}
                curind = optind;
	}


	if (optind < argc) {
		fprintf(stderr, "Unexpected argument(s): ");
		while (optind < argc)
			fprintf(stderr, "%s ", argv[optind++]);
		fprintf(stderr, "\n");
	}

	if (bad_option)
		exit(EXIT_FAILURE);
}

/* Entry point */
int
main(int argc, char **argv)
{
	struct rlimit limit;

	/* Init debugging level */
	mem_allocated = 0;
	debug = 0;

	/*
	 * Parse command line and set debug level.
	 * bits 0..7 reserved by main.c
	 */
	parse_cmdline(argc, argv);

	openlog(PROG, LOG_PID | ((debug & 1) ? LOG_CONS : 0), log_facility);
	syslog(LOG_INFO, "Starting " VERSION_STRING "\n");

	if (getenv("FSWAN_PID_FILE"))
		__prog_pid_file = getenv("FSWAN_PID_FILE");

	/* Check if fastswan is already running */
	if (process_running(__prog_pid_file)) {
		syslog(LOG_INFO, "daemon is already running");
		goto end;
	}

	/* We are the parent process */
	prog_type = PROG_TYPE_PARENT;

	/* daemonize process */
	if (!(debug & 2))
		xdaemon(0, 0, 0);

	/* write the pidfile */
	if (!pidfile_write(__prog_pid_file, getpid()))
		goto end;

	/* Increase maximum fd limit */
	getrlimit(RLIMIT_NOFILE, &limit);
	limit.rlim_max = limit.rlim_cur = 8192;
	setrlimit(RLIMIT_NOFILE, &limit);

	/* Create the master thread */
	master = thread_make_master(false);

	/* Signal handling initialization  */
	signal_init();

	/* Init daemon */
	start_fswan();

	/* Launch the scheduling I/O multiplexer */
	launch_thread_scheduler(master);

	/* Finish daemon process */
	stop_fswan();

	/*
	 * Reached when terminate signal catched.
	 * finally return from system
	 */
      end:
	closelog();
	exit(EXIT_SUCCESS);
}
