#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Makefile.am
#
# Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#

if HAVE_OFFLINE_LOGIN

AM_CPPFLAGS = -I$(top_srcdir)/lib -I$(top_srcdir)/compat

sbin_PROGRAMS = duo_offline_enroll

duo_offline_enroll_SOURCES = duo_offline_enroll.c
duo_offline_enroll_LDADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la -lqrencode

dist_man_MANS = duo_offline_enroll.8

endif