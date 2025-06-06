/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * acconfig.h
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

@BOTTOM@

#ifndef HAVE_ASPRINTF
#include <stdarg.h>

int	asprintf(char **ret, const char *format, ...);
int	vasprintf(char **ret, const char *format, va_list ap);
#endif

#ifndef HAVE_GETGROUPLIST
#include <grp.h>

int	getgrouplist(const char *name, gid_t basegid, gid_t *groups, int *ngroups);
#endif

#ifndef HAVE_STRLCPY
#include <sys/types.h>

size_t	strlcpy(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRNLEN
#include <sys/types.h>

size_t strnlen(const char *str, size_t maxlen);
#endif

#ifndef HAVE_TIMEGM

time_t timegm(struct tm *tm);
#endif