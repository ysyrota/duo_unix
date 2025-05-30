/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * duo_private.h
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "https.h"
#include <stdlib.h>

struct duo_ctx {

    https_t *https;    /* HTTPS handle */
    char    *host;     /* host[:port] */
    char    err[512];  /* error message */

    char    *argv[16]; /* request arguments */
    int     argc;

    const char *body;  /* response body */
    int     body_len;

    int     https_timeout; /* milliseconds */

    char *ikey;
    char *skey;
    char *useragent;

    char *(*conv_prompt)(void *arg, const char *pr, char *buf, size_t sz);
    void  (*conv_status)(void *arg, const char *msg);
    void   *conv_arg;
    long time_offset; /* time difference in seconds between Duo's current time and the local system time */
};

duo_code_t
duo_add_param(struct duo_ctx *ctx, const char *name, const char *value);

duo_code_t
duo_add_optional_param(struct duo_ctx *ctx, const char *name, const char *value);

int _duo_add_hostname_param(struct duo_ctx *ctx);

int _duo_add_failmode_param(struct duo_ctx *ctx, const int failmode);
