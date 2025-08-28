/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * pam_duo_offline.c
 *
 * Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#include "pam_duo_offline.h"
#include "util.h"

/* Load offline user data from secrets file */
struct offline_user *
load_offline_user(const char *secrets_path, const char *username)
{
    char filepath[PATH_MAX];  /* Reused buffer for both secret and auth files */
    FILE *fp;
    struct offline_user *user;
    char secret_line[256];
    struct stat st;

    if (!secrets_path || !username) {
        return NULL;
    }

    /* Construct secret file path */
    if (snprintf(filepath, sizeof filepath, "%s/%s.secret",
                 secrets_path, username) >= (int)sizeof filepath) {
        return NULL;
    }

    /* Check if secret file exists and is readable */
    if (stat(filepath, &st) != 0) {
        return NULL; /* User not enrolled */
    }

    user = calloc(1, sizeof(struct offline_user));
    if (!user) {
        return NULL;
    }

    /* Load secret */
    fp = fopen(filepath, "r");
    if (!fp) {
        free(user);
        return NULL;
    }

    if (fgets(secret_line, sizeof secret_line, fp) == NULL) {
        fclose(fp);
        free(user);
        return NULL;
    }

    fclose(fp);

    char *newline = strchr(secret_line, '\n');
    if (newline) {
        *newline = '\0';
    }

    user->secret = strdup(secret_line);

    if (!user->secret) {
        free_offline_user(user);
        return NULL;
    }

    /* Load last auth time (optional - defaults to 0) */
    user->last_auth_time = 0;

    /* Reuse buffer for auth file path */
    if (snprintf(filepath, sizeof filepath, "%s/%s.auth",
                 secrets_path, username) >= (int)sizeof filepath) {
        /* If we can't construct the path, just use default auth time of 0 */
        user->enrolled_time = st.st_mtime;
        return user;
    }

    fp = fopen(filepath, "r");
    if (fp) {
        char time_line[64];
        if (fgets(time_line, sizeof time_line, fp)) {
            user->last_auth_time = (time_t)atoll(time_line);
        }
        fclose(fp);
    }

    /* Set enrolled time from secret file modification time */
    user->enrolled_time = st.st_mtime;

    return user;
}

/* Free offline user structure */
void
free_offline_user(struct offline_user *user)
{
    if (user) {
        free(user->secret);
        free(user);
    }
}

/* Verify TOTP code with time window and replay protection */
offline_auth_result_t
verify_offline_totp(struct offline_user *user, uint32_t code, time_t current_time)
{
    unsigned char *decoded_secret;
    int secret_len;
    uint64_t time_step, last_step, start_step, end_step;
    uint64_t step;

    if (!user || !user->secret) {
        return OFFLINE_AUTH_USER_NOT_ENROLLED;
    }

    if (code > 999999) { /* Invalid 6-digit code */
        return OFFLINE_AUTH_INVALID_CODE;
    }

    /* Decode base32 secret */
    decoded_secret = duo_base32_decode(user->secret, &secret_len);
    if (!decoded_secret) {
        return OFFLINE_AUTH_DECODE_ERROR;
    }

    /* Calculate time steps */
    time_step = current_time / TOTP_STEP_SIZE;
    last_step = user->last_auth_time / TOTP_STEP_SIZE;

    /* Time travel detection */
    if (time_step < last_step) {
        free(decoded_secret);
        return OFFLINE_AUTH_TIME_TRAVEL;
    }

    /* Define verification window: ±2 minutes (8 steps total = ±4 steps) */
    start_step = time_step > (TOTP_WINDOW_SIZE / 2) ?
                 time_step - (TOTP_WINDOW_SIZE / 2) : 0;
    end_step = time_step + (TOTP_WINDOW_SIZE / 2) + 1;

    /* Check codes in time window, but skip already used time steps */
    for (step = start_step; step < end_step; step++) {
        /* Skip steps that have already been used (replay protection) */
        if (step <= last_step) {
            continue;
        }

        uint32_t expected_code = duo_compute_totp_code(decoded_secret, secret_len, step);
        if (expected_code == code) {
            /* Update user's last auth time to this step */
            user->last_auth_time = step * TOTP_STEP_SIZE;
            free(decoded_secret);
            return OFFLINE_AUTH_SUCCESS;
        }
    }

    free(decoded_secret);
    return OFFLINE_AUTH_INVALID_CODE;
}

/* Update user's last auth time on disk */
int
update_offline_user_auth_time(const char *secrets_path, struct offline_user *user, const char *username)
{
    char auth_filepath[PATH_MAX];
    char temp_filepath[PATH_MAX];
    FILE *fp;

    if (!secrets_path || !user || !username) {
        return -1;
    }

    if (snprintf(auth_filepath, sizeof auth_filepath, "%s/%s.auth",
                 secrets_path, username) >= (int)sizeof auth_filepath) {
        return -1;
    }

    if (snprintf(temp_filepath, sizeof temp_filepath, "%s/.%s.auth.tmp.%d",
                 secrets_path, username, getpid()) >= (int)sizeof temp_filepath) {
        return -1;
    }

    fp = fopen(temp_filepath, "w");
    if (!fp) {
        return -1;
    }

    if (fprintf(fp, "%ld\n", (long)user->last_auth_time) < 0) {
        fclose(fp);
        unlink(temp_filepath);
        return -1;
    }

    if (fclose(fp) != 0) {
        unlink(temp_filepath);
        return -1;
    }

    if (rename(temp_filepath, auth_filepath) != 0) {
        unlink(temp_filepath);
        return -1;
    }

    return 0;
}

int
is_offline_available(const char *secrets_path, const char *username)
{
    char secret_filepath[PATH_MAX];
    struct stat st;

    if (!secrets_path || !username) {
        return 0;
    }

    if (snprintf(secret_filepath, sizeof secret_filepath, "%s/%s.secret",
                 secrets_path, username) >= (int)sizeof secret_filepath) {
        return 0;
    }

    /* Check if secret file exists and is readable */
    return (stat(secret_filepath, &st) == 0 && S_ISREG(st.st_mode));
}
