/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * pam_duo_offline.h
 *
 * Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#ifndef PAM_DUO_OFFLINE_H
#define PAM_DUO_OFFLINE_H

#include <time.h>
#include <stdint.h>

#define TOTP_WINDOW_SIZE 8  /* +/- 2 minutes (4 steps each way) */
#define TOTP_STEP_SIZE 30   /* 30 seconds per step */

typedef enum {
    OFFLINE_AUTH_SUCCESS = 0,
    OFFLINE_AUTH_INVALID_CODE = 1,
    OFFLINE_AUTH_USER_NOT_ENROLLED = 2,
    OFFLINE_AUTH_TIME_TRAVEL = 3,
    OFFLINE_AUTH_REPLAY_ATTACK = 4,
    OFFLINE_AUTH_FILE_ERROR = 5,
    OFFLINE_AUTH_DECODE_ERROR = 6,
    OFFLINE_AUTH_SYSTEM_ERROR = 7
} offline_auth_result_t;

struct offline_user {
    char *secret;         /* Base32-encoded TOTP secret */
    time_t last_auth_time; /* Last successful offline auth timestamp */
    time_t enrolled_time;  /* When user was enrolled for offline */
};

/**
 * Load offline user data from disk
 * @param secrets_path Path to secrets directory
 * @param username Username to load
 * @return Pointer to offline_user struct or NULL on failure
 */
struct offline_user *load_offline_user(const char *secrets_path, const char *username);

/**
 * Free offline user structure
 * @param user Pointer to offline_user struct
 */
void free_offline_user(struct offline_user *user);

/**
 * Verify TOTP code for offline authentication
 * @param user Offline user data
 * @param code 6-digit TOTP code to verify
 * @param current_time Current system time
 * @return offline_auth_result_t indicating success or failure reason
 */
offline_auth_result_t verify_offline_totp(struct offline_user *user,
                                          uint32_t code,
                                          time_t current_time);

/**
 * Update user's last auth time on disk after successful authentication
 * @param secrets_path Path to secrets directory
 * @param user Offline user data with updated last_auth_time
 * @param username Username for file path construction
 * @return 0 on success, -1 on failure
 */
int update_offline_user_auth_time(const char *secrets_path, struct offline_user *user, const char *username);

/**
 * Check if offline authentication is available for user
 * @param secrets_path Path to secrets directory
 * @param username Username to check
 * @return 1 if offline auth available, 0 if not
 */
int is_offline_available(const char *secrets_path, const char *username);

#endif /* PAM_DUO_OFFLINE_H */
