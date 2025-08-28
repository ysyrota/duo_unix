/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * util.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <endian.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "util.h"
#include "groupaccess.h"

int duo_debug = 0;

void
duo_config_default(struct duo_config *cfg)
{
    memset(cfg, 0, sizeof(struct duo_config));
    cfg->failmode = DUO_FAIL_SAFE;
    cfg->prompts = MAX_PROMPTS;
    cfg->local_ip_fallback = 0;
    cfg->https_timeout = -1;
    cfg->fips_mode = 0;
    cfg->gecos_username_pos = -1;
    cfg->gecos_delim = ',';
    cfg->offline_secrets_path = strdup(DUO_DEFAULT_OFFLINE_SECRETS_PATH);
}

int
duo_set_boolean_option(const char *val)
{
    if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
        strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
        return (1);
    } else {
        return (0);
    }
}

int
duo_common_ini_handler(struct duo_config *cfg, const char *section,
    const char *name, const char*val)
{
    if (strcmp(name, "ikey") == 0) {
        cfg->ikey = strdup(val);
    } else if (strcmp(name, "skey") == 0) {
        cfg->skey = strdup(val);
    } else if (strcmp(name, "host") == 0) {
        cfg->apihost = strdup(val);
    } else if (strcmp(name, "cafile") == 0) {
        cfg->cafile = strdup(val);
    } else if (strcmp(name, "http_proxy") == 0) {
        cfg->http_proxy = strdup(val);
    } else if (strcmp(name, "offline_secrets_path") == 0) {
        cfg->offline_secrets_path = strdup(val);
    } else if (strcmp(name, "groups") == 0 || strcmp(name, "group") == 0) {
        size_t len = strlen(val);
        size_t i = 0, j = 0;
        int inEscape = 0;
        char *currWord;
        if ((currWord = malloc(len + 1)) == NULL) {
            fprintf(stderr, "Out of memory parsing groups\n");
            return (0);
        }

        for (i = 0; i <= len; ++i) {
            if (val[i] == '\\' && val[i + 1] == ' ' && !inEscape) {
                inEscape = 1;
                continue;
            }

            if (inEscape) {
                currWord[j++] = ' ';
                inEscape = 0;
            } else if (val[i] == ' ' || val[i] == '\0') {
                if (j > 0) {
                    currWord[j] = '\0';
                    cfg->groups[cfg->groups_cnt++] = strdup(currWord);
                    if (cfg->groups_cnt >= MAX_GROUPS) {
                        fprintf(stderr, "Exceeded max %d groups\n", MAX_GROUPS);
                        cleanup_config_groups(cfg);
                        free(currWord);
                        return (0);
                    }
                    j = 0;
                }
                if (val[i] == '\0') {
                    break;
                }
            } else {
                currWord[j++] = val[i];
            }
        }
        free(currWord);
    } else if (strcmp(name, "failmode") == 0) {
        if (strcmp(val, "secure") == 0) {
            cfg->failmode = DUO_FAIL_SECURE;
        } else if (strcmp(val, "safe") == 0) {
            cfg->failmode = DUO_FAIL_SAFE;
        } else {
            fprintf(stderr, "Invalid failmode: '%s'\n", val);
            return (0);
        }
    } else if (strcmp(name, "pushinfo") == 0) {
        cfg->pushinfo = duo_set_boolean_option(val);
    } else if (strcmp(name, "noverify") == 0) {
        cfg->noverify = duo_set_boolean_option(val);
    } else if (strcmp(name, "prompts") == 0) {
        int int_val = atoi(val);
        /* Clamp the value into acceptable range */
        if (int_val <= 0) {
            int_val = 1;
        } 
        if (int_val < cfg->prompts) {
            cfg->prompts = int_val;
        }
    } else if (strcmp(name, "autopush") == 0) {
        cfg->autopush = duo_set_boolean_option(val);
    } else if (strcmp(name, "accept_env_factor") == 0) {
        cfg->accept_env = duo_set_boolean_option(val);
    } else if (strcmp(name, "fallback_local_ip") == 0) {
        cfg->local_ip_fallback = duo_set_boolean_option(val);
    } else if (strcmp(name, "https_timeout") == 0) {
        cfg->https_timeout = atoi(val);
        if (cfg->https_timeout <= 0) {
            cfg->https_timeout = -1; /* no timeout */
        } else {
            /* Make timeout milliseconds */
            cfg->https_timeout *= 1000;
        }
    } else if (strcmp(name, "send_gecos") == 0) {
        cfg->send_gecos = duo_set_boolean_option(val);
    } else if (strcmp(name, "gecos_parsed") == 0) {
        duo_log(LOG_ERR, "The gecos_parsed configuration item for Duo Unix is deprecated and no longer has any effect. Use gecos_delim and gecos_username_pos instead", NULL, NULL, NULL);
    } else if (strcmp(name, "gecos_delim") == 0) {
        if (strlen(val) != 1) {
            fprintf(stderr, "Invalid character option length. Character fields must be 1 character long: '%s'\n", val);
            return (0);
        }

        char delim = val[0];
        if (!ispunct(delim) || delim == ':') {
            fprintf(stderr, "Invalid gecos_delim '%c' (delimiter must be punctuation other than ':')\n", delim);
            return (0);
        }
        cfg->gecos_delim = delim;
    } else if (strcmp(name, "gecos_username_pos") == 0) {
        int gecos_username_pos = atoi(val);
        if (gecos_username_pos < 1) {
            fprintf(stderr, "Gecos position starts at 1\n");
            return (0);
        }
        else {
            // Offset the position so user facing first position is 1
            cfg->gecos_username_pos = gecos_username_pos - 1;
        }
    } else if (strcmp(name, "verified_push") == 0) {
        cfg->verified_push = duo_set_boolean_option(val);
    } else if (strcmp(name, "dev_fips_mode") == 0) {
        /* This flag is for development */
        cfg->fips_mode = duo_set_boolean_option(val);
    } else {
        /* Couldn't handle the option, maybe it's target specific? */
        return (0);
    }
    return (1);
}

void
close_config(struct duo_config *cfg)
{
    if (cfg == NULL) {
        return;
    }
    if (cfg->ikey != NULL) {
        duo_zero_free(cfg->ikey, strlen(cfg->ikey));
        cfg->ikey = NULL;
    }
    if (cfg->skey != NULL) {
        duo_zero_free(cfg->skey, strlen(cfg->skey));
        cfg->skey = NULL;
    }
    if (cfg->apihost != NULL) {
        duo_zero_free(cfg->apihost, strlen(cfg->apihost));
        cfg->apihost = NULL;
    }
    if (cfg->cafile != NULL) {
        duo_zero_free(cfg->cafile, strlen(cfg->cafile));
        cfg->cafile = NULL;
    }
    if (cfg->http_proxy != NULL) {
        duo_zero_free(cfg->http_proxy, strlen(cfg->http_proxy));
        cfg->http_proxy = NULL;
    }
    if (cfg->offline_secrets_path != NULL) {
        duo_zero_free(cfg->offline_secrets_path, strlen(cfg->offline_secrets_path));
        cfg->offline_secrets_path = NULL;
    }
    cleanup_config_groups(cfg);
}

void
cleanup_config_groups(struct duo_config *cfg)
{
    int i = 0;
    for (i = 0; i < MAX_GROUPS; ++i) {
        if (cfg->groups[i] != NULL) {
            free(cfg->groups[i]);
            cfg->groups[i] = NULL;
        }
    }
    cfg->groups_cnt = 0;
}


int
duo_check_groups(struct passwd *pw, char **groups, int groups_cnt)
{
    int i;

    if (groups_cnt > 0) {
        int matched = 0;

        if (ga_init(pw->pw_name, pw->pw_gid) < 0) {
            duo_log(LOG_ERR, "Couldn't get groups",
                pw->pw_name, NULL, strerror(errno));
            return (-1);
        }
        for (i = 0; i < groups_cnt; i++) {
            if (ga_match_pattern_list(groups[i])) {
                matched = 1;
                break;
            }
        }
        ga_free();

        /* User in configured groups for Duo auth? */
        return matched;
    } else {
        return 1;
    }
}

void
duo_log(int priority, const char*msg, const char *user, const char *ip,
        const char *err)
{
    char buf[512];
    int i, n;

    n = snprintf(buf, sizeof(buf), "%s", msg);

    if (user != NULL &&
        (i = snprintf(buf + n, sizeof(buf) - n, " for '%s'", user)) > 0) {
        n += i;
    }
    if (ip != NULL &&
        (i = snprintf(buf + n, sizeof(buf) - n, " from %s", ip)) > 0) {
        n += i;
    }
    if (err != NULL &&
        (i = snprintf(buf + n, sizeof(buf) - n, ": %s", err)) > 0) {
        n += i;
    }
    duo_syslog(priority, "%s", buf);
}

void
duo_syslog(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (duo_debug) {
        fprintf(stderr, "[%d] ", priority);
        vfprintf(stderr, fmt, ap);
        fputs("\n", stderr);
    } else {
        vsyslog(priority, fmt, ap);
    }
    va_end(ap);
}

const char *
duo_local_ip()
{
    struct sockaddr_in sin;
    socklen_t slen;
    int fd;
    const char *ip = NULL;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("8.8.8.8"); /* XXX Google's DNS Server */
    sin.sin_port = htons(53);
    slen = sizeof(sin);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) != -1) {
        if (connect(fd, (struct sockaddr *)&sin, slen) != -1 &&
            getsockname(fd, (struct sockaddr *)&sin, &slen) != -1) {
            ip = inet_ntoa(sin.sin_addr); /* XXX statically allocated */
        }
        close(fd);
    }
    return (ip);
}

char *
duo_split_at(char *s, char delimiter, unsigned int position)
{
    unsigned int count = 0;
    char *iter = NULL;
    char *result = s;

    for (iter = s; *iter; iter++) {
        if (*iter == delimiter) {
            if (count < position) {
                result = iter + 1;
                count++;
            }
            *iter = '\0';
        }
    }

    if (count < position) {
        return NULL;
    }

    return result;
}

void
duo_zero_free(void *ptr, size_t size)
{
    /*
     * A compiler's usage of dead store optimization may skip the memory
     * zeroing if it doesn't detect futher usage. Different systems use explicit
     * zeroing functions to prevent this. If none of those are available we fall back
     * on volatile pointers to prevent optimization. There is no guarantee in the standard
     * that this will work, but gcc and other major compilers will respect it.
     * Idea and technique borrowed from https://github.com/openssh/openssh-portable
     */
    if (ptr != NULL) {
#ifdef HAVE_EXPLICIT_BZERO
        explicit_bzero(ptr, size);
#elif HAVE_MEMSET_S
        (void)memset_s(ptr, size, 0, size);
#else
        static void* (* volatile duo_memset)(void *, int, size_t) = memset;
        duo_memset(ptr, 0, size);
#endif
        free(ptr);
    }
}

static int
compute_hmac_sha1(const unsigned char *key, int key_len,
                  const unsigned char *data, int data_len,
                  unsigned char *hmac_out)
{
    unsigned int hmac_len;

    if (!HMAC(EVP_sha1(), key, key_len, data, data_len, hmac_out, &hmac_len)) {
        return -1;
    }

    return hmac_len;
}

unsigned char *
duo_base32_decode(const char *encoded, int *output_len)
{
    int len = strlen(encoded);
    int i, j, bits, value;
    unsigned char *result;

    if (!encoded || len == 0 || len > BASE32_INPUT_SIZE_LIMIT) {
        *output_len = 0;
        return NULL;
    }

    *output_len = (len * 5) / 8;

    result = malloc(*output_len);
    if (!result) {
        return NULL;
    }

    bits = 0;
    value = 0;
    j = 0;

    for (i = 0; i < len; i++) {
        char c = encoded[i];

        /* Fast mathematical Base32 character decode */
        int val;
        if (c == ' ' || c == '-') {
            continue;                   /* Skip separators */
        } else if (c >= 'A' && c <= 'Z') {
            val = c - 'A';              /* A-Z → 0-25 */
        } else if (c >= '2' && c <= '7') {
            val = c - '2' + 26;         /* 2-7 → 26-31 */
        } else {
            free(result);
            return NULL;
        }

        value = (value << 5) | val;
        bits += 5;

        if (bits >= 8) {
            result[j++] = (value >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }

    *output_len = j;
    return result;
}

uint32_t
duo_compute_totp_code(const unsigned char *secret, int secret_len, uint64_t timestamp)
{
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    uint64_t counter = htobe64(timestamp);
    int hmac_len;

    hmac_len = compute_hmac_sha1(secret, secret_len,
                                (unsigned char *)&counter, sizeof counter,
                                hmac_result);
    if (hmac_len < 0) {
        return 0;
    }

    int offset = hmac_result[hmac_len - 1] & 0x0F;
    uint32_t code = ((hmac_result[offset] & 0x7F) << 24) |
                    ((hmac_result[offset + 1] & 0xFF) << 16) |
                    ((hmac_result[offset + 2] & 0xFF) << 8) |
                    (hmac_result[offset + 3] & 0xFF);

    return code % 1000000; /* 10^6 for 6-digit TOTP codes */
}

int
duo_verify_totp_code(const char *secret, uint32_t code, time_t current_time)
{
    unsigned char *decoded_secret;
    int secret_len;
    const int seconds_per_step = 30;
    const int window_steps = 8; /* +/-2 minutes security window */
    uint64_t time_step = current_time / seconds_per_step;
    uint64_t start_step, end_step;

    decoded_secret = duo_base32_decode(secret, &secret_len);
    if (!decoded_secret) {
        return 0;
    }

    start_step = time_step - window_steps / 2;
    end_step = time_step + window_steps / 2 + 1;

    for (uint64_t step = start_step; step < end_step; step++) {
        uint32_t expected_code = duo_compute_totp_code(decoded_secret, secret_len, step);
        if (expected_code == code) {
            free(decoded_secret);
            return 1;
        }
    }

    free(decoded_secret);
    return 0; /* Invalid code */
}
