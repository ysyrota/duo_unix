/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * duo_offline_enroll.c
 *
 * Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>
#include <limits.h>

#include <qrencode.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "duo.h"
#include "util.h"

#ifndef DUO_CONF
#define DUO_CONF DUO_CONF_DIR "/pam_duo.conf"
#endif

static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static void
usage(void)
{
	fprintf(stderr, "Usage: duo_offline_enroll [-c config] [-i ikey] [-s skey] [-h host] [-o qrfile] [-p secrets_path] username\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -c config     Duo configuration file path [default: " DUO_CONF "]\n");
	fprintf(stderr, "  -i ikey       Integration key\n");
	fprintf(stderr, "  -s skey       Secret key\n");
	fprintf(stderr, "  -h host       API hostname\n");
	fprintf(stderr, "  -o qrfile     Write QR code to PBM file\n");
	fprintf(stderr, "  -p path       Path for storing offline secret [default: " DUO_DEFAULT_OFFLINE_SECRETS_PATH "]\n");
	fprintf(stderr, "  -v            Show version information\n");
}

static void
version(void)
{
	fprintf(stderr, "duo_offline_enroll (duo_unix) " PACKAGE_VERSION "\n");
}

static int
generate_random_bytes(unsigned char *buf, int len)
{
	return (RAND_bytes(buf, len) == 1) ? 0 : -1;
}

static char *
base32_encode(const unsigned char *data, int len)
{
	char *result;
	int i, j;
	unsigned int buffer = 0;
	int bits = 0;
	int output_len = ((len * 8) + 4) / 5;

	result = malloc(output_len + 1);
	if (!result) {
		return NULL;
	}

	j = 0;
	for (i = 0; i < len; i++) {
		buffer = (buffer << 8) | data[i];
		bits += 8;

		while (bits >= 5) {
			if (j >= output_len) { /* Buffer overflow protection */
				free(result);
				return NULL;
			}
			result[j++] = base32_alphabet[(buffer >> (bits - 5)) & 0x1F];
			bits -= 5;
		}
	}

	if (bits > 0) {
		if (j >= output_len) { /* Buffer overflow protection */
			free(result);
			return NULL;
		}
		result[j++] = base32_alphabet[(buffer << (5 - bits)) & 0x1F];
	}

	result[j] = '\0';
	return result;
}

static char *
create_enrollment_json(const char *secret, const char *akey, const char *username)
{
	char *json;
	time_t now = time(NULL);

	if (asprintf(&json,
		"{"
		"\"seed\":\"%s\","
		"\"akey\":\"%s\","
		"\"uname\":\"%s\","
		"\"ts\":%ld,"
		"\"v\":1,"
		"\"type\":\"mac\""
		"}",
		secret, akey, username, now) < 0) {
		return NULL;
	}

	return json;
}

/* Generate QR code as text for terminal display */
static void
print_qr_text(QRcode *qr)
{
	int y, x;
	unsigned char *data = qr->data;
	int width = qr->width;
	int margin = 2;

	/* Unicode block characters for proper square display */
	const char *empty = " ";
	const char *lowhalf = "\342\226\204";  /* ▄ */
	const char *uphalf = "\342\226\200";   /* ▀ */
	const char *full = "\342\226\210";     /* █ */

	/* Process two rows at a time to create square appearance */
	for (y = -margin; y < width + margin; y += 2) {
		for (x = -margin; x < width + margin; x++) {
			int upper = 0, lower = 0;

			/* Check upper pixel */
			if (y >= 0 && y < width && x >= 0 && x < width) {
				upper = data[y * width + x] & 1;
			}

			/* Check lower pixel */
			if ((y + 1) >= 0 && (y + 1) < width && x >= 0 && x < width) {
				lower = data[(y + 1) * width + x] & 1;
			}

			/* Print appropriate Unicode block character */
			if (upper && lower) {
				printf("%s", full);
			} else if (upper && !lower) {
				printf("%s", uphalf);
			} else if (!upper && lower) {
				printf("%s", lowhalf);
			} else {
				printf("%s", empty);
			}
		}
		printf("\n");
	}
}

/* Write QR code as PBM (P4) format */
static int
write_qr_pbm(QRcode *qr, const char *filename)
{
	FILE *fp;
	int y, x, sy, sx;
	unsigned char *data = qr->data;
	int width = qr->width;
	const int scale = 4; /* Scale factor: each QR module becomes 8x8 pixels */
	int scaled_width = width * scale;
	int bytes_per_row = (scaled_width + 7) / 8;
	unsigned char *row_data;

	fp = fopen(filename, "wb");
	if (!fp) {
		fprintf(stderr, "Error: Cannot open %s for writing: %s\n",
			filename, strerror(errno));
		return -1;
	}

	/* Write PBM header with scaled dimensions */
	fprintf(fp, "P4\n%d %d\n", scaled_width, scaled_width);

	row_data = calloc(bytes_per_row, 1);
	if (!row_data) {
		fclose(fp);
		return -1;
	}

	/* Write bitmap data with scaling */
	for (y = 0; y < width; y++) {
		/* Each QR module becomes scale x scale pixels */
		for (sy = 0; sy < scale; sy++) {
			memset(row_data, 0, bytes_per_row);

			for (x = 0; x < width; x++) {
				if (data[y * width + x] & 1) {
					/* Fill scale pixels horizontally for this module */
					for (sx = 0; sx < scale; sx++) {
						int pixel_x = x * scale + sx;
						row_data[pixel_x / 8] |= (0x80 >> (pixel_x % 8));
					}
				}
			}

			if (fwrite(row_data, bytes_per_row, 1, fp) != 1) {
				fprintf(stderr, "Error writing to %s: %s\n",
					filename, strerror(errno));
				free(row_data);
				fclose(fp);
				return -1;
			}
		}
	}

	free(row_data);
	fclose(fp);
	return 0;
}

/* Parse configuration file */
static int
config_handler(void *arg, const char *section, const char *name, const char *val)
{
	struct duo_config *cfg = (struct duo_config *)arg;
	return duo_common_ini_handler(cfg, section, name, val);
}

static int
parse_config(const char *filename, struct duo_config *cfg)
{
	return duo_parse_config(filename, config_handler, cfg);
}

/* Helper function to safely replace config string value */
static int
replace_config_string(char **dest, const char *src, const char *field_name)
{
	if (src) {
		free(*dest);
		*dest = strdup(src);
		if (!*dest) {
			fprintf(stderr, "Error: Memory allocation failed for %s\n", field_name);
			return -1;
		}
	}
	return 0;
}

/* Create directory with mode 0700 if it doesn't exist */
static int
create_secrets_directory(const char *path)
{
	struct stat st;

	if (stat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "Error: %s exists but is not a directory\n", path);
			return -1;
		}
		/* Directory exists, check permissions */
		if ((st.st_mode & 0777) != 0700) {
			if (chmod(path, 0700) != 0) {
				fprintf(stderr, "Error: Cannot set directory permissions on %s: %s\n",
					path, strerror(errno));
				return -1;
			}
		}
		return 0;
	}

	/* Directory doesn't exist, create it */
	if (mkdir(path, 0700) != 0) {
		fprintf(stderr, "Error: Cannot create directory %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	return 0;
}

/* Write data to file using safe-write semantics (write to temp, fsync, rename) */
static int
write_secrets_file(const char *base_path, const char *filename, const char *data)
{
	char filepath[PATH_MAX];
	char temppath[PATH_MAX];
	int fd = -1;
	int ret = -1;

	/* Construct full file paths */
	if (snprintf(filepath, sizeof filepath, "%s/%s", base_path, filename) >= (int)sizeof filepath) {
		fprintf(stderr, "Error: Path too long: %s/%s\n", base_path, filename);
		return -1;
	}

	if (snprintf(temppath, sizeof temppath, "%s/.%s.tmp.%d", base_path, filename, getpid())
	    >= (int)sizeof temppath) {
		fprintf(stderr, "Error: Temp path too long\n");
		return -1;
	}

	/* Create and open temp file with exclusive lock */
	fd = open(temppath, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1) {
		fprintf(stderr, "Error: Cannot create temp file %s: %s\n",
			temppath, strerror(errno));
		return -1;
	}

	/* Acquire exclusive lock for portability */
	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(fd, F_SETLK, &fl) != 0) {
		fprintf(stderr, "Error: Cannot lock temp file %s: %s\n",
			temppath, strerror(errno));
		goto cleanup;
	}

	size_t data_len = strlen(data);
	ssize_t written = write(fd, data, data_len);
	if (written < 0 || (size_t)written != data_len) {
		fprintf(stderr, "Error: Cannot write to temp file %s: %s\n",
			temppath, strerror(errno));
		goto cleanup;
	}

	if (fsync(fd) != 0) {
		fprintf(stderr, "Error: Cannot sync temp file %s: %s\n",
			temppath, strerror(errno));
		goto cleanup;
	}

	close(fd);
	fd = -1;

	if (rename(temppath, filepath) != 0) {
		fprintf(stderr, "Error: Cannot rename %s to %s: %s\n",
			temppath, filepath, strerror(errno));
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (fd != -1) {
		close(fd);
	}

	unlink(temppath);

	return ret;
}

/* Persist enrollment artifacts to disk */
static int
persist_enrollment_artifacts(const char *secrets_path, const char *username,
                            const char *secret)
{
	char secret_filename[NAME_MAX];

	if (create_secrets_directory(secrets_path) != 0) {
		return -1;
	}

	if (snprintf(secret_filename, sizeof secret_filename, "%s.secret", username)
	    >= (int)sizeof secret_filename) {
		fprintf(stderr, "Error: Username too long for filename: %s\n", username);
		return -1;
	}

	if (write_secrets_file(secrets_path, secret_filename, secret) != 0) {
		return -1;
	}

	printf("Offline secret written to %s/%s\n", secrets_path, secret_filename);

	return 0;
}

int
main(int argc, char **argv)
{
	struct duo_config cfg;
	char *config_file = NULL;
	char *username = NULL;
	char *qr_file = NULL;
	char *cmd_secrets_path = NULL;
	int opt;

	unsigned char random_bytes[16]; /* 128 bits */
	char *secret = NULL;
	char *json = NULL;
	QRcode *qr = NULL;
	int ret = 1;

	duo_config_default(&cfg);

	char *cmd_ikey = NULL, *cmd_skey = NULL, *cmd_host = NULL;

	while ((opt = getopt(argc, argv, "c:i:s:h:o:p:v?")) != -1) {
		switch (opt) {
		case 'c':
			config_file = optarg;
			break;
		case 'i':
			cmd_ikey = optarg;
			break;
		case 's':
			cmd_skey = optarg;
			break;
		case 'h':
			cmd_host = optarg;
			break;
		case 'o':
			qr_file = optarg;
			break;
		case 'p':
			cmd_secrets_path = optarg;
			break;
		case 'v':
			version();
			ret = 0;
			goto cleanup;
		default:
			usage();
			goto cleanup;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: Username is required as positional argument\n");
		usage();
		goto cleanup;
	}
	username = argv[optind];

	if (optind + 1 < argc) {
		fprintf(stderr, "Error: Too many arguments\n");
		usage();
		goto cleanup;
	}

	if (config_file) {
		if (parse_config(config_file, &cfg) != 0) {
			fprintf(stderr, "Error: Failed to parse config file %s\n", config_file);
			goto cleanup;
		}
	} else { /* Try default config file */
		parse_config(DUO_CONF, &cfg); /* Ignore errors for default file */
	}

	if (replace_config_string(&cfg.ikey, cmd_ikey, "ikey") < 0 ||
	    replace_config_string(&cfg.skey, cmd_skey, "skey") < 0 ||
	    replace_config_string(&cfg.apihost, cmd_host, "host") < 0 ||
	    replace_config_string(&cfg.offline_secrets_path, cmd_secrets_path, "offline_secrets_path") < 0) {
		goto cleanup;
	}

	if (!cfg.ikey || !cfg.skey || !cfg.apihost) {
		fprintf(stderr, "Error: Missing required parameters. Use -c or specify -i, -s, -h\n");
		fprintf(stderr, "       Default config file: %s\n", DUO_CONF);
		usage();
		goto cleanup;
	}

	if (!cfg.offline_secrets_path) {
		fprintf(stderr, "Error: No offline secrets path configured\n");
		goto cleanup;
	}

	if (generate_random_bytes(random_bytes, sizeof random_bytes) != 0) {
		fprintf(stderr, "Error: Failed to generate random bytes\n");
		goto cleanup;
	}

	secret = base32_encode(random_bytes, sizeof random_bytes);
	if (!secret) {
		fprintf(stderr, "Error: Failed to encode secret\n");
		goto cleanup;
	}

	json = create_enrollment_json(secret, cfg.ikey, username);
	if (!json) {
		fprintf(stderr, "Error: Failed to create enrollment JSON\n");
		goto cleanup;
	}

	qr = QRcode_encodeString(json, 0, QR_ECLEVEL_M, QR_MODE_8, 1);
	if (!qr) {
		fprintf(stderr, "Error: Failed to generate QR code\n");
		goto cleanup;
	}

	/* Output QR code */
	if (qr_file) {
		if (write_qr_pbm(qr, qr_file) != 0) {
			goto cleanup;
		}
		printf("QR code written to %s\n", qr_file);
	} else {
		printf("Scan this QR code with Duo Mobile:\n\n");
		print_qr_text(qr);
		printf("\n");
	}

	printf("Enrollment data: %s\n", json);

	if (persist_enrollment_artifacts(cfg.offline_secrets_path, username, secret) != 0) {
		fprintf(stderr, "Error: Failed to persist enrollment secret\n");
		goto cleanup;
	}

	printf("Please enter the %d-digit verification code from Duo Mobile to verify enrollment: ",
	       TOTP_CODE_DIGITS);
	fflush(stdout);

	char verification_code[TOTP_CODE_DIGITS + 2];
	if (fgets(verification_code, sizeof verification_code, stdin)) {
		char *newline = strchr(verification_code, '\n');
		if (newline) *newline = '\0';

		if (strlen(verification_code) == TOTP_CODE_DIGITS &&
		    strspn(verification_code, "0123456789") == TOTP_CODE_DIGITS) {
			uint32_t code = (uint32_t)atol(verification_code);
			printf("Verification code received: %s\n", verification_code);

			/* Use more secure verification with tighter window */
			if (duo_verify_totp_code(secret, code, time(NULL))) {
				printf("Verification successful! TOTP code is valid.\n");
				printf("Enrollment completed successfully!\n");
			} else {
				printf("Verification failed. Invalid TOTP code.\n");
				printf("Please ensure your device's clock is synchronized and try again.\n");
				printf("Enrollment data has been generated, but verification failed.\n");
			}
		} else {
			printf("Invalid verification code format. Expected %d digits.\n", TOTP_CODE_DIGITS);
			printf("Enrollment data has been generated, but verification failed.\n");
		}
	} else {
		printf("Failed to read verification code.\n");
		printf("Enrollment data has been generated, but verification skipped.\n");
	}

	ret = 0;

cleanup:
	close_config(&cfg);
	if (secret) free(secret);
	if (json) free(json);
	if (qr) QRcode_free(qr);

	return ret;
}