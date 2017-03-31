/*
 * BSD 2-clause "Simplified" License
 *
 * Copyright (c) 2017, Lans Zhang <jia.zhang@windriver.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LIBSIGN_H
#define LIBSIGN_H

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <getopt.h>
#include <dlfcn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>

#define stringify(x)			#x

#ifndef offsetof
  #define offsetof(type, member)	((unsigned long)&((type *)0)->member)
#endif

#define container_of(ptr, type, member)	({	\
	const __typeof__(((type *)0)->member) *__ptr = (ptr);	\
	(type *)((char *)__ptr - offsetof(type, member));})

#define align_up(x, n)	(((x) + ((n) - 1)) & ~((n) - 1))
#define aligned(x, n)	(!!((x) & ((n) - 1)))

#define libsign_assert(condition, fmt, ...)	\
	do {	\
		if (!(condition)) {	\
			err(fmt ": %s\n", ##__VA_ARGS__, strerror(errno)); \
			exit(EXIT_FAILURE);	\
		}	\
	} while (0)

#define gettid()		syscall(__NR_gettid)

#define __pr__(level, io, fmt, ...)	\
	do {	\
		time_t __t__ = time(NULL);	\
		struct tm __loc__;	\
		localtime_r(&__t__, &__loc__);	\
		char __buf__[64]; \
		strftime(__buf__, sizeof(__buf__), "%a %b %e %T %Z %Y", &__loc__);	\
		fprintf(io, "%s: [" #level "] " fmt, __buf__, ##__VA_ARGS__);	\
	} while (0)

#define die(fmt, ...)	\
	do {	\
		__pr__(FAULT, stderr, fmt, ##__VA_ARGS__);	\
		exit(EXIT_FAILURE);	\
	} while (0)

#ifdef DEBUG_BUILD
  #define dbg(fmt, ...)	\
	do {	\
		__pr__(DEBUG, stdout, fmt, ##__VA_ARGS__);	\
	} while (0)

  #define dbg_cont(fmt, ...)	\
	do {	\
		fprintf(stdout, fmt, ##__VA_ARGS__);	\
	} while (0)
#else
  #define dbg(fmt, ...)
  #define dbg_cont(fmt, ...)
#endif

#define info(fmt, ...)	\
	do {	\
		__pr__(INFO, stdout, fmt, ##__VA_ARGS__);	\
	} while (0)

#define info_cont(fmt, ...)	\
	fprintf(stdout, fmt, ##__VA_ARGS__)

#define warn(fmt, ...)	\
	do {	\
		__pr__(WARNING, stdout, fmt, ##__VA_ARGS__);	\
	} while (0)

#define err(fmt, ...)	\
	do {	\
		__pr__(ERROR, stderr, fmt, ##__VA_ARGS__);	\
	} while (0)

#define err_cont(fmt, ...)	\
	fprintf(stderr, fmt, ##__VA_ARGS__)

typedef enum {
	LIBSIGN_DIGEST_ALG_NONE,
	LIBSIGN_DIGEST_ALG_SHA224,
	LIBSIGN_DIGEST_ALG_SHA256,
	LIBSIGN_DIGEST_ALG_SHA384,
	LIBSIGN_DIGEST_ALG_SHA512,
	LIBSIGN_DIGEST_ALG_SHA1,
	LIBSIGN_DIGEST_ALG_MAX
} LIBSIGN_DIGEST_ALG;

typedef enum {
	LIBSIGN_CIPHER_ALG_NONE,
	LIBSIGN_CIPHER_ALG_RSA,
} LIBSIGN_CIPHER_ALG;

extern const char *libsign_git_commit;
extern const char *libsign_build_machine;

int
libsign_utils_verbose(void);

void
libsign_utils_set_verbosity(int verbose);

bool
libsign_utils_file_exists(const char *file_path);

int
libsign_utils_load_file(const char *path, uint8_t **out_buf,
			unsigned int *out_size);

int
libsign_utils_save_file(const char *file_path, uint8_t *buf,
			unsigned int size);

void
libsign_utils_hex_dump(const char *prompt, uint8_t *data,
		       unsigned int data_size);

bool
libsign_digest_supported(LIBSIGN_DIGEST_ALG digest_alg);

int
libsign_digest_init(LIBSIGN_DIGEST_ALG digest_alg);

int
libsign_digest_size(LIBSIGN_DIGEST_ALG digest_alg, unsigned int *digest_size);

int
libsign_digest_calculate(LIBSIGN_DIGEST_ALG digest_alg, uint8_t *data,
			 unsigned int data_size, uint8_t **digest);

EVP_PKEY *
libsign_key_load(const char *path);

void
libsign_key_unload(EVP_PKEY *key);

X509 *
libsign_x509_load(const char *path);

void
libsign_x509_unload(X509 *cert);

#endif	/* LIBSIGN_H */
