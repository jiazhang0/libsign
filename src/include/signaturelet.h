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

#ifndef SIGNATURELET_H
#define SIGNATURELET_H

#include <libsign.h>

typedef struct {
	unsigned long flag;
	const char *suffix_if_flag_set;
	const char *suffix_if_flag_unset;
} signaturelet_suffix_pattern_t;

typedef struct __libsign_signaturelet	libsign_signaturelet_t;

typedef struct __libsign_signaturelet {
	const char *id;
	const char *description;
	LIBSIGN_DIGEST_ALG digest_alg;
	LIBSIGN_CIPHER_ALG cipher_alg;
	bool detached;
	int (*sign)(libsign_signaturelet_t *siglet, uint8_t *data,
		    unsigned int data_size, const char *key,
		    const char **cert_list, unsigned int nr_cert,
		    uint8_t **out_sig, unsigned int *out_sig_size,
		    unsigned long flags);
	const signaturelet_suffix_pattern_t **suffix_pattern;
} libsign_signaturelet_t;

int
signaturelet_register(libsign_signaturelet_t *sig);

int
signaturelet_unregister(const char *id);

int
signaturelet_load(const char *id);

int
signaturelet_suffix_pattern(const char *id, unsigned long flags,
			    const char **suffix_pattern);

int
signaturelet_sign(const char *id, uint8_t *data, unsigned int data_size,
		  const char *key, const char **cert_list,
		  unsigned int nr_cert, uint8_t **out_sig,
		  unsigned int *out_sig_size, unsigned long flags);

#endif	/* SIGNATURELET_H */
