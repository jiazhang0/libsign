/*
 * Copyright (c) 2017, Wind River Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3) Neither the name of Wind River Systems nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Author:
 *        Lans Zhang <jia.zhang@windriver.com>
 */

#include <signlet.h>
#include <signaturelet.h>
#include "bcll.h"

#ifndef SIGNATURELET_DIR
#  define SIGNATURELET_DIR	"/usr/lib/libsign/signaturelet"
#endif

#define MAX_NR_SIGNATURELETS	16

typedef struct {
	libsign_signaturelet_t *sig;
	bcll_t link;
	void *handle;
} signaturelet_t;

static BCLL_DECLARE(signaturelet_list);
static unsigned int nr_handles;
static void *handles[MAX_NR_SIGNATURELETS];

static void
add_siglet_handle(void *handle)
{
	if (nr_handles >= MAX_NR_SIGNATURELETS) {
		err("Unable to add the new handle for signaturelet\n");
		return;
	}

	handles[nr_handles++] = handle;
}

static signaturelet_t *
find_signaturelet(const char *id)
{
	signaturelet_t *siglet;

	bcll_for_each_link(siglet, &signaturelet_list, link) {
		if (!strcmp(siglet->sig->id, id))
			return siglet;
	}

	return NULL;
}

int
signaturelet_load(const char *id)
{
	signaturelet_t *siglet = find_signaturelet(id);
	if (siglet)
		return EXIT_SUCCESS;

	char path[PATH_MAX];
	int path_len = snprintf(path, sizeof(path) - 1, SIGNATURELET_DIR
				"/%s.siglet", id);
	path[path_len] = 0;

	dbg("On-demond loading signaturelet %s ...\n", id);

	void *handle = dlopen(path, RTLD_LAZY);
	if (!handle) {
		char *libdir;

		libdir = getenv("LD_LIBRARY_PATH");
		if (!libdir) {
			err("Define $LD_LIBRARY_PATH/signaturelet to locate "
			    "siglet\n");
			return EXIT_FAILURE;
		}

		char *search = strdup(libdir);
		if (!search)
			return EXIT_FAILURE;

		char *p = search;

		while ((libdir = strtok(p, ":"))) {
			path_len = snprintf(path, sizeof(path) - 1,
					    "%s/signaturelet"
					    "/%s.siglet", libdir, id);
			path[path_len] = 0;

			dbg("Attempting to load signaturelet %s.siglet at "
			    "%s ...\n", id, path);

			handle = dlopen(path, RTLD_LAZY);
			if (handle)
				break;

			p = NULL;
		}

		free(search);

		if (!libdir)
			return EXIT_FAILURE;
	}

	add_siglet_handle(handle);

	dbg("signaturelet %s loaded\n", id);

	return EXIT_SUCCESS;
}

int
signaturelet_suffix_pattern(const char *id, unsigned long flags,
			    const char **suffix_pattern)
{
	signaturelet_t *siglet;

	siglet = find_signaturelet(id);
	if (!siglet)
		return EXIT_FAILURE;

	const signaturelet_suffix_pattern_t **pattern;

	pattern = siglet->sig->suffix_pattern;
	do {
		if ((*pattern)->flag & flags) {
			if ((*pattern)->suffix_if_flag_set) {
				*suffix_pattern = (*pattern)->suffix_if_flag_set;
				return EXIT_SUCCESS;
			}
		} else if ((*pattern)->suffix_if_flag_unset) {
			*suffix_pattern = (*pattern)->suffix_if_flag_unset;
			return EXIT_SUCCESS;
		}
	} while (*++pattern);

	return EXIT_SUCCESS;
}

static int
sanity_check_suffix_pattern(const signaturelet_suffix_pattern_t **pattern)
{
	int check_suffix(const char *suffix)
	{
		char op = *suffix++;
		int rc = EXIT_FAILURE;

		switch (op) {
		case '+':
			if (strlen(suffix))
				rc = EXIT_SUCCESS;
			else
				err("Suffix character too short in pattern "
				    "%s\n", suffix);
			break;
		default:
			err("Unsupported operator character in pattern %s\n",
			    suffix);
		}

		return rc;
	}

	do {
		int rc;

		if (!(*pattern)->flag) {
			err("A suffix pattern must be specified with "
			    "a non-empty flag\n");
			return EXIT_FAILURE;
		}

		if (!(*pattern)->suffix_if_flag_unset &&
		    !(*pattern)->suffix_if_flag_set) {
			err("A suffix string must be specified in either set "
			    "case or unset case\n");
			return EXIT_FAILURE;
		}


		if ((*pattern)->suffix_if_flag_set) {
			rc = check_suffix((*pattern)->suffix_if_flag_set);
			if (rc)
				return EXIT_FAILURE;
		}

		if ((*pattern)->suffix_if_flag_unset) {
			rc = check_suffix((*pattern)->suffix_if_flag_unset);
			if (rc)
				return EXIT_FAILURE;
		}
	} while (*++pattern);
	
	return EXIT_SUCCESS;
}

static int
sanity_check(libsign_signaturelet_t *sig)
{
	if (!sig) {
		err("Invalid signaturelet\n");
		return EXIT_FAILURE;
	}

	if (!sig->id || !sig->id[0]) {
		err("signaturelet must have a valid id\n");
		return EXIT_FAILURE;
	}

	if (!sig->sign) {
		err("The sign() is not provided by signaturelet %s\n",
		    sig->id);
		return EXIT_FAILURE;
	}

	if (!libsign_digest_supported(sig->digest_alg)) {
		err("Unsupported digest algorithm %#x specified by "
		    "signaturelet %s\n", sig->digest_alg,
		    sig->id);
		return EXIT_FAILURE;
	}

	if (!sig->suffix_pattern || !sig->suffix_pattern[0]) {
		err("Suffix pattern is not specified by signaturelet %s\n",
		    sig->id);
		return EXIT_FAILURE;
	}

	if (sanity_check_suffix_pattern(sig->suffix_pattern))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int
signaturelet_register(libsign_signaturelet_t *sig)
{
	dbg("Registering signaturelet %s ...\n", sig->id);

	int rc = sanity_check(sig);
	if (rc)
		return rc;	

	dbg("Post-loading signaturelet %s ...\n", sig->id);

	void *handle = dlopen(NULL, RTLD_LAZY);
	if (!handle)
		return EXIT_FAILURE;

	signaturelet_t *siglet = malloc(sizeof(*sig) + sizeof(*siglet));
	if (!siglet) {
		dlclose(handle);
		return EXIT_FAILURE;
	}

	siglet->sig = (libsign_signaturelet_t *)(siglet + 1);
	*(siglet->sig) = *sig;
	bcll_add_tail(&signaturelet_list, &siglet->link);
	libsign_digest_init(sig->digest_alg);
	siglet->handle = handle;

	info("signaturelet %s registered\n", sig->id);

	return EXIT_SUCCESS;
}

int
signaturelet_unregister(const char *id)
{
	dbg("Unregistering signaturelet %s ...\n", id);

	signaturelet_t *siglet = find_signaturelet(id);
	if (!siglet) {
		err("Unregistering a not existing signaturelet %s\n",
		    id);
		return EXIT_FAILURE;
	}

	bcll_del(&siglet->link);
	dlclose(siglet->handle);

	return EXIT_SUCCESS;
}

int
signaturelet_sign(const char *id, uint8_t *data, unsigned int data_size,
		  const char *key, const char **cert_list,
		  unsigned int nr_cert, uint8_t **out_sig,
		  unsigned int *out_sig_size, unsigned long flags)
{
	if (!id || !out_sig || !out_sig_size || !key || !cert_list)
		return EXIT_FAILURE;

	if (data_size && !data)
		return EXIT_FAILURE;

	if (nr_cert && !cert_list)
		return EXIT_FAILURE;

	signaturelet_t *siglet = find_signaturelet(id);
	if (!siglet) {
		err("Failed to search the signaturelet %s\n",
		    id);
		return EXIT_FAILURE;
	}

	return siglet->sig->sign(siglet->sig, data, data_size, key, cert_list,
				 nr_cert, out_sig, out_sig_size, flags);
}
