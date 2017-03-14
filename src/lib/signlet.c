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

#include <signlet.h>
#include <signaturelet.h>

typedef struct {
	const char *siglet;
	const char **signed_file_list;
	unsigned int nr_signed_file;
	const char **output_file_list;
	const char *key;
	const char *cert_list[SIGNLET_MAX_NR_CERT];
	unsigned int nr_cert;
	unsigned long flags;
} signlet_context;

static int
parse_request(signlet_request_t *request, signlet_context *context)
{
	memset(context, 0, sizeof(*context));

	if (!request)
		return EXIT_FAILURE;

	if (!request->siglet) {
		err("The requested signaturelet is not specified\n");
		return EXIT_FAILURE;
	}

	if ((request->flags & SIGNLET_FLAGS_CONTENT_ATTACHED) &&
	    (request->flags & SIGNLET_FLAGS_DETACHED_SIGNATURE)) {
		err("Invalid flags (0x%lx)\n", request->flags);
		return EXIT_FAILURE;
	}

	if (!request->signed_file_list) {
		err("The signed file list is not specified\n");
		return EXIT_FAILURE;
	} else if (!request->signed_file_list[0]) {
		err("The signed file list should not be empty\n");
		return EXIT_FAILURE;
	}

	if (!request->key) {
		err("The signing key is not specified\n");
		return EXIT_FAILURE;
	}

	EVP_PKEY *key = libsign_key_load(request->key);
	if (!key) {
		err("Faild to load the signing key\n");
		return EXIT_FAILURE;
	} else
		libsign_key_unload(key);

	const char *file;
	const char **list = request->signed_file_list;

	for (file = *list; file; file = *(++list)) {
		/* XXX: allow to ignore nonexistent signed file */
		if (!libsign_utils_file_exists(file)) {
			err("The signed file %s doesn't exist\n",
			    file);
			return EXIT_FAILURE;
		}

		if (++context->nr_signed_file >= SIGNLET_MAX_NR_REQUEST) {
			warn("The numer of igned files truncated to %d\n",
			     SIGNLET_MAX_NR_REQUEST);
			break;	
		}
	}

	list = request->output_file_list;
	if (list) {
		unsigned int i = 0;

		for (file = *list; i < context->nr_signed_file; file = *(++list)) {
			if (!file) {
				err("The output file for %s is not specified\n",
				    context->signed_file_list[i]);
				return EXIT_FAILURE;
			}

			++i;
		}
	}

	list = request->cert_list;
	if (list && list[0]) {
		file = *list;

		do {
			/* XXX: allow to ignore nonexistent certificate */
			X509 *cert = libsign_x509_load(file);
			if (cert)
				libsign_x509_unload(cert);
			else {
				err("Failed to load the certificate %s\n",
				    file);
				return EXIT_FAILURE;
			}

			context->cert_list[context->nr_cert++] = file;
			file = *(++list);
		} while (file);
	} else
		dbg("The certificate list is not specified\n");

	context->signed_file_list = request->signed_file_list;
	context->output_file_list = request->output_file_list;
	context->siglet = request->siglet;
	context->key = request->key;
	context->flags = request->flags;

	return EXIT_SUCCESS;
}

static void
release_request(signlet_context *context)
{
}

static int
sign_file(signlet_context *context, const char *path,
	  uint8_t **out_sig, unsigned int *out_sig_size)
{
	uint8_t *data;
	unsigned data_size;
	int rc;

	rc = libsign_utils_load_file(path, &data, &data_size);
	if (rc)
		return rc;

	rc = signaturelet_sign(context->siglet, data, data_size,
			       context->key, context->cert_list,
			       context->nr_cert, out_sig, out_sig_size,
			       context->flags);
	free(data);

	if (rc)
		err("%s: failed to sign the file %s\n",
		    context->siglet, path);
	else
		dbg("%s: succeeded to sign the file %s\n",
		    context->siglet, path);

	return rc;
}

static const char **
build_output_file_list(signlet_context *context)
{
	const char *pattern;
	int rc;

	rc = signaturelet_naming_pattern(context->siglet, &pattern);
	if (rc)
		return NULL;

	const char **output_path_list = malloc((context->nr_signed_file + 1) *
					       sizeof(char *));
	if (!output_path_list)
		return NULL;

	char op = *pattern++;
	int suffix_size = strlen(pattern);
	unsigned int i;

	for (i = 0; i < context->nr_signed_file; ++i) {
		const char *path = context->signed_file_list[i];
		char *output_path = NULL;
		int output_path_size = 0;

		if (context->output_file_list)
			output_path = strdup(context->output_file_list[i]);
		else if (op == '+') {
			output_path_size = strlen(path) + suffix_size;
			output_path = malloc(output_path_size + 1);
		}

		if (!output_path)
			break;

		if (output_path_size) {
			sprintf(output_path, "%s%s", path, pattern);
			output_path[output_path_size] = '\0';
		}

		output_path_list[i] = output_path;
	}

	if (i != context->nr_signed_file) {
		while ((int)--i >= 0)
			free((void *)output_path_list[i]);
		free(output_path_list);
		return NULL;
	}

	output_path_list[i] = NULL; 

	return output_path_list;
}

static void
free_output_file_list(const char **output_path_list)
{
	const char **list = output_path_list;

	for (const char *path = *list; path; path = *(++list))
		free((void *)path);

	free(output_path_list);
}

int
signlet_request(signlet_request_t *request)
{
	signlet_context context;
	int rc;

	rc = parse_request(request, &context);
	if (rc)
		return rc;

	rc = signaturelet_load(request->siglet);
	if (rc) {
		release_request(&context);
		return rc;
	}

	struct __out_sig {
		uint8_t *sig;
		unsigned int sig_len;
	} sigs[context.nr_signed_file], *sig = sigs;

	const char **list = context.signed_file_list;
	const char *file;
	unsigned int i = 0;

	rc = EXIT_FAILURE;

	for (file = *list; i < context.nr_signed_file; file = *(++list)) {
		rc = sign_file(&context, file, &sig->sig, &sig->sig_len);
		if (rc) {
			err("Failed to sign %s with the key %s\n",
			    file, request->key);
			goto err_on_sign_file; 
		}

		++sig;
		++i;
	}

	const char **output_file_list;
	output_file_list = build_output_file_list(&context);
	if (!output_file_list)
		goto err_on_build_output_file_list;

	list = output_file_list;
	sig = sigs;
	i = 0;
	for (file = *list; i < context.nr_signed_file; file = *(++list)) {
		rc = libsign_utils_save_file(file, sig->sig, sig->sig_len);
		if (rc) {
			err("Failed to save the signature file %s\n",
			    file);
			goto err_on_save_file;
		}

		++sig;
		++i;
	}

	rc = EXIT_SUCCESS;

err_on_save_file:
	free_output_file_list(output_file_list);

err_on_build_output_file_list:
err_on_sign_file:
	while ((int)--context.nr_signed_file >= 0)
		free(sigs[context.nr_signed_file].sig);

	release_request(&context);

	return rc;
}

int
signlet_wait(const char *id)
{
	return 0;
}

int
signlet_cancel(const char *id)
{
	return 0;
}

int
signlet_finish(const char *id)
{
	return 0;
}
