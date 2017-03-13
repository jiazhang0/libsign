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

#include <libsign.h>

#if 0
static int
cipher_init(void)
{
	OpenSSL_add_all_ciphers();

	return EXIT_SUCCESS;
}
#endif

bool
libsign_digest_supported(LIBSIGN_DIGEST_ALG digest_alg)
{
	return digest_alg >= LIBSIGN_DIGEST_ALG_NONE &&
	       digest_alg < LIBSIGN_DIGEST_ALG_MAX;
}

int
libsign_digest_init(LIBSIGN_DIGEST_ALG digest_alg)
{
	if (!libsign_digest_supported(digest_alg)) {
		err("Unsupported digest algorithm %#x\n", digest_alg);
		return EXIT_FAILURE;
	}

	switch (digest_alg) {
	case LIBSIGN_DIGEST_ALG_SHA224:
		EVP_add_digest(EVP_sha224());
		break;
	case LIBSIGN_DIGEST_ALG_SHA256:
		EVP_add_digest(EVP_sha256());
		break;
	case LIBSIGN_DIGEST_ALG_SHA384:
		EVP_add_digest(EVP_sha384());
		break;
	case LIBSIGN_DIGEST_ALG_SHA512:
		EVP_add_digest(EVP_sha512());
		break;
	case LIBSIGN_DIGEST_ALG_SHA1:
		EVP_add_digest(EVP_sha1());
		break;
	default:
		break;
	}

	return EXIT_SUCCESS;
}

static const EVP_MD *
to_EVP_MD(LIBSIGN_DIGEST_ALG digest_alg)
{
	if (!libsign_digest_supported(digest_alg)) {
		err("Unsupported digest algorithm %#x\n", digest_alg);
		return NULL;
	}

	switch (digest_alg) {
	case LIBSIGN_DIGEST_ALG_SHA224:
		return EVP_sha224();
	case LIBSIGN_DIGEST_ALG_SHA256:
		return EVP_sha256();
	case LIBSIGN_DIGEST_ALG_SHA384:
		return EVP_sha384();
	case LIBSIGN_DIGEST_ALG_SHA512:
		return EVP_sha512();
	case LIBSIGN_DIGEST_ALG_SHA1:
		return EVP_sha1();
	default:
		break;
	}

	return NULL;
}

int
libsign_digest_calculate(LIBSIGN_DIGEST_ALG digest_alg, uint8_t *data,
			 unsigned int data_size, uint8_t **digest)
{
	if (!digest)
		return EXIT_FAILURE;

	if (data_size && !data)
		return EXIT_FAILURE;

	unsigned int digest_size;
	int rc = libsign_digest_size(digest_alg, &digest_size);
	if (rc)
		return rc;

	uint8_t *digest_calc = malloc(digest_size);
	if (!digest_calc)
		return EXIT_FAILURE;

	if (!EVP_Digest(data, data_size, digest_calc, &digest_size,
			to_EVP_MD(digest_alg), NULL)) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	*digest = digest_calc;

	return EXIT_SUCCESS;
}

int
libsign_digest_size(LIBSIGN_DIGEST_ALG digest_alg, unsigned int *digest_size)
{
	if (!libsign_digest_supported(digest_alg)) {
		err("Unsupported digest algorithm %#x\n", digest_alg);
		return EXIT_FAILURE;
	}

	switch (digest_alg) {
	case LIBSIGN_DIGEST_ALG_SHA224:
		*digest_size = EVP_MD_size(EVP_sha224());
		break;
	case LIBSIGN_DIGEST_ALG_SHA256:
		*digest_size = EVP_MD_size(EVP_sha256());
		break;
	case LIBSIGN_DIGEST_ALG_SHA384:
		*digest_size = EVP_MD_size(EVP_sha384());
		break;
	case LIBSIGN_DIGEST_ALG_SHA512:
		*digest_size = EVP_MD_size(EVP_sha512());
		break;
	case LIBSIGN_DIGEST_ALG_SHA1:
		*digest_size = EVP_MD_size(EVP_sha1());
		break;
	default:
		*digest_size = 0;
	}

	return EXIT_SUCCESS;
}
