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
#include <signaturelet.h>

#define SELoader_signaturelet_id		"SELoader"

static int
SELoader_sign(libsign_signaturelet_t *siglet, uint8_t *data,
	      unsigned int data_size, const char *key, const char **cert_list,
	      unsigned int nr_cert, uint8_t **out_sig,
	      unsigned int *out_sig_size, unsigned long flags)
{
	EVP_PKEY *privkey;

	privkey = libsign_key_load(key);
	if (!privkey) {
		err("Failed to load the private key %s\n", key);
		return EXIT_FAILURE;
	}

	X509 *x509_certs[nr_cert];
	int i = 0;

	for (i = 0; i < (int)nr_cert; ++i) {
		x509_certs[i] = libsign_x509_load(cert_list[i]);
		if (!x509_certs[i]) {
			err("Failed to load the X.509 certificate %s\n",
			    cert_list[i]);
			while (--i >= 0)
				libsign_x509_unload(x509_certs[i]);
			libsign_key_unload(privkey);
			return EXIT_FAILURE;
		}
	}

#if 0
	uint8_t *digest;
	int rc = libsign_digest_calculate(siglet->digest_alg, data,
					  data_size, &digest);
	if (rc) {
		while (--i >= 0)
			libsign_x509_unload(x509_certs[i]);
		libsign_key_unload(privkey);
		return rc;
	}

	unsigned int digest_size;
	libsign_digest_size(siglet->digest_alg, &digest_size);

	BIO *signed_data = BIO_new_mem_buf(digest, digest_size);
	if (!signed_data) {
		ERR_print_errors_fp(stderr);
		free(digest);
		while (--i >= 0)
			libsign_x509_unload(x509_certs[i]);
		libsign_key_unload(privkey);
		return EXIT_FAILURE;
	}

	libsign_utils_hex_dump("Signed content", digest, digest_size);
#else
	BIO *signed_data = BIO_new_mem_buf(data, data_size);
	if (!signed_data) {
		ERR_print_errors_fp(stderr);
		while (--i >= 0)
			libsign_x509_unload(x509_certs[i]);
		libsign_key_unload(privkey);
		return EXIT_FAILURE;
	}
#endif

	bool detached_signature = 0;
	int sign_flags;

	if (!detached_signature)
		sign_flags = PKCS7_BINARY;
	else
		sign_flags = PKCS7_DETACHED;

	/* XXX: support to use CA list */
	PKCS7 *pkcs7 = PKCS7_sign(x509_certs[0], privkey, NULL,
				  signed_data, sign_flags);
	BIO_free(signed_data);
	//free(digest);
	while (--i >= 0)
		libsign_x509_unload(x509_certs[i]);
	libsign_key_unload(privkey);

	if (!pkcs7) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	unsigned int sig_size = i2d_PKCS7(pkcs7, NULL);

	uint8_t *tmp, *sig;
	tmp = sig = malloc(sig_size);
	if (!sig) {
		PKCS7_free(pkcs7);
		return EXIT_FAILURE;
	}

	i2d_PKCS7(pkcs7, &tmp);
	PKCS7_free(pkcs7);

	*out_sig = sig;
	*out_sig_size = sig_size;

	info("SELoader PKCS#7 signature (signed content %d-byte) generated\n",
	     data_size);
	     //digest_size);

	return EXIT_SUCCESS;
}

static libsign_signaturelet_t SEloader_signaturelet = {
	.id = SELoader_signaturelet_id,
	.description = "SELoader PKCS#7 signature",
	.naming_pattern = "+.p7a",
	.digest_alg = LIBSIGN_DIGEST_ALG_SHA256,
	.cipher_alg = LIBSIGN_CIPHER_ALG_RSA,
	.detached = 1,
	.sign = SELoader_sign,
};

void __attribute__ ((constructor))
SEloader_signaturelet_init(void)
{
	signaturelet_register(&SEloader_signaturelet);
}

void __attribute__((destructor))
SEloader_signaturelet_fini(void)
{
	signaturelet_unregister(SELoader_signaturelet_id);
}
