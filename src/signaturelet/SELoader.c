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
#include <signlet.h>

#include "SELoader.h"

#define SELoader_signaturelet_id		"SELoader"

static int
construct_sel_signature(uint8_t *sig_content, unsigned sig_content_size,
			unsigned long flags, BIO **out_signed_data)
{
	BIO *signed_data;

	signed_data = BIO_new(BIO_s_mem());
	if (!signed_data)
		return EXIT_FAILURE;

	BIO *tag_directory;

	tag_directory = BIO_new(BIO_s_mem());
	if (!signed_data)
		return EXIT_FAILURE;

	BIO *payload;

	payload = BIO_new(BIO_s_mem());
	if (!signed_data)
		return EXIT_FAILURE;

	SEL_SIGNATURE_HEADER header;

	strncpy((char *)&header.Magic, SelSigantureMagic,
		sizeof(header.Magic));
	header.Revision = SelSignatureRevision;
	header.HeaderSize = sizeof(header);
	header.Flags = 0;

	unsigned int nr_tag = 0;
	unsigned int payload_size = 0;

	if (!(flags & SIGNLET_FLAGS_CONTENT_ATTACHED)) {
		SEL_SIGNATURE_TAG hash_alg_tag;

		hash_alg_tag.Tag = SelSignatureTagHashAlgorithm;
		hash_alg_tag.Revision = 0;
		hash_alg_tag.Reserved = 0;
		hash_alg_tag.Flags = 0;
		hash_alg_tag.DataOffset = payload_size;
		hash_alg_tag.DataSize = sizeof(SEL_SIGNATURE_TAG_HASH_ALGORITHM);
		BIO_write(tag_directory, &hash_alg_tag, sizeof(hash_alg_tag));
		++nr_tag;

		SEL_SIGNATURE_TAG_HASH_ALGORITHM hash_alg;

		hash_alg.Algorithm = SelHashAlgorithmSha256;
		BIO_write(payload, &hash_alg, sizeof(hash_alg));

		payload_size += hash_alg_tag.DataSize;
	}

	SEL_SIGNATURE_TAG content_tag;

	content_tag.Tag = SelSignatureTagContent;
	content_tag.Revision = 0;
	content_tag.Reserved = 0;
	content_tag.Flags = 0;
	content_tag.DataOffset = payload_size;
	content_tag.DataSize = sig_content_size;
	BIO_write(tag_directory, &content_tag, sizeof(content_tag));
	++nr_tag;

	BIO_write(payload, sig_content, sig_content_size);
	payload_size += content_tag.DataSize;

	header.TagDirectorySize = nr_tag * sizeof(SEL_SIGNATURE_TAG);
	header.NumberOfTag = nr_tag;
	header.PayloadSize = payload_size;

	BIO_write(signed_data, &header, header.HeaderSize);

	char *write_data;
	long write_len;

	write_len = BIO_get_mem_data(tag_directory, &write_data);
	BIO_write(signed_data, write_data, write_len);
	BIO_free(tag_directory);

	write_len = BIO_get_mem_data(payload, &write_data);
	BIO_write(signed_data, write_data, write_len);
	BIO_free(payload);

	write_len = BIO_get_mem_data(signed_data, &write_data);
	libsign_utils_hex_dump("SELoader signature", (uint8_t *)write_data,
			       write_len);

	*out_signed_data = signed_data;

	return EXIT_SUCCESS;
}

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
			goto err;
		}
	}

	int sign_flags;
	BIO *signed_data;
	unsigned int sig_content_size;

	if (!(flags & SIGNLET_FLAGS_DETACHED_SIGNATURE)) {
		uint8_t *sig_content;
		uint8_t *digest = NULL;
		int rc;

		if (!(flags & SIGNLET_FLAGS_CONTENT_ATTACHED)) {
			rc = libsign_digest_calculate(siglet->digest_alg, data,
						      data_size, &digest);
			if (rc)
				goto err;

			unsigned int digest_size;
			libsign_digest_size(siglet->digest_alg, &digest_size);

			libsign_utils_hex_dump("Signed content", digest,
					       digest_size);

			sig_content = digest;
			sig_content_size = digest_size;
		} else {
			sig_content = data;
			sig_content_size = data_size;
		}

		rc = construct_sel_signature(sig_content, sig_content_size,
					     flags, &signed_data);
		free(digest);
		if (rc)
			goto err;

		sig_content_size = BIO_ctrl_pending(signed_data);
		sign_flags = PKCS7_BINARY;
	} else {
		signed_data = BIO_new_mem_buf(data, data_size);
		if (!signed_data)
			goto err;

		sign_flags = PKCS7_DETACHED;
		sig_content_size = 0;
	}

	/* XXX: support to use CA list */
	PKCS7 *pkcs7 = PKCS7_sign(x509_certs[0], privkey, NULL,
				  signed_data, sign_flags);
	BIO_free(signed_data);
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

	libsign_utils_hex_dump("Signature dump", sig, sig_size);

	info("SELoader PKCS#7 %s signature (signed content %d-byte) "
	     "generated\n", flags & SIGNLET_FLAGS_DETACHED_SIGNATURE ?
			    "detached" : "attached", sig_content_size);

	return EXIT_SUCCESS;
err:
	while (--i >= 0)
		libsign_x509_unload(x509_certs[i]);
	libsign_key_unload(privkey);

	return EXIT_FAILURE;
}

static const signaturelet_suffix_pattern_t SELoader_suffix_pattern = {
	SIGNLET_FLAGS_DETACHED_SIGNATURE, "+.p7s", "+.p7a",
};

static const signaturelet_suffix_pattern_t *suffix_patterns[] = {
	&SELoader_suffix_pattern,
	NULL
};

static libsign_signaturelet_t SEloader_signaturelet = {
	.id = SELoader_signaturelet_id,
	.description = "SELoader PKCS#7 signature",
	.digest_alg = LIBSIGN_DIGEST_ALG_SHA256,
	.cipher_alg = LIBSIGN_CIPHER_ALG_RSA,
	.detached = 1,
	.sign = SELoader_sign,
	.suffix_pattern = suffix_patterns,
};

void __attribute__ ((constructor))
SELoader_signaturelet_init(void)
{
	signaturelet_register(&SEloader_signaturelet);
}

void __attribute__((destructor))
SELoader_signaturelet_fini(void)
{
	signaturelet_unregister(SELoader_signaturelet_id);
}
