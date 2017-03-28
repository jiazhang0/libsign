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
#include <signlet.h>

#ifndef SELSIGN_KEY
#  define SELSIGN_KEY		"/etc/keys/SEL_privkey.pem"
#endif

#ifndef SELSIGN_CERT
#  define SELSIGN_CERT		"/etc/keys/SEL_x509.pem"
#endif

#ifndef SELSIGN_CA_CERT
#  define SELSIGN_CA_CERT	"/etc/keys/SEL_ca_x509.pem"
#endif

static void
show_banner(void)
{
	info_cont("\nSELoader signing tool\n");
	info_cont("Copyright (c) 2017, Lans Zhang "
		  "<jia.zhang@windriver.com>");
	info_cont("Version: %s+git%s\n", LIBSIGN_VERSION, libsign_git_commit);
	info_cont("Build Machine: %s\n", libsign_build_machine);
	info_cont("Build Time: " __DATE__ " " __TIME__ "\n\n");
}

static void
show_usage(const char *prog)
{
	info_cont("Usage: %s [options] --key <key_file> --cert <cert_file> "
		  "<signed_file>\n"
		  "Sign a file for use with SELoader.\n\n"
		  "Required arguments:\n"
		  "    --key <key_file>      Signing key (PEM-encoded RSA "
					    "private key)\n"
		  "    --cert <cert_file>    Certificate corresponding to the "
					    "signing key (PEM-encoded X.509 "
					    "certificate)\n"
		  "    <signed_file>         The file to be signed\n"
		  "Options:\n"
		  "    --ca <cert_file>      CA certificate in certificate "
					    "chain (PEM-encoded X.509 "
					    "certificate)\n"
		  "                          This option may be specified "
					    "multiple times\n"
		  "    --detached-signature  Generate the detached signature "
					    "(.p7s)\n"
		  "    --attached-content    Content the signed content in "
					    "the signature\n"
		  "    --output <sig_file>   Write the signature to <sig_file> "
					    "(DER-encoded PKCS#7 signature)\n"
		  "                          Default <signed_file>.p7a\n",
		  prog);
}

static void
show_version(void)
{
	info_cont("%s\n", SELSIGN_VERSION);
}

static int opt_quite;
static char *opt_key = SELSIGN_KEY;
static char *opt_cert = SELSIGN_CERT;
static char *opt_ca_cert = SELSIGN_CA_CERT;
static char *opt_digest_alg = "sha256";
static char *opt_cipher_alg = "rsa";
static char *opt_output;
static char *opt_signed_file;
static bool opt_detached_signature = false;
static bool opt_attached_content = false;

static int
parse_options(int argc, char *argv[])
{
	char opts[] = "hVvqk:c:C:S:S:o:da";
	struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "quite", no_argument, NULL, 'q' },
		{ "key", required_argument, NULL, 'k' },
		{ "cert", required_argument, NULL, 'c' },
		{ "ca", required_argument, NULL, 'C' },
		{ "digest-alg", required_argument, NULL, 'D' },
		{ "cipher-alg", required_argument, NULL, 'S' },
		{ "detached-signature", no_argument, NULL, 'd' },
		{ "attached-content", no_argument, NULL, 'a' },
		{ "output", required_argument, NULL, 'o' },
		{ NULL },	/* NULL terminated */
	};

	while (1) {
		int opt;

		opt = getopt_long(argc, argv, opts, long_opts, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			show_usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
		case 'v':
			libsign_utils_set_verbosity(1);
			break;
		case 'q':
			opt_quite = 1;
			break;
		case 'k':
			opt_key = optarg;
			break;
		case 'c':
			opt_cert = optarg;
			break;
		case 'C':
			opt_ca_cert = optarg;
			break;
		case 'D':
			opt_digest_alg = optarg;
			break;
		case 'S':
			opt_cipher_alg = optarg;
			break;
		case 'd':
			opt_detached_signature = true;
			break;
		case 'a':
			opt_attached_content = true;
			break;
		case 'o':
			opt_output = optarg;
			break;
		case '?':
		default:
			err("Unrecognized option\n");
			show_usage(argv[0]);
			return EXIT_FAILURE;	
		}
	}

	if (!opt_key) {
		err("No key specified (with --key)\n");
		show_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (!opt_cert) {
		err("No certificate specified (with --cert)\n");
		show_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* <signed_file> is not specified */
	if (argc != optind + 1) {
		show_usage(argv[0]);
		return EXIT_FAILURE;
	}

	opt_signed_file = argv[optind];
	if (!opt_signed_file || !opt_signed_file[0]) {
		err("Invalid path of signed file specified\n");
		show_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (opt_detached_signature == true) {
		err("The detached signature is still not "
		    "supported\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static void
exit_notify(void)
{
	if (libsign_utils_verbose())
		info("essential-sign exiting with %d (%s)\n", errno,
		     strerror(errno));
}

int
main(int argc, char **argv)
{
	atexit(exit_notify);

	int rc = parse_options(argc, argv);
	if (rc)
		return rc;

	if (!opt_quite)
		show_banner();

	unsigned long flags = 0;

	if (!opt_detached_signature) {
		if (opt_attached_content == true)
			flags |= SIGNLET_FLAGS_CONTENT_ATTACHED;
	} else
		flags |= SIGNLET_FLAGS_DETACHED_SIGNATURE;

	const char *signed_file_list[] = {
		opt_signed_file,
		NULL
	};
	const char *cert_list[] = {
		opt_cert,
		NULL
	};
	const char *id = "SELoader";
	signlet_request_t request = {
		.siglet = id,
		.signed_file_list = signed_file_list,
		.output_file_list = NULL,
		.key = opt_key,
		.cert_list = cert_list,
		.digest_alg = LIBSIGN_DIGEST_ALG_SHA256,
		.cipher_alg = LIBSIGN_CIPHER_ALG_RSA,
		.flags = flags,
	};

	rc = signlet_request(&request);
	if (rc)
		return rc;

	rc = signlet_wait(id);
	if (rc) {
		signlet_cancel(id);
		return rc;
	}

	signlet_finish(id);

	return EXIT_SUCCESS;
}
