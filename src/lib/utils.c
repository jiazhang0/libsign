/*
 * Utility routines
 *
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

static int show_verbose;

int
libsign_utils_verbose(void)
{
	return show_verbose;
}

void
libsign_utils_set_verbosity(int verbose)
{
	show_verbose = verbose;
}

char **
libsign_utils_split_string(char *in, char *delim, unsigned int *nr)
{
	char **out = NULL;
	unsigned int delim_sz = strlen(delim);

	*nr = 0;
	while (*in) {
		char *p = strstr(in, delim);
		int len;

		if (p)
			len = p - in;
		else
			len = strlen(in);

		char *str = strndup(in, len + 1);
		if (!str) {
			free(out);
			return NULL;
		}

		out = realloc(out, sizeof(char *) * (*nr + 1));
		if (!out) {
			free(str);
			return NULL;
		}

		str[len] = 0;
		out[(*nr)++] = str;

		in += len;
		if (p)
			in += delim_sz;
	}

	return out;
}

int
libsign_utils_mkdir(const char *dir, mode_t mode)
{
	const char *dir_delim = dir;
	const char *dir_start = dir;
	char *dir_name;

	do {
		dir = dir_delim + strspn(dir_delim, "/");
                dir_delim = dir + strcspn(dir, "/");
                dir_name = strndup(dir_start, dir - dir_start);
                if (*dir_name) {
                        if (mkdir(dir_name, mode) && errno != EEXIST) {
                                err("Unable to create directory %s", dir_name);
                                free(dir_name);
                                return -1;
                        }
                }
                free(dir_name);
        } while (dir != dir_delim);

        return 0;
}

bool
libsign_utils_file_exists(const char *file_path)
{
	if (!file_path)
		return EXIT_FAILURE;

	return !access(file_path, R_OK);
}

int
libsign_utils_load_file(const char *path, uint8_t **out_buf,
			unsigned int *out_size)
{
	dbg("Reading file %s ...\n", path);

	if (!path || !path[0]) {
		err("Invalid file path to read\n");
		return EXIT_FAILURE;
	}

	if (!out_buf) {
		err("Invalid read buffer\n");
		return EXIT_FAILURE;
	}

	if (!out_size) {
		err("Invalid read buffer size\n");
		return EXIT_FAILURE;
	}

	FILE *fp = fopen(path, "rb");
	if (!fp) {
		dbg("Failed to open input file\n");
		return EXIT_FAILURE;
	}

	int rc = EXIT_FAILURE;

	if (fseek(fp, 0, SEEK_END)) {
		err("Failed to seek the end of file\n");
		goto err;
	}

	unsigned int size = ftell(fp);
	if (!size) {
		err("Empty input file\n");
		goto err;
	}

	rewind(fp);

	uint8_t *buf = (uint8_t *)malloc(size);
	if (!buf) {
		err("Failed to allocate memory for input file\n");
		goto err;
	}

	if (fread(buf, size, 1, fp) != 1) {
		err("Failed to read input file\n");
		free(buf);
	} else {
		*out_buf = buf;
		*out_size = size;
		rc = EXIT_SUCCESS;
	}

err:
	fclose(fp);

	return rc;
}

int
libsign_utils_save_file(const char *path, uint8_t *buf,
			unsigned int size)
{
	dbg("Saving file %s ...\n", path);

	FILE *fp = fopen(path, "w");
	if (!fp) {
		err("Failed to create output file\n");
		return EXIT_FAILURE;
	}

	if (fwrite(buf, size, 1, fp) != 1) {
		fclose(fp);
		err("Failed to write output file\n");
		return EXIT_FAILURE;
	}

	fclose(fp);

	return EXIT_SUCCESS;
}

void
libsign_utils_hex_dump(const char *prompt, uint8_t *data,
		       unsigned int data_size)
{
	if (prompt)
		dbg("%s (%d-byte): ", prompt, data_size);

	for (unsigned int i = 0; i < data_size; ++i)
		dbg_cont("%02x", data[i]);

	dbg_cont("\n");
}
