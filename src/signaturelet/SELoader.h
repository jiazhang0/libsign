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

#ifndef SELOADER_H
#define SELOADER_H

#include <libsign.h>

#pragma pack(1)

#define SelSignatureRevision			1
#define SelSigantureMagic			"SELS"

typedef struct {
	uint32_t Magic;
	uint8_t Revision;			/* Signature format version */
	uint32_t HeaderSize;
	uint32_t TagDirectorySize;
	uint32_t NumberOfTag;
	uint32_t PayloadSize;
	uint32_t Flags;
} SEL_SIGNATURE_HEADER;

typedef struct {
	uint32_t Tag;
	uint8_t Revision;
	uint8_t Reserved;
	uint16_t Flags;
	uint32_t DataOffset;
	uint32_t DataSize;
} SEL_SIGNATURE_TAG;

/* Revision 0 is reserved for "current" revision */
#define SelSignatureTagHashAlgorithm		1

typedef enum {
	SelHashAlgorithmNone,
	SelHashAlgorithmSha1,
	SelHashAlgorithmSha224,
	SelHashAlgorithmSha256,
	SelHashAlgorithmSha384,
	SelHashAlgorithmSha512,
} SEL_SIGNATURE_HASH_ALGORITHM;

typedef struct {
	SEL_SIGNATURE_HASH_ALGORITHM Algorithm;
} SEL_SIGNATURE_TAG_HASH_ALGORITHM;

#define SelSignatureTagSignatureAlgorithm	2

typedef enum {
	SelSignatureAlgorithmPkcs7,
} SEL_SIGNATURE_SIGNATURE_ALGORITHM;

typedef struct {
	SEL_SIGNATURE_SIGNATURE_ALGORITHM Algorithm;
} SEL_SIGNATURE_TAG_SIGNATURE_ALGORITHM;

#define SelSignatureTagSignature		3

typedef struct {
	uint8_t Signature[0];
} SEL_SIGNATURE_TAG_SIGNATURE;

#define SelSignatureTagSignaturePkcs7FlagsDetached	(1 << 0)

typedef struct {
	uint32_t Flags;
	uint8_t Signature[0];
} SEL_SIGNATURE_TAG_SIGNATURE_PKCS7;

/* Content of message */
#define SelSignatureTagContent			9

#define SelSignatureTagCreationTime		10
#define SelSignatureTagFileName			11
#define SelSignatureTagFileSize			12

#pragma pack()

#endif	/* SELOADER_H */
