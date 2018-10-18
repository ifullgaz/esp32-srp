/*
 * Secure Remote Password 6a implementation based on mbedtls.
 *
 * Copyright (c) 2017 Emmanuel Merali
 * https://github.com/ifullgaz/esp32-srp
 *
 * Derived from:
 * Copyright (c) 2015 Dieter Wimberger
 * https://github.com/dwimberger/mbedtls-csrp
 *
 * Derived from:
 * Copyright (c) 2010 Tom Cocagne. All rights reserved.
 * https://github.com/cocagne/csrp
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _SRP_H
#define _SRP_H

#include "mbedtls/bignum.h"

#define SRP_VERSION_MAJ                 0
#define SRP_VERSION_MIN                 4
#define SRP_VERSION_REV                 1
#define SRP_VERSION_STR                 "0.4.1"
#define SRP_VERSION_CHK(maj, min)       ((maj==SRP_VERSION_MAJ) && (min<=SRP_VERSION_MIN))

#define SRP_ERR_OK                      0
#define SRP_ERR_BAD_INPUT_DATA          MBEDTLS_ERR_MPI_BAD_INPUT_DATA
#define SRP_ERR_INVALID_CHARACTER       MBEDTLS_ERR_MPI_INVALID_CHARACTER
#define SRP_ERR_BUFFER_TOO_SMALL        MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL
#define SRP_ERR_NEGATIVE_VALUE          MBEDTLS_ERR_MPI_NEGATIVE_VALUE
#define SRP_ERR_DIVISION_BY_ZERO        MBEDTLS_ERR_MPI_DIVISION_BY_ZERO
#define SRP_ERR_NOT_ACCEPTABLE          MBEDTLS_ERR_MPI_NOT_ACCEPTABLE
#define SRP_ERR_ALLOC_FAILED            MBEDTLS_ERR_MPI_ALLOC_FAILED
#define SRP_ERR_OUT_OF_MEMORY           SRP_ERR_ALLOC_FAILED
#define SRP_ERR_NOT_INITIALIZED         -0x1002
#define SRP_ERR_ARGUMENTS_MISMATCH      -0x1004
#define SRP_ERR_UNSUPPORTED_ROLE        -0x1006
#define SRP_ERR_UNSUPPORTED_HASH        -0x1008
#define SRP_ERR_SAFETY_CHECK            -0x100A

#define ESP32_SRP_CHK(f) \
if (( ret = f ) != SRP_ERR_OK) { \
    goto cleanup; \
}

#define ESP32_SRP_SET(v, f) \
if (!( v = f )) { \
    ret = errno; \
    goto cleanup; \
}

/**
 * SRP role, client or server.
 */
typedef enum {
    SRP_ROLE_CLIENT,
    SRP_ROLE_SERVER,
} SRP_ROLE;

/**
 * SRP type, predefined or custom.
 */
typedef enum {
    SRP_TYPE_1024,
    SRP_TYPE_1536,
    SRP_TYPE_2048,
    SRP_TYPE_3072,
    SRP_TYPE_4096,
    SRP_TYPE_6144,
    SRP_TYPE_8192,
    SRP_TYPE_CUSTOM
} SRP_TYPE;

/**
 * SRP hash algorithm, SHA256 or SHA512.
 */
typedef enum  {
    SRP_CRYPTO_HASH_ALGORITHM_SHA256,
    SRP_CRYPTO_HASH_ALGORITHM_SHA512
} SRP_CRYPTO_HASH_ALGORITHM;

/**
 * SRP context. Note that it should be considered read only
 */
typedef struct _srp_context *srp_context_t;

// Must be called before calling any of the srp functions
// crypto_seed is optional and can be NULL
int srp_init(const unsigned char *crypto_seed, int crypto_seed_len);

// Create a new SRP client context
srp_context_t srp_new_client(SRP_TYPE type, SRP_CRYPTO_HASH_ALGORITHM halg);
// Create a new SRP server context
srp_context_t srp_new_server(SRP_TYPE type, SRP_CRYPTO_HASH_ALGORITHM halg);
// Get the salt from the context (s)
mbedtls_mpi *srp_get_salt(srp_context_t srp_ctx);
// Get the public key from the context
mbedtls_mpi *srp_get_public_key(srp_context_t srp_ctx);
// Get the session secret (K)
mbedtls_mpi *srp_get_session_secret(srp_context_t srp_ctx);
// Get the verification key from the context (M1 for client, M2 for server)
mbedtls_mpi *srp_get_verify_key(srp_context_t srp_ctx);
// Set the username
int srp_set_username(srp_context_t srp_ctx, const char *username);
// Set the password
int srp_set_auth_password(srp_context_t srp_ctx, const unsigned char * p, int plen);
// Set params N, g and s. Wither of these parameters can be NULL, in which case existing values are not affected
int srp_set_params(srp_context_t srp_ctx, mbedtls_mpi *modulus, mbedtls_mpi *generator, mbedtls_mpi *salt);
// Generate the private and public key
int srp_gen_pub(srp_context_t srp_ctx);
// Compute the secret key and associated verification keys
int srp_compute_key(srp_context_t srp_ctx, mbedtls_mpi *public_key);
// Check the verification key from the counterpart
int srp_verify_key(srp_context_t srp_ctx, mbedtls_mpi *M);
// Ends the SRP session
void srp_free(void *srp_ctx);

// Utility to display a context
void srp_dump_context(srp_context_t srp_ctx, const char *description);

#endif // _SRP_H
#ifdef __cplusplus
}
#endif
