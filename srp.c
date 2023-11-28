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

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "esp_system.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#include "esp_log.h"

#include "esp32-srp/srp.h"

#define SHA256_DIGEST_LENGTH 32
#define SHA512_DIGEST_LENGTH 64

typedef struct _NGStringPair {
    const char *n_hex;
    const char *g_hex;
} NGStringPair;

// Constants from Appendix A of RFC 5054
static const NGStringPair rfc5054_constants[] = {
    { /*1024 */
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496"
    "EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E"
    "F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA"
    "9AFD5138FE8376435B9FC61D2FC0EB06E3",
    "2"
    },
    { /*1536 */
    "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961"
    "4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843"
    "80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B"
    "E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5"
    "6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A"
    "F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E"
    "8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
    "2"
    },
    { /*2048 */
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
    "2"
    },
    { /*3072 */
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    "5"
    },
    { /*4096 */
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
    "FFFFFFFFFFFFFFFF",
    "5"
    },
    { /*6144 */
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
    "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
    "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
    "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
    "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
    "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
    "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
    "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
    "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
    "6DCC4024FFFFFFFFFFFFFFFF",
    "5"
    },
    { /*8192 */
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
    "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
    "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
    "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
    "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
    "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
    "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
    "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
    "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
    "6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA"
    "3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C"
    "5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
    "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886"
    "2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6"
    "6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5"
    "0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268"
    "359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6"
    "FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
    "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
    "13"
    }
};

struct _srp_context {
    SRP_ROLE                    role;
    SRP_CRYPTO_HASH_ALGORITHM   halg;
    const char                  *username;
    // Modulus - A large safe prime (N = 2q+1, where q is prime)
    mbedtls_mpi                 *N;
    // Generator - A generator modulo N
    mbedtls_mpi                 *g;
    // Salt - random value generated by server
    mbedtls_mpi                 *s;
    // Private key calculated by client     H(s | H(I | ":" | P))
    mbedtls_mpi                 *x;
    // Server's verifier                    g^x % N
    mbedtls_mpi                 *v;
    // Multiplier parameter                 H(N | PAD(g))
    mbedtls_mpi                 *k;
    // Session Key - Client: (B - (k * g^x)) ^ (a + (u * x)) % N, Server: (A * v^u) ^ b % N
    mbedtls_mpi                 *S;
    // A random value
    mbedtls_mpi                 *private_key;
    // Client: g^a % N, Server: k*v + g^b % N
    mbedtls_mpi                 *public_key;
    // Shared session secret
    mbedtls_mpi                 *K;
    // Client proof
    mbedtls_mpi                 *M1;
    // Server proof
    mbedtls_mpi                 *M2;
};

static const char *srp_role_name[] = {"Client", "Server"};
static const char *srp_crypto_hash_alogrithm_name[] = {"SHA256", "SHA512"};

// TAG for ESP_LOG
static const char *TAG = "SRP";

// For multi precision integer mod calculations
static mbedtls_mpi *RR = NULL;

/***************************************************************************************
*                                    SRP Crypto                                        *
****************************************************************************************/

typedef union {
    mbedtls_sha256_context sha256;
    mbedtls_sha512_context sha512;
} HashSHACTX;

typedef struct {
    SRP_CRYPTO_HASH_ALGORITHM halg;
    HashSHACTX sha;
} HashCTX;

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;

static void srp_system_random_buffer(void * const buf, const size_t size) {
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < size; i++) {
        p[i] = esp_random();
    }
}

/*
 *  Random functions
 */
static int srp_crypto_random_init(const unsigned char *crypto_seed, int crypto_seed_len) {
    int ret;
    mbedtls_entropy_init(&entropy_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    ESP32_SRP_CHK(mbedtls_ctr_drbg_seed(
        &ctr_drbg_ctx,
        mbedtls_entropy_func,
        &entropy_ctx,
        crypto_seed,
        crypto_seed ? crypto_seed_len : 0
    ));
cleanup:
    return ret;
}

/*
 *  Hash functions
 */
static int srp_crypto_hash_init(HashCTX *c) {
    switch (c->halg)
    {
      case SRP_CRYPTO_HASH_ALGORITHM_SHA256: mbedtls_sha256_init(&c->sha.sha256); return SRP_ERR_OK;
      case SRP_CRYPTO_HASH_ALGORITHM_SHA512: mbedtls_sha512_init(&c->sha.sha512); return SRP_ERR_OK;
      default:
        return SRP_ERR_UNSUPPORTED_HASH;
    };
}

static int srp_crypto_hash_start(HashCTX *c) {
    switch (c->halg)
    {
      case SRP_CRYPTO_HASH_ALGORITHM_SHA256: mbedtls_sha256_starts(&c->sha.sha256, 0); return SRP_ERR_OK;
      case SRP_CRYPTO_HASH_ALGORITHM_SHA512: mbedtls_sha512_starts(&c->sha.sha512, 0); return SRP_ERR_OK;
      default:
        return SRP_ERR_UNSUPPORTED_HASH;
    };
}

static int srp_crypto_hash_update(HashCTX *c, const void *data, size_t len) {
    switch (c->halg)
    {
      case SRP_CRYPTO_HASH_ALGORITHM_SHA256: mbedtls_sha256_update(&c->sha.sha256, data, len); return SRP_ERR_OK;
      case SRP_CRYPTO_HASH_ALGORITHM_SHA512: mbedtls_sha512_update(&c->sha.sha512, data, len); return SRP_ERR_OK;
      default:
        return SRP_ERR_UNSUPPORTED_HASH;
    };
}

static int srp_crypto_hash_update_n(HashCTX *c, const mbedtls_mpi *n) {
    int ret;
    unsigned long size = mbedtls_mpi_size(n);
    unsigned char bytes[size];
    ESP32_SRP_CHK(mbedtls_mpi_write_binary(n, bytes, size));
    return srp_crypto_hash_update(c, bytes, size);
cleanup:
    return ret;
}

static int srp_crypto_hash_final(HashCTX *c, unsigned char *md) {
    switch (c->halg)
    {
      case SRP_CRYPTO_HASH_ALGORITHM_SHA256: mbedtls_sha256_finish(&c->sha.sha256, md); return SRP_ERR_OK;
      case SRP_CRYPTO_HASH_ALGORITHM_SHA512: mbedtls_sha512_finish(&c->sha.sha512, md); return SRP_ERR_OK;
      default:
        return SRP_ERR_UNSUPPORTED_HASH;
    };
}

static int srp_crypto_hash(SRP_CRYPTO_HASH_ALGORITHM alg, const unsigned char *d, size_t n, unsigned char *md) {
    switch (alg)
    {
      case SRP_CRYPTO_HASH_ALGORITHM_SHA256: mbedtls_sha256(d, n, md, 0); return SRP_ERR_OK;
      case SRP_CRYPTO_HASH_ALGORITHM_SHA512: mbedtls_sha512(d, n, md, 0); return SRP_ERR_OK;
      default:
        return SRP_ERR_UNSUPPORTED_HASH;
    };
}

static int srp_crypto_hash_length(SRP_CRYPTO_HASH_ALGORITHM alg) {
    switch (alg)
    {
      case SRP_CRYPTO_HASH_ALGORITHM_SHA256: return SHA256_DIGEST_LENGTH; return SRP_ERR_OK;
      case SRP_CRYPTO_HASH_ALGORITHM_SHA512: return SHA512_DIGEST_LENGTH; return SRP_ERR_OK;
      default:
        return SRP_ERR_UNSUPPORTED_HASH;
    };
}

/***************************************************************************************
*                                      SRP MPI                                         *
****************************************************************************************/

#define SRP_DECLARE_MPI(variable) \
    mbedtls_mpi *variable=NULL;

static int srp_mpi_new(mbedtls_mpi **i) {
    if (!(*i = (mbedtls_mpi *)malloc(sizeof(mbedtls_mpi)))) {
        return SRP_ERR_ALLOC_FAILED;
    }
    mbedtls_mpi_init(*i);
    return SRP_ERR_OK;
}

static void srp_mpi_free(mbedtls_mpi *i) {
    if (i) {
   	  mbedtls_mpi_free(i);
   	  free(i);
    }
}

#ifndef _SRP_TEST_VECTOR
static int srp_mpi_fill_random(mbedtls_mpi *i, int nbytes) {
    int ret;
    ESP32_SRP_CHK(mbedtls_mpi_fill_random(i, nbytes, &mbedtls_ctr_drbg_random, (void *)&ctr_drbg_ctx));
cleanup:
    return ret;
}
#endif

/***************************************************************************************
*                                    SRP Context                                       *
****************************************************************************************/

#define srp_context_set_mpi(srp_ctx, field, value) { \
    SRP_DECLARE_MPI(tmp_n); \
    ESP32_SRP_CHK(srp_mpi_new(&tmp_n)); \
    ESP32_SRP_CHK(mbedtls_mpi_copy(tmp_n, value)); \
    srp_mpi_free((srp_ctx)->field); \
    (srp_ctx)->field = tmp_n; \
}

#define srp_context_set_str(srp_ctx, field, value) { \
    char *tmp_c = NULL; \
    if (value) { \
        if (!(tmp_c = strdup(value))) { \
            ESP_LOGI(TAG, "Could not duplicate string string \"%s\"", value); \
            ret = SRP_ERR_ALLOC_FAILED; \
            goto cleanup; \
        } \
    } \
    if ((srp_ctx)->field) { \
        free((void *)(srp_ctx)->field); \
    } \
    (srp_ctx)->field = tmp_c; \
    ret = SRP_ERR_OK; \
}

#define srp_context_set_N(srp_ctx, value) srp_context_set_mpi(srp_ctx, N, value)
#define srp_context_set_g(srp_ctx, value) srp_context_set_mpi(srp_ctx, g, value)
#define srp_context_set_s(srp_ctx, value) srp_context_set_mpi(srp_ctx, s, value)
#define srp_context_set_v(srp_ctx, value) srp_context_set_mpi(srp_ctx, v, value)
#define srp_context_set_x(srp_ctx, value) srp_context_set_mpi(srp_ctx, x, value)
#define srp_context_set_k(srp_ctx, value) srp_context_set_mpi(srp_ctx, k, value)
#define srp_context_set_S(srp_ctx, value) srp_context_set_mpi(srp_ctx, S, value)
#define srp_context_set_K(srp_ctx, value) srp_context_set_mpi(srp_ctx, K, value)
#define srp_context_set_M1(srp_ctx, value) srp_context_set_mpi(srp_ctx, M1, value)
#define srp_context_set_M2(srp_ctx, value) srp_context_set_mpi(srp_ctx, M2, value)
#define srp_context_set_private_key(srp_ctx, value) srp_context_set_mpi(srp_ctx, private_key, value)
#define srp_context_set_public_key(srp_ctx, value) srp_context_set_mpi(srp_ctx, public_key, value)
#define srp_context_set_username(srp_ctx, value) srp_context_set_str(srp_ctx, username, value)

void srp_context_free(srp_context_t srp_ctx);

// Create a new srp_context_t and fill in N and g if predefined type
static int srp_context_new(SRP_ROLE role, SRP_TYPE type, SRP_CRYPTO_HASH_ALGORITHM halg, srp_context_t *srp_ctx) {
    int ret;
    const char *s_hex;
    SRP_DECLARE_MPI(N);
    SRP_DECLARE_MPI(g);

    *srp_ctx = (srp_context_t)malloc(sizeof(struct _srp_context));
    if (!*srp_ctx) {
        ESP_LOGI(TAG, "Could not allocate memory for new context\n");
        return SRP_ERR_ALLOC_FAILED;
    }
    memset(*srp_ctx, 0, sizeof(struct _srp_context));
    (*srp_ctx)->role = role;
    (*srp_ctx)->halg = halg;
    // Set our modulus and generator here if we are a preset type
    if (type == SRP_TYPE_CUSTOM) {
        return SRP_ERR_OK;
    }
    s_hex = rfc5054_constants[type].n_hex;
    ESP32_SRP_CHK(srp_mpi_new(&N));
    ESP32_SRP_CHK(mbedtls_mpi_read_string(N, 16, s_hex));
    srp_context_set_N(*srp_ctx, N);
    s_hex = rfc5054_constants[type].g_hex;
    ESP32_SRP_CHK(srp_mpi_new(&g));
    ESP32_SRP_CHK(mbedtls_mpi_read_string(g, 16, s_hex));
    srp_context_set_g(*srp_ctx, g);
    ret = SRP_ERR_OK;
cleanup:
    if (ret != SRP_ERR_OK) {
        srp_context_free(*srp_ctx);
        *srp_ctx = NULL;
    }
    srp_mpi_free(N);
    srp_mpi_free(g);
    return ret;
}

// Free srp_context_t
void srp_context_free(srp_context_t srp_ctx) {
    if (srp_ctx) {
        srp_mpi_free(srp_ctx->N);
        srp_mpi_free(srp_ctx->g);
        srp_mpi_free(srp_ctx->s);
        srp_mpi_free(srp_ctx->x);
        srp_mpi_free(srp_ctx->v);
        srp_mpi_free(srp_ctx->k);
        srp_mpi_free(srp_ctx->S);
        srp_mpi_free(srp_ctx->K);
        srp_mpi_free(srp_ctx->M1);
        srp_mpi_free(srp_ctx->M2);
        srp_mpi_free(srp_ctx->private_key);
        srp_mpi_free(srp_ctx->public_key);
        if (srp_ctx->username) free((void *)srp_ctx->username);
        free(srp_ctx);
    }
}

static void srp_context_dump(srp_context_t srp_ctx, const char *description) {
    if (description) {
        ESP_LOGI(TAG, "%s", description);
    }

    // ESP_LOGI(TAG, "Context - Role = %s, Hash = %s", srp_role_name[srp_ctx->role], srp_crypto_hash_alogrithm_name[srp_ctx->role]);
    // dump_string(srp_ctx->username, "User name");
    // dump_big_number(srp_ctx->N, "srp_ctx->N");
    // dump_big_number(srp_ctx->g, "srp_ctx->g");
    // dump_big_number(srp_ctx->s, "srp_ctx->s");
    // dump_big_number(srp_ctx->x, "srp_ctx->x");
    // dump_big_number(srp_ctx->v, "srp_ctx->v");
    // dump_big_number(srp_ctx->S, "srp_ctx->S");
    // dump_big_number(srp_ctx->K, "srp_ctx->K");
    // dump_big_number(srp_ctx->M1, "srp_ctx->M1");
    // dump_big_number(srp_ctx->M2, "srp_ctx->M2");
    // dump_big_number(srp_ctx->private_key, "srp_ctx->private_key");
    // dump_big_number(srp_ctx->public_key, "srp_ctx->public_key");
    // ESP_LOGI(TAG, "}");
}


/***********************************************************************************************************
 * Private interface
 ***********************************************************************************************************/
static int srp_context_adjust_size_for_padding(srp_context_t srp_ctx, int len) {
    int modulus_size = mbedtls_mpi_size(srp_ctx->N);
    return len < modulus_size ? modulus_size : len;
}

// Hash of two mbedtls_mpi numbers n1 and n2
// Return result into hnn
// Optionally, left pad to size of modulus with 0s
static int srp_crypto_hash_nn(srp_context_t srp_ctx, const mbedtls_mpi *n1, int pad1, const mbedtls_mpi *n2, int pad2, mbedtls_mpi *hnn) {
    int ret;
    SRP_CRYPTO_HASH_ALGORITHM alg = srp_ctx->halg;
    int hash_len = srp_crypto_hash_length(alg);
    unsigned char buff[hash_len];
    int len_n1     = mbedtls_mpi_size(n1);
    int adj_len_n1 = pad1 ? srp_context_adjust_size_for_padding(srp_ctx, len_n1) : len_n1;
    int len_n2     = mbedtls_mpi_size(n2);
    int adj_len_n2 = pad2 ? srp_context_adjust_size_for_padding(srp_ctx, len_n2) : len_n2;
    int nbytes     = adj_len_n1 + adj_len_n2;
    unsigned char bin[nbytes];
    memset(bin, 0, nbytes);
    ESP32_SRP_CHK(mbedtls_mpi_write_binary(n1, bin+adj_len_n1 - len_n1, len_n1));
    ESP32_SRP_CHK(mbedtls_mpi_write_binary(n2, bin+adj_len_n1 + adj_len_n2 - len_n2, len_n2));
    ESP32_SRP_CHK(srp_crypto_hash(alg, bin, nbytes, buff));
    ESP32_SRP_CHK(mbedtls_mpi_read_binary(hnn, buff, hash_len));
    return SRP_ERR_OK;
cleanup:
    return ret;
}

// Hash of a mbedtls_mpi and a byte string
static int srp_crypto_hash_ns(srp_context_t srp_ctx, const mbedtls_mpi *n, const unsigned char *s, int s_len, mbedtls_mpi *hns) {
    int ret;
    SRP_CRYPTO_HASH_ALGORITHM alg = srp_ctx->halg;
    int hash_len = srp_crypto_hash_length(alg);
    unsigned char buff[hash_len];
    int n_len  = mbedtls_mpi_size(n);
    int nbytes = n_len + s_len;
    unsigned char bin[nbytes];
    ESP32_SRP_CHK(mbedtls_mpi_write_binary(n, bin, n_len));
    memcpy(bin + n_len, s, s_len);
    ESP32_SRP_CHK(srp_crypto_hash(alg, bin, nbytes, buff));
    ESP32_SRP_CHK(mbedtls_mpi_read_binary(hns, buff, hash_len));
    return SRP_ERR_OK;
cleanup:
    return ret;
}

static int srp_crypto_hash_num(srp_context_t srp_ctx, const mbedtls_mpi *n, unsigned char *dest) {
    int ret;
    SRP_CRYPTO_HASH_ALGORITHM alg = srp_ctx->halg;
    int nbytes = mbedtls_mpi_size(n);
    unsigned char bin[nbytes];
    ESP32_SRP_CHK(mbedtls_mpi_write_binary(n, bin, nbytes));
    return srp_crypto_hash(alg, bin, nbytes, dest);
cleanup:
    return ret;
}

/*k = SHA(N | PAD(g)) */
static int srp_context_calculate_k(srp_context_t srp_ctx, mbedtls_mpi *k) {
    return srp_crypto_hash_nn(srp_ctx, srp_ctx->N, 0, srp_ctx->g, 1, k);
}

/*u = SHA(PAD(A) | PAD(B)) */
static int srp_context_calculate_server_u(srp_context_t srp_ctx, const mbedtls_mpi *public_key, mbedtls_mpi *u) {
    return srp_crypto_hash_nn(srp_ctx, public_key, 1, srp_ctx->public_key, 1, u);
}

/*u = SHA(PAD(A) | PAD(B)) */
static int srp_context_calculate_client_u(srp_context_t srp_ctx, const mbedtls_mpi *public_key, mbedtls_mpi *u) {
    return srp_crypto_hash_nn(srp_ctx, srp_ctx->public_key, 1, public_key, 1, u);
}

/*u = SHA(PAD(A) | PAD(B)) */
static int srp_context_calculate_u(srp_context_t srp_ctx, const mbedtls_mpi *public_key, mbedtls_mpi *u) {
    switch (srp_ctx->role) {
        case SRP_ROLE_SERVER:
            return srp_context_calculate_server_u(srp_ctx, public_key, u);
        case SRP_ROLE_CLIENT:
            return srp_context_calculate_client_u(srp_ctx, public_key, u);
        default:
            return SRP_ERR_UNSUPPORTED_ROLE;
    }
}

/* x = H(s | H(I | ":" | P)) */
static int srp_context_calculate_x(srp_context_t srp_ctx, const unsigned char *password, int password_len, mbedtls_mpi *x) {
    int ret;
    SRP_CRYPTO_HASH_ALGORITHM alg = srp_ctx->halg;
    int hash_len = srp_crypto_hash_length(alg);
    if (hash_len < 0) {
        return hash_len;
    }
    unsigned char ucp_hash[hash_len];
    HashCTX ctx = { .halg = alg };
    ESP32_SRP_CHK(srp_crypto_hash_init(&ctx));
    ESP32_SRP_CHK(srp_crypto_hash_start(&ctx));
    ESP32_SRP_CHK(srp_crypto_hash_update(&ctx, srp_ctx->username, strlen(srp_ctx->username)));
    ESP32_SRP_CHK(srp_crypto_hash_update(&ctx, ":", 1));
    ESP32_SRP_CHK(srp_crypto_hash_update(&ctx, password, password_len));
    ESP32_SRP_CHK(srp_crypto_hash_final(&ctx, ucp_hash));
    return srp_crypto_hash_ns(srp_ctx, srp_ctx->s, ucp_hash, hash_len, x);
cleanup:
    return ret;
}

/* v = g^x % N */
static int srp_context_calculate_v(srp_context_t srp_ctx, mbedtls_mpi *x, mbedtls_mpi *v) {
    int ret;
    ESP32_SRP_CHK(mbedtls_mpi_exp_mod(v, srp_ctx->g, x, srp_ctx->N, RR));
cleanup:
    return ret;
}

/* K = H(S) */
static int srp_compute_K(srp_context_t srp_ctx, mbedtls_mpi *K) {
    int ret;
    SRP_CRYPTO_HASH_ALGORITHM alg = srp_ctx->halg;
    int hash_len = srp_crypto_hash_length(alg);
    if (hash_len < 0) {
        return hash_len;
    }
    unsigned char hash_K[hash_len];
    ESP32_SRP_CHK(srp_crypto_hash_num(srp_ctx, srp_ctx->S, hash_K));
    ESP32_SRP_CHK(mbedtls_mpi_read_binary(K, hash_K, hash_len));
cleanup:
    return ret;
}

static int srp_compute_M1(srp_context_t srp_ctx, mbedtls_mpi *A, mbedtls_mpi *B, mbedtls_mpi *M1) {
    int ret;
    SRP_CRYPTO_HASH_ALGORITHM alg = srp_ctx->halg;
    int hash_len = srp_crypto_hash_length(alg);
    if (hash_len < 0) {
        return hash_len;
    }
    unsigned char hash_N[hash_len];
    unsigned char hash_g[hash_len];
    unsigned char hash_u[hash_len];
    unsigned char hash_M1[hash_len];
    ESP32_SRP_CHK(srp_crypto_hash_num(srp_ctx, srp_ctx->N, hash_N));
    ESP32_SRP_CHK(srp_crypto_hash_num(srp_ctx, srp_ctx->g, hash_g));
    ESP32_SRP_CHK(srp_crypto_hash(alg, (const unsigned char*)srp_ctx->username, strlen(srp_ctx->username), hash_u));
    for (int i = 0; i < hash_len; i++) {
        hash_N[i]^= hash_g[i];
    }
    HashCTX ctx = { .halg = alg };
    ESP32_SRP_CHK(srp_crypto_hash_init(&ctx));
    ESP32_SRP_CHK(srp_crypto_hash_start(&ctx));
    ESP32_SRP_CHK(srp_crypto_hash_update(&ctx, hash_N, hash_len));
    ESP32_SRP_CHK(srp_crypto_hash_update(&ctx, hash_u, hash_len));
    ESP32_SRP_CHK(srp_crypto_hash_update_n(&ctx, srp_ctx->s));
    ESP32_SRP_CHK(srp_crypto_hash_update_n(&ctx, A));
    ESP32_SRP_CHK(srp_crypto_hash_update_n(&ctx, B));
    ESP32_SRP_CHK(srp_crypto_hash_update_n(&ctx, srp_ctx->K));
    ESP32_SRP_CHK(srp_crypto_hash_final(&ctx, hash_M1));
    ESP32_SRP_CHK(mbedtls_mpi_read_binary(M1, hash_M1, hash_len));
cleanup:
    return ret;
}

static int srp_compute_M2(srp_context_t srp_ctx, mbedtls_mpi *A, mbedtls_mpi *M2) {
    int ret;
    SRP_CRYPTO_HASH_ALGORITHM alg = srp_ctx->halg;
    int hash_len = srp_crypto_hash_length(alg);
    unsigned char hash_M2[hash_len];
    HashCTX ctx = { .halg = alg };
    ESP32_SRP_CHK(srp_crypto_hash_init(&ctx));
    ESP32_SRP_CHK(srp_crypto_hash_start(&ctx));
    ESP32_SRP_CHK(srp_crypto_hash_update_n(&ctx, A));
    ESP32_SRP_CHK(srp_crypto_hash_update_n(&ctx, srp_ctx->M1));
    ESP32_SRP_CHK(srp_crypto_hash_update_n(&ctx, srp_ctx->K));
    ESP32_SRP_CHK(srp_crypto_hash_final(&ctx, hash_M2));
    return mbedtls_mpi_read_binary(M2, hash_M2, hash_len);
cleanup:
    return ret;
}

// Server verification step
static int srp_compute_key_server(srp_context_t srp_ctx, mbedtls_mpi *A) {
    /*SRP-6a safety check */
    if (!(mbedtls_mpi_cmp_int(A, 0) == 1) || !(mbedtls_mpi_cmp_mpi(A, srp_ctx->N) == -1)) {
        return SRP_ERR_SAFETY_CHECK;
    }
    int ret;
    SRP_DECLARE_MPI(S);
    SRP_DECLARE_MPI(u);
    SRP_DECLARE_MPI(K);
    SRP_DECLARE_MPI(M1);
    SRP_DECLARE_MPI(M2);
    SRP_DECLARE_MPI(tmp1);
    SRP_DECLARE_MPI(tmp2);

    ESP32_SRP_CHK(srp_mpi_new(&S));
    ESP32_SRP_CHK(srp_mpi_new(&u));
    ESP32_SRP_CHK(srp_mpi_new(&K));
    ESP32_SRP_CHK(srp_mpi_new(&M1));
    ESP32_SRP_CHK(srp_mpi_new(&M2));
    ESP32_SRP_CHK(srp_mpi_new(&tmp1));
    ESP32_SRP_CHK(srp_mpi_new(&tmp2));

    /* u = SHA(PAD(A) | PAD(B)) */
    ESP32_SRP_CHK(srp_context_calculate_u(srp_ctx, A, u));
    /* S = (A * (v^u)) ^ b % N                      */
    /* tmp1 = (v^ux)                                */
    ESP32_SRP_CHK(mbedtls_mpi_exp_mod(tmp1, srp_ctx->v, u, srp_ctx->N, RR));
    /* tmp2 = (A * (v^ux))                          */
    ESP32_SRP_CHK(mbedtls_mpi_mul_mpi(tmp2, A, tmp1));
    /* S = (A * (v^u)) ^ b % N                      */
    ESP32_SRP_CHK(mbedtls_mpi_exp_mod(S, tmp2, srp_ctx->private_key, srp_ctx->N, RR));
    srp_context_set_S(srp_ctx, S);
    ESP32_SRP_CHK(srp_compute_K(srp_ctx, K));
    /* K = H(S) */
    srp_context_set_K(srp_ctx, K);
    ESP32_SRP_CHK(srp_compute_M1(srp_ctx, A, srp_ctx->public_key, M1));
    srp_context_set_M1(srp_ctx, M1);
    ESP32_SRP_CHK(srp_compute_M2(srp_ctx, A, M2));
    srp_context_set_M2(srp_ctx, M2);

cleanup:
    srp_mpi_free(S);
    srp_mpi_free(u);
    srp_mpi_free(K);
    srp_mpi_free(M1);
    srp_mpi_free(M2);
    srp_mpi_free(tmp1);
    srp_mpi_free(tmp2);
    return ret;
}

// Client verification step
static int srp_compute_key_client(srp_context_t srp_ctx, mbedtls_mpi *B) {
    /*SRP-6a safety check */
    if (!(mbedtls_mpi_cmp_int(B, 0) == 1) || !(mbedtls_mpi_cmp_mpi(B, srp_ctx->N) == -1)) {
        return SRP_ERR_SAFETY_CHECK;
    }
    int ret;
    SRP_DECLARE_MPI(S);
    SRP_DECLARE_MPI(u);
    SRP_DECLARE_MPI(K);
    SRP_DECLARE_MPI(M1);
    SRP_DECLARE_MPI(M2);
    SRP_DECLARE_MPI(tmp1);
    SRP_DECLARE_MPI(tmp2);
    SRP_DECLARE_MPI(tmp3);

    ESP32_SRP_CHK(srp_mpi_new(&S));
    ESP32_SRP_CHK(srp_mpi_new(&u));
    ESP32_SRP_CHK(srp_mpi_new(&K));
    ESP32_SRP_CHK(srp_mpi_new(&M1));
    ESP32_SRP_CHK(srp_mpi_new(&M2));
    ESP32_SRP_CHK(srp_mpi_new(&tmp1));
    ESP32_SRP_CHK(srp_mpi_new(&tmp2));
    ESP32_SRP_CHK(srp_mpi_new(&tmp3));

    /*u = SHA(PAD(A) | PAD(B))    */
    ESP32_SRP_CHK(srp_context_calculate_u(srp_ctx, B, u));
    /* S = (B - (k * g^x)) ^ (a + (u * x)) % N      */
    /* tmp1 = (u * x)                               */
    ESP32_SRP_CHK(mbedtls_mpi_mul_mpi(tmp1, u, srp_ctx->x));
    /* tmp2 = (a + (u * x))                         */
    ESP32_SRP_CHK(mbedtls_mpi_add_mpi(tmp2, srp_ctx->private_key, tmp1));
    /* tmp1 = g^x%N                                 */
    ESP32_SRP_CHK(mbedtls_mpi_exp_mod(tmp1, srp_ctx->g, srp_ctx->x, srp_ctx->N, RR));
    /* tmp3 = k * (g^x)%N                           */
    ESP32_SRP_CHK(mbedtls_mpi_mul_mpi(tmp3, srp_ctx->k, tmp1));
    /* tmp1 = (B - k * (g^x)%N)                     */
    ESP32_SRP_CHK(mbedtls_mpi_sub_mpi(tmp1, B, tmp3));
    /* S = (B - k * (g^x)%N) ^ (a + (u * x) % N     */
    ESP32_SRP_CHK(mbedtls_mpi_exp_mod(S, tmp1, tmp2, srp_ctx->N, RR));
    srp_context_set_S(srp_ctx, S);
    /* K = H(S) */
    ESP32_SRP_CHK(srp_compute_K(srp_ctx, K));
    srp_context_set_K(srp_ctx, K);
    ESP32_SRP_CHK(srp_compute_M1(srp_ctx, srp_ctx->public_key, B, M1));
    srp_context_set_M1(srp_ctx, M1);
    ESP32_SRP_CHK(srp_compute_M2(srp_ctx, srp_ctx->public_key, M2));
    srp_context_set_M2(srp_ctx, M2);

cleanup:
    srp_mpi_free(S);
    srp_mpi_free(u);
    srp_mpi_free(K);
    srp_mpi_free(M1);
    srp_mpi_free(M2);
    srp_mpi_free(tmp1);
    srp_mpi_free(tmp2);
    srp_mpi_free(tmp3);
    return ret;
}

static int srp_gen_pub_server(srp_context_t srp_ctx) {
    int ret;
    SRP_DECLARE_MPI(b);
    SRP_DECLARE_MPI(B);
    SRP_DECLARE_MPI(k);
    SRP_DECLARE_MPI(tmp1);
    SRP_DECLARE_MPI(tmp2);
    SRP_DECLARE_MPI(tmp3);

    ESP32_SRP_CHK(srp_mpi_new(&b));
    ESP32_SRP_CHK(srp_mpi_new(&B));
    ESP32_SRP_CHK(srp_mpi_new(&k));
    ESP32_SRP_CHK(srp_mpi_new(&tmp1));
    ESP32_SRP_CHK(srp_mpi_new(&tmp2));
    ESP32_SRP_CHK(srp_mpi_new(&tmp3));

#ifdef _SRP_TEST_VECTOR
    ESP32_SRP_CHK(mbedtls_mpi_read_string(b, 16, "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20"));
#else
    ESP32_SRP_CHK(srp_mpi_fill_random(b, 32));
#endif
    srp_context_set_private_key(srp_ctx, b);

    /* k = SHA(N | PAD(g)) */
    ESP32_SRP_CHK(srp_context_calculate_k(srp_ctx, k));
    srp_context_set_k(srp_ctx, k);
    /* B = kv + g^b % N */
    /* tmp1 = kv */
    ESP32_SRP_CHK(mbedtls_mpi_mul_mpi(tmp1, k, srp_ctx->v));
    /* tmp2 = g^b % N */
    ESP32_SRP_CHK(mbedtls_mpi_exp_mod(tmp2, srp_ctx->g, srp_ctx->private_key, srp_ctx->N, RR));
    /* tmp3 = kv + g^b % N */
    ESP32_SRP_CHK(mbedtls_mpi_add_mpi(tmp3, tmp1, tmp2));
    /* B = (kv + g^b % N) % N */
    ESP32_SRP_CHK(mbedtls_mpi_mod_mpi(B, tmp3, srp_ctx->N));
    srp_context_set_public_key(srp_ctx, B);

cleanup:
    srp_mpi_free(k);
    srp_mpi_free(b);
    srp_mpi_free(B);
    srp_mpi_free(tmp1);
    srp_mpi_free(tmp2);
    srp_mpi_free(tmp3);
    return ret;
}

static int srp_gen_pub_client(srp_context_t srp_ctx) {
    int ret;
    SRP_DECLARE_MPI(a);
    SRP_DECLARE_MPI(A);
    SRP_DECLARE_MPI(k);

    ESP32_SRP_CHK(srp_mpi_new(&a));
    ESP32_SRP_CHK(srp_mpi_new(&A));
    ESP32_SRP_CHK(srp_mpi_new(&k));

#ifdef _SRP_TEST_VECTOR
    ESP32_SRP_CHK(mbedtls_mpi_read_string(a, 16, "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393"));
#else
    ESP32_SRP_CHK(srp_mpi_fill_random(a, 32));
#endif
    srp_context_set_private_key(srp_ctx, a);

    /*k = SHA(N | PAD(g)) */
    ESP32_SRP_CHK(srp_context_calculate_k(srp_ctx, k));
    srp_context_set_k(srp_ctx, k);
    /* A = g^a % N */
    ESP32_SRP_CHK(mbedtls_mpi_exp_mod(A, srp_ctx->g, a, srp_ctx->N, RR));
    srp_context_set_public_key(srp_ctx, A);

cleanup:
    srp_mpi_free(k);
    srp_mpi_free(a);
    srp_mpi_free(A);
    return ret;
}

/***********************************************************************************************************
 * Public interface
 ***********************************************************************************************************/

// Must be called before using the srp functions
int srp_init(const unsigned char *crypto_seed, int crypto_seed_len) {
    uint8_t seed_buffer[128];
    if (!RR) {
        if (srp_mpi_new(&RR)) {
            return SRP_ERR_ALLOC_FAILED;
        }
        if (!crypto_seed || !crypto_seed_len) {
            srp_system_random_buffer(seed_buffer, 128);
            crypto_seed = seed_buffer;
            crypto_seed_len = 128;
        }
        return srp_crypto_random_init(crypto_seed, crypto_seed_len);
    }
    return SRP_ERR_OK;
}

srp_context_t srp_new_client(SRP_TYPE type, SRP_CRYPTO_HASH_ALGORITHM halg) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        errno = SRP_ERR_NOT_INITIALIZED;
        return NULL;
    }
    int ret;
    srp_context_t srp_ctx = NULL;
    ESP32_SRP_CHK(srp_context_new(SRP_ROLE_CLIENT, type, halg, &srp_ctx));

cleanup:
    errno = ret;
    return srp_ctx;
}

srp_context_t srp_new_server(SRP_TYPE type, SRP_CRYPTO_HASH_ALGORITHM halg) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        errno = SRP_ERR_NOT_INITIALIZED;
        return NULL;
    }
    int ret;
    SRP_DECLARE_MPI(s);

    ESP32_SRP_CHK(srp_mpi_new(&s));

    srp_context_t srp_ctx = NULL;
    ESP32_SRP_CHK(srp_context_new(SRP_ROLE_SERVER, type, halg, &srp_ctx));
#ifdef _SRP_TEST_VECTOR
    ESP32_SRP_CHK(mbedtls_mpi_read_string(s, 16, "BEB25379D1A8581EB5A727673A2441EE"));
#else
    ESP32_SRP_CHK(srp_mpi_fill_random(s, 16));
#endif
    srp_context_set_s(srp_ctx, s);

cleanup:
    errno = ret;
    srp_mpi_free(s);
    if (ret) {
        srp_context_free(srp_ctx);
        srp_ctx = NULL;
    }
    return srp_ctx;
}

mbedtls_mpi *srp_get_salt(srp_context_t srp_ctx) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        errno = SRP_ERR_NOT_INITIALIZED;
        return NULL;
    }
    return srp_ctx->s;
}

mbedtls_mpi *srp_get_public_key(srp_context_t srp_ctx) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        errno = SRP_ERR_NOT_INITIALIZED;
        return NULL;
    }
    return srp_ctx->public_key;
}

mbedtls_mpi *srp_get_session_secret(srp_context_t srp_ctx) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        errno = SRP_ERR_NOT_INITIALIZED;
        return NULL;
    }
    return srp_ctx->K;
}

mbedtls_mpi *srp_get_verify_key(srp_context_t srp_ctx) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        errno = SRP_ERR_NOT_INITIALIZED;
        return NULL;
    }
    switch (srp_ctx->role) {
        case SRP_ROLE_SERVER:
            return srp_ctx->M2;
        case SRP_ROLE_CLIENT:
            return srp_ctx->M1;
        default:
            errno = SRP_ERR_UNSUPPORTED_ROLE;
    }
    return NULL;
}

int srp_set_params(srp_context_t srp_ctx, mbedtls_mpi *modulus, mbedtls_mpi *generator, mbedtls_mpi *salt) {
    int ret = SRP_ERR_OK;
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        return SRP_ERR_NOT_INITIALIZED;
    }
    if (modulus) {
        srp_context_set_N(srp_ctx, modulus);
    }
    if (generator) {
        srp_context_set_g(srp_ctx, generator);
    }
    if (salt) {
        srp_context_set_s(srp_ctx, salt);
    }

cleanup:
    return ret;
}

int srp_set_username(srp_context_t srp_ctx, const char *username) {
    int ret;
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        return SRP_ERR_NOT_INITIALIZED;
    }
    srp_context_set_username(srp_ctx, username);

cleanup:
    return ret;
}

// Only useful for servers
int srp_set_auth_password(srp_context_t srp_ctx, const unsigned char *password, int password_len) {
    int ret;
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        return SRP_ERR_NOT_INITIALIZED;
    }
    if (!srp_ctx->username || !srp_ctx->s) {
        return SRP_ERR_ARGUMENTS_MISMATCH;
    }
    SRP_DECLARE_MPI(x);
    SRP_DECLARE_MPI(v);

    ESP32_SRP_CHK(srp_mpi_new(&x));
    ESP32_SRP_CHK(srp_mpi_new(&v));
    ESP32_SRP_CHK(srp_context_calculate_x(srp_ctx, password, password_len, x));
    srp_context_set_x(srp_ctx, x);
    if (srp_ctx->role == SRP_ROLE_SERVER) {
        ESP32_SRP_CHK(srp_context_calculate_v(srp_ctx, x, v));
        srp_context_set_v(srp_ctx, v);
    }

cleanup:
    srp_mpi_free(x);
    srp_mpi_free(v);
    return ret;
}

int srp_gen_pub(srp_context_t srp_ctx) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        return SRP_ERR_NOT_INITIALIZED;
    }
    if (srp_ctx->role == SRP_ROLE_SERVER) {
        return srp_gen_pub_server(srp_ctx);
    }
    else if (srp_ctx->role == SRP_ROLE_CLIENT) {
        return srp_gen_pub_client(srp_ctx);
    }
    return SRP_ERR_UNSUPPORTED_ROLE;
}

int srp_compute_key(srp_context_t srp_ctx, mbedtls_mpi *public_key) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        return SRP_ERR_NOT_INITIALIZED;
    }
    if (srp_ctx->role == SRP_ROLE_SERVER) {
        return srp_compute_key_server(srp_ctx, public_key);
    }
    else if (srp_ctx->role == SRP_ROLE_CLIENT) {
        return srp_compute_key_client(srp_ctx, public_key);
    }
    return SRP_ERR_UNSUPPORTED_ROLE;
}

int srp_verify_key(srp_context_t srp_ctx, mbedtls_mpi *M) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        return SRP_ERR_NOT_INITIALIZED;
    }
    if (srp_ctx->role == SRP_ROLE_SERVER) {
        return mbedtls_mpi_cmp_mpi(srp_ctx->M1, M);
    }
    else if (srp_ctx->role == SRP_ROLE_CLIENT) {
        return mbedtls_mpi_cmp_mpi(srp_ctx->M2, M);
    }
    return SRP_ERR_UNSUPPORTED_ROLE;
}

void srp_free(void *s) {
    if (!RR) {
        ESP_LOGI(TAG, "SRP not initialized! Please call srp_init() before using SRP functions");
        return;
    }
    srp_context_free((srp_context_t)s);
}

void srp_dump_context(srp_context_t srp_ctx, const char *description) {
    if (!srp_ctx) {
        return;
    }
    srp_context_dump(srp_ctx, description);
}
