/*
 * Secure Remote Password 6a implementation based on mbedtls.
 *
 * Copyright (c) 2017 Emmanuel Merali
 * https://github.com/ifullgaz/esp32-srp
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "esp32-srp/srp.h"

// Can generate seed with openssl rand -hex 128
const unsigned char crypto_seed[128] = {
    0xE3, 0xC3, 0x6E, 0xF8, 0x41, 0xCA, 0x4B, 0xEF, 0x1A, 0xF4, 0x3A, 0x83, 0xDF, 0xC6, 0x7A, 0x56,
    0x99, 0x02, 0xBF, 0x70, 0x60, 0x04, 0x14, 0x81, 0x2F, 0xE7, 0x76, 0x09, 0xDB, 0x55, 0x94, 0x97,
    0xBB, 0x9C, 0xC5, 0x72, 0x99, 0x80, 0x9E, 0xB6, 0x09, 0x9C, 0xDD, 0x3B, 0x42, 0x56, 0xE5, 0x27,
    0x8B, 0xD4, 0xA0, 0xD7, 0x9F, 0x0B, 0x67, 0x22, 0xD5, 0xC3, 0xE6, 0x51, 0xC4, 0xDC, 0x76, 0x04,
    0x4A, 0xC0, 0x05, 0xB6, 0x0F, 0xB0, 0x98, 0xC4, 0x1C, 0xFB, 0xBE, 0xCE, 0xC9, 0x2E, 0xBA, 0xCF,
    0x4A, 0x33, 0x22, 0xC2, 0x36, 0xA6, 0x19, 0x43, 0xE4, 0x95, 0xE3, 0x73, 0xB3, 0xAE, 0x0F, 0x49,
    0xB4, 0xD4, 0x94, 0xB4, 0xFA, 0xDB, 0xA7, 0x87, 0x89, 0x17, 0x76, 0x89, 0x7D, 0x2A, 0x0E, 0x0B,
    0x49, 0xE2, 0x09, 0x36, 0x3F, 0xCE, 0x91, 0xA9, 0x47, 0x33, 0xF0, 0x52, 0x3D, 0xEC, 0xAA, 0x91
};

unsigned long long get_usec()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (((unsigned long long)t.tv_sec) * 1000000) + t.tv_usec;
}

void app_main() {
    unsigned long long start, duration;
    unsigned long long inter_start, inter_duration;
    unsigned long long client_duration = 0, server_duration = 0;
    
    const SRP_TYPE ng_type    = SRP_TYPE_3072;
    const SRP_CRYPTO_HASH_ALGORITHM alg = SRP_CRYPTO_HASH_ALGORITHM_SHA512;
    
    const char *username = "alice";
    const char *password = "password123";

    const int niter = 2;

    int retS, retC;
    int successes = 0, failures = 0;

    start = get_usec();    
    srp_init(crypto_seed, 128);
    for (int i = 0; i < niter; i++) {
        printf("\nIteration: %d -------------------------------------------------------------------------------------------\n\n", i + 1);

        inter_start = get_usec();
        SRPContext *srp_server = srp_new_server(ng_type, alg);
        inter_duration = get_usec() - inter_start;        
        server_duration+= inter_duration;
        printf("Usec srp_new_server: %llu\n", inter_duration);
        srp_dump_context(srp_server, "srp_new_server");

        printf("====================== M1: Client -> Server -- 'SRP Start Request'\n");

        inter_start = get_usec();
        SRPContext *srp_client = srp_new_client(ng_type, alg);
        inter_duration = get_usec() - inter_start;        
        client_duration+= inter_duration;
        printf("Usec srp_new_client: %llu\n", inter_duration);
        srp_dump_context(srp_client, "srp_new_client");

        printf("====================== M2: Server -> Client -- 'SRP Start Response'\n");

        inter_start = get_usec();
        srp_set_username(srp_server, username);
        inter_duration = get_usec() - inter_start;        
        server_duration+= inter_duration;
        printf("Usec server srp_set_username: %llu\n", inter_duration);
        srp_dump_context(srp_server, "srp_set_username");
        
        inter_start = get_usec();
        srp_set_auth_password(srp_server, (const unsigned char *)password, strlen(password));
        inter_duration = get_usec() - inter_start;        
        server_duration+= inter_duration;
        printf("Usec server srp_set_auth_password: %llu\n", inter_duration);
        srp_dump_context(srp_server, "srp_set_auth_password");
        
        inter_start = get_usec();
        srp_gen_pub(srp_server);
        inter_duration = get_usec() - inter_start;        
        server_duration+= inter_duration;
        printf("Usec server srp_gen_pub: %llu\n", inter_duration);
        srp_dump_context(srp_server, "srp_set_auth_password");

        printf("====================== M3: Client -> Server -- 'SRP Verify Request'\n");

        inter_start = get_usec();
        // This is safe because numbers are copied
        srp_set_params(srp_client, NULL, NULL, srp_server->s);
        inter_duration = get_usec() - inter_start;        
        client_duration+= inter_duration;
        printf("Usec client srp_set_params: %llu\n", inter_duration);
        srp_dump_context(srp_client, "srp_set_params");
        
        inter_start = get_usec();
        srp_gen_pub(srp_client);
        inter_duration = get_usec() - inter_start;        
        client_duration+= inter_duration;
        printf("Usec client srp_gen_pub: %llu\n", inter_duration);
        srp_dump_context(srp_client, "srp_gen_pub");
        
        inter_start = get_usec();
        // Get the password from the user but here we know it already
        srp_set_username(srp_client, username);
        inter_duration = get_usec() - inter_start;        
        client_duration+= inter_duration;
        printf("Usec client srp_set_username: %llu\n", inter_duration);
        srp_dump_context(srp_client, "srp_set_username");
        
        inter_start = get_usec();
        // Get the password from the user but here we know it already
        srp_set_auth_password(srp_client, (const unsigned char *)password, strlen(password));
        inter_duration = get_usec() - inter_start;        
        client_duration+= inter_duration;
        printf("Usec client srp_set_auth_password: %llu\n", inter_duration);
        srp_dump_context(srp_client, "srp_set_auth_password");
        
        inter_start = get_usec();
        // Get the password from the user; the server sent its public key earlier
        srp_compute_key(srp_client, srp_server->public_key);
        inter_duration = get_usec() - inter_start;        
        client_duration+= inter_duration;
        printf("Usec client srp_compute_key: %llu\n", inter_duration);
        srp_dump_context(srp_client, "srp_compute_key");

        printf("====================== M4: Server -> Client -- 'SRP Verify Response'\n");

        inter_start = get_usec();
        srp_compute_key(srp_server, srp_client->public_key);
        inter_duration = get_usec() - inter_start;        
        server_duration+= inter_duration;
        printf("Usec server srp_compute_key: %llu\n", inter_duration);
        srp_dump_context(srp_server, "srp_compute_key");

        inter_start = get_usec();
        retS = srp_verify_key(srp_server, srp_client->M1);
        inter_duration = get_usec() - inter_start;        
        server_duration+= inter_duration;
        printf("Usec server srp_compute_key: %llu\n", inter_duration);
        srp_dump_context(srp_server, "srp_compute_key");

        if (retS) {
            printf("!!!!!!!!!!!! Server failed to validate Client\n");
        }

        printf("====================== M5: Client -> Server -- 'Exchange Request'\n");

        inter_start = get_usec();
        retC = srp_verify_key(srp_client, srp_server->M2);
        inter_duration = get_usec() - inter_start;        
        client_duration+= inter_duration;
        printf("Usec client srp_compute_key: %llu\n", inter_duration);
        srp_dump_context(srp_client, "srp_compute_key");

        if (retC) {
            printf("!!!!!!!!!!!! Server failed to validate Client\n");
        }

        if (retS || retC) failures++; else successes++;
        srp_free(srp_server);
        srp_free(srp_client);
    }
    
    duration = get_usec() - start;
    
    printf("uSec total: %llu\n", duration);
    printf("uSec total CPU: %llu (avg: %llu)\n", server_duration + client_duration, (server_duration + client_duration) / niter);
    printf("uSec server CPU: %llu (avg: %llu)\n", server_duration, server_duration / niter);
    printf("uSec client CPU: %llu (avg: %llu)\n", client_duration, client_duration / niter);
    printf("Total tests: %d, successes: %d, failures: %d\n", niter, successes, failures);
}
