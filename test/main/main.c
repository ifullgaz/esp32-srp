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

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "errno.h"
#include "esp_log.h"

#include "esp32-srp/srp.h"

static const char *TAG = "SRP_TEST";

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

static void srp_test_task(void *context) {
    unsigned long long start, duration;
    unsigned long long inter_start, inter_duration;
    unsigned long long client_duration = 0, server_duration = 0;

    const SRP_TYPE ng_type = SRP_TYPE_3072;
    const SRP_CRYPTO_HASH_ALGORITHM alg = SRP_CRYPTO_HASH_ALGORITHM_SHA512;

    const char *username = "alice";
    const char *password = "password123";

    const int niter = 1000;

    int successes = 0, failures = 0;

    start = get_usec();

    for (int i = 0; i < niter; i++) {
        int ret = 0;
        SRPContext srp_server = NULL;
        SRPContext srp_client = NULL;
        mbedtls_mpi *salt;
        mbedtls_mpi *public_key;
        mbedtls_mpi *verify_key;

        ESP_LOGI(TAG, "\nIteration: %d -------------------------------------------------------------------------------------------\n", i + 1);

        ESP_LOGD(TAG, "srp_new_server");
        inter_start = get_usec();
        ESP32_SRP_SET(srp_server, srp_new_server(ng_type, alg));
        // if (!(srp_server = srp_new_server(ng_type, alg))) {
        //     ret = errno;
        //     goto cleanup;
        // }
        inter_duration = get_usec() - inter_start;
        server_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec srp_new_server: %llu", inter_duration);
        srp_dump_context(srp_server, "srp_new_server");

        ESP_LOGD(TAG, "====================== M1: Client -> Server -- 'SRP Start Request'");

        ESP_LOGD(TAG, "srp_new_client");
        inter_start = get_usec();
        ESP32_SRP_SET(srp_client, srp_new_client(ng_type, alg));
        // if (!(srp_client = srp_new_client(ng_type, alg))) {
        //     ret = errno;
        //     goto cleanup;            
        // }
        inter_duration = get_usec() - inter_start;
        client_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec srp_new_client: %llu", inter_duration);
        srp_dump_context(srp_client, "srp_new_client");

        ESP_LOGD(TAG, "====================== M2: Server -> Client -- 'SRP Start Response'");

        ESP_LOGD(TAG, "Server srp_set_username");
        inter_start = get_usec();
        ESP32_SRP_CHK(srp_set_username(srp_server, username));
        inter_duration = get_usec() - inter_start;
        server_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec server srp_set_username: %llu", inter_duration);
        srp_dump_context(srp_server, "srp_set_username");

        ESP_LOGD(TAG, "Server srp_set_auth_password");
        inter_start = get_usec();
        ESP32_SRP_CHK(srp_set_auth_password(srp_server, (const unsigned char *)password, strlen(password)));
        inter_duration = get_usec() - inter_start;
        server_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec server srp_set_auth_password: %llu", inter_duration);
        srp_dump_context(srp_server, "srp_set_auth_password");

        ESP_LOGD(TAG, "Server srp_gen_pub");
        inter_start = get_usec();
        ESP32_SRP_CHK(srp_gen_pub(srp_server));
        inter_duration = get_usec() - inter_start;
        server_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec server srp_gen_pub: %llu", inter_duration);
        srp_dump_context(srp_server, "srp_set_auth_password");

        ESP_LOGD(TAG, "====================== M3: Client -> Server -- 'SRP Verify Request'");

        ESP_LOGD(TAG, "Server srp_get_salt");
        inter_start = get_usec();
        ESP32_SRP_SET(salt, srp_get_salt(srp_server));
        // This is safe because numbers are copied
        ESP32_SRP_CHK(srp_set_params(srp_client, NULL, NULL, salt));
        inter_duration = get_usec() - inter_start;
        client_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec client srp_set_params: %llu", inter_duration);
        srp_dump_context(srp_client, "srp_set_params");

        ESP_LOGD(TAG, "Client srp_gen_pub");
        inter_start = get_usec();
        ESP32_SRP_CHK(srp_gen_pub(srp_client));
        inter_duration = get_usec() - inter_start;
        client_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec client srp_gen_pub: %llu", inter_duration);
        srp_dump_context(srp_client, "srp_gen_pub");

        ESP_LOGD(TAG, "Client srp_set_username");
        inter_start = get_usec();
        // Get the password from the user but here we know it already
        ESP32_SRP_CHK(srp_set_username(srp_client, username));
        inter_duration = get_usec() - inter_start;
        client_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec client srp_set_username: %llu", inter_duration);
        srp_dump_context(srp_client, "srp_set_username");

        ESP_LOGD(TAG, "Client srp_set_auth_password");
        inter_start = get_usec();
        // Get the password from the user but here we know it already
        ESP32_SRP_CHK(srp_set_auth_password(srp_client, (const unsigned char *)password, strlen(password)));
        inter_duration = get_usec() - inter_start;
        client_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec client srp_set_auth_password: %llu", inter_duration);
        srp_dump_context(srp_client, "srp_set_auth_password");

        ESP_LOGD(TAG, "Client srp_compute_key");
        inter_start = get_usec();
        ESP32_SRP_SET(public_key, srp_get_public_key(srp_server));
        // Get the password from the user; the server sent its public key earlier
        ESP32_SRP_CHK(srp_compute_key(srp_client, public_key));
        inter_duration = get_usec() - inter_start;
        client_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec client srp_compute_key: %llu", inter_duration);
        srp_dump_context(srp_client, "srp_compute_key");

        ESP_LOGD(TAG, "====================== M4: Server -> Client -- 'SRP Verify Response'");

        ESP_LOGD(TAG, "Server srp_compute_key");
        inter_start = get_usec();
        ESP32_SRP_SET(public_key, srp_get_public_key(srp_client));
        ESP32_SRP_CHK(srp_compute_key(srp_server, public_key));
        inter_duration = get_usec() - inter_start;
        server_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec server srp_compute_key: %llu", inter_duration);
        srp_dump_context(srp_server, "srp_compute_key");

        ESP_LOGD(TAG, "Server srp_verify_key");
        inter_start = get_usec();
        ESP32_SRP_SET(verify_key, srp_get_verify_key(srp_client));
        ret = srp_verify_key(srp_server, verify_key);
        inter_duration = get_usec() - inter_start;
        server_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec server srp_verify_key: %llu", inter_duration);
        srp_dump_context(srp_server, "srp_compute_key");

        if (ret) {
            ESP_LOGI(TAG, "!!!!!!!!!!!! Server failed to validate Client");
            goto cleanup;
        }

        ESP_LOGD(TAG, "====================== M5: Client -> Server -- 'Exchange Request'");

        ESP_LOGD(TAG, "Client srp_verify_key");
        inter_start = get_usec();
        ESP32_SRP_SET(verify_key, srp_get_verify_key(srp_server));
        ret = srp_verify_key(srp_client, verify_key);
        inter_duration = get_usec() - inter_start;
        client_duration+= inter_duration;
        ESP_LOGD(TAG, "Usec client srp_verify_key: %llu", inter_duration);
        srp_dump_context(srp_client, "srp_compute_key");

        if (ret) {
            ESP_LOGI(TAG, "!!!!!!!!!!!! Server failed to validate Client");
            goto cleanup;
        }

cleanup:
        if (ret) {
            ESP_LOGI(TAG, "Error code: %d", ret);
            failures++;
        }
        else {
            successes++;
            ESP_LOGD(TAG, "Authentication successful");
        }
        srp_free(srp_server);
        srp_free(srp_client);
        ESP_LOGI(TAG, "uSec server CPU: %llu (avg: %llu)", server_duration, server_duration / (i + 1));
        ESP_LOGI(TAG, "uSec client CPU: %llu (avg: %llu)", client_duration, client_duration / (i + 1));
        ESP_LOGI(TAG, "Total tests: %d, successes: %d, failures: %d", (i + 1), successes, failures);
    }

    duration = get_usec() - start;

    ESP_LOGD(TAG, "uSec total: %llu", duration);
    ESP_LOGD(TAG, "uSec total CPU: %llu (avg: %llu)", server_duration + client_duration, (server_duration + client_duration) / niter);
    ESP_LOGI(TAG, "uSec server CPU: %llu (avg: %llu)", server_duration, server_duration / niter);
    ESP_LOGI(TAG, "uSec client CPU: %llu (avg: %llu)", client_duration, client_duration / niter);
    ESP_LOGI(TAG, "Total tests: %d, successes: %d, failures: %d", niter, successes, failures);
    vTaskDelete(NULL);
}

int start_srp_test_task() {
    xTaskHandle handle;
    int ret = xTaskCreate(srp_test_task,
                      "SRP_Task",
                      10240,
                      NULL,
                      5,
                      &handle); 

    if (ret != pdPASS)  {
        ESP_LOGI(TAG, "create task %s failed", "SRP_Task");
    }
    return ret;
}

void app_main() {

    ESP_LOGD(TAG, "\nSRP Version: %s\n", SRP_VERSION_STR);
    // It is imperative to initialize the SRP system first
    // The system will be seeded with new random 128 bits
    srp_init(NULL, 0);
    // The system can also be seeded with supplied seed
    // srp_init(crypto_seed, 128);
    start_srp_test_task();
}
