/*
 * SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TESTS_CRYPTO_LEANCRYPTO_TEST_SUPPORT_H_
#define TESTS_CRYPTO_LEANCRYPTO_TEST_SUPPORT_H_

#include <zephyr/kernel.h>

/* Suites run sequentially; every operation recreates and joins this worker. */
K_THREAD_STACK_DECLARE(test_operation_stack, CONFIG_TEST_LEANCRYPTO_STACK_SIZE);
extern struct k_thread test_operation_thread;

#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
extern int test_injected_error;
extern size_t test_csrand_calls;
#endif

#endif /* TESTS_CRYPTO_LEANCRYPTO_TEST_SUPPORT_H_ */
