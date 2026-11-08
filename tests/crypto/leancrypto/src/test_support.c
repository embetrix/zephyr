/*
 * SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "test_support.h"

K_THREAD_STACK_DEFINE(test_operation_stack, CONFIG_TEST_LEANCRYPTO_STACK_SIZE);
struct k_thread test_operation_thread;

#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
int test_injected_error;
size_t test_csrand_calls;

int __real_z_impl_sys_csrand_get(void *dst, size_t len);
int __wrap_z_impl_sys_csrand_get(void *dst, size_t len);

int __wrap_z_impl_sys_csrand_get(void *dst, size_t len)
{
	test_csrand_calls++;
	if (test_injected_error != 0) {
		/* Model a provider which writes partial output before failing. */
		memset(dst, 0xa5, len);
		return test_injected_error;
	}
	return __real_z_impl_sys_csrand_get(dst, len);
}
#endif
