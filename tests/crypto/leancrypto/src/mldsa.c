/*
 * SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/ztest.h>

#include "test_support.h"

#ifndef TEST_DSA_BITS
#if defined(CONFIG_TEST_LEANCRYPTO_ML_DSA_44)
#define TEST_DSA_BITS 44
#elif defined(CONFIG_TEST_LEANCRYPTO_ML_DSA_65)
#define TEST_DSA_BITS 65
#else
#define TEST_DSA_BITS 87
#endif
#endif

#ifndef TEST_SUITE_NAME
#define TEST_SUITE_NAME leancrypto_mldsa
#endif

#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
#if TEST_DSA_BITS == 44
#include <lc_dilithium_44.h>
#elif TEST_DSA_BITS == 65
#include <lc_dilithium_65.h>
#else
#include <lc_dilithium_87.h>
#endif
#include <lc_hash.h>
#include <lc_sha3.h>
#include "mldsa_kat.h"
#endif

#if TEST_DSA_BITS == 44
#define TEST_DSA(name) lc_dilithium_44_##name
#define TEST_PK_SIZE 1312
#define TEST_SK_SIZE 2560
#define TEST_SIG_SIZE 2420
#elif TEST_DSA_BITS == 65
#define TEST_DSA(name) lc_dilithium_65_##name
#define TEST_PK_SIZE 1952
#define TEST_SK_SIZE 4032
#define TEST_SIG_SIZE 3309
#else
#define TEST_DSA(name) lc_dilithium_87_##name
#define TEST_PK_SIZE 2592
#define TEST_SK_SIZE 4896
#define TEST_SIG_SIZE 4627
#endif

enum operation {
	KEYGEN,
	SIGN,
	VERIFY,
};

/* Identical caller-owned storage in the crypto and baseline images. */
struct buffers {
	uint8_t pk[TEST_PK_SIZE];
	uint8_t sk[TEST_SK_SIZE];
	uint8_t sig[TEST_SIG_SIZE];
	uint8_t message[64];
};

static struct buffers *test_buffers(void)
{
	static struct buffers buffers __aligned(8);

	return &buffers;
}

struct job {
	enum operation operation;
	struct buffers *buffers;
	int result;
	uint32_t cycles;
	bool deterministic;
};

#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
BUILD_ASSERT(sizeof(struct TEST_DSA(pk)) == sizeof(((struct buffers *)0)->pk));
BUILD_ASSERT(sizeof(struct TEST_DSA(sk)) == sizeof(((struct buffers *)0)->sk));
BUILD_ASSERT(sizeof(struct TEST_DSA(sig)) == sizeof(((struct buffers *)0)->sig));

static int fixed_generate(void *state, const uint8_t *additional,
			  size_t additional_len, uint8_t *out, size_t len)
{
	size_t *offset = state;

	ARG_UNUSED(additional);
	ARG_UNUSED(additional_len);
	if (len > sizeof(kat_seed) - *offset) {
		return -ENODATA;
	}
	memcpy(out, &kat_seed[*offset], len);
	*offset += len;
	return 0;
}

static void check_digest(const uint8_t *data, size_t len, const uint8_t *expected)
{
	uint8_t digest[32];

	zassert_ok(lc_hash(lc_sha3_256, data, len, digest));
	zassert_mem_equal(digest, expected, sizeof(digest));
}
#endif

static void operation_entry(void *arg, void *unused1, void *unused2)
{
	struct job *job = arg;
	struct buffers *b = job->buffers;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	job->cycles = k_cycle_get_32();
#ifdef CONFIG_TEST_LEANCRYPTO_BASELINE
	/* Retain all caller buffers and the same CSPRNG in the baseline. */
	job->result = sys_csrand_get(b, sizeof(*b));
#else
	switch (job->operation) {
	case KEYGEN:
		job->result = TEST_DSA(keypair)((struct TEST_DSA(pk) *)b->pk,
					       (struct TEST_DSA(sk) *)b->sk, NULL);
		break;
	case SIGN:
		job->result = TEST_DSA(sign)((struct TEST_DSA(sig) *)b->sig,
					     b->message, sizeof(b->message),
					     (const struct TEST_DSA(sk) *)b->sk,
					     job->deterministic ? NULL : lc_seeded_rng);
		break;
	case VERIFY:
		job->result = TEST_DSA(verify)((const struct TEST_DSA(sig) *)b->sig,
					       b->message, sizeof(b->message),
					       (const struct TEST_DSA(pk) *)b->pk);
		break;
	}
#endif
	job->cycles = k_cycle_get_32() - job->cycles;
}

static int run_operation(enum operation operation, struct buffers *buffers, const char *mode,
			 bool deterministic)
{
	static const char *const names[] = {"keygen", "sign", "verify"};
	struct job job = {
		.operation = operation,
		.buffers = buffers,
		.result = -EINPROGRESS,
		.deterministic = deterministic,
	};
	size_t unused;
	size_t usable;

	/* Recreating a joined thread repaints the entire stack with CONFIG_INIT_STACKS. */
	k_thread_create(&test_operation_thread, test_operation_stack,
			K_THREAD_STACK_SIZEOF(test_operation_stack), operation_entry,
			&job, NULL, NULL, K_PRIO_PREEMPT(1), 0, K_FOREVER);
	usable = test_operation_thread.stack_info.size;
	k_thread_start(&test_operation_thread);
	zassert_ok(k_thread_join(&test_operation_thread, K_SECONDS(60)));
	zassert_ok(k_thread_stack_space_get(&test_operation_thread, &unused));
	zassert_true(unused <= usable);
	zassert_true(unused >= 256U, "Insufficient stack headroom");
	printk("LC_STACK mode=%s op=%s peak=%zu usable=%zu reserved=%zu caller=%zu heap=0\n",
	       mode, names[operation], usable - unused, usable, sizeof(test_operation_stack),
	       sizeof(*buffers));
	printk("LC_TIME mode=%s op=%s cycles=%u duration_us=%llu result=%d\n",
	       mode, names[operation], job.cycles,
	       (unsigned long long)k_cyc_to_us_floor64(job.cycles), job.result);
	return job.result;
}

static void *suite_setup(void)
{
	struct buffers *buffers = test_buffers();

	printk("LC_PARAMETER_SET ML-DSA-%d\n", TEST_DSA_BITS);
	printk("LC_BUFFERS unit=bytes pk=%zu sk=%zu sig=%zu message=%zu total=%zu\n",
	       sizeof(buffers->pk), sizeof(buffers->sk), sizeof(buffers->sig),
	       sizeof(buffers->message), sizeof(*buffers));
	printk("LC_TIMER frequency_hz=%llu\n", (unsigned long long)sys_clock_hw_cycles_per_sec());
	return NULL;
}

ZTEST(TEST_SUITE_NAME, test_known_answer)
{
	struct buffers *buffers = test_buffers();
#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
	static const struct lc_rng fixed_rng = {.generate = fixed_generate};
	size_t offset = 0U;
	struct lc_rng_ctx fixed_ctx = {.rng = &fixed_rng, .rng_state = &offset};
	int result;

	memcpy(buffers->message, kat_msg, sizeof(kat_msg));
	zassert_ok(lc_rng_set_seeded(&fixed_ctx));
	result = run_operation(KEYGEN, buffers, "kat", true);
	zassert_ok(lc_rng_set_seeded(NULL));
	zassert_ok(result);
	zassert_equal(offset, sizeof(kat_seed));
	check_digest(buffers->pk, sizeof(buffers->pk), kat_pk);
	check_digest(buffers->sk, sizeof(buffers->sk), kat_sk);

	zassert_ok(run_operation(SIGN, buffers, "kat", true));
	check_digest(buffers->sig, sizeof(buffers->sig), kat_sig);
	zassert_ok(run_operation(VERIFY, buffers, "kat", true));
#else
	zassert_ok(run_operation(KEYGEN, buffers, "baseline", false));
	zassert_ok(run_operation(SIGN, buffers, "baseline", false));
	zassert_ok(run_operation(VERIFY, buffers, "baseline", false));
#endif
	memset(buffers, 0, sizeof(*buffers));
}

ZTEST(TEST_SUITE_NAME, test_random_sign_verify)
{
	struct buffers *buffers = test_buffers();
#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
	size_t before;

	zassert_ok(sys_csrand_get(buffers->message, sizeof(buffers->message)));
	before = test_csrand_calls;
#endif
	zassert_ok(run_operation(KEYGEN, buffers, "random", false));
#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
	zassert_true(test_csrand_calls > before, "Key generation bypassed sys_csrand_get");
	before = test_csrand_calls;
#endif
	zassert_ok(run_operation(SIGN, buffers, "random", false));
#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
	zassert_true(test_csrand_calls > before, "Signing bypassed sys_csrand_get");
#endif
	zassert_ok(run_operation(VERIFY, buffers, "random", false));
#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
	buffers->message[0] ^= 1U;
	zassert_true(run_operation(VERIFY, buffers, "invalid_message", false) < 0);
	buffers->message[0] ^= 1U;
	buffers->sig[0] ^= 1U;
	zassert_true(run_operation(VERIFY, buffers, "invalid_signature", false) < 0);
#endif
	memset(buffers, 0, sizeof(*buffers));
}

ZTEST(TEST_SUITE_NAME, test_random_failure)
{
#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
	struct buffers *buffers = test_buffers();
	uint8_t out[32];
	const uint8_t zeros[sizeof(out)] = {0};
	int keygen_result;
	int sign_result;
	int rng_result;

	zassert_ok(run_operation(KEYGEN, buffers, "failure_setup", false));
	test_injected_error = -EIO;
	rng_result = lc_rng_generate(lc_seeded_rng, NULL, 0U, out, sizeof(out));
	keygen_result = run_operation(KEYGEN, buffers, "rng_failure", false);
	sign_result = run_operation(SIGN, buffers, "rng_failure", false);
	test_injected_error = 0;
	zassert_equal(rng_result, -EIO);
	zassert_mem_equal(out, zeros, sizeof(out));
	zassert_equal(keygen_result, -EIO);
	zassert_equal(sign_result, -EIO);
	memset(buffers, 0, sizeof(*buffers));
#endif
}

ZTEST_SUITE(TEST_SUITE_NAME, NULL, suite_setup, NULL, NULL, NULL);
