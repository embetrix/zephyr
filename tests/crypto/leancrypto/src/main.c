/*
 * SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/ztest.h>

#include "test_support.h"

#ifndef TEST_KEM_BITS
#if defined(CONFIG_TEST_LEANCRYPTO_ML_KEM_512)
#define TEST_KEM_BITS 512
#elif defined(CONFIG_TEST_LEANCRYPTO_ML_KEM_1024)
#define TEST_KEM_BITS 1024
#else
#define TEST_KEM_BITS 768
#endif
#endif

#ifndef TEST_SUITE_NAME
#define TEST_SUITE_NAME leancrypto
#endif

#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
#if TEST_KEM_BITS == 512
#include <lc_kyber_512.h>
#elif TEST_KEM_BITS == 1024
#include <lc_kyber_1024.h>
#else
#include <lc_kyber_768.h>
#endif
#include <lc_hash.h>
#include <lc_sha3.h>
#include "kat.h"
#endif

#if TEST_KEM_BITS == 512
#define TEST_KEM(name) lc_kyber_512_##name
#define TEST_PK_SIZE 800
#define TEST_SK_SIZE 1632
#define TEST_CT_SIZE 768
#elif TEST_KEM_BITS == 1024
#define TEST_KEM(name) lc_kyber_1024_##name
#define TEST_PK_SIZE 1568
#define TEST_SK_SIZE 3168
#define TEST_CT_SIZE 1568
#else
#define TEST_KEM(name) lc_kyber_768_##name
#define TEST_PK_SIZE 1184
#define TEST_SK_SIZE 2400
#define TEST_CT_SIZE 1088
#endif

enum operation {
	KEYGEN,
	ENCAPSULATE,
	DECAPSULATE,
};

/* Identical caller-owned storage in the crypto and baseline images. */
struct buffers {
	uint8_t pk[TEST_PK_SIZE];
	uint8_t sk[TEST_SK_SIZE];
	uint8_t ct[TEST_CT_SIZE];
	uint8_t enc_ss[32];
	uint8_t dec_ss[32];
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
};

#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
BUILD_ASSERT(sizeof(struct TEST_KEM(pk)) == sizeof(((struct buffers *)0)->pk));
BUILD_ASSERT(sizeof(struct TEST_KEM(sk)) == sizeof(((struct buffers *)0)->sk));
BUILD_ASSERT(sizeof(struct TEST_KEM(ct)) == sizeof(((struct buffers *)0)->ct));
BUILD_ASSERT(sizeof(struct TEST_KEM(ss)) == sizeof(((struct buffers *)0)->enc_ss));

static int fixed_generate(void *state, const uint8_t *additional,
			  size_t additional_len, uint8_t *out, size_t len)
{
	size_t *offset = state;

	ARG_UNUSED(additional);
	ARG_UNUSED(additional_len);
	if (len > sizeof(kat_random) - *offset) {
		return -ENODATA;
	}
	memcpy(out, &kat_random[*offset], len);
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
		job->result = TEST_KEM(keypair)((struct TEST_KEM(pk) *)b->pk,
						 (struct TEST_KEM(sk) *)b->sk, NULL);
		break;
	case ENCAPSULATE:
		job->result = TEST_KEM(enc)((struct TEST_KEM(ct) *)b->ct,
					     (struct TEST_KEM(ss) *)b->enc_ss,
					     (const struct TEST_KEM(pk) *)b->pk);
		break;
	case DECAPSULATE:
		job->result = TEST_KEM(dec)((struct TEST_KEM(ss) *)b->dec_ss,
					     (const struct TEST_KEM(ct) *)b->ct,
					     (const struct TEST_KEM(sk) *)b->sk);
		break;
	}
#endif
	job->cycles = k_cycle_get_32() - job->cycles;
}

static int run_operation(enum operation operation, struct buffers *buffers, const char *mode)
{
	static const char *const names[] = {"keygen", "encapsulate", "decapsulate"};
	struct job job = {.operation = operation, .buffers = buffers, .result = -EINPROGRESS};
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

	printk("LC_PARAMETER_SET ML-KEM-%d\n", TEST_KEM_BITS);
	printk("LC_BUFFERS unit=bytes pk=%zu sk=%zu ct=%zu enc_ss=%zu dec_ss=%zu total=%zu\n",
	       sizeof(buffers->pk), sizeof(buffers->sk), sizeof(buffers->ct),
	       sizeof(buffers->enc_ss), sizeof(buffers->dec_ss), sizeof(*buffers));
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

	zassert_ok(lc_rng_set_seeded(&fixed_ctx));
	result = run_operation(KEYGEN, buffers, "kat");
	zassert_ok(lc_rng_set_seeded(NULL));
	zassert_ok(result);
	zassert_equal(offset, 64U);
	check_digest(buffers->pk, sizeof(buffers->pk), kat_pk);
	check_digest(buffers->sk, sizeof(buffers->sk), kat_sk);

	zassert_ok(lc_rng_set_seeded(&fixed_ctx));
	result = run_operation(ENCAPSULATE, buffers, "kat");
	zassert_ok(lc_rng_set_seeded(NULL));
	zassert_ok(result);
	zassert_equal(offset, sizeof(kat_random));
	check_digest(buffers->ct, sizeof(buffers->ct), kat_ct);
	zassert_mem_equal(buffers->enc_ss, kat_ss, sizeof(kat_ss));

	zassert_ok(run_operation(DECAPSULATE, buffers, "kat"));
	zassert_mem_equal(buffers->dec_ss, kat_ss, sizeof(kat_ss));
#else
	zassert_ok(run_operation(KEYGEN, buffers, "baseline"));
	zassert_ok(run_operation(ENCAPSULATE, buffers, "baseline"));
	zassert_ok(run_operation(DECAPSULATE, buffers, "baseline"));
#endif
	memset(buffers, 0, sizeof(*buffers));
}

ZTEST(TEST_SUITE_NAME, test_random_round_trip)
{
	struct buffers *buffers = test_buffers();
#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
	size_t before = test_csrand_calls;
#endif

	zassert_ok(run_operation(KEYGEN, buffers, "random"));
	zassert_ok(run_operation(ENCAPSULATE, buffers, "random"));
	zassert_ok(run_operation(DECAPSULATE, buffers, "random"));
#ifndef CONFIG_TEST_LEANCRYPTO_BASELINE
	zassert_true(test_csrand_calls >= before + 2U, "Operations bypassed sys_csrand_get");
	zassert_mem_equal(buffers->enc_ss, buffers->dec_ss, sizeof(buffers->enc_ss));

	/* FIPS 203 implicit rejection: modified ciphertext must not recover the key. */
	buffers->ct[0] ^= 1U;
	zassert_ok(run_operation(DECAPSULATE, buffers, "invalid_ciphertext"));
	zassert_not_equal(memcmp(buffers->enc_ss, buffers->dec_ss, sizeof(buffers->enc_ss)), 0);
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
	int enc_result;
	int rng_result;

	zassert_ok(run_operation(KEYGEN, buffers, "failure_setup"));
	test_injected_error = -EIO;
	rng_result = lc_rng_generate(lc_seeded_rng, NULL, 0U, out, sizeof(out));
	keygen_result = run_operation(KEYGEN, buffers, "rng_failure");
	enc_result = run_operation(ENCAPSULATE, buffers, "rng_failure");
	test_injected_error = 0;
	zassert_equal(rng_result, -EIO);
	zassert_mem_equal(out, zeros, sizeof(out));
	zassert_equal(keygen_result, -EIO);
	zassert_equal(enc_result, -EIO);
	memset(buffers, 0, sizeof(*buffers));
#endif
}

ZTEST_SUITE(TEST_SUITE_NAME, NULL, suite_setup, NULL, NULL, NULL);
