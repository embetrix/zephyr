/*
 * SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <lc_dilithium.h>
#include <lc_hash.h>
#include <lc_kyber.h>
#include <lc_sha3.h>

enum operation {
	KEYGEN,
	ENCAPSULATE,
	DECAPSULATE,
	SIGN,
	VERIFY,
};

struct blob {
	const uint8_t *data;
	size_t len;
};

struct vector {
	const char *id;
	enum operation operation;
	uint32_t type;
	bool dsa;
	bool valid;
	struct blob seed;
	struct blob pk;
	struct blob sk;
	struct blob ct;
	struct blob ss;
	struct blob sig;
	struct blob msg;
	struct blob context;
};

#include "vectors.h"

/* Shared by sequential cases; the worker is recreated before every operation. */
static K_THREAD_STACK_DEFINE(worker_stack, 160 * 1024);

struct buffers {
	union {
		struct {
			struct lc_kyber_pk pk;
			struct lc_kyber_sk sk;
			struct lc_kyber_ct ct;
			struct lc_kyber_ss ss;
		} kem;
		struct {
			struct lc_dilithium_pk pk;
			struct lc_dilithium_sk sk;
			struct lc_dilithium_sig sig;
		} dsa;
	};
	/* One extra byte allows long-import tests without reading past the input. */
	uint8_t encoded[sizeof(struct lc_dilithium_87_sig) + 1U];
};

static struct buffers *caller_buffers(void)
{
	static struct buffers buffers;

	return &buffers;
}

struct fixed_rng {
	struct blob seed;
	size_t used;
};

struct job {
	const struct vector *vector;
	struct buffers *buffers;
	struct lc_rng_ctx *rng;
	struct blob context;
	int result;
	uint32_t cycles;
};

static int generate(void *state, const uint8_t *additional, size_t additional_len,
		    uint8_t *out, size_t len)
{
	struct fixed_rng *rng = state;

	ARG_UNUSED(additional);
	ARG_UNUSED(additional_len);
	if (rng->used > rng->seed.len || len > rng->seed.len - rng->used) {
		return -ENODATA;
	}
	memcpy(out, rng->seed.data + rng->used, len);
	rng->used += len;
	return 0;
}

static int dsa_operation(struct job *job)
{
	const struct vector *v = job->vector;
	struct buffers *b = job->buffers;

	if (v->operation == KEYGEN) {
		return lc_dilithium_keypair(&b->dsa.pk, &b->dsa.sk, job->rng, v->type);
	}

	LC_DILITHIUM_CTX_ON_STACK(ctx);
	lc_dilithium_ctx_userctx(ctx, job->context.data, job->context.len);
	if (v->operation == SIGN) {
		return lc_dilithium_sign_ctx(&b->dsa.sig, ctx, v->msg.data, v->msg.len,
					    &b->dsa.sk, v->seed.len > 0U ? job->rng : NULL);
	}
	return lc_dilithium_verify_ctx(&b->dsa.sig, ctx, v->msg.data, v->msg.len, &b->dsa.pk);
}

static void operation_entry(void *arg, void *unused1, void *unused2)
{
	struct job *job = arg;
	struct buffers *b = job->buffers;
	const struct vector *v = job->vector;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	job->cycles = k_cycle_get_32();
	if (v->dsa) {
		job->result = dsa_operation(job);
	} else {
		switch (v->operation) {
		case KEYGEN:
			job->result = lc_kyber_keypair(&b->kem.pk, &b->kem.sk, job->rng, v->type);
			break;
		case ENCAPSULATE:
			job->result = lc_kyber_enc(&b->kem.ct, &b->kem.ss, &b->kem.pk);
			break;
		case DECAPSULATE:
			job->result = lc_kyber_dec(&b->kem.ss, &b->kem.ct, &b->kem.sk);
			break;
		default:
			job->result = -EINVAL;
			break;
		}
	}
	job->cycles = k_cycle_get_32() - job->cycles;
}

static int run_operation(const struct vector *v, struct buffers *b, struct blob context)
{
	static struct k_thread thread;
	static const struct lc_rng rng = {.generate = generate};
	struct fixed_rng fixed = {.seed = v->seed};
	struct lc_rng_ctx rng_ctx = {.rng = &rng, .rng_state = &fixed};
	struct job job = {.vector = v, .buffers = b, .context = context, .rng = &rng_ctx};
	size_t unused;
	size_t usable;
	int join_result;

	if (v->operation == ENCAPSULATE) {
		zassert_ok(lc_rng_set_seeded(&rng_ctx));
	}
	k_thread_create(&thread, worker_stack, K_THREAD_STACK_SIZEOF(worker_stack),
			operation_entry, &job, NULL, NULL, K_PRIO_PREEMPT(1), 0, K_FOREVER);
	usable = thread.stack_info.size;
	k_thread_start(&thread);
	join_result = k_thread_join(&thread, K_SECONDS(60));
	if (v->operation == ENCAPSULATE) {
		zassert_ok(lc_rng_set_seeded(NULL));
	}
	zassert_ok(join_result);
	zassert_ok(k_thread_stack_space_get(&thread, &unused));
	zassert_true(unused >= 256U && unused <= usable);
	zassert_equal(fixed.used, v->seed.len, "%s: unexpected RNG consumption", v->id);
	printk("LC_ACVP %s op=%u result=%d peak=%zu usable=%zu reserved=%zu caller=%zu "
	       "heap=0 duration_us=%llu\n", v->id, v->operation, job.result, usable - unused,
	       usable, sizeof(worker_stack), sizeof(*b),
	       (unsigned long long)k_cyc_to_us_floor64(job.cycles));
	return job.result;
}

static void prepare(const struct vector *v, struct buffers *b)
{
	memset(b, 0, sizeof(*b));
	switch (v->operation) {
	case KEYGEN:
		break;
	case ENCAPSULATE:
		zassert_ok(lc_kyber_pk_load(&b->kem.pk, v->pk.data, v->pk.len));
		break;
	case DECAPSULATE:
		zassert_ok(lc_kyber_sk_load(&b->kem.sk, v->sk.data, v->sk.len));
		zassert_ok(lc_kyber_ct_load(&b->kem.ct, v->ct.data, v->ct.len));
		break;
	case SIGN:
		zassert_ok(lc_dilithium_sk_load(&b->dsa.sk, v->sk.data, v->sk.len));
		break;
	case VERIFY:
		zassert_ok(lc_dilithium_pk_load(&b->dsa.pk, v->pk.data, v->pk.len));
		zassert_ok(lc_dilithium_sig_load(&b->dsa.sig, v->sig.data, v->sig.len));
		break;
	}
}

static void check_digest(const uint8_t *data, size_t len, struct blob expected)
{
	uint8_t digest[32];

	zassert_equal(expected.len, sizeof(digest));
	zassert_ok(lc_hash(lc_sha3_256, data, len, digest));
	zassert_mem_equal(digest, expected.data, sizeof(digest));
}

static void check_output(const struct vector *v, struct buffers *b)
{
	uint8_t *data;
	size_t len;

	switch (v->operation) {
	case KEYGEN:
		if (v->dsa) {
			zassert_ok(lc_dilithium_pk_ptr(&data, &len, &b->dsa.pk));
		} else {
			zassert_ok(lc_kyber_pk_ptr(&data, &len, &b->kem.pk));
		}
		check_digest(data, len, v->pk);
		if (v->dsa) {
			zassert_ok(lc_dilithium_sk_ptr(&data, &len, &b->dsa.sk));
		} else {
			zassert_ok(lc_kyber_sk_ptr(&data, &len, &b->kem.sk));
		}
		check_digest(data, len, v->sk);
		break;
	case ENCAPSULATE:
		zassert_ok(lc_kyber_ct_ptr(&data, &len, &b->kem.ct));
		check_digest(data, len, v->ct);
		__fallthrough;
	case DECAPSULATE:
		zassert_ok(lc_kyber_ss_ptr(&data, &len, &b->kem.ss));
		zassert_equal(len, v->ss.len);
		zassert_mem_equal(data, v->ss.data, len);
		break;
	case SIGN:
		zassert_ok(lc_dilithium_sig_ptr(&data, &len, &b->dsa.sig));
		check_digest(data, len, v->sig);
		break;
	case VERIFY:
		break;
	}
}

ZTEST(leancrypto_acvp, test_vectors)
{
	struct buffers *b = caller_buffers();

	for (size_t i = 0U; i < ARRAY_SIZE(vectors); i++) {
		const struct vector *v = &vectors[i];
		int result;

		prepare(v, b);
		result = run_operation(v, b, v->context);
		if (v->valid) {
			zassert_ok(result, "%s", v->id);
			check_output(v, b);
		} else {
			zassert_true(result < 0, "%s: invalid signature accepted", v->id);
		}
	}
	memset(b, 0, sizeof(*b));
}

ZTEST(leancrypto_acvp, test_boundaries)
{
	static const uint8_t long_context[256];
	static const uint8_t wrong_context[] = "wrong";
	struct buffers *b = caller_buffers();

	for (size_t i = 0U; i < ARRAY_SIZE(vectors); i++) {
		const struct vector *v = &vectors[i];
		uint8_t *key;
		size_t key_len;

		if (v->operation == DECAPSULATE) {
			memcpy(b->encoded, v->ct.data, v->ct.len);
			zassert_true(lc_kyber_ct_load(&b->kem.ct, b->encoded, v->ct.len - 1U) < 0);
			zassert_true(lc_kyber_ct_load(&b->kem.ct, b->encoded, v->ct.len + 1U) < 0);
		}
		if (v->operation != VERIFY || !v->valid) {
			continue;
		}
		prepare(v, b);
		/* Changing rho produces another public key without changing its encoding size. */
		zassert_ok(lc_dilithium_pk_ptr(&key, &key_len, &b->dsa.pk));
		zassert_true(key_len > 0U);
		key[0] ^= 1U;
		zassert_true(run_operation(v, b, v->context) < 0, "Wrong key accepted");
		key[0] ^= 1U;
		zassert_true(run_operation(v, b, (struct blob){wrong_context,
			     sizeof(wrong_context) - 1U}) < 0, "Wrong context accepted");
		zassert_true(run_operation(v, b, (struct blob){long_context,
			     sizeof(long_context)}) < 0, "256-byte context accepted");
		memcpy(b->encoded, v->sig.data, v->sig.len);
		zassert_true(lc_dilithium_sig_load(&b->dsa.sig, b->encoded, v->sig.len - 1U) < 0);
		zassert_true(lc_dilithium_sig_load(&b->dsa.sig, b->encoded, v->sig.len + 1U) < 0);
	}
	memset(b, 0, sizeof(*b));
}

ZTEST_SUITE(leancrypto_acvp, NULL, NULL, NULL, NULL, NULL);
