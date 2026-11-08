/*
 * SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/random/random.h>

#include <lc_rng.h>
#include <lc_memset_secure.h>

static int zephyr_rng_generate(void *state, const uint8_t *additional,
			       size_t additional_len, uint8_t *out, size_t len)
{
	int ret;

	ARG_UNUSED(state);
	ARG_UNUSED(additional);
	ARG_UNUSED(additional_len);

	if (len == 0U) {
		return 0;
	}
	if (out == NULL) {
		return -EINVAL;
	}

	ret = sys_csrand_get(out, len);
	if (ret != 0) {
		lc_memset_secure(out, 0, len);
	}
	return ret;
}

static const struct lc_rng zephyr_rng = {
	.generate = zephyr_rng_generate,
};
static struct lc_rng_ctx zephyr_rng_ctx = {
	.rng = &zephyr_rng,
};

struct lc_rng_ctx *lc_seeded_rng = &zephyr_rng_ctx;
struct lc_rng_ctx *lc_seeded_rng_internal = &zephyr_rng_ctx;
