/*
 * SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>

#include <lc_memory_support.h>

/* Optional allocating APIs use the application's system heap, never libc. */
int lc_alloc_aligned(void **memptr, size_t alignment, size_t size)
{
	if (memptr == NULL || alignment == 0U || (alignment & (alignment - 1U)) != 0U) {
		return -EINVAL;
	}
	*memptr = k_aligned_alloc(MAX(alignment, sizeof(void *)), size);
	if (*memptr == NULL) {
		return -ENOMEM;
	}
	memset(*memptr, 0, size);
	return 0;
}

int lc_alloc_aligned_secure(void **memptr, size_t alignment, size_t size)
{
	return lc_alloc_aligned(memptr, alignment, size);
}

int lc_alloc_high_aligned(void **memptr, size_t alignment, size_t size)
{
	return lc_alloc_aligned(memptr, alignment, size);
}

void lc_free(void *ptr)
{
	k_free(ptr);
}

void lc_free_high_aligned(void *ptr, size_t size)
{
	ARG_UNUSED(size);
	k_free(ptr);
}
