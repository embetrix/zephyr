/*
 * SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_LEANCRYPTO_PLATFORM_H_
#define ZEPHYR_MODULES_LEANCRYPTO_PLATFORM_H_

/* Replace upstream's POSIX environment before its quoted includes are parsed. */
#define EXT_HEADERS_H

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define LC_PURE __attribute__((pure))
#define lc_member_size(type, member) sizeof(((type *)0)->member)
#define SYSV_ABI
#define LC_FIPS_RODATA_SECTION
#ifndef noinline
#define noinline __attribute__((noinline))
#endif
#ifndef fallthrough
#define fallthrough __attribute__((fallthrough))
#endif

#endif /* ZEPHYR_MODULES_LEANCRYPTO_PLATFORM_H_ */
