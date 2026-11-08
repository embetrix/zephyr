.. SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
.. SPDX-License-Identifier: Apache-2.0

LeanCrypto module
#################

Zephyr integration maintainer: Ayoub Zaki (GitHub: ``embetrix``),
<ayoub.zaki@embetrix.com>.

This integration uses LeanCrypto v1.9.1, upstream commit
``65eb4e7e84e3a5499460a66b1623ccf6c59628b1``.

The module wrapper contains ``zephyr/module.yml`` and an ``upstream/`` Git
submodule pinned to the unmodified library. The metadata selects the CMake and
Kconfig files in this directory, alongside the randomness and memory adapters.

The repository URL and revision in ``west.yml`` still need to be replaced with
the published wrapper repository and commit. ``submodules: true`` initializes
its pinned library. This wrapper layout remains subject to mainline acceptance.

Until the wrapper is published, select a checkout with its submodule initialized:

.. code-block:: console

   export ZEPHYR_EXTRA_MODULES=/path/to/leancrypto-zephyr

Build configuration
*******************

CMake explicitly selects portable ML-KEM/ML-DSA, SHA-3/SHAKE, cSHAKE/KMAC,
RNG API, and support sources. Shared routines compile once; parameter-dependent
routines compile for each enabled size. Public headers are generated from the
upstream templates. The build uses ``LC_STATIC``, ``LC_SHA3``, ``LC_KMAC``,
parameter-set feature definitions, and ``-fno-strict-aliasing``.

Assembly, XDRBG, upstream seed sources, runtime self-tests, hybrid algorithms,
and ``LC_MEM_ON_HEAP`` are disabled. ``platform.c`` supplies randomness through
``sys_csrand_get()``. ``leancrypto_platform.h`` replaces the upstream POSIX header
environment. ``memory.c`` maps optional allocating APIs to the Zephyr heap.

See ``doc/services/crypto/leancrypto.rst`` for application usage and
``tests/crypto/leancrypto/README.rst`` for validation and footprint results.
