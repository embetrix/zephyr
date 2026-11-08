.. SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
.. SPDX-License-Identifier: Apache-2.0

.. _leancrypto:

LeanCrypto
##########

LeanCrypto provides portable C implementations of ML-KEM-512/768/1024 and
ML-DSA-44/65/87 through its upstream API.

Configuration
*************

See :zephyr_file:`modules/leancrypto/README.rst` for module setup.
Enable an entropy driver and configure the application:

.. code-block:: cfg

   CONFIG_CSPRNG_NEEDED=y
   CONFIG_LEANCRYPTO=y
   CONFIG_LEANCRYPTO_ML_KEM_768=y

ML-KEM-768 defaults to enabled when LeanCrypto is selected. The other parameter
sets are independently selectable through ``CONFIG_LEANCRYPTO_ML_KEM_512``,
``CONFIG_LEANCRYPTO_ML_KEM_1024``, and ``CONFIG_LEANCRYPTO_ML_DSA_{44,65,87}``.
Disable ``CONFIG_LEANCRYPTO_ML_KEM_768`` for a signature-only build.

Link the application after ``find_package(Zephyr ...)``:

.. code-block:: cmake

   target_link_libraries(app PRIVATE leancrypto)

API and randomness
******************

Include ``<lc_kyber_768.h>`` for ``lc_kyber_768_keypair()``,
``lc_kyber_768_enc()``, and ``lc_kyber_768_dec()``. Replace ``768`` with ``512``
or ``1024`` for the other parameter sets.

Include ``<lc_dilithium_44.h>`` for ``lc_dilithium_44_keypair()``,
``lc_dilithium_44_sign()``, and ``lc_dilithium_44_verify()``. Replace ``44``
with ``65`` or ``87`` for the other parameter sets.

Key generation with a NULL RNG and ML-KEM encapsulation use
:c:func:`sys_csrand_get`. For randomized ML-DSA signing, pass ``lc_seeded_rng``:

.. code-block:: c

   ret = lc_dilithium_44_sign(&signature, message, message_size,
                              &secret_key, lc_seeded_rng);

A NULL signing RNG selects deterministic ML-DSA. The adapter clears its RNG
output on failure and propagates the provider's error. Check operation return
values before using outputs. Do not replace the global RNG during concurrent use.

Memory and tests
****************

Callers provide key, ciphertext/signature, and shared-secret buffers. Library
scratch uses the calling thread's stack. ``LC_MEM_ON_HEAP`` is disabled; the
one-shot operations require no heap. Optional allocating APIs require a configured
Zephyr system heap.

See :zephyr_file:`tests/crypto/leancrypto/README.rst` for buffer sizes, per-operation
stack and timing results, image baselines, and build/flash commands.

Licensing
*********

The integration uses LeanCrypto's BSD licensing alternatives. Preserve the
upstream ``LICENSE``, ``LICENSE.bsd``, and individual source notices when
redistributing the library. The Apache-2.0 license on the Zephyr glue does not
relicense LeanCrypto.
