.. SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
.. SPDX-License-Identifier: Apache-2.0

Independent ACVP regression tests
#################################

The two ztests execute 30 NIST cases across all six parameter sets and additional
wrong-key, wrong-context, 256-byte context, and short/long import checks.
ML-DSA cases include deterministic and randomized signing, altered messages, and
malformed hints. ML-KEM decapsulation compares the exact published shared secret
for valid and modified ciphertexts. Large generated outputs are checked against
SHA3-256 digests computed with Python's ``hashlib`` from NIST's expected bytes.

Each cryptographic operation uses a freshly initialized 160 KiB worker stack.
``LC_ACVP`` records its case ID, result, stack peak, caller buffers, and time.
The heap capacity is zero. Caller buffers and the reserved worker stack are
already included in linker RAM totals. This scenario has no matching baseline;
use the parent suite for the documented image-delta comparisons.

Run on MPS2/AN385 QEMU:

.. code-block:: console

   west twister -p mps2/an385 -T tests/crypto/leancrypto/acvp -O /tmp/lc-acvp -i

For STM32F769I Discovery, use ``-p stm32f769i_disco`` and add
``--device-testing --device-serial /dev/ttyACM0 --west-flash --west-runner openocd``.

On STM32F769I Discovery with SDK 1.0.1 / GNU Arm 14.3.0, the scenario passed
on November 8, 2026. The Twister image used 196256 FLASH and 191616 RAM bytes,
including the 163904-byte worker reservation and 16746-byte caller buffers.
The maximum observed worker peak was 123872 bytes. QEMU also passed. Both runs
used the companion module metadata commit; the manifest update remains pending.

Vector source
*************

NIST ACVP-Server revision ``975de31eb83d87039ec88934fdc47d8c312b892d``, under
``gen-val/json-files``: ML-KEM keyGen/encapDecap (FIPS203) and ML-DSA
keyGen/sigGen/sigVer (FIPS204). Generated entries retain the source name,
``tgId``, and ``tcId``. See the `pinned NIST corpus`_.

To regenerate, save each directory's ``internalProjection.json`` as
``<directory-name>.json`` in one directory, then run:

.. code-block:: console

   python3 tests/crypto/leancrypto/acvp/generate.py /path/to/json-files

The generator checks all five input SHA-256 hashes before emitting the vectors.
The data retains NIST's notice in ``LICENSES/NIST-Software.txt``. These sampled
regressions do not constitute ACVP certification.

.. _pinned NIST corpus:
   https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files
