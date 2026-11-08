.. SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
.. SPDX-License-Identifier: Apache-2.0

LeanCrypto tests
################

The suite covers all three ML-KEM and ML-DSA parameter sets with known-answer
vectors, randomized operations, invalid-input rejection, and RNG failure checks.
KATs compare SHA3-256 digests of upstream vector outputs; deterministic test RNGs
are confined to the test. STM32 uses its hardware RNG; QEMU uses a test CSPRNG.

The separate ``crypto.leancrypto.acvp`` scenario checks 30 pinned NIST cases,
including exact implicit-rejection secrets, plus wrong-key/context and import
length boundaries. It has its own footprint; see ``acvp/README.rst``.

Build and run
*************

Run from the Zephyr checkout with the west environment and SDK configured.
The LeanCrypto checkout must contain ``zephyr/module.yml``; see
``modules/leancrypto/README.rst`` for the pending manifest update.

Build all six parameter sets into one image, flash, and open the console:

.. code-block:: console

   west build -b stm32f769i_disco tests/crypto/leancrypto \
     -d build/leancrypto -- -DEXTRA_CONF_FILE=combined.conf
   west flash -d build/leancrypto --runner openocd
   minicom -D /dev/ttyACM0 -b 115200

Press RESET to run all 18 cases. Close Minicom before using Twister.

Run all scenarios, including baselines, on the simulator or board:

.. code-block:: console

   west twister -p mps2/an385 -T tests/crypto/leancrypto \
     -O /tmp/lc-sim -i
   west twister -p stm32f769i_disco -T tests/crypto/leancrypto \
     -O /tmp/lc-board --device-testing --device-serial /dev/ttyACM0 \
     --west-flash --west-runner openocd -j 1 -i

For Cortex-M build-only validation, replace the device-testing, serial, and
runner options with ``--build-only``. To select one scenario, add
``-s crypto.leancrypto.combined``, ``-s crypto.leancrypto.ml_kem_768``, or
``-s crypto.leancrypto.ml_dsa_44``; substitute the desired parameter set.

Twister saves serial output in each scenario's ``handler.log``:

.. code-block:: console

   rg --no-heading 'LC_' /tmp/lc-board -g handler.log

``LC_BUFFERS`` reports caller storage, ``LC_STACK`` stack peaks and budgets, and
``LC_TIME`` operation durations. Linker FLASH/RAM totals are in ``build.log``.

Measurement
***********

Each operation runs in a dedicated worker thread. The controller joins it and
queries ``k_thread_stack_space_get()``. Recreating the thread with
``CONFIG_INIT_STACKS=y`` paints the stack afresh for the next operation. Peaks
include library scratch, RNG calls, and worker overhead; output checking and
logging run outside the worker.

ML-KEM tests reserve 24576 usable stack bytes; ML-DSA and combined tests reserve
163840. STM32 and MPS2 add 64 guard bytes. The combined test shares one worker
stack across all six suites. These are measured peaks, not worst-case bounds.

Timing surrounds the API call and includes interrupts, RNG waits, and counter
read overhead. Measurements are single observations; signing time varies with
rejection sampling. QEMU timing is simulated, not hardware performance.

``LC_MEM_ON_HEAP`` is disabled and reserved heap capacity is zero. Heap relocation
and peak heap usage were not evaluated. Static RAM totals already include caller
buffers, full reserved stacks, guards, and kernel/test state: do not add measured
stack peaks or buffer sizes again.

Baselines retain the same harness, console, CSPRNG, caller buffers, and stack
budget with LeanCrypto disabled. Flash deltas include library, adapter, and
additional test/vector code. They are not library-only sizes or additive costs.

Recorded results
****************

November 8, 2026: Zephyr ``c4b2cc1d85e2`` plus this integration, LeanCrypto v1.9.1
(``65eb4e7e84e3a5499460a66b1623ccf6c59628b1``), SDK 1.0.1, GNU Arm 14.3.0,
``CONFIG_SIZE_OPTIMIZATIONS=y``. All sizes are bytes.

The 14 individual/coexistence scenarios passed on STM32F769I Discovery and QEMU.
The combined image passed all 18 cases on both targets; its baseline passed in
QEMU and was built, but not run, on STM32. The full QEMU run passed 16 scenarios
and 78 cases.

.. csv-table:: Caller buffers, excluding alignment
   :header: "Variant", "Public key", "Secret key", "Ciphertext/signature", "Other", "Total"

   ML-KEM-512, 800, 1632, 768, 64, 3264
   ML-KEM-768, 1184, 2400, 1088, 64, 4736
   ML-KEM-1024, 1568, 3168, 1568, 64, 6368
   ML-DSA-44, 1312, 2560, 2420, 64, 6356
   ML-DSA-65, 1952, 4032, 3309, 64, 9357
   ML-DSA-87, 2592, 4896, 4627, 64, 12179

"Other" is two 32-byte shared secrets for ML-KEM or a 64-byte message for ML-DSA.
Combined caller storage is 42260 bytes before alignment.

.. csv-table:: Individual-image stack peaks: key generation / encap or sign / decap or verify
   :header: "Variant", "STM32 hardware", "MPS2/AN385 QEMU"

   ML-KEM-512, 6820 / 9276 / 10268, 6856 / 9312 / 10304
   ML-KEM-768, 10924 / 13820 / 15132, 10960 / 13856 / 15168
   ML-KEM-1024, 16044 / 19452 / 21280, 16080 / 19488 / 21280
   ML-DSA-44, 30848 / 53224 / 28628, 30848 / 53224 / 28628
   ML-DSA-65, 50312 / 80880 / 47060, 50312 / 80880 / 47096
   ML-DSA-87, 83080 / 123888 / 77780, 83080 / 123888 / 77780

Baseline worker peaks were 216 bytes and are not subtracted. Combined hardware
peaks matched the individual images except ML-KEM-1024 decapsulation (21244).
The largest combined peak was 123888 bytes, leaving 39952 usable bytes untouched.

.. csv-table:: STM32 randomized durations (microseconds, 216 MHz timer)
   :header: "Variant", "Key generation", "Encapsulation/signing", "Decapsulation/verification"

   ML-KEM-512, 8706, 9554, 12350
   ML-KEM-768, 17045, 19536, 24927
   ML-KEM-1024, 26174, 28992, 35774
   ML-DSA-44, 30582, 94341, 32163
   ML-DSA-65, 65808, 168701, 66601
   ML-DSA-87, 91645, 115347, 93900

.. csv-table:: STM32 linker usage: baseline / functional image / delta
   :header: "Variant", "FLASH", "Static RAM"

   ML-KEM-512, 37264 / 50080 / +12816, 35712 / 35776 / +64
   ML-KEM-768, 37264 / 49960 / +12696, 37184 / 37248 / +64
   ML-KEM-1024, 37264 / 50192 / +12928, 38784 / 38912 / +128
   ML-DSA-44, 37276 / 55120 / +17844, 178048 / 178176 / +128
   ML-DSA-65, 37276 / 54600 / +17324, 181056 / 181184 / +128
   ML-DSA-87, 37276 / 54912 / +17636, 183872 / 184000 / +128
   Combined, 42976 / 92268 / +49292, 214336 / 214464 / +128

STM32 images use zero DTCM. The combined totals above are direct ``west build``
results. Its Twister image used 92392 FLASH bytes and 214464 RAM bytes; the run
identifier adds flash overhead. The board has 2097152 FLASH and 393216 RAM bytes.

.. csv-table:: MPS2/AN385 QEMU linker usage: baseline / functional image / delta
   :header: "Variant", "FLASH", "Static RAM"

   ML-KEM-512, 26876 / 39684 / +12808, 39296 / 39424 / +128
   ML-KEM-768, 26876 / 39572 / +12696, 40768 / 40896 / +128
   ML-KEM-1024, 26876 / 39788 / +12912, 42432 / 42496 / +64
   ML-DSA-44, 26888 / 44592 / +17704, 181696 / 181760 / +64
   ML-DSA-65, 26888 / 44104 / +17216, 184640 / 184768 / +128
   ML-DSA-87, 26888 / 44392 / +17504, 187520 / 187584 / +64

Reproduce the combined baseline:

.. code-block:: console

   west build -b stm32f769i_disco tests/crypto/leancrypto \
     -d build/leancrypto-baseline -- -DCONFIG_LEANCRYPTO=n \
     -DCONFIG_TEST_LEANCRYPTO_BASELINE=y -DCONFIG_TEST_LEANCRYPTO_ALL=y

Individual baseline scenarios are ``crypto.leancrypto.baseline`` (ML-KEM-768),
``crypto.leancrypto.baseline_{512,1024}``, and
``crypto.leancrypto.baseline_ml_dsa_{44,65,87}``. ``all_enabled`` scenarios call
only one parameter set; use ``combined`` to retain and exercise all six.

For symbol breakdowns, run ``west build -d <scenario-build-dir> -t rom_report``
and ``-t ram_report``. Compare matching target, toolchain, and configuration.
