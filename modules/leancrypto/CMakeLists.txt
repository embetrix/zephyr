# SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
# SPDX-License-Identifier: Apache-2.0

if(NOT CONFIG_LEANCRYPTO)
  return()
endif()

set(lc_dir "${ZEPHYR_LEANCRYPTO_MODULE_DIR}/upstream")
if(NOT EXISTS "${lc_dir}/meson.build")
  message(FATAL_ERROR
    "LeanCrypto requires a module wrapper with an initialized upstream/ submodule."
  )
endif()

set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/include")
file(MAKE_DIRECTORY "${generated_dir}")

# Reconfigure generated APIs when an upstream template changes after west update.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${lc_dir}/ml-kem/api/lc_kyber_size.h.in"
  "${lc_dir}/ml-dsa/api/lc_dilithium_size.h.in"
  "${lc_dir}/hash/api/lc_hash.h.in"
  "${lc_dir}/internal/api/lc_memory_support.h.in"
)

# Remove disabled headers: upstream detects available sizes with __has_include.
foreach(size IN ITEMS 512 768 1024)
  if(CONFIG_LEANCRYPTO_ML_KEM_${size})
    math(EXPR kyber_strength "${size} / 256")
    set(kyber_name "lc_kyber_${size}")
    set(kex_name "lc_kex_${size}")
    set(kyber_header "${size}_")
    file(READ "${lc_dir}/ml-kem/api/lc_kyber_size.h.in" contents)
    string(REGEX REPLACE "#mesondefine ([A-Za-z0-9_]+)" "/* #undef \\1 */" contents "${contents}")
    string(CONFIGURE "${contents}" contents @ONLY)
    file(CONFIGURE OUTPUT "${generated_dir}/lc_kyber_${size}.h" CONTENT "${contents}" @ONLY)
  else()
    file(REMOVE "${generated_dir}/lc_kyber_${size}.h")
  endif()
endforeach()

foreach(size IN ITEMS 44 65 87)
  if(CONFIG_LEANCRYPTO_ML_DSA_${size})
    if(size EQUAL 44)
      set(dilithium_strength 2)
    elseif(size EQUAL 65)
      set(dilithium_strength 3)
    else()
      set(dilithium_strength 5)
    endif()
    set(dilithium_name "lc_dilithium_${size}")
    set(dilithium_macro "LC_DILITHIUM_${size}")
    set(dilithium_header "${size}_")
    file(READ "${lc_dir}/ml-dsa/api/lc_dilithium_size.h.in" contents)
    string(REGEX REPLACE "#mesondefine ([A-Za-z0-9_]+)" "/* #undef \\1 */" contents "${contents}")
    string(CONFIGURE "${contents}" contents @ONLY)
    file(CONFIGURE OUTPUT "${generated_dir}/lc_dilithium_${size}.h" CONTENT "${contents}" @ONLY)
  else()
    file(REMOVE "${generated_dir}/lc_dilithium_${size}.h")
  endif()
endforeach()

set(hash_common_alignment 8)
foreach(header IN ITEMS
    internal/api/lc_memory_support
    hash/api/lc_hash
)
  file(READ "${lc_dir}/${header}.h.in" contents)
  string(REGEX REPLACE "#mesondefine ([A-Za-z0-9_]+)" "/* #undef \\1 */" contents "${contents}")
  string(CONFIGURE "${contents}" contents @ONLY)
  get_filename_component(output "${header}.h" NAME)
  file(CONFIGURE OUTPUT "${generated_dir}/${output}" CONTENT "${contents}" @ONLY)
endforeach()

zephyr_library_named(leancrypto)
# Consumers link this target to obtain the upstream API and platform environment.
target_include_directories(leancrypto PUBLIC
  "${generated_dir}"
  "${lc_dir}/ml-kem/api"
  "${lc_dir}/ml-dsa/api"
  "${lc_dir}/hash/api"
  "${lc_dir}/drng/api"
  "${lc_dir}/internal/api"
  "${lc_dir}/kmac/api"
)
target_compile_options(leancrypto PUBLIC
  "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/leancrypto_platform.h"
)
target_compile_definitions(leancrypto PUBLIC LC_STATIC LC_SHA3 LC_KMAC)
zephyr_library_compile_options(-fno-strict-aliasing)
zephyr_library_include_directories(
  "${lc_dir}/ml-kem/src"
  "${lc_dir}/hash/src"
)
zephyr_library_sources(
  platform.c
  memory.c
  "${lc_dir}/hash/src/hash.c"
  "${lc_dir}/hash/src/sha3_c.c"
  "${lc_dir}/hash/src/sha3_selftest.c"
  "${lc_dir}/hash/src/cshake.c"
  "${lc_dir}/kmac/src/kmac.c"
  "${lc_dir}/drng/src/rng_api.c"
  "${lc_dir}/drng/src/rng_api_non_fips.c"
  "${lc_dir}/drng/src/static_rng.c"
  "${lc_dir}/internal/src/fips_mode.c"
  "${lc_dir}/internal/src/compare.c"
  "${lc_dir}/internal/src/null_buffer.c"
  "${lc_dir}/internal/src/status_algorithms.c"
  "${lc_dir}/internal/src/memcmp_secure_c.c"
  "${lc_dir}/internal/src/memcpy_secure_c.c"
  "${lc_dir}/internal/src/left_encode.c"
)

if(CONFIG_LEANCRYPTO_ML_KEM_512 OR CONFIG_LEANCRYPTO_ML_KEM_768 OR CONFIG_LEANCRYPTO_ML_KEM_1024)
  target_compile_definitions(leancrypto PUBLIC LC_KYBER)
  zephyr_library_sources(
    "${lc_dir}/ml-kem/src/kyber_api.c"
    "${lc_dir}/ml-kem/src/kyber_cbd.c"
    "${lc_dir}/ml-kem/src/kyber_zetas.c"
    "${lc_dir}/ml-kem/src/kyber_ntt.c"
  )
endif()

# Match Meson's separate compilation of the parameter-dependent sources.
foreach(size IN ITEMS 512 768 1024)
  if(CONFIG_LEANCRYPTO_ML_KEM_${size})
    zephyr_library_named(leancrypto_ml_kem_${size})
    target_link_libraries(leancrypto_ml_kem_${size} PUBLIC leancrypto)
    if(NOT size EQUAL 1024)
      zephyr_library_compile_definitions(LC_KYBER_TYPE_${size})
    endif()
    zephyr_library_compile_options(-fno-strict-aliasing)
    zephyr_library_include_directories("${lc_dir}/ml-kem/src")
    zephyr_library_sources(
      "${lc_dir}/ml-kem/src/kyber_kem.c"
      "${lc_dir}/ml-kem/src/kyber_kem_c.c"
      "${lc_dir}/ml-kem/src/kyber_kem_api_c.c"
      "${lc_dir}/ml-kem/src/kyber_indcpa.c"
      "${lc_dir}/ml-kem/src/kyber_poly.c"
      "${lc_dir}/ml-kem/src/kyber_polyvec.c"
      "${lc_dir}/ml-kem/src/kyber_selftest.c"
      "${lc_dir}/ml-kem/src/kyber_selftest_kdf.c"
    )
  endif()
endforeach()

if(CONFIG_LEANCRYPTO_ML_DSA_44 OR CONFIG_LEANCRYPTO_ML_DSA_65 OR CONFIG_LEANCRYPTO_ML_DSA_87)
  target_compile_definitions(leancrypto PUBLIC LC_DILITHIUM)
  zephyr_library_named(leancrypto_ml_dsa_common)
  target_link_libraries(leancrypto_ml_dsa_common PUBLIC leancrypto)
  # Shared polynomial routines need a type header, but have size-independent code.
  if(NOT CONFIG_LEANCRYPTO_ML_DSA_87)
    if(CONFIG_LEANCRYPTO_ML_DSA_65)
      zephyr_library_compile_definitions(LC_DILITHIUM_TYPE_65)
    else()
      zephyr_library_compile_definitions(LC_DILITHIUM_TYPE_44)
    endif()
  endif()
  zephyr_library_compile_options(-fno-strict-aliasing)
  zephyr_library_include_directories("${lc_dir}/curve25519/api")
  zephyr_library_sources(
    "${lc_dir}/ml-dsa/src/dilithium_common_api.c"
    "${lc_dir}/ml-dsa/src/dilithium_keygen_api.c"
    "${lc_dir}/ml-dsa/src/dilithium_siggen_api.c"
    "${lc_dir}/ml-dsa/src/dilithium_sigver_api.c"
    "${lc_dir}/ml-dsa/src/dilithium_ntt.c"
    "${lc_dir}/ml-dsa/src/dilithium_poly.c"
    "${lc_dir}/ml-dsa/src/dilithium_rounding.c"
    "${lc_dir}/ml-dsa/src/dilithium_zetas.c"
    "${lc_dir}/internal/src/signature_domain_separation.c"
  )
endif()

foreach(size IN ITEMS 44 65 87)
  if(CONFIG_LEANCRYPTO_ML_DSA_${size})
    target_compile_definitions(leancrypto PUBLIC LC_DILITHIUM_${size}_OPT_ENABLED)
    zephyr_library_named(leancrypto_ml_dsa_${size})
    target_link_libraries(leancrypto_ml_dsa_${size} PUBLIC leancrypto)
    if(NOT size EQUAL 87)
      zephyr_library_compile_definitions(LC_DILITHIUM_TYPE_${size})
    endif()
    zephyr_library_compile_options(-fno-strict-aliasing)
    zephyr_library_sources(
      "${lc_dir}/ml-dsa/src/dilithium_poly_type.c"
      "${lc_dir}/ml-dsa/src/dilithium_rounding_type.c"
      "${lc_dir}/ml-dsa/src/dilithium_selftest.c"
      "${lc_dir}/ml-dsa/src/dilithium_signature_helper.c"
      "${lc_dir}/ml-dsa/src/dilithium_signature_keygen_c.c"
      "${lc_dir}/ml-dsa/src/dilithium_signature_siggen_c.c"
      "${lc_dir}/ml-dsa/src/dilithium_signature_sigver_c.c"
      "${lc_dir}/ml-dsa/src/dilithium_signature_keygen_api_c.c"
      "${lc_dir}/ml-dsa/src/dilithium_signature_siggen_api_c.c"
      "${lc_dir}/ml-dsa/src/dilithium_signature_sigver_api_c.c"
    )
  endif()
endforeach()
