# SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(leancrypto)

target_sources(app PRIVATE src/test_support.c)

if(CONFIG_TEST_LEANCRYPTO_ALL)
  foreach(family IN ITEMS kem dsa)
    if(family STREQUAL "kem")
      set(parameter_sets 512 768 1024)
      set(source_file "src/main.c")
      set(parameter_macro "TEST_KEM_BITS")
    else()
      set(parameter_sets 44 65 87)
      set(source_file "src/mldsa.c")
      set(parameter_macro "TEST_DSA_BITS")
    endif()
    foreach(bits IN LISTS parameter_sets)
      set(test_target "leancrypto_test_${family}_${bits}")
      add_library(${test_target} OBJECT "${source_file}")
      add_dependencies(${test_target} zephyr_generated_headers)
      target_link_libraries(${test_target} PRIVATE zephyr_interface)
      if(NOT CONFIG_TEST_LEANCRYPTO_BASELINE)
        target_link_libraries(${test_target} PRIVATE leancrypto)
      endif()
      target_compile_definitions(${test_target} PRIVATE
        "${parameter_macro}=${bits}"
        "TEST_SUITE_NAME=leancrypto_ml_${family}_${bits}"
      )
      target_sources(app PRIVATE "$<TARGET_OBJECTS:${test_target}>")
    endforeach()
  endforeach()
elseif(CONFIG_TEST_LEANCRYPTO_ML_DSA)
  target_sources(app PRIVATE src/mldsa.c)
else()
  target_sources(app PRIVATE src/main.c)
endif()
if(NOT CONFIG_TEST_LEANCRYPTO_BASELINE)
  target_link_libraries(app PRIVATE leancrypto)
  zephyr_ld_options(-Wl,--wrap=z_impl_sys_csrand_get)
endif()
