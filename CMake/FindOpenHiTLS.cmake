#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
# Find the openHiTLS library
#
# Input variables:
#
# - `OPENHITLS_INCLUDE_DIR`:      Absolute path to openHiTLS include directory.
# - `OPENHITLS_TLS_LIBRARY`:      Absolute path to `hitls_tls` library.
# - `OPENHITLS_PKI_LIBRARY`:      Absolute path to `hitls_pki` library.
# - `OPENHITLS_CRYPTO_LIBRARY`:   Absolute path to `hitls_crypto` library.
# - `OPENHITLS_BSL_LIBRARY`:      Absolute path to `hitls_bsl` library.
#
# Defines:
#
# - `OPENHITLS_FOUND`:            System has openHiTLS.
# - `OPENHITLS_VERSION`:          Version of openHiTLS.
# - `CURL::openhitls`:            openHiTLS library target.

find_path(OPENHITLS_INCLUDE_DIR NAMES "hitls/tls/hitls.h")
find_library(OPENHITLS_TLS_LIBRARY NAMES "hitls_tls")
find_library(OPENHITLS_PKI_LIBRARY NAMES "hitls_pki")
find_library(OPENHITLS_CRYPTO_LIBRARY NAMES "hitls_crypto")
find_library(OPENHITLS_BSL_LIBRARY NAMES "hitls_bsl")

unset(OPENHITLS_VERSION CACHE)
if(OPENHITLS_INCLUDE_DIR AND
   EXISTS "${OPENHITLS_INCLUDE_DIR}/hitls/bsl/bsl_version.h")
  set(_version_regex "#[\t ]*define[\t ]+OPENHITLS_VERSION_S[\t ]+\"openHiTLS[\t ]+([0-9.]+).*\"")
  file(STRINGS "${OPENHITLS_INCLUDE_DIR}/hitls/bsl/bsl_version.h" _version_str REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
  set(OPENHITLS_VERSION "${_version_str}")
  unset(_version_regex)
  unset(_version_str)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenHiTLS
  REQUIRED_VARS
    OPENHITLS_INCLUDE_DIR
    OPENHITLS_TLS_LIBRARY
    OPENHITLS_PKI_LIBRARY
    OPENHITLS_CRYPTO_LIBRARY
    OPENHITLS_BSL_LIBRARY
  VERSION_VAR
    OPENHITLS_VERSION
)

if(OPENHITLS_FOUND)
  set(_openhitls_INCLUDE_DIRS
    "${OPENHITLS_INCLUDE_DIR}"
    "${OPENHITLS_INCLUDE_DIR}/hitls"
    "${OPENHITLS_INCLUDE_DIR}/hitls/tls"
    "${OPENHITLS_INCLUDE_DIR}/hitls/pki"
    "${OPENHITLS_INCLUDE_DIR}/hitls/crypto"
    "${OPENHITLS_INCLUDE_DIR}/hitls/bsl")
  set(_openhitls_LIBRARIES
    "${OPENHITLS_TLS_LIBRARY}"
    "${OPENHITLS_PKI_LIBRARY}"
    "${OPENHITLS_CRYPTO_LIBRARY}"
    "${OPENHITLS_BSL_LIBRARY}")

  if(NOT TARGET CURL::openhitls)
    add_library(CURL::openhitls INTERFACE IMPORTED)
    set_target_properties(CURL::openhitls PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${_openhitls_INCLUDE_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_openhitls_LIBRARIES}")
  endif()
endif()

mark_as_advanced(
  OPENHITLS_INCLUDE_DIR
  OPENHITLS_TLS_LIBRARY
  OPENHITLS_PKI_LIBRARY
  OPENHITLS_CRYPTO_LIBRARY
  OPENHITLS_BSL_LIBRARY)
