/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * Test TLCP (Transport Layer Cryptography Protocol) API options
 */

#include "first.h"

#include "memdebug.h"

static CURLcode test_lib8001(const char *URL)
{
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;

  (void)URL; /* not used */

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  /* Test CURLOPT_TLCP_ENC_CERT - TLCP encryption certificate */
  test_setopt(curl, CURLOPT_TLCP_ENC_CERT,
              "tests/certs/test-tlcp-enc-cert.pem");

  /* Test CURLOPT_TLCP_ENC_KEY - TLCP encryption private key */
  test_setopt(curl, CURLOPT_TLCP_ENC_KEY,
              "tests/certs/test-tlcp-enc-cert.key");

  /* Test CURLOPT_TLCP_ENC_KEYPASSWD - TLCP encryption key password */
  test_setopt(curl, CURLOPT_TLCP_ENC_KEYPASSWD, "test123");

  /* Test setting TLCP signing cert/key (using standard SSL options) */
  test_setopt(curl, CURLOPT_SSLCERT,
              "tests/certs/test-tlcp-sign-cert.pem");
  test_setopt(curl, CURLOPT_SSLKEY,
              "tests/certs/test-tlcp-sign-cert.key");

  /* Test multiple set (override previous value) */
  test_setopt(curl, CURLOPT_TLCP_ENC_CERT,
              "tests/certs/test-tlcp-enc-cert.pem");

  /* Test setting to NULL (clear value) */
  test_setopt(curl, CURLOPT_TLCP_ENC_KEYPASSWD, NULL);

  /* Test setting empty string */
  test_setopt(curl, CURLOPT_TLCP_ENC_KEYPASSWD, "");

  test_setopt(curl, CURLOPT_SSL_CIPHER_LIST,
              "ECDHE-SM4-CBC-SM3:ECC-SM4-CBC-SM3:"
              "ECDHE-SM4-GCM-SM3:ECC-SM4-GCM-SM3");

  curl_mprintf("TLCP API test: all setopt calls succeeded\n");

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
