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
 * Test that TLCP options are rejected on non-openHiTLS backends
 */

#include "first.h"

static CURLcode test_lib8002(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;

  (void)URL; /* not used */
  (void)curl; /* not used */
  (void)result; /* not used */

#ifdef USE_OPENHITLS
  /* This test should NOT run when openHiTLS is enabled */
  curl_mprintf("SKIP: This test is for non-openHiTLS backends only\n");
  return CURLE_OK;
#else
  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  /* Try to set TLCP encryption certificate on non-openHiTLS backend */
  result = curl_easy_setopt(curl, CURLOPT_TLCP_ENC_CERT, "test.pem");
  if(result == CURLE_NOT_BUILT_IN || result == CURLE_UNKNOWN_OPTION) {
    /* Expected: option not supported */
    curl_mprintf("TLCP option correctly rejected: CURLOPT_TLCP_ENC_CERT\n");
  }
  else if(result == CURLE_OK) {
    /* Unexpected: option accepted */
    curl_mprintf("ERROR: TLCP option should be rejected on "
                 "non-openHiTLS backend\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  else {
    /* Unexpected error */
    curl_mprintf("ERROR: Unexpected error code: %d\n", result);
    goto test_cleanup;
  }

  /* Try to set TLCP encryption key */
  result = curl_easy_setopt(curl, CURLOPT_TLCP_ENC_KEY, "test_key.pem");
  if(result == CURLE_NOT_BUILT_IN || result == CURLE_UNKNOWN_OPTION) {
    curl_mprintf("TLCP option correctly rejected: CURLOPT_TLCP_ENC_KEY\n");
  }
  else if(result == CURLE_OK) {
    curl_mprintf("ERROR: TLCP option should be rejected\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  else {
    curl_mprintf("ERROR: Unexpected error code: %d\n", result);
    goto test_cleanup;
  }

  /* Try to set TLCP encryption key password */
  result = curl_easy_setopt(curl, CURLOPT_TLCP_ENC_KEYPASSWD, "password");
  if(result == CURLE_NOT_BUILT_IN || result == CURLE_UNKNOWN_OPTION) {
    curl_mprintf("TLCP option correctly rejected: "
                 "CURLOPT_TLCP_ENC_KEYPASSWD\n");
  }
  else if(result == CURLE_OK) {
    curl_mprintf("ERROR: TLCP option should be rejected\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  else {
    curl_mprintf("ERROR: Unexpected error code: %d\n", result);
    goto test_cleanup;
  }

  curl_mprintf("Non-openHiTLS backend test: PASS\n");
  result = CURLE_OK;

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
#endif
}
