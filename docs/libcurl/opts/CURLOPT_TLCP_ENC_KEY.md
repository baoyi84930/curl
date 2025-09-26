---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TLCP_ENC_KEY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSLKEY (3)
  - CURLOPT_TLCP_ENC_CERT (3)
  - CURLOPT_TLCP_ENC_KEYPASSWD (3)
Protocol:
  - TLS
TLS-backend:
  - openHiTLS
Added-in: 8.16.0
---

# NAME

CURLOPT_TLCP_ENC_KEY - TLCP encryption private key

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TLCP_ENC_KEY, char *keyfile);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the filename of your TLCP encryption private key.

**This option is only available when curl is built with openHiTLS support.**

TLCP (Transport Layer Cryptography Protocol) is a Chinese national cryptographic
standard that uses a dual-certificate system where separate private keys are used
for signing and encryption operations.

This option specifies the encryption private key that corresponds to the
encryption certificate set with CURLOPT_TLCP_ENC_CERT(3). The default format
is PEM but can also be DER.

For TLCP connections, both the signing private key (CURLOPT_SSLKEY(3)) and
encryption private key (CURLOPT_TLCP_ENC_KEY(3)) must be provided along with
their corresponding certificates.

If the private key is password-protected, use CURLOPT_TLCP_ENC_KEYPASSWD(3)
to provide the passphrase.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://tlcp-server.example.com/");

    /* Set TLCP signing certificate and key */
    curl_easy_setopt(curl, CURLOPT_SSLCERT, "tlcp_sign.pem");
    curl_easy_setopt(curl, CURLOPT_SSLKEY, "tlcp_sign_key.pem");

    /* Set TLCP encryption certificate and key */
    curl_easy_setopt(curl, CURLOPT_TLCP_ENC_CERT, "tlcp_enc.pem");
    curl_easy_setopt(curl, CURLOPT_TLCP_ENC_KEY, "tlcp_enc_key.pem");

    /* If encryption key is password protected */
    curl_easy_setopt(curl, CURLOPT_TLCP_ENC_KEYPASSWD, "enc_secret");

    /* Force TLCP protocol */
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
