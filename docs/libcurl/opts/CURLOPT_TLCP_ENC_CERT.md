---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TLCP_ENC_CERT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSLCERT (3)
  - CURLOPT_TLCP_ENC_KEY (3)
  - CURLOPT_TLCP_ENC_KEYPASSWD (3)
Protocol:
  - TLS
TLS-backend:
  - openHiTLS
Added-in: 8.16.0
---

# NAME

CURLOPT_TLCP_ENC_CERT - TLCP encryption certificate

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TLCP_ENC_CERT, char *cert);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the filename of your TLCP encryption certificate.

**This option is only available when curl is built with openHiTLS support.**

TLCP (Transport Layer Cryptography Protocol) is a Chinese national cryptographic
standard that uses a dual-certificate system where separate certificates are used
for signing and encryption operations.

This option specifies the encryption certificate, which is used for key
exchange and data encryption in TLCP connections. It must be used in
conjunction with CURLOPT_SSLCERT(3) which provides the signing certificate.

The certificate format is typically PEM but can be DER. For TLCP connections,
both the signing certificate (CURLOPT_SSLCERT(3)) and encryption certificate
(CURLOPT_TLCP_ENC_CERT(3)) must be provided along with their corresponding
private keys.

When using TLCP encryption certificate, you also need to provide the
corresponding private key with CURLOPT_TLCP_ENC_KEY(3).

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
