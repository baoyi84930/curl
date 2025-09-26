---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlcp-enc-cert
Arg: <certificate[:password]>
Help: TLCP encryption certificate file and password
Protocols: TLS
Category: tls
Added: 8.16.0
Multi: single
See-also:
  - tlcp-enc-key
  - tlcp1.1
  - cert
  - key
Example:
  - --tlcp-enc-cert encryptcert.pem $URL
---

# `--tlcp-enc-cert`

Specify the TLCP encryption certificate file when using TLCP (Transport Layer Cryptography Protocol). In TLCP, separate certificates are used for signing and encryption operations.

The certificate must be in PEM format. This option works in conjunction with --tlcp-enc-key to provide the encryption certificate and private key pair.

This option is only available when curl is built with openHiTLS support that includes TLCP capabilities.