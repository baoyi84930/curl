---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlcp-enc-key
Arg: <key>
Help: TLCP encryption private key file
Protocols: TLS
Category: tls
Added: 8.16.0
Multi: single
See-also:
  - tlcp-enc-cert
  - tlcp1.1
  - cert
  - key
Example:
  - --tlcp-enc-key encryptkey.pem $URL
---

# `--tlcp-enc-key`

Specify the TLCP encryption private key file when using TLCP (Transport Layer Cryptography Protocol). In TLCP, separate private keys are used for signing and encryption operations.

The private key must be in PEM format. This option works in conjunction with --tlcp-enc-cert to provide the encryption certificate and private key pair.

This option is only available when curl is built with openHiTLS support that includes TLCP capabilities.