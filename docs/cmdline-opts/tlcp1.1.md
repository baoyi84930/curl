---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlcp1.1
Help: TLCP v1.1 or greater
Protocols: TLS
Category: tls
Added: 8.16.0
Multi: mutex
See-also:
  - tlsv1.1
  - tls-max
  - tlcp-enc-cert
Example:
  - --tlcp1.1 $URL
---

# `--tlcp1.1`

Force curl to use TLCP (Transport Layer Cryptography Protocol) version 1.1 or later when connecting to a remote server. TLCP is a Chinese national cryptographic protocol standard (GM/T 0024).

This option is only available when curl is built with openHiTLS support that includes TLCP capabilities.