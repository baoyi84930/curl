# curl TLS 选项与 openHiTLS 支持状态

本文档记录当前 openHiTLS 后端对 curl TLS 相关选项的支持状态。结论以当前 `lib/vtls/openhitls.c` 的实现和 `Curl_ssl_openhitls.supports` 能力位为准。

## 1. 支持状态总览

| 能力/选项 | 命令行 | libcurl API | openHiTLS 状态 | 说明 |
| --- | --- | --- | --- | --- |
| CA 文件 | `--cacert` | `CURLOPT_CAINFO` | 支持 | 用于验证对端证书 |
| CA 目录 | `--capath` | `CURLOPT_CAPATH` | 支持 | 声明 `SSLSUPP_CA_PATH` |
| CA blob | 无 | `CURLOPT_CAINFO_BLOB` | 支持 | 声明 `SSLSUPP_CAINFO_BLOB`，proxy CA blob 同样可用 |
| 系统默认 CA | 默认行为 | 默认行为 | 支持 | 未显式配置 CA 时调用 openHiTLS 默认 CA 路径加载 |
| 客户端证书文件 | `--cert` | `CURLOPT_SSLCERT` | 支持 | PEM/DER，PEM 证书链使用 chain file 接口 |
| 客户端证书 blob | 无 | `CURLOPT_SSLCERT_BLOB` | 支持 | 使用 certificate chain buffer |
| 客户端私钥文件 | `--key` | `CURLOPT_SSLKEY` | 支持 | PEM/DER |
| 客户端私钥 blob | 无 | `CURLOPT_SSLKEY_BLOB` | 部分支持 | 调用 openHiTLS key buffer 接口；当前失败时返回 `CURLE_NOT_BUILT_IN` |
| 私钥密码 | `--pass` | `CURLOPT_KEYPASSWD` | 支持 | 通过 openHiTLS password callback 配置 |
| 证书格式 | `--cert-type` | `CURLOPT_SSLCERTTYPE` | 支持 | PEM/DER/P12；P12 走专用加载路径 |
| 私钥格式 | `--key-type` | `CURLOPT_SSLKEYTYPE` | 支持 | PEM/DER；P12 私钥单独加载不支持 |
| CRL 文件 | `--crlfile` | `CURLOPT_CRLFILE` | 支持 | 声明 `SSLSUPP_CRLFILE` |
| issuer cert | 无 | `CURLOPT_ISSUERCERT` | 不支持 | 未声明 `SSLSUPP_ISSUERCERT` |
| issuer cert blob | 无 | `CURLOPT_ISSUERCERT_BLOB` | 不支持 | 未声明 `SSLSUPP_ISSUERCERT_BLOB` |
| 对端证书验证 | `-k/--insecure` | `CURLOPT_SSL_VERIFYPEER` | 支持 | 默认验证，`-k` 关闭 |
| 主机名验证 | `-k/--insecure` | `CURLOPT_SSL_VERIFYHOST` | 支持 | DNS hostname 支持；当前 IP address hostname verify 未实现 |
| OCSP stapling | `--cert-status` | `CURLOPT_SSL_VERIFYSTATUS` | 不支持 | `cert_status_request` 回调为空 |
| 证书信息 | 无 | `CURLOPT_CERTINFO` | 支持 | 声明 `SSLSUPP_CERTINFO` |
| pinned public key | `--pinnedpubkey` | `CURLOPT_PINNEDPUBLICKEY` | 支持 | 声明 `SSLSUPP_PINNEDPUBKEY` |
| TLS 1.2 | `--tlsv1.2` | `CURLOPT_SSLVERSION` | 支持 | 标准 TLS |
| TLS 1.3 | `--tlsv1.3` | `CURLOPT_SSLVERSION` | 支持 | 标准 TLS |
| TLS 1.0/1.1 | `--tlsv1.0` / `--tlsv1.1` | `CURLOPT_SSLVERSION` | 不支持 | 后端版本兼容检查会拒绝 |
| TLS 最大版本 | `--tls-max` | `CURLOPT_SSLVERSION` | 支持 | TLS 1.2/1.3 范围内 |
| TLS 1.2 cipher list | `--ciphers` | `CURLOPT_SSL_CIPHER_LIST` | 支持 | 声明 `SSLSUPP_CIPHER_LIST` |
| TLS 1.3 ciphersuites | `--tls13-ciphers` | `CURLOPT_TLS13_CIPHERS` | 支持 | 声明 `SSLSUPP_TLS13_CIPHERSUITES` |
| groups/curves | `--curves` | `CURLOPT_SSL_EC_CURVES` | 支持 | 声明 `SSLSUPP_SSL_EC_CURVES`，调用 `HITLS_CFG_SetGroupList()` |
| signature algorithms | `--sigalgs` | `CURLOPT_SSL_SIGNATURE_ALGORITHMS` | 支持 | 声明 `SSLSUPP_SIGNATURE_ALGORITHMS` |
| ALPN | `--no-alpn` | `CURLOPT_SSL_ENABLE_ALPN` | 支持 | 用于 HTTP/2 协商 |
| session id cache | `--no-sessionid` | `CURLOPT_SSL_SESSIONID_CACHE` | 基础可用 | curl 通用选项可设置，openHiTLS 后端当前未声明专门能力位 |
| CA cache timeout | 无 | `CURLOPT_CA_CACHE_TIMEOUT` | 不支持 | 未声明 `SSLSUPP_CA_CACHE` |
| SSL ctx callback | 无 | `CURLOPT_SSL_CTX_FUNCTION` | 支持 | 声明 `SSLSUPP_SSL_CTX`，回调收到 `HITLS_Config *` |
| ECH | `--ech` | `CURLOPT_ECH` | 不支持 | 未声明 `SSLSUPP_ECH` |

## 2. HTTPS proxy TLS 选项

openHiTLS 声明 `SSLSUPP_HTTPS_PROXY`，proxy 侧 TLS 配置会复用对应的 proxy ssl config。

| 命令行 | libcurl API | openHiTLS 状态 |
| --- | --- | --- |
| `--proxy-cacert` | `CURLOPT_PROXY_CAINFO` | 支持 |
| `--proxy-capath` | `CURLOPT_PROXY_CAPATH` | 支持 |
| 无 | `CURLOPT_PROXY_CAINFO_BLOB` | 支持 |
| `--proxy-cert` | `CURLOPT_PROXY_SSLCERT` | 支持 |
| `--proxy-key` | `CURLOPT_PROXY_SSLKEY` | 支持 |
| `--proxy-pass` | `CURLOPT_PROXY_KEYPASSWD` | 支持 |
| `--proxy-insecure` | `CURLOPT_PROXY_SSL_VERIFYPEER` / `CURLOPT_PROXY_SSL_VERIFYHOST` | 支持 |
| `--proxy-ciphers` | `CURLOPT_PROXY_SSL_CIPHER_LIST` | 支持 |
| `--proxy-tls13-ciphers` | `CURLOPT_PROXY_TLS13_CIPHERS` | 支持 |
| `--proxy-pinnedpubkey` | `CURLOPT_PROXY_PINNEDPUBLICKEY` | 支持 |
| 无 | `CURLOPT_PROXY_ISSUERCERT` / `CURLOPT_PROXY_ISSUERCERT_BLOB` | 不支持 |

## 3. groups/curves

curl 入口：

```bash
curl --curves X25519 https://www.google.com/
```

libcurl 入口：

```c
curl_easy_setopt(curl, CURLOPT_SSL_EC_CURVES, "X25519");
```

实现说明：

- openHiTLS 后端直接把 curl 传入的字符串交给 `HITLS_CFG_SetGroupList(config, curves, len)`。
- 该配置在 `HITLS_New()` 前完成。
- 无效 group 会返回 `CURLE_SSL_CIPHER`。
- 当前没有新增 curl 通用测试用例，避免对所有 TLS 后端强加同一规格；已通过命令行 smoke 验证。

## 4. signature algorithms

curl 入口：

```bash
curl --sigalgs rsa_pss_rsae_sha256 https://www.google.com/
curl --sigalgs ECDSA+SHA256 https://www.google.com/
```

libcurl 入口：

```c
curl_easy_setopt(curl, CURLOPT_SSL_SIGNATURE_ALGORITHMS,
                 "rsa_pss_rsae_sha256");
```

实现说明：

- 支持 IANA 风格签名算法名称。
- 支持 curl/OpenSSL 常见别名，例如 `ECDSA+SHA256`。
- 支持 `0xNNNN` 十六进制 codepoint。
- curl 侧只保留必要别名表；未知名称会调用 openHiTLS 新增接口：

```c
int32_t HITLS_CFG_GetSignatureSchemeId(const HITLS_Config *config,
                                       const char *name,
                                       uint16_t *id);
```

这样 provider 新增的签名算法只要能被 openHiTLS config 识别，就不需要修改 curl 的固定映射表。

## 5. 证书加载时机

openHiTLS 当前有一个约束：`HITLS_New()` 之后再修改 `HITLS_Config` 中的证书/信任材料，已创建的 SSL 对象建链时无法感知。

因此当前 openHiTLS 后端的顺序是：

1. 创建 `HITLS_Config`。
2. 设置 TLS 版本、cipher、TLS 1.3 cipher、groups、sigalgs。
3. 加载客户端证书、证书链和私钥。
4. 加载 CAfile、CApath、CAinfo blob 和 CRL。
5. 调用 `CURLOPT_SSL_CTX_FUNCTION`。
6. 调用 `HITLS_New()` 创建 SSL 对象。
7. 设置 SNI、ALPN 并开始握手。

这与 OpenSSL/wolfSSL/mbedTLS 的总体思路一致：影响 TLS 配置上下文的材料先放到 config/ctx，再创建或初始化具体连接对象。

## 6. smoke 验证建议

不为 `--curves`、`--sigalgs` 新增 curl 通用测试用例，原因是 TLS 后端支持规格差异较大。当前建议使用构建出的 curl 二进制做定向 smoke：

```bash
LD_LIBRARY_PATH=/path/to/openhitls/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    -w "ca_ok http_code=%{http_code} ssl_verify=%{ssl_verify_result}\n" \
    https://www.google.com/

LD_LIBRARY_PATH=/path/to/openhitls/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --curves X25519 https://www.google.com/

LD_LIBRARY_PATH=/path/to/openhitls/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --sigalgs rsa_pss_rsae_sha256 https://www.google.com/

LD_LIBRARY_PATH=/path/to/openhitls/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --sigalgs ECDSA+SHA256 https://www.google.com/
```

错误参数应失败：

```bash
LD_LIBRARY_PATH=/path/to/openhitls/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --curves NONSENSE https://www.google.com/

LD_LIBRARY_PATH=/path/to/openhitls/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --sigalgs NONSENSE https://www.google.com/
```

## 7. TLCP 说明

当前仓库中仍保留 TLCP 相关适配内容，但社区首批 PR 计划不包含 TLCP：

- `--tlcp1.1`
- `--tlcp-enc-cert`
- `--tlcp-enc-key`
- `CURLOPT_TLCP_ENC_CERT`
- `CURLOPT_TLCP_ENC_KEY`
- `CURLOPT_TLCP_ENC_KEYPASSWD`

这些内容后续作为单独 TLCP patch 维护和评审。

## 最后更新

2026-07-14
