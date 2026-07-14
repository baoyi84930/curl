# curl + openHiTLS 集成适配总结

## 1. 当前基线

本文档记录当前 `curl/` 目录中 openHiTLS 后端的实际适配状态。

- curl 基线：`8.21.1-DEV`，已从历史 `8.16.0` 适配刷新到当前 master。
- openHiTLS 基线：主分支，curl 构建侧最低要求后续 `0.4.0`，通过 `OPENHITLS_VERSION_I >= 0x00400000ULL` 检查。
- openHiTLS 不再依赖外部 Secure_C，curl 集成文档和构建脚本不再需要 Secure_C 相关步骤。
- autotools 和 CMake 构建路径均已适配 openHiTLS。
- TLCP 相关命令行参数、API 和文档仍作为独立 patch 维护，暂不纳入准备提交 curl 社区的首批 PR。

## 2. 代码集成范围

主要代码和构建文件：

- `lib/vtls/openhitls.c`：openHiTLS TLS 后端实现。
- `lib/vtls/vtls.c`、`lib/vtls/vtls_int.h`：TLS 后端注册和能力位接入。
- `configure.ac`、`m4/curl-openhitls.m4`：autotools 检测。
- `CMakeLists.txt`、`CMake/FindOpenHiTLS.cmake`、`CMake/curl-config.in.cmake`：CMake 检测和安装包支持。
- `docs/INSTALL.md`、`docs/cmdline-opts/*`、`docs/libcurl/opts/*`：用户可见文档。

openHiTLS 后端注册名为 `openhitls`，`curl -V` 中显示为 `OpenHiTLS`。

## 3. 构建适配

### 3.1 autotools

启用方式：

```bash
autoreconf -fi
./configure --with-openhitls=/path/to/install --without-openssl
```

当前行为：

- 不依赖 `openhitls.pc`，因为 openHiTLS 当前安装目录不会生成 `.pc` 文件。
- 直接检查 openHiTLS 头文件、版本宏和基础链接能力。
- 基础链接检查使用 `HITLS_CFG_NewTLSConfig()`、`HITLS_New()` 等基础 API。
- openHiTLS 库写入 `OPENHITLS_LIBS`，并进入 `libcurl.pc` 的 `Libs.private`。
- 不写 `Requires.private: openhitls`，避免生成无法解析的 pkg-config 依赖。
- versioned symbols 已包含 `OPENHITLS_` 分支，启用后生成 `CURL_OPENHITLS_4` 符号版本前缀。
- 默认 SSL 后端提示信息包含 `--with-openhitls`。

### 3.2 CMake

启用方式：

```bash
cmake -S curl -B build-openhitls \
    -DCMAKE_PREFIX_PATH=/path/to/install \
    -DCURL_USE_OPENHITLS=ON \
    -DCURL_USE_OPENSSL=OFF
```

当前行为：

- curl 自带 `CMake/FindOpenHiTLS.cmake`，不要求 openHiTLS 提供 `OpenHiTLSConfig.cmake`。
- 版本检查读取 `include/hitls/bsl/bsl_version.h`。
- `FindOpenHiTLS.cmake` 会随 curl 的 CMake package 安装到 `lib/cmake/CURL/`。
- `CURLConfig.cmake` 中通过 `find_dependency(OpenHiTLS 0.4.0 MODULE)` 复用该 Find 模块。
- 与 curl 其他 TLS 后端保持一致，安装后的共享库导出目标不把私有 TLS 库附加到 `CURL::libcurl` 的 public link interface。

## 4. TLS 功能状态

### 4.1 已支持能力位

`Curl_ssl_openhitls.supports` 当前声明：

| 能力位 | 状态 | 说明 |
| --- | --- | --- |
| `SSLSUPP_CA_PATH` | 支持 | `CURLOPT_CAPATH` / `--capath` |
| `SSLSUPP_CERTINFO` | 支持 | `CURLOPT_CERTINFO` |
| `SSLSUPP_SSL_CTX` | 支持 | `CURLOPT_SSL_CTX_FUNCTION`，回调参数是 `HITLS_Config *` |
| `SSLSUPP_HTTPS_PROXY` | 支持 | HTTPS proxy 的 TLS 配置 |
| `SSLSUPP_PINNEDPUBKEY` | 支持 | `CURLOPT_PINNEDPUBLICKEY` / `--pinnedpubkey` |
| `SSLSUPP_TLS13_CIPHERSUITES` | 支持 | `CURLOPT_TLS13_CIPHERS` / `--tls13-ciphers` |
| `SSLSUPP_SIGNATURE_ALGORITHMS` | 支持 | `CURLOPT_SSL_SIGNATURE_ALGORITHMS` / `--sigalgs` |
| `SSLSUPP_SSL_EC_CURVES` | 支持 | `CURLOPT_SSL_EC_CURVES` / `--curves` |
| `SSLSUPP_CIPHER_LIST` | 支持 | `CURLOPT_SSL_CIPHER_LIST` / `--ciphers` |
| `SSLSUPP_CRLFILE` | 支持 | `CURLOPT_CRLFILE` / `--crlfile` |
| `SSLSUPP_CAINFO_BLOB` | 支持 | `CURLOPT_CAINFO_BLOB` 和 proxy CA blob |

未声明支持的能力位：

- `SSLSUPP_ECH`
- `SSLSUPP_CA_CACHE`
- `SSLSUPP_ISSUERCERT`
- `SSLSUPP_ISSUERCERT_BLOB`

### 4.2 协议和算法

- TLS 1.2：支持。
- TLS 1.3：支持。
- TLS 1.0/1.1：当前后端不支持。
- DTLS：当前 curl 后端不支持。
- TLS 1.2 及以下 cipher list：支持。
- TLS 1.3 ciphersuites：支持。
- groups/curves：支持，使用 `HITLS_CFG_SetGroupList()`。
- signature algorithms：支持。curl 先处理自身兼容别名和十六进制 codepoint，无法识别时调用 openHiTLS 的 `HITLS_CFG_GetSignatureSchemeId(config, name, id)`，再通过 `HITLS_CFG_SetSignature()` 配置。

### 4.3 证书加载时机

当前所有会影响 `HITLS_Config` 的配置都在 `HITLS_New()` 前完成，包括：

- CAfile、CApath、CAinfo blob、CRL。
- 客户端证书、证书链、私钥、key password、证书 blob。
- TLS 版本、cipher、TLS 1.3 cipher、groups、signature algorithms。
- `CURLOPT_SSL_CTX_FUNCTION` 回调。

这样可以避开 openHiTLS 当前遗留限制：`HITLS_New()` 之后再修改 `HITLS_Config` 中的证书相关配置，已创建的 SSL 对象建链时无法感知。

具体顺序：

1. 创建 `HITLS_Config`。
2. 设置 TLS/TLCP 版本、cipher、groups、sigalgs。
3. 加载客户端证书和私钥。
4. 加载 CA/CRL 信任材料。
5. 调用 `CURLOPT_SSL_CTX_FUNCTION`。
6. 调用 `HITLS_New()` 创建 SSL 对象。
7. 设置 SNI、ALPN，开始握手。

## 5. 已验证内容

已完成的验证：

- autotools `autoreconf -fi`。
- autotools debug/warnings 构建。
- CMake debug 构建。
- CMake 安装包生成 `FindOpenHiTLS.cmake`。
- `curl -V` 显示 openHiTLS 后端。
- `curl-config --ssl-backends` 显示 `openHiTLS`。
- `curl-config --static-libs` 包含 openHiTLS 静态链接依赖。
- `libcurl.pc` 不包含不存在的 `Requires.private: openhitls`。
- `--curves X25519 https://www.google.com/` 命令行 smoke。
- `--sigalgs rsa_pss_rsae_sha256 https://www.google.com/` 命令行 smoke。
- `--sigalgs ECDSA+SHA256 https://www.google.com/` 别名形式 smoke。
- 默认 CA 信任路径访问公开 HTTPS 站点 smoke。
- curl 全量测试已完成一次：`1723 tests out of 1723 reported OK: 100%`。

## 6. 社区提交策略

准备提交 curl 社区的首批内容建议整理为一个 PR、两个 commit：

1. 构建集成 commit：autotools、CMake、安装包、文档中的构建入口。
2. TLS 后端源码 commit：`lib/vtls/openhitls.c`、能力位、标准 TLS 选项支持、非 TLCP 文档。

TLCP 相关 API、命令行参数、文档和测试暂时单独保留为后续 patch，不进入首批社区 PR。

## 7. 剩余事项

- 代码检视：重点看构建系统风格、后端能力位、错误码、内存释放、证书加载顺序。
- TLCP patch 拆分：把 TLCP API、命令行参数、文档和后端实现从首批社区 PR 中拆出。
- GitHub Actions 策略：确认是否在个人 fork 先跑 curl 现有门禁，再评估是否新增 openHiTLS 专项 workflow。
- 最终 rebase：提交社区 PR 前再基于 curl 最新 master 做一次 rebase。
- 可选 smoke：CAfile、CApath、CAinfo blob、客户端证书、证书链、私钥、key password、cert blob 的定向命令行/libcurl smoke。

## 最后更新

2026-07-14
