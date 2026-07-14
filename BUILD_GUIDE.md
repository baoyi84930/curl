# curl 适配 openHiTLS 构建指导

## 当前状态

本文档描述当前仓库中 curl 使用 openHiTLS 作为 TLS 后端的构建和验证方式。

- curl 基线：`8.21.1-DEV`，已从历史 `8.16.0` 适配刷新到当前 master 代码。
- openHiTLS 基线：主分支，curl 侧最低要求 `OPENHITLS_VERSION_I >= 0x00400000ULL`，即后续 `0.4.0` 及以上版本。
- openHiTLS 已不再依赖外部 Secure_C，构建脚本和安装目录都不需要复制 `platform/Secure_C`。
- curl 的 autotools 和 CMake 构建路径都已适配 openHiTLS。
- openHiTLS 当前不安装 `openhitls.pc`，也不安装 `OpenHiTLSConfig.cmake`；curl 会直接按头文件和库文件查找 openHiTLS。

## 目录约定

```bash
export PROJECT_ROOT=/home/zhangcheng/fly_curl
export INSTALL_PREFIX=${PROJECT_ROOT}/install
```

目录结构：

```text
fly_curl/
├── curl/
├── openhitls/
├── nghttp2/
└── install/
```

`INSTALL_PREFIX` 可以放在其他位置。若 openHiTLS 安装在非系统目录，运行 curl 时需要设置 `LD_LIBRARY_PATH`，或者通过 rpath/ldconfig 让系统能找到 `libhitls_*.so`。

## 基础依赖

Ubuntu/Debian：

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake autoconf automake libtool \
    pkg-config python3 git libpsl-dev zlib1g-dev
```

CentOS/RHEL：

```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake3 autoconf automake libtool pkgconfig python3 \
    git libpsl-devel zlib-devel
```

curl 当前 CMakeLists 要求 CMake `3.18+`。openHiTLS 自身使用 CMake 构建。

## 构建 openHiTLS

```bash
cmake -S ${PROJECT_ROOT}/openhitls -B ${PROJECT_ROOT}/openhitls/build \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
    -DHITLS_BUILD_PROFILE=full \
    -DHITLS_BUILD_SHARED=ON \
    -DHITLS_BUILD_STATIC=ON \
    -DHITLS_BUILD_GEN_INFO=ON \
    -DHITLS_EAL_INIT_OPTS=9 \
    -DHITLS_CRYPTO_RAND_CB=ON \
    -DHITLS_CRYPTO_ENTROPY=ON \
    -DHITLS_CRYPTO_ENTROPY_DEVRANDOM=ON \
    -DHITLS_CRYPTO_ENTROPY_GETENTROPY=ON \
    -DHITLS_CRYPTO_ENTROPY_SYS=ON \
    -DHITLS_CRYPTO_ENTROPY_HARDWARE=ON \
    -DHITLS_CRYPTO_DRBG_GM=ON \
    -DHITLS_TLS_FEATURE_SM_TLS13=ON \
    -DHITLS_BSL_UIO_SCTP=ON

cmake --build ${PROJECT_ROOT}/openhitls/build --parallel $(nproc)
cmake --install ${PROJECT_ROOT}/openhitls/build
```

检查安装产物：

```bash
ls ${INSTALL_PREFIX}/include/hitls/bsl/bsl_version.h
ls ${INSTALL_PREFIX}/lib/libhitls_*.so
```

curl 的版本检查读取 `include/hitls/bsl/bsl_version.h` 中的 `OPENHITLS_VERSION_I`，低于 `0x00400000ULL` 会在 configure/CMake 阶段报错。

## 构建 nghttp2

nghttp2 用于 HTTP/2，非 openHiTLS 必需项，但推荐保留。

```bash
cd ${PROJECT_ROOT}/nghttp2
./configure --prefix=${INSTALL_PREFIX} --enable-lib-only
make -j$(nproc)
make install
```

## 使用 autotools 构建 curl

首次构建或修改 `configure.ac`/`m4/*.m4` 后，需要重新生成 configure 脚本：

```bash
cd ${PROJECT_ROOT}/curl
autoreconf -fi
```

配置并构建：

```bash
./configure \
    --prefix=${INSTALL_PREFIX} \
    --with-openhitls=${INSTALL_PREFIX} \
    --without-openssl \
    --with-nghttp2=${INSTALL_PREFIX} \
    --enable-debug \
    --enable-warnings \
    --disable-dependency-tracking

make -j$(nproc)
make install
```

说明：

- `--with-openhitls=PATH` 指向 openHiTLS 安装根目录。
- 建议显式加 `--without-openssl`，避免系统 OpenSSL 被自动选中。
- openHiTLS 检测不依赖 `openhitls.pc`；会直接查找 `hitls/*.h`、`bsl/bsl_version.h` 和 `libhitls_tls/libhitls_pki/libhitls_crypto/libhitls_bsl`。
- `libcurl.pc` 中 openHiTLS 依赖会进入 `Libs.private`，不会写入不存在的 `Requires.private: openhitls`。
- 启用 versioned symbols 时，openHiTLS 后端使用 `CURL_OPENHITLS_4` 符号版本前缀。

配置摘要中应能看到：

```text
SSL:              enabled (openHiTLS)
HTTP2:            enabled
```

也可以直接检查：

```bash
./curl-config --ssl-backends
./curl-config --static-libs
```

## 使用 CMake 构建 curl

```bash
cmake -S ${PROJECT_ROOT}/curl -B ${PROJECT_ROOT}/curl/build-openhitls \
    -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
    -DCURL_USE_OPENHITLS=ON \
    -DCURL_USE_OPENSSL=OFF \
    -DUSE_NGHTTP2=ON \
    -DENABLE_DEBUG=ON

cmake --build ${PROJECT_ROOT}/curl/build-openhitls --parallel $(nproc)
cmake --install ${PROJECT_ROOT}/curl/build-openhitls
```

说明：

- `CMAKE_PREFIX_PATH` 用于让 curl 找到 `${INSTALL_PREFIX}/include` 和 `${INSTALL_PREFIX}/lib`。
- `CURL_USE_OPENHITLS=ON` 启用 openHiTLS 后端。
- 建议显式设置 `CURL_USE_OPENSSL=OFF`，避免同时满足多个 TLS 后端查找条件时选错后端。
- curl 内置 `CMake/FindOpenHiTLS.cmake`，不要求 openHiTLS 安装 `OpenHiTLSConfig.cmake`。
- 安装 curl 后，`lib/cmake/CURL/FindOpenHiTLS.cmake` 会随 `CURLConfig.cmake` 一起安装，供下游 `find_package(CURL CONFIG)` 时复用。
- 与 curl 其他非 OpenSSL TLS 后端保持一致，安装后的共享库导出目标不会把私有 TLS 库强行挂到 `CURL::libcurl` public link interface 上。非系统路径运行时仍需处理动态库搜索路径。

## 功能验证

查看版本和 TLS 后端：

```bash
cd ${PROJECT_ROOT}/curl
LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib ./src/curl -V
```

输出中应包含 `OpenHiTLS`，若构建了 nghttp2，Features 中应包含 `HTTP2`。

验证默认 CA 信任路径和 HTTPS：

```bash
LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    -w "http_code=%{http_code} ssl_verify=%{ssl_verify_result}\n" \
    https://www.google.com/
```

验证 group/curve 配置：

```bash
LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --curves X25519 https://www.google.com/
```

验证签名算法配置：

```bash
LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --sigalgs rsa_pss_rsae_sha256 https://www.google.com/

LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --sigalgs ECDSA+SHA256 https://www.google.com/
```

错误参数应失败：

```bash
LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --curves NONSENSE https://www.google.com/

LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib \
./src/curl --connect-timeout 10 -fsS -o /dev/null \
    --sigalgs NONSENSE https://www.google.com/
```

## 运行 curl 测试

推荐从 `tests/` 目录直接并发运行：

```bash
cd ${PROJECT_ROOT}/curl/tests
LD_LIBRARY_PATH=${PROJECT_ROOT}/curl/lib/.libs:${INSTALL_PREFIX}/lib \
./runtests.pl -n -a -s -j8
```

当前适配已完成一次全量验证：`1723 tests out of 1723 reported OK: 100%`。

需要单独调试某个用例时：

```bash
LD_LIBRARY_PATH=${PROJECT_ROOT}/curl/lib/.libs:${INSTALL_PREFIX}/lib \
./runtests.pl -n -a -s 313
```

## 常见问题

### configure 找不到 openHiTLS

检查安装目录是否包含：

```bash
${INSTALL_PREFIX}/include/hitls/bsl/bsl_version.h
${INSTALL_PREFIX}/lib/libhitls_tls.so
${INSTALL_PREFIX}/lib/libhitls_pki.so
${INSTALL_PREFIX}/lib/libhitls_crypto.so
${INSTALL_PREFIX}/lib/libhitls_bsl.so
```

openHiTLS 当前没有 `.pc` 文件，这是预期行为。

### 运行时报 libhitls_*.so 找不到

设置动态库路径：

```bash
export LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib:${LD_LIBRARY_PATH}
```

或者在系统中配置 rpath/ldconfig。

### CMake find_package(OpenHiTLS CONFIG) 不可用

这是 openHiTLS 当前安装能力限制。curl 适配使用自己的 `FindOpenHiTLS.cmake`，通过 `CMAKE_PREFIX_PATH` 指向 openHiTLS 安装目录即可。

### debug 构建 warning 变 error

当前 openHiTLS 后端已按 curl debug/warnings 构建清理过告警。若新增代码，建议同时验证：

```bash
./configure --with-openhitls=${INSTALL_PREFIX} --without-openssl \
    --enable-debug --enable-warnings --disable-dependency-tracking
make -j$(nproc)
```

## 最后更新

2026-07-14
