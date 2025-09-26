# curl 适配 openHiTLS 构建指导

## 项目简介

本项目是 curl 与 openHiTLS 的集成版本，使用 openHiTLS 作为 SSL/TLS 后端。openHiTLS 支持国密算法（GM/SM）和标准 TLS 协议。

项目包含三个主要组件：
- **curl** - HTTP/HTTPS 客户端工具和 libcurl 库
- **openHiTLS** - TLS/SSL 加密库，提供密码学功能
- **nghttp2** - HTTP/2 协议库，提供 HTTP/2 支持

## 系统要求

### 操作系统
- Linux (推荐 Ubuntu 18.04+, CentOS 7+)
- 其他 UNIX-like 系统

### 编译工具
- GCC 或 Clang (支持 C99)
- CMake 3.10+
- GNU Autotools (autoconf, automake, libtool)
- Make
- Python 3.6+

### 基础依赖
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake autoconf automake libtool \
    pkg-config python3 git libpsl-dev zlib1g-dev

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake3 autoconf automake libtool pkgconfig python3 \
    git libpsl-devel zlib-devel
```

## 构建步骤

### 第一步：准备工作目录

设置环境变量，定义项目根目录和安装目录：

```bash
export PROJECT_ROOT=/path/to/your/project
export INSTALL_PREFIX=/path/to/install
```

**说明：**
- `PROJECT_ROOT`: 项目根目录，包含 curl、openHiTLS、nghttp2 源码
- `INSTALL_PREFIX`: 所有组件的安装目标目录（可以是任意位置，不必在项目目录内）


进入工作目录：

```bash
cd ${PROJECT_ROOT}
```

项目目录结构应该如下：
```
project_root/
├── curl/          # curl 源码
├── openhitls/     # openHiTLS 源码
└── nghttp2/       # nghttp2 源码
```

### 第二步：构建 openHiTLS

openHiTLS 是整个项目的基础，必须首先构建和安装。

#### 2.1 编译 openHiTLS 和 Secure_C

```bash
cd ${PROJECT_ROOT}/openhitls/testcode/script
bash build_hitls.sh
```

#### 2.2 安装 openHiTLS 到指定目录

```bash
cd ../../build
cmake .. -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}
make -j$(nproc)
make install
```

参数说明：
- `-DCMAKE_INSTALL_PREFIX`: 指定安装目录
- `-j$(nproc)`: 使用所有 CPU 核心并行编译

#### 2.3 安装 Secure_C 依赖库

openHiTLS 依赖 Secure_C 库提供安全的字符串操作函数：

```bash
cd ${PROJECT_ROOT}
cp openhitls/platform/Secure_C/include/* ${INSTALL_PREFIX}/include/
cp openhitls/platform/Secure_C/lib/* ${INSTALL_PREFIX}/lib/
```

**验证 openHiTLS 安装：**
```bash
ls ${INSTALL_PREFIX}/lib/libhitls*.so
ls ${INSTALL_PREFIX}/include/hitls/
```

应该能看到 `libhitls_bsl.so`, `libhitls_crypto.so`, `libhitls_tls.so` 等库文件。

### 第三步：构建 nghttp2 (HTTP/2 支持)

nghttp2 提供 HTTP/2 协议支持，是可选但推荐安装的组件。

```bash
cd ${PROJECT_ROOT}/nghttp2

# 配置
./configure --prefix=${INSTALL_PREFIX} \
            --enable-lib-only

# 编译和安装
make -j$(nproc)
make install
```

参数说明：
- `--prefix`: 安装目录，与 openHiTLS 保持一致
- `--enable-lib-only`: 只构建 libnghttp2 库，不构建工具

**验证 nghttp2 安装：**
```bash
ls ${INSTALL_PREFIX}/lib/libnghttp2.*
ls ${INSTALL_PREFIX}/include/nghttp2/
```

### 第四步：构建 curl

最后构建集成了 openHiTLS 和 nghttp2 的 curl。

#### 4.1 配置 curl

如果是第一次构建，需要生成配置脚本：

```bash
cd ${PROJECT_ROOT}/curl
autoreconf -fi
```

运行配置脚本：

```bash
./configure \
    --with-openhitls=${INSTALL_PREFIX} \
    --with-nghttp2=${INSTALL_PREFIX} \
    --prefix=${INSTALL_PREFIX} \
    --enable-debug \
    --enable-warnings
```

配置选项说明：
- `--with-openhitls`: 指定 openHiTLS 安装路径
- `--with-nghttp2`: 指定 nghttp2 安装路径（可选）
- `--prefix`: curl 的安装目录
- `--enable-debug`: 启用调试信息（可选）
- `--enable-warnings`: 启用编译警告（可选）

**检查配置输出：**
确保看到以下信息：
```
SSL support:      enabled (openHiTLS)
HTTP2 support:    enabled (nghttp2)
```

#### 4.2 编译 curl

```bash
make -j$(nproc)
```

#### 4.3 安装 curl

```bash
make install
```

## 验证安装

### 检查 curl 版本和支持的特性

```bash
cd ${PROJECT_ROOT}/curl
LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib ./src/curl -V
```

关键点：
- SSL 后端应显示 `openHiTLS/x.x.x`
- Features 中应包含 `HTTP2`

### 测试 HTTPS 连接

```bash
LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib \
./src/curl -v https://www.example.com
```

成功的连接应该显示 TLS 握手过程和响应内容。

## 运行测试套件

### curl 测试套件

```bash
cd ${PROJECT_ROOT}/curl

# 基础测试
make test

# 完整测试套件
make test-full

# 非不稳定测试
make test-nonflaky
```

**注意：** 运行测试时需要设置 `LD_LIBRARY_PATH`：

```bash
cd tests
LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib \
perl runtests.pl -c ../src/.libs/curl
```

## 常见问题与故障排除

待补充

本构建指导基于：
- curl 8.x
- openHiTLS 主分支
- nghttp2 1.x

### 最后更新

2025-10-22

---

如有问题或建议，请提交 Issue 或 Pull Request。
