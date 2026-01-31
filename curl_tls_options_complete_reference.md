# curl TLS相关选项完整规格表

以下是所有TLS相关选项的完整映射表。

## libcurl API使用模板

以下是一个包含常用TLS选项的libcurl代码模板，可作为测试和开发参考：

```c
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        // 基础URL设置
        curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

        // === 基础TLS配置 ===
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/ca-bundle.pem");
        curl_easy_setopt(curl, CURLOPT_CAPATH, "/etc/ssl/certs");

        // === 客户端证书配置 ===
        curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLKEY, "private.key");
        curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "password");

        // === TLCP双证书配置(openHiTLS专用) ===
        curl_easy_setopt(curl, CURLOPT_TLCP_ENC_CERT, "encrypt.pem");
        curl_easy_setopt(curl, CURLOPT_TLCP_ENC_KEY, "encrypt.key");
        curl_easy_setopt(curl, CURLOPT_TLCP_ENC_KEYPASSWD, "encpass");

        // === TLS版本控制 ===
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        // 或使用TLCP: CURL_SSLVERSION_TLSv1_3 (for TLCP 1.1)

        // === 密码套件配置 ===
        curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "ECDHE-RSA-AES256-GCM-SHA384");
        curl_easy_setopt(curl, CURLOPT_TLS13_CIPHERS, "TLS_AES_256_GCM_SHA384");
        curl_easy_setopt(curl, CURLOPT_SSL_EC_CURVES, "P-256:P-384");

        // === 验证控制 ===
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);     // 验证对端证书
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);     // 验证主机名
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);   // OCSP验证

        // === 证书信息提取 ===
        curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

        // === 高级选项 ===
        curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 1L);

        // === 内存证书示例 ===
        struct curl_blob cert_blob = {cert_data, cert_size, 0};
        curl_easy_setopt(curl, CURLOPT_SSLCERT_BLOB, &cert_blob);

        // 执行请求
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        // 获取证书信息(如果启用了CERTINFO)
        struct curl_certinfo *certinfo;
        res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &certinfo);
        if(res == CURLE_OK && certinfo) {
            printf("Certificate chain has %d certificates:\n", certinfo->num_of_certs);
            for(int i = 0; i < certinfo->num_of_certs; i++) {
                printf("Certificate %d:\n", i);
                for(struct curl_slist *slist = certinfo->certinfo[i]; slist; slist = slist->next) {
                    printf("  %s\n", slist->data);
                }
            }
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return 0;
}
```

📚 **参考资源**:
- 📁 [完整示例代码](docs/examples/) - curl源码中的examples目录
- 📖 [libcurl选项文档](docs/libcurl/opts/) - 每个选项的详细文档
- 🔗 [HTTPS示例](docs/examples/https.c) - 基础HTTPS连接
- 🔗 [证书内存加载示例](docs/examples/usercertinmem.c) - 内存证书使用
- 🔗 [SMTP TLS示例](docs/examples/smtp-tls.c) - 邮件TLS连接

## 基础TLS/SSL配置选项

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--cacert <file>` | `CURLOPT_CAINFO` | string | CA证书文件验证对端 | `curl --cacert ca-bundle.pem https://example.com` | `curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/ca-bundle.pem");`<br/>📄 [CURLOPT_CAINFO](docs/libcurl/opts/CURLOPT_CAINFO.md) | ✅ |
| `--capath <dir>` | `CURLOPT_CAPATH` | string | CA证书目录验证对端 | `curl --capath /etc/ssl/certs https://example.com` | `curl_easy_setopt(curl, CURLOPT_CAPATH, "/etc/ssl/certs");`<br/>📄 [CURLOPT_CAPATH](docs/libcurl/opts/CURLOPT_CAPATH.md) | ✅ |
| `--ca-native` | (内部标志) | boolean | 从操作系统加载CA证书 | `curl --ca-native https://example.com` | `/* 无对应API选项，由TLS后端自动处理 */` | ❌ |
| `-E, --cert <cert[:pass]>` | `CURLOPT_SSLCERT` | string | 客户端证书文件和密码 | `curl --cert client.pem https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");`<br/>📄 [CURLOPT_SSLCERT](docs/libcurl/opts/CURLOPT_SSLCERT.md)<br/>🔗 [示例](docs/examples/usercertinmem.c) | ✅ |
| `--cert-status` | `CURLOPT_SSL_VERIFYSTATUS` | long | 验证服务器证书状态(OCSP) | `curl --cert-status https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);`<br/>📄 [CURLOPT_SSL_VERIFYSTATUS](docs/libcurl/opts/CURLOPT_SSL_VERIFYSTATUS.md) | ❌ |
| `--cert-type <type>` | `CURLOPT_SSLCERTTYPE` | string | 证书类型(DER/PEM/P12) | `curl --cert-type PEM --cert client.pem https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");`<br/>📄 [CURLOPT_SSLCERTTYPE](docs/libcurl/opts/CURLOPT_SSLCERTTYPE.md) | ✅ |
| `--ciphers <list>` | `CURLOPT_SSL_CIPHER_LIST` | string | TLS 1.2及以下密码套件 | `curl --ciphers "ECDHE-RSA-AES256-GCM-SHA384" https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "ECDHE-RSA-AES256-GCM-SHA384");`<br/>📄 [CURLOPT_SSL_CIPHER_LIST](docs/libcurl/opts/CURLOPT_SSL_CIPHER_LIST.md) | ✅ |
| `--crlfile <file>` | `CURLOPT_CRLFILE` | string | 证书吊销列表文件 | `curl --crlfile crl.pem https://example.com` | `curl_easy_setopt(curl, CURLOPT_CRLFILE, "crl.pem");`<br/>📄 [CURLOPT_CRLFILE](docs/libcurl/opts/CURLOPT_CRLFILE.md) | ✅ |
| `--curves <list>` | `CURLOPT_SSL_EC_CURVES` | string | 椭圆曲线密钥交换算法 | `curl --curves "P-256:P-384" https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_EC_CURVES, "P-256:P-384");`<br/>📄 [CURLOPT_SSL_EC_CURVES](docs/libcurl/opts/CURLOPT_SSL_EC_CURVES.md) | ❌ |
| `-k, --insecure` | `CURLOPT_SSL_VERIFYPEER=0` | boolean | 允许不安全的服务器连接 | `curl --insecure https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);`<br/>`curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);`<br/>📄 [CURLOPT_SSL_VERIFYPEER](docs/libcurl/opts/CURLOPT_SSL_VERIFYPEER.md) | ✅ |
| `--key <key>` | `CURLOPT_SSLKEY` | string | 私钥文件名 | `curl --key private.key https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLKEY, "private.key");`<br/>📄 [CURLOPT_SSLKEY](docs/libcurl/opts/CURLOPT_SSLKEY.md) | ✅ |
| `--key-type <type>` | `CURLOPT_SSLKEYTYPE` | string | 私钥文件类型(DER/PEM) | `curl --key-type PEM --key private.key https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");`<br/>📄 [CURLOPT_SSLKEYTYPE](docs/libcurl/opts/CURLOPT_SSLKEYTYPE.md) | ✅ |
| `--pass <phrase>` | `CURLOPT_KEYPASSWD` | string | 私钥密码短语 | `curl --pass secret123 --key encrypted.key https://example.com` | `curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "secret123");`<br/>📄 [CURLOPT_KEYPASSWD](docs/libcurl/opts/CURLOPT_KEYPASSWD.md) | ✅ |
| `--pinnedpubkey <hashes>` | `CURLOPT_PINNEDPUBLICKEY` | string | 验证对端的公钥 | `curl --pinnedpubkey "sha256//hash" https://example.com` | `curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//hash");`<br/>📄 [CURLOPT_PINNEDPUBLICKEY](docs/libcurl/opts/CURLOPT_PINNEDPUBLICKEY.md) | ❌ |
| `--sigalgs <list>` | `CURLOPT_SSL_SIGNATURE_ALGORITHMS` | string | TLS签名算法 | `curl --sigalgs "ecdsa_secp256r1_sha256" https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_SIGNATURE_ALGORITHMS, "ecdsa_secp256r1_sha256");`<br/>📄 [CURLOPT_SSL_SIGNATURE_ALGORITHMS](docs/libcurl/opts/CURLOPT_SSL_SIGNATURE_ALGORITHMS.md) | ❌ |

## TLS版本控制选项

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--ssl` | `CURLOPT_USE_SSL` | values | 尝试启用TLS | `curl --ssl ftps://example.com` | `curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);`<br/>📄 [CURLOPT_USE_SSL](docs/libcurl/opts/CURLOPT_USE_SSL.md) | ✅ |
| `--ssl-reqd` | `CURLOPT_USE_SSL` | values | 要求SSL/TLS连接 | `curl --ssl-reqd ftps://example.com` | `curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);`<br/>📄 [CURLOPT_USE_SSL](docs/libcurl/opts/CURLOPT_USE_SSL.md) | ✅ |
| `-1, --tlsv1` | `CURLOPT_SSLVERSION` | values | TLSv1.0或更高 | `curl --tlsv1 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);`<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ❌ |
| `--tlsv1.0` | `CURLOPT_SSLVERSION` | values | TLSv1.0或更高 | `curl --tlsv1.0 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);`<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ❌ |
| `--tlsv1.1` | `CURLOPT_SSLVERSION` | values | TLSv1.1或更高 | `curl --tlsv1.1 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_1);`<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ❌ |
| `--tlsv1.2` | `CURLOPT_SSLVERSION` | values | TLSv1.2或更高 | `curl --tlsv1.2 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);`<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ✅ |
| `--tlsv1.3` | `CURLOPT_SSLVERSION` | values | TLSv1.3或更高 | `curl --tlsv1.3 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);`<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ✅ |
| `--tls-max <version>` | `CURLOPT_SSLVERSION` | string | 最大允许的TLS版本 | `curl --tls-max 1.3 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_MAX_TLSv1_3);`<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ✅ |
| `--tls13-ciphers <list>` | `CURLOPT_TLS13_CIPHERS` | string | TLS 1.3密码套件 | `curl --tls13-ciphers "TLS_AES_256_GCM_SHA384" https://example.com` | `curl_easy_setopt(curl, CURLOPT_TLS13_CIPHERS, "TLS_AES_256_GCM_SHA384");`<br/>📄 [CURLOPT_TLS13_CIPHERS](docs/libcurl/opts/CURLOPT_TLS13_CIPHERS.md) | ✅ |

## openHiTLS专用选项(TLCP支持)

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--tlcp1.1` | `CURLOPT_SSLVERSION` | values | TLCP v1.1或更高 | `curl --tlcp1.1 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);`<br/>/* TLCP 1.1使用TLS 1.3常量 */<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ✅ |
| `--tlcp-enc-cert <certificate[:password]>` | `CURLOPT_TLCP_ENC_CERT` | string | TLCP加密证书文件 | `curl --tlcp-enc-cert enc.pem https://example.com` | `curl_easy_setopt(curl, CURLOPT_TLCP_ENC_CERT, "enc.pem");`<br/>/* openHiTLS专用选项 */ | ✅ |
| `--tlcp-enc-key <key>` | `CURLOPT_TLCP_ENC_KEY` | string | TLCP加密私钥文件 | `curl --tlcp-enc-key enc.key https://example.com` | `curl_easy_setopt(curl, CURLOPT_TLCP_ENC_KEY, "enc.key");`<br/>/* openHiTLS专用选项 */ | ✅ |

## 高级TLS配置选项

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--no-alpn` | `CURLOPT_SSL_ENABLE_ALPN=0` | boolean | 禁用ALPN TLS扩展 | `curl --no-alpn https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);`<br/>📄 [CURLOPT_SSL_ENABLE_ALPN](docs/libcurl/opts/CURLOPT_SSL_ENABLE_ALPN.md) | ✅ |
| `--no-sessionid` | `CURLOPT_SSL_SESSIONID_CACHE=0` | boolean | 禁用SSL会话ID重用 | `curl --no-sessionid https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L);`<br/>📄 [CURLOPT_SSL_SESSIONID_CACHE](docs/libcurl/opts/CURLOPT_SSL_SESSIONID_CACHE.md) | ❌ |
| `--ssl-allow-beast` | `CURLOPT_SSL_OPTIONS` | long | 允许安全缺陷以提高互操作性 | `curl --ssl-allow-beast https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_ALLOW_BEAST);`<br/>📄 [CURLOPT_SSL_OPTIONS](docs/libcurl/opts/CURLOPT_SSL_OPTIONS.md) | ❌ |
| `--ssl-no-revoke` | `CURLOPT_SSL_OPTIONS` | long | 禁用证书吊销检查 | `curl --ssl-no-revoke https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE);`<br/>📄 [CURLOPT_SSL_OPTIONS](docs/libcurl/opts/CURLOPT_SSL_OPTIONS.md) | ❌ |
| `--ssl-revoke-best-effort` | `CURLOPT_SSL_OPTIONS` | long | 忽略缺失的CRL分发点 | `curl --ssl-revoke-best-effort https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_REVOKE_BEST_EFFORT);`<br/>📄 [CURLOPT_SSL_OPTIONS](docs/libcurl/opts/CURLOPT_SSL_OPTIONS.md) | ❌ |

## 代理TLS选项

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--proxy-cacert <file>` | `CURLOPT_PROXY_CAINFO` | string | 验证代理的CA证书 | `curl --proxy-cacert proxy-ca.pem --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_CAINFO, "proxy-ca.pem");`<br/>📄 [CURLOPT_PROXY_CAINFO](docs/libcurl/opts/CURLOPT_PROXY_CAINFO.md) | ✅ |
| `--proxy-capath <dir>` | `CURLOPT_PROXY_CAPATH` | string | 验证代理的CA目录 | `curl --proxy-capath /etc/ssl/certs --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_CAPATH, "/etc/ssl/certs");`<br/>📄 [CURLOPT_PROXY_CAPATH](docs/libcurl/opts/CURLOPT_PROXY_CAPATH.md) | ✅ |
| `--proxy-cert <cert>` | `CURLOPT_PROXY_SSLCERT` | string | 设置代理客户端证书 | `curl --proxy-cert proxy-cert.pem --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_SSLCERT, "proxy-cert.pem");`<br/>📄 [CURLOPT_PROXY_SSLCERT](docs/libcurl/opts/CURLOPT_PROXY_SSLCERT.md) | ✅ |
| `--proxy-cert-type <type>` | `CURLOPT_PROXY_SSLCERTTYPE` | string | HTTPS代理的客户端证书类型 | `curl --proxy-cert-type PEM --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_SSLCERTTYPE, "PEM");`<br/>📄 [CURLOPT_PROXY_SSLCERTTYPE](docs/libcurl/opts/CURLOPT_PROXY_SSLCERTTYPE.md) | ✅ |
| `--proxy-ciphers <list>` | `CURLOPT_PROXY_SSL_CIPHER_LIST` | string | 代理使用的TLS密码套件 | `curl --proxy-ciphers "ECDHE-RSA-AES128-GCM-SHA256" --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_SSL_CIPHER_LIST, "ECDHE-RSA-AES128-GCM-SHA256");`<br/>📄 [CURLOPT_PROXY_SSL_CIPHER_LIST](docs/libcurl/opts/CURLOPT_PROXY_SSL_CIPHER_LIST.md) | ✅ |
| `--proxy-insecure` | `CURLOPT_PROXY_SSL_VERIFYPEER=0` | boolean | 跳过HTTPS代理证书验证 | `curl --proxy-insecure --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);`<br/>`curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 0L);`<br/>📄 [CURLOPT_PROXY_SSL_VERIFYPEER](docs/libcurl/opts/CURLOPT_PROXY_SSL_VERIFYPEER.md) | ✅ |
| `--proxy-key <key>` | `CURLOPT_PROXY_SSLKEY` | string | HTTPS代理的私钥 | `curl --proxy-key proxy-key.pem --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_SSLKEY, "proxy-key.pem");`<br/>📄 [CURLOPT_PROXY_SSLKEY](docs/libcurl/opts/CURLOPT_PROXY_SSLKEY.md) | ✅ |
| `--proxy-key-type <type>` | `CURLOPT_PROXY_SSLKEYTYPE` | string | 代理私钥文件类型 | `curl --proxy-key-type PEM --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_SSLKEYTYPE, "PEM");`<br/>📄 [CURLOPT_PROXY_SSLKEYTYPE](docs/libcurl/opts/CURLOPT_PROXY_SSLKEYTYPE.md) | ✅ |
| `--proxy-pass <phrase>` | `CURLOPT_PROXY_KEYPASSWD` | string | HTTPS代理私钥密码短语 | `curl --proxy-pass secret --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_KEYPASSWD, "secret");`<br/>📄 [CURLOPT_PROXY_KEYPASSWD](docs/libcurl/opts/CURLOPT_PROXY_KEYPASSWD.md) | ✅ |
| `--proxy-tls13-ciphers <list>` | `CURLOPT_PROXY_TLS13_CIPHERS` | string | 代理TLS 1.3密码套件 | `curl --proxy-tls13-ciphers "TLS_AES_128_GCM_SHA256" --proxy https://proxy:8080 https://example.com` | `curl_easy_setopt(curl, CURLOPT_PROXY_TLS13_CIPHERS, "TLS_AES_128_GCM_SHA256");`<br/>📄 [CURLOPT_PROXY_TLS13_CIPHERS](docs/libcurl/opts/CURLOPT_PROXY_TLS13_CIPHERS.md) | ✅ |

## FTP over TLS选项

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--ftp-ssl-ccc` | `CURLOPT_FTP_SSL_CCC` | long | 认证后发送CCC | `curl --ftp-ssl-ccc ftps://example.com` | `curl_easy_setopt(curl, CURLOPT_FTP_SSL_CCC, CURLFTPSSL_CCC_ACTIVE);`<br/>📄 [CURLOPT_FTP_SSL_CCC](docs/libcurl/opts/CURLOPT_FTP_SSL_CCC.md) | ✅ |
| `--ftp-ssl-ccc-mode <mode>` | `CURLOPT_FTP_SSL_CCC` | long | 设置CCC模式 | `curl --ftp-ssl-ccc-mode passive ftps://example.com` | `curl_easy_setopt(curl, CURLOPT_FTP_SSL_CCC, CURLFTPSSL_CCC_PASSIVE);`<br/>📄 [CURLOPT_FTP_SSL_CCC](docs/libcurl/opts/CURLOPT_FTP_SSL_CCC.md) | ✅ |
| `--ftp-ssl-control` | `CURLOPT_USE_SSL` | values | 登录需要TLS，传输为明文 | `curl --ftp-ssl-control ftps://example.com` | `curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_CONTROL);`<br/>📄 [CURLOPT_USE_SSL](docs/libcurl/opts/CURLOPT_USE_SSL.md) | ✅ |

## 已废弃的TLS选项

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--engine <name>` | `CURLOPT_SSLENGINE` | string | 使用的加密引擎 | `curl --engine pkcs11 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLENGINE, "pkcs11");`<br/>📄 [CURLOPT_SSLENGINE](docs/libcurl/opts/CURLOPT_SSLENGINE.md) | ❌ |
| `--egd-file <file>` | `CURLOPT_EGDSOCKET` | string | EGD套接字路径获取随机数据 | `curl --egd-file /var/run/egd-pool https://example.com` | `curl_easy_setopt(curl, CURLOPT_EGDSOCKET, "/var/run/egd-pool");`<br/>📄 [CURLOPT_EGDSOCKET](docs/libcurl/opts/CURLOPT_EGDSOCKET.md) | ❌ |
| `--false-start` | `CURLOPT_SSL_FALSESTART` | long | 启用TLS False Start | `curl --false-start https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_FALSESTART, 1L);`<br/>📄 [CURLOPT_SSL_FALSESTART](docs/libcurl/opts/CURLOPT_SSL_FALSESTART.md) | ❌ |
| `--no-npn` | `CURLOPT_SSL_ENABLE_NPN=0` | boolean | 禁用NPN TLS扩展 | `curl --no-npn https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);`<br/>📄 [CURLOPT_SSL_ENABLE_NPN](docs/libcurl/opts/CURLOPT_SSL_ENABLE_NPN.md) | ❌ |
| `--random-file <file>` | `CURLOPT_RANDOM_FILE` | string | 读取随机数据的文件 | `curl --random-file /dev/urandom https://example.com` | `curl_easy_setopt(curl, CURLOPT_RANDOM_FILE, "/dev/urandom");`<br/>📄 [CURLOPT_RANDOM_FILE](docs/libcurl/opts/CURLOPT_RANDOM_FILE.md) | ❌ |
| `-2, --sslv2` | `CURLOPT_SSLVERSION` | values | SSLv2 | `curl --sslv2 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv2);`<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ❌ |
| `-3, --sslv3` | `CURLOPT_SSLVERSION` | values | SSLv3 | `curl --sslv3 https://example.com` | `curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);`<br/>📄 [CURLOPT_SSLVERSION](docs/libcurl/opts/CURLOPT_SSLVERSION.md) | ❌ |

## 仅libcurl API可用的选项(无命令行对应)

| libcurl选项 | 参数类型 | 描述 | libcurl API示例 | openHiTLS支持 |
|------------|---------|------|--------------|-------------|
| `CURLOPT_CAINFO_BLOB` | blob | CA证书包作为内存数据 | `struct curl_blob ca_blob = {ca_data, ca_size, 0};`<br/>`curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &ca_blob);`<br/>📄 [CURLOPT_CAINFO_BLOB](docs/libcurl/opts/CURLOPT_CAINFO_BLOB.md) | ✅ |
| `CURLOPT_SSLCERT_BLOB` | blob | 客户端证书作为内存数据 | `struct curl_blob cert_blob = {cert_data, cert_size, 0};`<br/>`curl_easy_setopt(curl, CURLOPT_SSLCERT_BLOB, &cert_blob);`<br/>📄 [CURLOPT_SSLCERT_BLOB](docs/libcurl/opts/CURLOPT_SSLCERT_BLOB.md)<br/>🔗 [示例](docs/examples/usercertinmem.c) | ✅ |
| `CURLOPT_SSLKEY_BLOB` | blob | 私钥作为内存数据 | `struct curl_blob key_blob = {key_data, key_size, 0};`<br/>`curl_easy_setopt(curl, CURLOPT_SSLKEY_BLOB, &key_blob);`<br/>📄 [CURLOPT_SSLKEY_BLOB](docs/libcurl/opts/CURLOPT_SSLKEY_BLOB.md) | ✅ |
| `CURLOPT_ISSUERCERT` | string | 颁发者证书文件 | `curl_easy_setopt(curl, CURLOPT_ISSUERCERT, "issuer.pem");`<br/>📄 [CURLOPT_ISSUERCERT](docs/libcurl/opts/CURLOPT_ISSUERCERT.md) | ✅ |
| `CURLOPT_ISSUERCERT_BLOB` | blob | 颁发者证书作为内存数据 | `struct curl_blob issuer_blob = {issuer_data, issuer_size, 0};`<br/>`curl_easy_setopt(curl, CURLOPT_ISSUERCERT_BLOB, &issuer_blob);`<br/>📄 [CURLOPT_ISSUERCERT_BLOB](docs/libcurl/opts/CURLOPT_ISSUERCERT_BLOB.md) | ✅ |
| `CURLOPT_PROXY_CAINFO_BLOB` | blob | 代理CA证书包作为内存数据 | `struct curl_blob proxy_ca_blob = {proxy_ca_data, proxy_ca_size, 0};`<br/>`curl_easy_setopt(curl, CURLOPT_PROXY_CAINFO_BLOB, &proxy_ca_blob);`<br/>📄 [CURLOPT_PROXY_CAINFO_BLOB](docs/libcurl/opts/CURLOPT_PROXY_CAINFO_BLOB.md) | ✅ |
| `CURLOPT_PROXY_SSLCERT_BLOB` | blob | 代理客户端证书作为内存数据 | `struct curl_blob proxy_cert_blob = {proxy_cert_data, proxy_cert_size, 0};`<br/>`curl_easy_setopt(curl, CURLOPT_PROXY_SSLCERT_BLOB, &proxy_cert_blob);`<br/>📄 [CURLOPT_PROXY_SSLCERT_BLOB](docs/libcurl/opts/CURLOPT_PROXY_SSLCERT_BLOB.md) | ✅ |
| `CURLOPT_PROXY_SSLKEY_BLOB` | blob | 代理私钥作为内存数据 | `struct curl_blob proxy_key_blob = {proxy_key_data, proxy_key_size, 0};`<br/>`curl_easy_setopt(curl, CURLOPT_PROXY_SSLKEY_BLOB, &proxy_key_blob);`<br/>📄 [CURLOPT_PROXY_SSLKEY_BLOB](docs/libcurl/opts/CURLOPT_PROXY_SSLKEY_BLOB.md) | ✅ |
| `CURLOPT_PROXY_ISSUERCERT` | string | 代理颁发者证书文件 | `curl_easy_setopt(curl, CURLOPT_PROXY_ISSUERCERT, "proxy_issuer.pem");`<br/>📄 [CURLOPT_PROXY_ISSUERCERT](docs/libcurl/opts/CURLOPT_PROXY_ISSUERCERT.md) | ✅ |
| `CURLOPT_PROXY_ISSUERCERT_BLOB` | blob | 代理颁发者证书作为内存数据 | `struct curl_blob proxy_issuer_blob = {proxy_issuer_data, proxy_issuer_size, 0};`<br/>`curl_easy_setopt(curl, CURLOPT_PROXY_ISSUERCERT_BLOB, &proxy_issuer_blob);`<br/>📄 [CURLOPT_PROXY_ISSUERCERT_BLOB](docs/libcurl/opts/CURLOPT_PROXY_ISSUERCERT_BLOB.md) | ✅ |
| `CURLOPT_SSL_CTX_FUNCTION` | function | SSL上下文回调函数 | `curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback);`<br/>`curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, userdata);`<br/>📄 [CURLOPT_SSL_CTX_FUNCTION](docs/libcurl/opts/CURLOPT_SSL_CTX_FUNCTION.md) | ✅ |
| `CURLOPT_SSL_CTX_DATA` | callback pointer | SSL上下文回调数据 | `curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, userdata);`<br/>📄 [CURLOPT_SSL_CTX_DATA](docs/libcurl/opts/CURLOPT_SSL_CTX_DATA.md) | ✅ |
| `CURLOPT_SSLENGINE_DEFAULT` | long | 设置默认SSL引擎 | *不支持* | ❌ |
| `CURLOPT_TLCP_ENC_KEYPASSWD` | string | TLCP加密密钥密码 | `curl_easy_setopt(curl, CURLOPT_TLCP_ENC_KEYPASSWD, "encpass");`<br/>/* openHiTLS专用选项 */ | ✅ |
| `CURLOPT_CA_CACHE_TIMEOUT` | long | CA证书缓存超时 | `curl_easy_setopt(curl, CURLOPT_CA_CACHE_TIMEOUT, 300L);`<br/>📄 [CURLOPT_CA_CACHE_TIMEOUT](docs/libcurl/opts/CURLOPT_CA_CACHE_TIMEOUT.md) | ✅ |
| `CURLOPT_CERTINFO` | long | 获取证书信息 | `curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);`<br/>📄 [CURLOPT_CERTINFO](docs/libcurl/opts/CURLOPT_CERTINFO.md)<br/>🔗 [示例](docs/examples/certinfo.c) | ✅ |
| `CURLOPT_SSL_ENABLE_ALPN` | long | 启用/禁用ALPN | `curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 1L);`<br/>📄 [CURLOPT_SSL_ENABLE_ALPN](docs/libcurl/opts/CURLOPT_SSL_ENABLE_ALPN.md) | ✅ |
| `CURLOPT_SSL_ENABLE_NPN` | long | 启用/禁用NPN(已废弃) | *不支持* | ❌ |
| `CURLOPT_SSL_FALSESTART` | long | TLS False Start(已废弃) | *不支持* | ❌ |
| `CURLOPT_SSL_OPTIONS` | long | SSL选项标志位 | *不支持* | ❌ |
| `CURLOPT_SSL_SESSIONID_CACHE` | long | SSL会话ID缓存 | `curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 1L);`<br/>📄 [CURLOPT_SSL_SESSIONID_CACHE](docs/libcurl/opts/CURLOPT_SSL_SESSIONID_CACHE.md) | ✅ |
| `CURLOPT_SSL_VERIFYHOST` | long | 验证主机名 | `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);`<br/>📄 [CURLOPT_SSL_VERIFYHOST](docs/libcurl/opts/CURLOPT_SSL_VERIFYHOST.md) | ✅ |
| `CURLOPT_SSL_VERIFYPEER` | long | 验证对端证书 | `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);`<br/>📄 [CURLOPT_SSL_VERIFYPEER](docs/libcurl/opts/CURLOPT_SSL_VERIFYPEER.md) | ✅ |
| `CURLOPT_SSL_VERIFYSTATUS` | long | 验证证书状态 | *不支持* | ❌ |

## DoH (DNS-over-HTTPS) TLS选项

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--doh-cert-status` | `CURLOPT_DOH_SSL_VERIFYSTATUS` | long | 验证DoH服务器证书状态 | `curl --doh-cert-status --doh-url https://dns.google/dns-query https://example.com` | *不支持* | ❌ |
| `--doh-insecure` | `CURLOPT_DOH_SSL_VERIFYPEER=0` | boolean | 允许不安全的DoH服务器连接 | `curl --doh-insecure --doh-url https://dns.google/dns-query https://example.com` | *不支持* |  ✅ |

## TLS认证选项

| 命令行参数 | 对应libcurl选项 | 参数类型 | 描述 | 命令行示例 | libcurl API示例 | openHiTLS支持 |
|-----------|---------------|---------|------|----------|--------------|-------------|
| `--tlsauthtype <type>` | `CURLOPT_TLSAUTH_TYPE` | string | TLS认证类型 | `curl --tlsauthtype SRP https://example.com` | *不支持* | ❌ |
| `--tlspassword <string>` | `CURLOPT_TLSAUTH_PASSWORD` | string | TLS认证密码 | `curl --tlspassword secret https://example.com` | *不支持* | ❌ |
| `--tlsuser <name>` | `CURLOPT_TLSAUTH_USERNAME` | string | TLS认证用户名 | `curl --tlsuser username https://example.com` | *不支持* | ❌ |

## 支持状态说明

- ✅ **完全支持**: 功能完全实现并经过openHiTLS测试
- 🔄 **部分支持**: 功能可能工作但支持程度因实现而异
- ❌ **不支持**: 功能不受支持或不适用于openHiTLS

## 关键说明

1. **TLCP专用功能**: `--tlcp1.1`、`--tlcp-enc-cert`、`--tlcp-enc-key`是openHiTLS独有的选项，提供中国传输层密码协议(TLCP/GM)支持。

2. **TLS版本限制**: openHiTLS出于安全考虑不支持TLS 1.0和1.1，仅支持TLS 1.2、1.3和TLCP 1.1。

3. **密码套件差异**: 除了标准TLS密码套件，openHiTLS还支持中国国家密码算法(SM2、SM3、SM4)。

4. **引擎支持**: 与OpenSSL引擎相关的选项不适用于openHiTLS，因为它使用不同的架构。

5. **证书格式**: openHiTLS主要支持PEM和DER证书格式，P12格式有限支持。

6. **内存证书**: libcurl的*_BLOB选项允许从内存加载证书，这在openHiTLS中完全支持。

---

**版本**: v2.0
**最后更新**: 2025-09-19
**基于**: curl 8.16.0-DEV with openHiTLS integration