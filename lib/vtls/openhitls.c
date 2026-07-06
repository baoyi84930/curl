/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_OPENHITLS

#include <errno.h>
#include <stdint.h>
#include <tls/hitls.h>
#include <tls/hitls_config.h>
#include <tls/hitls_error.h>
#include <tls/hitls_cert_type.h>
#include <tls/hitls_cert.h>
#include <tls/hitls_type.h>
#include <tls/hitls_sni.h>
#include <tls/hitls_alpn.h>
#include <crypto/crypt_eal_init.h>
#include <crypto/crypt_eal_rand.h>
#include <crypto/crypt_eal_md.h>
#include <crypto/crypt_eal_codecs.h>
#include <crypto/crypt_algid.h>
#include <bsl/bsl_uio.h>
#include <bsl/bsl_sal.h>
#include <bsl/bsl_err.h>
#include <bsl/bsl_errno.h>
#include <bsl/bsl_log.h>
#include <tls/hitls_cert_init.h>
#include <tls/hitls_crypt_init.h>
#include <crypto/crypt_errno.h>
#include <pki/hitls_pki_x509.h>
#include <pki/hitls_pki_errno.h>
#include <pki/hitls_pki_pkcs12.h>
#include <bsl/bsl_list.h>
/* Removed PKI module direct includes to avoid mixing interfaces */

#include "urldata.h"
#include "sendf.h"
#include "multiif.h"
#include "cfilters.h"
#include "connect.h"
#include "curl_trc.h"
#include "curl_sha256.h"
#include "strcase.h"
#include "curlx/strdup.h"
#include "vtls.h"
#include "vtls_int.h"
#include "x509asn1.h"
#include "cipher_suite.h"
#include "keylog.h"
#include "curl_printf.h"
#include "openhitls.h"

/*
 * Thread-Local Storage (TLS) for logging context
 */
/* Define a general thread-local storage macro */
#if __STDC_VERSION__ >= 201112L
/* C11 or later supports _Thread_local */
/* C11 defines thread_local as an alias for _Thread_local in <threads.h> */
/* To avoid including <threads.h> (not all C11 implementations fully support
 * it), we use _Thread_local directly. */
#define THREAD_LOCAL _Thread_local

#elif defined(__GNUC__) || defined(__clang__)
/* GCC or Clang supports __thread extension */
#define THREAD_LOCAL __thread

#elif defined(_MSC_VER)
/* Microsoft Visual C++ supports __declspec(thread) extension */
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL
#define NO_OPENHITLS_BIN_LOG
#endif

/* Thread-local storage for current Curl_easy and Curl_cfilter pointers */
static THREAD_LOCAL struct Curl_easy *tls_current_data = NULL;
static THREAD_LOCAL struct Curl_cfilter *tls_current_cf = NULL;

#ifndef NO_OPENHITLS_BIN_LOG
#define HITLS_SET_CONTEXT(d, c) \
  do { \
    struct Curl_easy *_prev_data = tls_current_data; \
    struct Curl_cfilter *_prev_cf = tls_current_cf; \
    tls_current_data = (d); \
    tls_current_cf = (c)

#define HITLS_RESTORE_CONTEXT() \
    tls_current_data = _prev_data; \
    tls_current_cf = _prev_cf; \
  } while(0)
#else
#define HITLS_SET_CONTEXT(d, c)
#define HITLS_RESTORE_CONTEXT()
#endif

struct hitls_ctx {
  HITLS_Ctx *ssl;
  HITLS_Config *config;
  BSL_UIO *uio;
  BSL_UIO_Method *uio_method;  /* Custom UIO method */
  /* New fields for enhanced functionality */
  bool ca_store_setup;           /* Flag for CA store setup status */
  bool reused_session;           /* Flag for session reuse */
};

/* Forward declarations for openHiTLS logging callbacks */
void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
                      void *format, void *para1, void *para2,
                      void *para3, void *para4);
void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
                      void *format, void *para);

/* Forward declarations for custom UIO callbacks */
static int32_t curl_uio_write(BSL_UIO *uio, const void *buf,
                               uint32_t len, uint32_t *writeLen);
static int32_t curl_uio_read(BSL_UIO *uio, void *buf, uint32_t len,
                              uint32_t *readLen);
static int32_t curl_uio_ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg,
                              void *parg);
static int32_t curl_uio_create(BSL_UIO *uio);
static int32_t curl_uio_destroy(BSL_UIO *uio);

/* Forward declarations for new step-based connect functions */
static CURLcode hitls_connect_step1(struct Curl_cfilter *cf,
                                    struct Curl_easy *data);
static CURLcode hitls_connect_step2(struct Curl_cfilter *cf,
                                    struct Curl_easy *data);
static CURLcode hitls_connect_step3(struct Curl_cfilter *cf,
                                    struct Curl_easy *data);

/* Forward declarations for refactored certificate functions */
static CURLcode Curl_hitls_ctx_init(struct hitls_ctx *hctx,
                                    struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ssl_peer *peer,
                                    const struct alpn_spec *alpns_requested,
                                    void *ssl_user_data);

static CURLcode hitls_client_cert(struct Curl_easy *data,
                                  HITLS_Config *config,
                                  char *cert_file,
                                  const struct curl_blob *cert_blob,
                                  const char *cert_type,
                                  char *key_file,
                                  const struct curl_blob *key_blob,
                                  const char *key_type,
                                  char *key_passwd);

static CURLcode Curl_hitls_check_peer_cert(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct hitls_ctx *hctx,
                                           struct ssl_peer *peer);

static CURLcode Curl_hitls_setup_x509_store(struct Curl_cfilter *cf,
                                            struct Curl_easy *data,
                                            HITLS_Config *config);

/* Forward declarations */
static CURLcode hitls_certchain(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct hitls_ctx *hctx);
static CURLcode hitls_translate_error(int hitls_error);
static int hitls_do_file_type(const char *type);

/* OpenHiTLS keylog callback function */
static void hitls_keylog_callback(HITLS_Ctx *ctx, const char *line)
{
  (void)ctx;  /* Unused parameter */
  Curl_tls_keylog_write_line(line);
}

/* SSL object initialization */
static CURLcode hitls_init_ssl(struct hitls_ctx *hctx,
                               struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct ssl_peer *peer,
                               const struct alpn_spec *alpns_requested,
                               void *ssl_user_data);
static CURLcode hitls_pkcs12_load(struct Curl_easy *data, HITLS_Config *config,
                                  const struct curl_blob *cert_blob,
                                  const char *cert_file,
                                  const char *key_passwd);
static CURLcode hitls_verifyhost(struct Curl_easy *data,
                                 struct connectdata *conn,
                                 struct ssl_peer *peer,
                                 HITLS_CERT_X509 *server_cert);

/* File type enumeration */
#define HITLS_FILETYPE_PEM  1
#define HITLS_FILETYPE_ASN1 2
#define HITLS_FILETYPE_PKCS12 3

/* Certificate chain information extraction */
static CURLcode
hitls_certchain(struct Curl_cfilter *cf, struct Curl_easy *data,
                struct hitls_ctx *hctx)
{
  CURLcode result = CURLE_OK;
  HITLS_CERT_Chain *cert_chain = NULL;
  HITLS_CERT_X509 *cert = NULL;
  int cert_count = 0;
  int cert_index = 0;

  (void)cf; /* unused parameter */

  /* Get peer certificate chain */
  cert_chain = HITLS_GetPeerCertChain(hctx->ssl);
  if(!cert_chain) {
    infof(data, "OpenHiTLS: No peer certificate chain available");
    return CURLE_OK;  /* Not an error, just no certificates */
  }

  /* Calculate certificate chain length */
  cert_count = BSL_LIST_COUNT(cert_chain);
  if(cert_count == 0) {
    infof(data, "OpenHiTLS: Empty certificate chain");
    return CURLE_OK;
  }

  /* Initialize curl certificate info storage */
  result = Curl_ssl_init_certinfo(data, cert_count);
  if(result != CURLE_OK) {
    return result;
  }

  /* Iterate through certificate chain and extract information */
  cert = (HITLS_CERT_X509 *)BSL_LIST_GET_FIRST(cert_chain);
  cert_index = 0;

  while(cert && cert_index < cert_count) {
    uint32_t cert_len = 0;
    uint8_t *cert_data = NULL;
    int32_t ret;

    /* Get certificate encoded length */
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODELEN,
                             &cert_len, sizeof(uint32_t));
    if(ret != HITLS_SUCCESS || cert_len == 0) {
      infof(data, "OpenHiTLS: Failed to get certificate %d length (ret=%d)",
            cert_index, ret);
      goto next_cert;
    }

    /* Get certificate raw data */
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODE,
                             (void *)&cert_data, 0);
    if(ret != HITLS_SUCCESS || !cert_data) {
      infof(data, "OpenHiTLS: Failed to get certificate %d data (ret=%d)",
            cert_index, ret);
      goto next_cert;
    }

    /* Pass to curl's x509 parser */
    result = Curl_extract_certinfo(data, cert_index,
                                  (const char *)cert_data,
                                  (const char *)cert_data + cert_len);
    if(result != CURLE_OK) {
      infof(data, "OpenHiTLS: Failed to extract certificate %d info",
            cert_index);
      /* Continue processing next certificate, don't abort for single
         failure */
    }
    else {
      infof(data, "OpenHiTLS: Successfully extracted info for certificate %d",
            cert_index);
    }

next_cert:
    cert_index++;
    cert = (HITLS_CERT_X509 *)BSL_LIST_GET_NEXT(cert_chain);
  }

  infof(data, "OpenHiTLS: Certificate info extraction completed for "
        "%d/%d certificates", cert_index, cert_count);
  return CURLE_OK;
}

static CURLcode
hitls_check_pinned_pubkey(struct Curl_cfilter *cf, struct Curl_easy *data,
                          HITLS_CERT_X509 *server_cert)
{
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const char * const pinnedpubkey = ssl_config->primary.pinned_key;
  CRYPT_EAL_PkeyCtx *pubkey = NULL;
  BSL_Buffer pubkey_der = { 0 };
  CURLcode result = CURLE_OK;
  int32_t ret;

  if(!pinnedpubkey)
    return CURLE_OK;

  ret = HITLS_X509_CertCtrl(server_cert, HITLS_X509_GET_PUBKEY,
                            &pubkey, sizeof(pubkey));
  if(ret != HITLS_SUCCESS || !pubkey) {
    failf(data, "OpenHiTLS: failed retrieving public key from certificate");
    return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
  }

  ret = CRYPT_EAL_EncodeBuffKey(pubkey, NULL, BSL_FORMAT_ASN1,
                                CRYPT_PUBKEY_SUBKEY, &pubkey_der);
  if(ret != CRYPT_SUCCESS || !pubkey_der.data || !pubkey_der.dataLen) {
    failf(data, "OpenHiTLS: failed encoding public key from certificate");
    result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    goto cleanup;
  }

  result = Curl_pin_peer_pubkey(data, pinnedpubkey,
                                pubkey_der.data, pubkey_der.dataLen);
  if(result)
    failf(data, "SSL: public key does not match pinned public key");

cleanup:
  BSL_SAL_FREE(pubkey_der.data);
  CRYPT_EAL_PkeyFreeCtx(pubkey);
  return result;
}

/* Map openHiTLS error codes to curl error codes */
static CURLcode
hitls_translate_error(int hitls_error)
{
  switch(hitls_error) {
    case HITLS_CERT_ERR_VERIFY_CERT_CHAIN:
      return CURLE_PEER_FAILED_VERIFICATION;
    case HITLS_REC_NORMAL_RECV_BUF_EMPTY:
    case HITLS_REC_NORMAL_IO_BUSY:
    case HITLS_WANT_READ:
    case HITLS_WANT_WRITE:
      return CURLE_AGAIN;
    case HITLS_CM_LINK_CLOSED:
    case HITLS_REC_NORMAL_IO_EOF:
      return CURLE_OK;
    default:
      return CURLE_SSL_CONNECT_ERROR;
  }
}

/* File type utility function */
static int hitls_do_file_type(const char *type)
{
  if(!type || !type[0])
    return HITLS_FILETYPE_PEM;
  if(curl_strequal(type, "PEM"))
    return HITLS_FILETYPE_PEM;
  if(curl_strequal(type, "DER"))
    return HITLS_FILETYPE_ASN1;
  if(curl_strequal(type, "P12"))
    return HITLS_FILETYPE_PKCS12;
  return -1;
}

static bool
hitls_size_to_uint32(size_t in, uint32_t *out)
{
  if(in > UINT32_MAX)
    return FALSE;
  *out = (uint32_t)in;
  return TRUE;
}

/* Password callback function for encrypted private keys */
static int hitls_passwd_callback(char *buf, int size, int rwflag,
                                 void *userdata)
{
  const char *passwd = (const char *)userdata;
  int passwd_len;

  if(!passwd || !buf)
    return 0;

  passwd_len = (int)strlen(passwd);
  if(passwd_len >= size)
    passwd_len = size - 1;

  memcpy(buf, passwd, passwd_len);
  buf[passwd_len] = '\0';
  return passwd_len;

  (void)rwflag; /* Unused parameter */
}

/* PKCS#12 certificate processing */
static CURLcode
hitls_pkcs12_load(struct Curl_easy *data, HITLS_Config *config,
                  const struct curl_blob *cert_blob, const char *cert_file,
                  const char *key_passwd)
{
  HITLS_PKCS12 *p12 = NULL;
  HITLS_X509_Cert *cert = NULL;
  CRYPT_EAL_PkeyCtx *pkey = NULL;
  BslList *cert_bags = NULL;
  HITLS_PKCS12_PwdParam pwdParam = {0};
  BSL_Buffer encPwd = {0};
  BSL_Buffer macPwd = {0};
  char *key_passwd_copy = NULL;
  int ret;
  CURLcode result = CURLE_SSL_CERTPROBLEM;

  if(key_passwd) {
    size_t passwd_len = strlen(key_passwd);
    if(!hitls_size_to_uint32(passwd_len, &encPwd.dataLen))
      return CURLE_SSL_CERTPROBLEM;
    key_passwd_copy = curlx_strdup(key_passwd);
    if(!key_passwd_copy)
      return CURLE_OUT_OF_MEMORY;
    encPwd.data = (uint8_t *)key_passwd_copy;
    macPwd.data = (uint8_t *)key_passwd_copy;
    macPwd.dataLen = encPwd.dataLen;
    pwdParam.encPwd = &encPwd;
    pwdParam.macPwd = &macPwd;
  }

  /* Step 1: Parse PKCS#12 data */
  if(cert_blob) {
    /* Parse from memory buffer */
    BSL_Buffer buffer;
    buffer.data = (uint8_t *)cert_blob->data;
    buffer.dataLen = (uint32_t)cert_blob->len;

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &buffer, &pwdParam, &p12,
                                 true);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to parse PKCS#12 blob data "
            "(error: 0x%x)", (unsigned int)ret);
      goto cleanup;
    }
  }
  else {
    /* Parse from file */
    ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, cert_file, &pwdParam, &p12,
                                 true);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to parse PKCS#12 file '%s' "
            "(error: 0x%x, check password)", cert_file, (unsigned int)ret);
      goto cleanup;
    }
  }

  if(!p12) {
    failf(data, "OpenHiTLS: PKCS#12 parsing returned NULL");
    goto cleanup;
  }

  /* Step 2: Extract entity certificate using HITLS_PKCS12_Ctrl */
  ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_CERT, &cert, 0);
  if(ret != HITLS_SUCCESS || !cert) {
    failf(data, "OpenHiTLS: Failed to extract certificate from PKCS#12 "
          "(error: 0x%x)", (unsigned int)ret);
    goto cleanup;
  }

  /* Step 3: Extract entity private key using HITLS_PKCS12_Ctrl */
  ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_KEY, &pkey, 0);
  if(ret != HITLS_SUCCESS || !pkey) {
    failf(data, "OpenHiTLS: Failed to extract private key from PKCS#12 "
          "(error: 0x%x)", (unsigned int)ret);
    goto cleanup;
  }

  /* Step 4: Load certificate and private key to config using correct APIs */
  ret = HITLS_CFG_SetCertificate(config, cert, true);  /* true = deep copy */
  if(ret != HITLS_SUCCESS) {
    failf(data, "OpenHiTLS: Failed to set certificate from PKCS#12 "
          "(error: 0x%x)", (unsigned int)ret);
    goto cleanup;
  }

  ret = HITLS_CFG_SetPrivateKey(config, pkey, true);  /* true = deep copy */
  if(ret != HITLS_SUCCESS) {
    failf(data, "OpenHiTLS: Failed to set private key from PKCS#12 "
          "(error: 0x%x)", (unsigned int)ret);
    goto cleanup;
  }

  /* Step 5: Verify certificate and key match */
  ret = HITLS_CFG_CheckPrivateKey(config);
  if(ret != HITLS_SUCCESS) {
    failf(data,
          "OpenHiTLS: Private key does not match certificate in PKCS#12 "
          "file '%s' (error: 0x%x)",
          cert_file ? cert_file : "(memory blob)", (unsigned int)ret);
    goto cleanup;
  }

  /* Step 6: Handle certificate chain (CA certificates) using
   * HITLS_PKCS12_Ctrl */
  ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_CERTBAGS, &cert_bags, 0);
  if(ret == HITLS_SUCCESS && cert_bags) {
    /* Process each certificate in the bag list */
    HITLS_PKCS12_Bag *bag =
      (HITLS_PKCS12_Bag *)BSL_LIST_GET_FIRST(cert_bags);
    while(bag) {
      HITLS_X509_Cert *ca_cert = NULL;
      ret = HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_VALUE, &ca_cert, 0);
      if(ret == HITLS_SUCCESS && ca_cert) {
        /* Add CA certificate to chain */
        ret = HITLS_CFG_AddChainCert(config, ca_cert, true);
        if(ret != HITLS_SUCCESS) {
          failf(data, "OpenHiTLS: Failed to add CA certificate from "
                "PKCS#12 chain (error: 0x%x)", (unsigned int)ret);
          /* Continue processing other certificates */
        }
      }
      /* Move to next element in the list */
      bag = (HITLS_PKCS12_Bag *)BSL_LIST_GET_NEXT(cert_bags);
    }
  }

  result = CURLE_OK;
  infof(data, "OpenHiTLS: Successfully loaded PKCS#12 certificate and key");

cleanup:
  /* Clean up resources - openHiTLS handles reference counting */
  if(p12)
    HITLS_PKCS12_Free(p12);
  curlx_free(key_passwd_copy);

  return result;
}

/* Create custom UIO method */
static BSL_UIO_Method *curl_create_uio_method(void)
{
  BSL_UIO_Method *method = BSL_UIO_NewMethod();
  if(!method) {
    return NULL;
  }

  /* Set transport type */
  if(BSL_UIO_SetMethodType(method, BSL_UIO_TCP) != BSL_SUCCESS) {
    BSL_UIO_FreeMethod(method);
    return NULL;
  }

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
  /* Set our custom callbacks. openHiTLS stores callback pointers as void *. */
  if(BSL_UIO_SetMethod(method, BSL_UIO_WRITE_CB,
                       (void *)curl_uio_write) != BSL_SUCCESS ||
     BSL_UIO_SetMethod(method, BSL_UIO_READ_CB,
                       (void *)curl_uio_read) != BSL_SUCCESS ||
     BSL_UIO_SetMethod(method, BSL_UIO_CTRL_CB,
                       (void *)curl_uio_ctrl) != BSL_SUCCESS ||
     BSL_UIO_SetMethod(method, BSL_UIO_CREATE_CB,
                       (void *)curl_uio_create) != BSL_SUCCESS ||
     BSL_UIO_SetMethod(method, BSL_UIO_DESTROY_CB,
                       (void *)curl_uio_destroy) != BSL_SUCCESS) {
    BSL_UIO_FreeMethod(method);
    return NULL;
  }
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

  return method;
}

/* UIO write callback - called when openHiTLS wants to send data */
static int32_t
curl_uio_write(BSL_UIO *uio, const void *buf, uint32_t len,
               uint32_t *writeLen)
{
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  size_t nwritten = 0;
  CURLcode result;

  if(!uio || !writeLen) {
    return BSL_UIO_FAIL;
  }

  *writeLen = 0;
  cf = (struct Curl_cfilter *)BSL_UIO_GetUserData(uio);
  if(!cf) {
    return BSL_UIO_FAIL;
  }

  data = CF_DATA_CURRENT(cf);
  if(!data) {
    return BSL_UIO_FAIL;
  }

  if(len == 0) {
    return BSL_SUCCESS;
  }

  /* Use curl's connection filter to send data */
  result = Curl_conn_cf_send(cf->next, data, (const uint8_t *)buf,
                             (size_t)len, FALSE, &nwritten);

  CURL_TRC_CF(data, cf, "curl_uio_write(len=%u) -> %d, %zu", len,
              (int)result, nwritten);

  if(result == CURLE_OK) {
    *writeLen = (uint32_t)nwritten;
    return BSL_SUCCESS;
  }
  else if(result == CURLE_AGAIN) {
    /* Would block - this is normal in non-blocking mode */
    return BSL_UIO_IO_BUSY;
  }
  else {
    /* Other errors */
    return BSL_UIO_FAIL;
  }
}

/* UIO read callback - called when openHiTLS wants to receive data */
static int32_t
curl_uio_read(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  struct ssl_connect_data *connssl;
  size_t nread = 0;
  CURLcode result;

  if(!uio || !readLen) {
    return BSL_UIO_FAIL;
  }

  *readLen = 0;
  cf = (struct Curl_cfilter *)BSL_UIO_GetUserData(uio);
  if(!cf) {
    return BSL_UIO_FAIL;
  }
  connssl = cf->ctx;

  data = CF_DATA_CURRENT(cf);
  if(!data) {
    return BSL_UIO_FAIL;
  }

  if(len == 0) {
    return BSL_SUCCESS;
  }

  /* Use curl's connection filter to receive data */
  result = Curl_conn_cf_recv(cf->next, data, (char *)buf,
                             (size_t)len, &nread);

  CURL_TRC_CF(data, cf, "curl_uio_read(len=%u) -> %d, %zu", len,
              (int)result, nread);

  /* Before returning server replies to the openHiTLS instance, we need
   * to have setup the x509 store or verification will fail. */
  if(result == CURLE_OK && nread > 0) {
    struct hitls_ctx *hctx = (struct hitls_ctx *)connssl->backend;

    if(hctx && !hctx->ca_store_setup) {
      CURLcode store_result = Curl_hitls_setup_x509_store(cf, data,
                                                          hctx->config);
      if(store_result != CURLE_OK) {
        CURL_TRC_CF(data, cf, "X509 store setup failed in UIO read: %d",
                    (int)store_result);
        /* Record error but don't interrupt data transmission, let handshake
         * step handle it */
      }
      else {
        hctx->ca_store_setup = TRUE;
        CURL_TRC_CF(data, cf, "X509 store setup completed in UIO read");
      }
    }
  }

  if(result == CURLE_OK) {
    *readLen = (uint32_t)nread;
    if(nread > 0) {
      connssl->input_pending = TRUE;
    }

    if(nread == 0) {
      connssl->peer_closed = TRUE;
      /* Connection closed by peer */
      return BSL_UIO_IO_EOF;
    }
    return BSL_SUCCESS;
  }
  else if(result == CURLE_AGAIN) {
    /* Would block - this is normal in non-blocking mode */
  /* Use BSL_UIO_IO_BUSY instead of BSL_UIO_RECV_BUF_EMPTY */
    *readLen = 0;
    return BSL_SUCCESS;
  }
  else {
    /* Other errors */
    return BSL_UIO_FAIL;
  }
}

/* UIO control callback - handle various control operations */
static int32_t
curl_uio_ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
  struct Curl_cfilter *cf;

  (void)larg; /* Suppress unused parameter warning */

  if(!uio) {
    return BSL_UIO_FAIL;
  }

  cf = (struct Curl_cfilter *)BSL_UIO_GetUserData(uio);
  if(!cf) {
    return BSL_UIO_FAIL;
  }

  switch(cmd) {
  case BSL_UIO_GET_FD:
    /* We don't expose the raw file descriptor */
    if(parg) {
      *(int32_t *)parg = -1;
    }
    return BSL_SUCCESS;

  case BSL_UIO_FLUSH:
    /* No explicit flush needed for curl's connection filters */
    return BSL_SUCCESS;

  case BSL_UIO_RESET:
    /* Reset state - nothing specific to do */
    return BSL_SUCCESS;

  case BSL_UIO_PENDING:
    /* Check if data is pending to be read */
    if(parg) {
      /* For now, assume no pending data */
      *(uint32_t *)parg = 0;
    }
    return BSL_SUCCESS;

  case BSL_UIO_WPENDING:
    /* Check if data is pending to be written */
    if(parg) {
      /* For now, assume no pending data */
      *(uint32_t *)parg = 0;
    }
    return BSL_SUCCESS;

  default:
    /* Unsupported command */
    return BSL_UIO_FAIL;
  }
}

/* UIO create callback - called when UIO is created */
static int32_t curl_uio_create(BSL_UIO *uio)
{
  (void)uio;
  BSL_UIO_SetInit(uio, true);
  /* Nothing special needed for creation */
  return BSL_SUCCESS;
}

/* UIO destroy callback - called when UIO is destroyed */
static int32_t curl_uio_destroy(BSL_UIO *uio)
{
  if(!uio) {
    return BSL_SUCCESS;
  }

  /* Simply clear the user data - no need to free since we don't own the cf */
  BSL_UIO_SetUserData(uio, NULL);

  return BSL_SUCCESS;
}

void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
  void *format, void *para1, void *para2, void *para3, void *para4)
{
  struct Curl_easy *data = tls_current_data;
  struct Curl_cfilter *cf = tls_current_cf;
  char msg[512];
  int len;

  if(!data|| !cf) {
    return;
  }
  (void)logType;  /* Currently unused */

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
  /* Format the message */
  len = curl_msnprintf(msg, sizeof(msg), (const char *)format,
                  para1, para2, para3, para4);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

  if(len > 0 && (size_t)len < sizeof(msg)) {
    CURL_TRC_CF(data, cf, "OpenHiTLS[%u][%u]: %s", logId, logLevel, msg);
  }
}

void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
  void *format, void *para)
{
  BinLogFixLenFunc(logId, logLevel, logType, format, para, NULL, NULL, NULL);
}

static int
hitls_init(void)
{
  int ret;
  void *malloc_func = (void *)(uintptr_t)malloc;
  void *free_func = (void *)(uintptr_t)free;
  BSL_LOG_BinLogFuncs logFunc;

  /* Register BSL memory capabilities */
  BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, malloc_func);
  BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free_func);
  BSL_ERR_Init();

  BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_DEBUG);
  logFunc.fixLenFunc = BinLogFixLenFunc;
  logFunc.varLenFunc = BinLogVarLenFunc;
  BSL_LOG_RegBinLogFunc(&logFunc);

  /* Initialize crypto library */
  ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
  if(ret != CRYPT_SUCCESS) {
    return 0; /* Failure */
  }

  /* Initialize certificate and crypto methods */
  HITLS_CertMethodInit();
  HITLS_CryptMethodInit();

  /* Open keylog file if SSLKEYLOGFILE environment variable is set */
  Curl_tls_keylog_open();

  return 1; /* Success */
}

static void
hitls_cleanup(void)
{
  /* Close keylog file if it was opened */
  Curl_tls_keylog_close();

  /* Deinitialize random number generator */
  CRYPT_EAL_RandDeinit();

  /* Note: CRYPT_EAL_Cleanup() may not be available,
   * OpenHiTLS cleanup is mostly handled automatically */
}

static CURLcode
hitls_shutdown(struct Curl_cfilter *cf, struct Curl_easy *data,
               bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;
  CURLcode result = CURLE_OK;
  char buf[1024];
  uint32_t nread = 0;
  int ret;
  size_t i;
  uint32_t shutdown_state = 0;

  (void)send_shutdown; /* Suppress unused parameter warning */

  DEBUGASSERT(backend);
  if(!backend->ssl || cf->shutdown) {
    *done = TRUE;
    goto out;
  }

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  *done = FALSE;

  /* Get current shutdown state */
  ret = HITLS_GetShutdownState(backend->ssl, &shutdown_state);
  if(ret != HITLS_SUCCESS) {
    failf(data, "OpenHiTLS: Failed to get shutdown state: %d", ret);
    *done = TRUE;
    result = CURLE_SSL_SHUTDOWN_FAILED;
    goto out;
  }

  /* Check if we haven't sent shutdown yet */
  if(!(shutdown_state & HITLS_SENT_SHUTDOWN)) {
    /* We have not started the shutdown from our side yet. Check
     * if the server already sent us one. */
    for(i = 0; i < 10; ++i) {
      nread = 0;
      ret = HITLS_Read(backend->ssl, (uint8_t *)buf, sizeof(buf), &nread);
      CURL_TRC_CF(data, cf, "OpenHiTLS shutdown not sent, read -> %u", nread);
      if(nread <= 0)
        break;
    }

    if(ret == HITLS_CM_LINK_CLOSED && nread == 0) {
      /* Server sent close notify */
      bool input_pending;
      if(!send_shutdown) {
        CURL_TRC_CF(data, cf, "OpenHiTLS shutdown received, not sending");
        *done = TRUE;
        goto out;
      }
      else if(!cf->next->cft->is_alive(cf->next, data, &input_pending)) {
        /* Server closed the connection after its close notify. It
         * seems not interested to see our close notify, so do not
         * send it. We are done. */
        connssl->peer_closed = TRUE;
        CURL_TRC_CF(data, cf, "peer closed connection");
        *done = TRUE;
        goto out;
      }
    }
  }

  /* Send shutdown if requested and not already sent */
  if(send_shutdown && !(shutdown_state & HITLS_SENT_SHUTDOWN)) {
    CURL_TRC_CF(data, cf, "send OpenHiTLS close notify");

    /* Set context before shutdown */
    HITLS_SET_CONTEXT(data, cf);

    /* Send close notify - may trigger openHiTLS logs */
    ret = HITLS_Close(backend->ssl);

    /* Restore context */
    HITLS_RESTORE_CONTEXT();

    (void)HITLS_GetShutdownState(backend->ssl, &shutdown_state);
    if((shutdown_state & HITLS_SENT_SHUTDOWN) &&
       (shutdown_state & HITLS_RECEIVED_SHUTDOWN)) {
      CURL_TRC_CF(data, cf, "OpenHiTLS shutdown finished");
      *done = TRUE;
      goto out;
    }
    else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
      CURL_TRC_CF(data, cf, "OpenHiTLS shutdown still wants to send");
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
      goto out;
    }
    /* Having sent the close notify, we use HITLS_Read() to get the
     * missing close notify from the server. */
  }

  /* Try to read the server's close notify */
  for(i = 0; i < 10; ++i) {
    nread = 0;
    ret = HITLS_Read(backend->ssl, (uint8_t *)buf, sizeof(buf), &nread);
    CURL_TRC_CF(data, cf, "OpenHiTLS shutdown read -> %u (ret=%d)",
                nread, ret);
    if(nread <= 0)
      break;
  }

  /* Handle the read result */
  switch(ret) {
  case HITLS_CM_LINK_CLOSED:
    CURL_TRC_CF(data, cf, "OpenHiTLS shutdown finished");
    *done = TRUE;
    break;
  case HITLS_SUCCESS:
  case HITLS_REC_NORMAL_RECV_BUF_EMPTY:
    CURL_TRC_CF(data, cf, "OpenHiTLS shutdown sent, want receive");
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    break;
  case HITLS_REC_NORMAL_IO_BUSY:
    CURL_TRC_CF(data, cf, "OpenHiTLS shutdown send blocked");
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
    break;
  default:
    CURL_TRC_CF(data, cf, "OpenHiTLS shutdown, ignore recv error: %d",
                ret);
    *done = TRUE;
    result = CURLE_OK;
    break;
  }

out:
  cf->shutdown = (result || *done);
  if(cf->shutdown || (connssl->io_need != CURL_SSL_IO_NEED_NONE))
    connssl->input_pending = FALSE;

  return result;
}

static void
hitls_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;

  (void)data;

  if(backend) {
    if(backend->ssl) {
      HITLS_Free(backend->ssl);
      backend->ssl = NULL;
    }
    if(backend->uio) {
      BSL_UIO_Free(backend->uio);
      backend->uio = NULL;
    }
    if(backend->uio_method) {
      BSL_UIO_FreeMethod(backend->uio_method);
      backend->uio_method = NULL;
    }
    if(backend->config) {
      HITLS_CFG_FreeConfig(backend->config);
      backend->config = NULL;
    }
  }
}

static void
hitls_close_all(struct Curl_easy *data)
{
  (void)data;
  /* Nothing specific to do for global cleanup */
}

static uint16_t
curl_to_hitls_version(long curl_version)
{
  switch(curl_version) {
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1_1:
      /* TLS 1.0/1.1 not supported by openHiTLS, return 0 (no limit) */
      return 0;
    case CURL_SSLVERSION_TLSv1_2:
    case CURL_SSLVERSION_MAX_TLSv1_2:
      return HITLS_VERSION_TLS12;
    case CURL_SSLVERSION_TLSv1_3:
    case CURL_SSLVERSION_MAX_TLSv1_3:
      return HITLS_VERSION_TLS13;
    case CURL_SSLVERSION_TLCP_1_1:
    case CURL_SSLVERSION_MAX_TLCP_1_1:
      return HITLS_VERSION_TLCP_DTLCP11;
    default:
      return 0; /* No version specified, no limit */
  }
}

/* Protocol type enumeration */
typedef enum {
  HITLS_PROTOCOL_TLS,     /* Standard TLS protocol */
  HITLS_PROTOCOL_TLCP     /* TLCP protocol */
} hitls_protocol_type_t;

/* Detect protocol type from version configuration */
static hitls_protocol_type_t
get_protocol_type_from_version(long ssl_version, long ssl_version_max)
{
  /* Check for TLCP version */
  if(ssl_version == CURL_SSLVERSION_TLCP_1_1 ||
     ssl_version_max == (CURL_SSLVERSION_MAX_TLCP_1_1 >> 16)) {
    return HITLS_PROTOCOL_TLCP;
  }

  return HITLS_PROTOCOL_TLS;  /* Default TLS protocol */
}

/* Validate version compatibility */
static CURLcode
hitls_validate_version_compatibility(long ssl_version, long ssl_version_max)
{
  bool min_is_tlcp = (ssl_version == CURL_SSLVERSION_TLCP_1_1);
  bool max_is_tlcp = (ssl_version_max == (CURL_SSLVERSION_MAX_TLCP_1_1 >> 16));

  /* Check TLCP mixed with standard TLS */
  if(min_is_tlcp && (ssl_version_max > 0 &&
                     ssl_version_max <= CURL_SSLVERSION_TLSv1_3)) {
    return CURLE_SSL_CONNECT_ERROR;  /* TLCP cannot mix with standard TLS */
  }

  if(max_is_tlcp && (ssl_version > 0 &&
                     ssl_version <= CURL_SSLVERSION_TLSv1_3)) {
    return CURLE_SSL_CONNECT_ERROR;  /* Standard TLS cannot mix with TLCP */
  }

  return CURLE_OK;
}

/* Configure TLS version settings */
static CURLcode
hitls_set_tls_version(HITLS_Config *config,
                      long ssl_version,
                      long ssl_version_max)
{
  uint16_t min_version = curl_to_hitls_version(ssl_version);
  uint16_t max_version = curl_to_hitls_version(ssl_version_max);
  int ret;

  /* Set TLS version range */
  ret = HITLS_CFG_SetVersion(config, min_version, max_version);
  if(ret != HITLS_SUCCESS) {
    return CURLE_SSL_CONNECT_ERROR;
  }

  return CURLE_OK;
}

/* Parse cipher list using cipher_suite.c - simplified version */
static CURLcode
hitls_set_selected_ciphers(struct Curl_easy *data,
                          HITLS_Config *config,
                          const char *ciphers12,
                          const char *ciphers13)
{
  uint16_t selected[256];  /* Direct storage of IANA IDs */
  size_t count = 0;
  const char *ptr, *end;
  const char *ciphers = ciphers12;
  int ret;

  /* Handle TLS 1.3 cipher suites */
  if(!ciphers13 && !ciphers) {
    /* Add default TLS 1.3 IANA IDs */
    selected[count++] = 0x1302; /* AES_256_GCM_SHA384 */
    selected[count++] = 0x1301; /* AES_128_GCM_SHA256 */
    selected[count++] = 0x1303; /* CHACHA20_POLY1305_SHA256 */
  }
  else if(ciphers13)
    ciphers = ciphers13;

add_ciphers:
  /* Parse cipher suite string - directly get IANA IDs! */
  for(ptr = ciphers; ptr[0] != '\0' && count < 256; ptr = end) {
    uint16_t iana_id = Curl_cipher_suite_walk_str(&ptr, &end);

    if(iana_id) {
      /* Check for duplicates */
      size_t i;
      for(i = 0; i < count && selected[i] != iana_id; i++);
      if(i == count) {
        selected[count++] = iana_id;  /* Store IANA ID directly! */
      }
    }
    else if(ptr[0] != '\0') {
      infof(data, "openHiTLS: unknown cipher: \"%.*s\"",
            (int)(end - ptr), ptr);
    }
  }

  /* Handle TLS 1.2 cipher suites */
  if(ciphers == ciphers13 && ciphers12) {
    ciphers = ciphers12;
    goto add_ciphers;
  }

  /* If no TLS 1.2 specified, add defaults */
  if(!ciphers12 && ciphers == ciphers13) {
    uint16_t default12[] = {
      0xC030, /* ECDHE-RSA-AES256-GCM-SHA384 */
      0xC02F, /* ECDHE-RSA-AES128-GCM-SHA256 */
      0xC02C, /* ECDHE-ECDSA-AES256-GCM-SHA384 */
      0xC02B, /* ECDHE-ECDSA-AES128-GCM-SHA256 */
      0xCCA8, /* ECDHE-RSA-CHACHA20-POLY1305 */
      0xCCA9, /* ECDHE-ECDSA-CHACHA20-POLY1305 */
      0
    };

    for(size_t i = 0; default12[i] != 0 && count < 256; i++) {
      size_t j;
      for(j = 0; j < count && selected[j] != default12[i]; j++);
      if(j == count) {
        selected[count++] = default12[i];
      }
    }
  }

  if(count == 0) {
    failf(data, "openHiTLS: no supported cipher in list");
    return CURLE_SSL_CIPHER;
  }

  /* Set IANA ID array directly! No conversion needed! */
  ret = HITLS_CFG_SetCipherSuites(config, selected, (uint32_t)count);
  if(ret != HITLS_SUCCESS) {
    failf(data, "openHiTLS: failed to set cipher suites");
    return CURLE_SSL_CIPHER;
  }

  return CURLE_OK;
}

/* Unified CA certificate loading using TLS module interfaces only */
static CURLcode
hitls_populate_ca_store(struct Curl_cfilter *cf, struct Curl_easy *data,
                        HITLS_Config *config)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ca_info_blob ? NULL : conn_config->CAfile);
  const char * const ssl_capath = conn_config->CApath;
  const char * const ssl_crlfile = ssl_config->primary.CRLfile;
  const bool verifypeer = conn_config->verifypeer;
  int ret;

  CURL_TRC_CF(data, cf, "hitls_populate_ca_store, path=%s, blob=%d",
              ssl_cafile ? ssl_cafile : "none", !!ca_info_blob);
  if(!config)
    return CURLE_OUT_OF_MEMORY;

  if(verifypeer) {
    if(ca_info_blob) {
      /* Load CA certificates from memory blob using TLS module interface
       * This supports loading multiple certificates from the blob */
      ret = HITLS_CFG_LoadVerifyBuffer(config,
                                      (const uint8_t *)ca_info_blob->data,
                                      (uint32_t)ca_info_blob->len,
                                      TLS_PARSE_FORMAT_PEM);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to load CA certificates from blob");
        return CURLE_SSL_CACERT_BADFILE;
      }

      infof(data, " CAinfo: blob loaded");
    }

    if(ssl_cafile) {
      /* Use HITLS_CFG_LoadVerifyFile to support multi-certificate file
       * loading (default PEM format) */
      ret = HITLS_CFG_LoadVerifyFile(config, ssl_cafile);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: error setting certificate file: %s",
              ssl_cafile);
        return CURLE_SSL_CACERT_BADFILE;
      }

      infof(data, " CAfile: %s", ssl_cafile);
    }

    if(ssl_capath) {
      /* Load CA certificates from directory using openHiTLS */
      ret = HITLS_CFG_LoadVerifyDir(config, ssl_capath);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to load CA directory: %s", ssl_capath);
        return CURLE_SSL_CACERT_BADFILE;
      }
      infof(data, " CApath: %s", ssl_capath);
    }

    if(ssl_crlfile) {
      /* Load CRL using TLS module interface (PEM format required) */
      ret = HITLS_CFG_LoadCrlFile(config, ssl_crlfile, TLS_PARSE_FORMAT_PEM);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to load CRL file: %s", ssl_crlfile);
        return CURLE_SSL_CRL_BADFILE;
      }
      ret = HITLS_CFG_SetVerifyFlags(config, HITLS_X509_VFY_FLAG_CRL_ALL);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to enable CRL verification: %s",
              ssl_crlfile);
        return CURLE_SSL_CRL_BADFILE;
      }
      infof(data, " CRLfile: %s", ssl_crlfile);
    }

    /* Set verification parameters */
    if(conn_config->verifypeer) {
      /* Enable certificate verification */
      infof(data, " Certificate verification: enabled");
    }
  }

  /* Fallback to default CA paths if no CA sources configured */
  if(verifypeer) {
    bool has_any_ca_source = (ca_info_blob || ssl_cafile || ssl_capath);
    if(!has_any_ca_source) {
      /* Try to load system default CA paths */
      ret = HITLS_CFG_LoadDefaultCAPath(config);
      if(ret != HITLS_SUCCESS) {
        infof(data, "OpenHiTLS: Failed to load default CA paths, "
                    "verification may fail");
        /* Non-fatal error, continue execution */
      }
      else {
        infof(data, " Default CA paths loaded");
      }
    }
  }

  return CURLE_OK;
}

static CURLcode
hitls_client_cert(struct Curl_easy *data, HITLS_Config *config,
                  char *cert_file, const struct curl_blob *cert_blob,
                  const char *cert_type, char *key_file,
                  const struct curl_blob *key_blob,
                  const char *key_type, char *key_passwd)
{
  int ret;
  int file_type = hitls_do_file_type(cert_type);
  bool pkcs12_done = FALSE;  /* Flag to indicate PKCS#12 was processed */

  /* Set password callback if password provided */
  if(key_passwd) {
    ret = HITLS_CFG_SetDefaultPasswordCbUserdata(config, key_passwd);
    if(ret != HITLS_SUCCESS) {
      failf(data,
            "OpenHiTLS: Failed to set password userdata (error code: %d)",
            ret);
      return CURLE_SSL_CERTPROBLEM;
    }

    ret = HITLS_CFG_SetDefaultPasswordCb(config, hitls_passwd_callback);
    if(ret != HITLS_SUCCESS) {
      failf(data,
            "OpenHiTLS: Failed to set password callback (error code: %d)",
            ret);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  if(cert_file || cert_blob) {
    switch(file_type) {
      case HITLS_FILETYPE_PEM:
      case HITLS_FILETYPE_ASN1:
      if(cert_blob) {
        uint32_t cert_blob_len;
        if(!hitls_size_to_uint32(cert_blob->len, &cert_blob_len)) {
          failf(data, "OpenHiTLS: client certificate blob too large");
          return CURLE_SSL_CERTPROBLEM;
        }
        ret = HITLS_CFG_UseCertificateChainBuffer(config, cert_blob->data,
          cert_blob_len, TLS_PARSE_FORMAT_BUTT);
        if(ret != HITLS_SUCCESS) {
          failf(data, "OpenHiTLS: Failed to load client certificate");
          return CURLE_SSL_CERTPROBLEM;
        }
      }
      else {
        /* Use certificate chain loading for PEM files */
        ret = HITLS_CFG_UseCertificateChainFile(config, cert_file);
        if(ret != HITLS_SUCCESS) {
          failf(data,
                "OpenHiTLS: Failed to load client certificate chain "
                "from %s (error code: %d, check file format and password)",
                cert_file, ret);
          return CURLE_SSL_CERTPROBLEM;
        }
        infof(data, " client certificate chain loaded from: %s", cert_file);
      }
      break;

    case HITLS_FILETYPE_PKCS12:
      /* PKCS#12 certificate processing */
      {
        CURLcode result = hitls_pkcs12_load(data, config, cert_blob,
                                            cert_file, key_passwd);
        if(result != CURLE_OK)
          return result;
        pkcs12_done = TRUE;
      }
      break;

    default:
      failf(data, "not supported file type '%s' for certificate", cert_type);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }


    if(!key_file && !key_blob) {
      key_file = cert_file;
      key_blob = cert_blob;
    }
    else
      file_type = hitls_do_file_type(key_type);

    switch(file_type) {
    case HITLS_FILETYPE_PEM:
    case HITLS_FILETYPE_ASN1:
      if(key_blob) {
        uint32_t key_blob_len;
        if(!hitls_size_to_uint32(key_blob->len, &key_blob_len)) {
          failf(data, "OpenHiTLS: private key blob too large");
          return CURLE_SSL_CERTPROBLEM;
        }
        ret = HITLS_CFG_LoadKeyBuffer(config, key_blob->data, key_blob_len,
          (file_type == HITLS_FILETYPE_PEM) ?
          TLS_PARSE_FORMAT_PEM :
          TLS_PARSE_FORMAT_ASN1);
        if(ret != HITLS_SUCCESS) {
          /* From memory blob loading private key (not yet supported) */
          failf(data, "OpenHiTLS: Private key blob loading not yet supported");
          return CURLE_NOT_BUILT_IN;
        }
      }
      else {
        ret = HITLS_CFG_LoadKeyFile(config, key_file,
                                    (file_type == HITLS_FILETYPE_PEM) ?
                                    TLS_PARSE_FORMAT_PEM :
                                    TLS_PARSE_FORMAT_ASN1);
        if(ret != HITLS_SUCCESS) {
          failf(data,
                "OpenHiTLS: Failed to load private key from '%s' type %s "
                "(error code: %d, check file format and password)",
                key_file, key_type ? key_type : "PEM", ret);
          return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        infof(data, " private key loaded from: %s", key_file);
      }
      break;

    case HITLS_FILETYPE_PKCS12:
      if(!pkcs12_done) {
        failf(data, "OpenHiTLS: PKCS#12 private key loading not supported");
        return CURLE_SSL_CERTPROBLEM;
      }
      break;
    default:
      failf(data, "not supported file type for private key");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    /* Verify certificate and key match */
    ret = HITLS_CFG_CheckPrivateKey(config);
    if(ret != HITLS_SUCCESS) {
      failf(data,
            "OpenHiTLS: Private key does not match the certificate public key "
            "(error code: %d)", ret);
      return CURLE_SSL_CERTPROBLEM;
    }
    infof(data, " certificate and private key verified to match");
  }

  return CURLE_OK;
}

/* TLCP encryption certificate and private key configuration */
static CURLcode
hitls_tlcp_enc_cert(struct Curl_easy *data, HITLS_Config *config,
                    char *enc_cert_file, const struct curl_blob *enc_cert_blob,
                    const char *cert_type, char *enc_key_file,
                    const struct curl_blob *enc_key_blob,
                    char *enc_key_passwd)
{
  int ret;
  int file_type = hitls_do_file_type(cert_type);

  /* Set encryption private key password callback if provided */
  if(enc_key_passwd) {
    infof(data, "TLCP encryption key password configured");
    ret = HITLS_CFG_SetDefaultPasswordCbUserdata(config, enc_key_passwd);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set encryption key password userdata "
            "(error code: %d)", ret);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* 1. Configure TLCP encryption certificate */
  if(enc_cert_file || enc_cert_blob) {
    HITLS_CERT_X509 *encCert = NULL;

    switch(file_type) {
    case HITLS_FILETYPE_PEM:
    case HITLS_FILETYPE_ASN1:
      if(enc_cert_blob) {
        uint32_t enc_cert_blob_len;
        if(!hitls_size_to_uint32(enc_cert_blob->len, &enc_cert_blob_len)) {
          failf(data, "OpenHiTLS: TLCP encryption certificate blob too large");
          return CURLE_SSL_CERTPROBLEM;
        }
        /* Load from memory blob */
        encCert = HITLS_CFG_ParseCert(config,
                                     enc_cert_blob->data,
                                     enc_cert_blob_len,
                                     TLS_PARSE_TYPE_BUFF,
                                     TLS_PARSE_FORMAT_BUTT);
        if(!encCert) {
          failf(data, "OpenHiTLS: Failed to parse TLCP encryption certificate "
                "from memory blob");
          return CURLE_SSL_CERTPROBLEM;
        }
        infof(data, " TLCP encryption certificate loaded from memory blob");
      }
      else {
        uint32_t enc_cert_file_len;
        if(!hitls_size_to_uint32(strlen(enc_cert_file) + 1,
                                 &enc_cert_file_len)) {
          failf(data, "OpenHiTLS: TLCP encryption certificate path too long");
          return CURLE_SSL_CERTPROBLEM;
        }
        /* Load from file */
        encCert = HITLS_CFG_ParseCert(config,
                                     (const uint8_t *)enc_cert_file,
                                     enc_cert_file_len,
                                     TLS_PARSE_TYPE_FILE,
                                     TLS_PARSE_FORMAT_BUTT);
        if(!encCert) {
          failf(data, "OpenHiTLS: Failed to parse TLCP encryption certificate "
                "from %s", enc_cert_file);
          return CURLE_SSL_CERTPROBLEM;
        }
        infof(data, " TLCP encryption certificate loaded from: %s",
              enc_cert_file);
      }
      break;

    case HITLS_FILETYPE_PKCS12:
      failf(data, "OpenHiTLS: PKCS#12 certificate loading not yet supported");
      return CURLE_NOT_BUILT_IN;

    default:
      failf(data, "not supported file type '%s' for encryption certificate",
            cert_type);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    /* Set TLCP encryption certificate */
    ret = HITLS_CFG_SetTlcpCertificate(config, encCert, true,
                                      true); /* true = encryption cert */
    HITLS_CFG_FreeCert(config, encCert);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set TLCP encryption certificate "
            "(error code: %d)", ret);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* 2. Configure TLCP encryption private key */
  if(enc_key_file || enc_key_blob) {
    HITLS_CERT_Key *encKey = NULL;

    /* If no key file specified, default to certificate file */
    if(!enc_key_file && !enc_key_blob) {
      enc_key_file = enc_cert_file;
    }

    switch(file_type) {
    case HITLS_FILETYPE_PEM:
    case HITLS_FILETYPE_ASN1:
      if(enc_key_blob) {
        uint32_t enc_key_blob_len;
        if(!hitls_size_to_uint32(enc_key_blob->len, &enc_key_blob_len)) {
          failf(data, "OpenHiTLS: TLCP encryption private key blob too large");
          return CURLE_SSL_CERTPROBLEM;
        }
        /* Load from memory blob */
        encKey = HITLS_CFG_ParseKey(config, enc_key_blob->data,
                   enc_key_blob_len, TLS_PARSE_TYPE_BUFF,
                   (file_type == HITLS_FILETYPE_PEM) ?
                   TLS_PARSE_FORMAT_PEM : TLS_PARSE_FORMAT_ASN1);
        if(!encKey) {
          failf(data, "OpenHiTLS: Failed to load TLCP encryption private key "
                "from memory blob");
          return CURLE_SSL_CERTPROBLEM;
        }
        infof(data, " TLCP encryption private key loaded from memory blob");
      }
      else {
        uint32_t enc_key_file_len;
        if(!hitls_size_to_uint32(strlen(enc_key_file) + 1,
                                 &enc_key_file_len)) {
          failf(data, "OpenHiTLS: TLCP encryption private key path too long");
          return CURLE_SSL_CERTPROBLEM;
        }
        /* Load from file */
        encKey = HITLS_CFG_ParseKey(config, (const uint8_t *)enc_key_file,
                   enc_key_file_len, TLS_PARSE_TYPE_FILE,
                   (file_type == HITLS_FILETYPE_PEM) ?
                   TLS_PARSE_FORMAT_PEM : TLS_PARSE_FORMAT_ASN1);
        if(!encKey) {
          failf(data, "OpenHiTLS: Failed to load TLCP encryption private key "
                "from %s", enc_key_file);
          return CURLE_SSL_CERTPROBLEM;
        }
        infof(data, " TLCP encryption private key loaded from: %s",
              enc_key_file);
      }
      break;

    case HITLS_FILETYPE_PKCS12:
      failf(data, "OpenHiTLS: PKCS#12 private key loading not yet supported");
      return CURLE_NOT_BUILT_IN;

    default:
      failf(data, "not supported file type '%s' for encryption private key",
            cert_type);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    /* Set TLCP encryption private key */
    ret = HITLS_CFG_SetTlcpPrivateKey(config, encKey, true,
                                     true); /* true = encryption key */
    HITLS_CFG_FreeKey(config, encKey);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set TLCP encryption private key "
            "(error code: %d)", ret);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  return CURLE_OK;
}

struct hitls_sigalg_alias {
  const char *name;
  const char *hitls_name;
  uint16_t id;
};

#define HITLS_SIGALG_ALIAS_ID(alias, codepoint) { (alias), NULL, (codepoint) }

static const struct hitls_sigalg_alias hitls_sigalg_aliases[] = {
  { "RSA+SHA1", "rsa_pkcs1_sha1", 0 },
  { "DSA+SHA1", "dsa_sha1", 0 },
  { "ECDSA+SHA1", "ecdsa_sha1", 0 },
  { "ECDSA+SHA224", "ecdsa_sha224", 0 },
  { "RSA+SHA224", "rsa_pkcs1_sha224", 0 },
  { "RSA+SHA256", "rsa_pkcs1_sha256", 0 },
  { "RSA+SHA384", "rsa_pkcs1_sha384", 0 },
  { "RSA+SHA512", "rsa_pkcs1_sha512", 0 },
  { "DSA+SHA224", "dsa_sha224", 0 },
  { "DSA+SHA256", "dsa_sha256", 0 },
  { "DSA+SHA384", "dsa_sha384", 0 },
  { "DSA+SHA512", "dsa_sha512", 0 },
  { "ECDSA+SHA256", "ecdsa_secp256r1_sha256", 0 },
  { "ECDSA+SHA384", "ecdsa_secp384r1_sha384", 0 },
  { "ECDSA+SHA512", "ecdsa_secp521r1_sha512", 0 },
  { "SM2+SM3", "sm2_sm3", 0 },
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_RSA_PKCS1_SHA1",
                        CERT_SIG_SCHEME_RSA_PKCS1_SHA1),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_DSA_SHA1",
                        CERT_SIG_SCHEME_DSA_SHA1),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_ECDSA_SHA1",
                        CERT_SIG_SCHEME_ECDSA_SHA1),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_ECDSA_SHA224",
                        CERT_SIG_SCHEME_ECDSA_SHA224),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_RSA_PKCS1_SHA224",
                        CERT_SIG_SCHEME_RSA_PKCS1_SHA224),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_RSA_PKCS1_SHA256",
                        CERT_SIG_SCHEME_RSA_PKCS1_SHA256),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_RSA_PKCS1_SHA384",
                        CERT_SIG_SCHEME_RSA_PKCS1_SHA384),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_RSA_PKCS1_SHA512",
                        CERT_SIG_SCHEME_RSA_PKCS1_SHA512),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_DSA_SHA224",
                        CERT_SIG_SCHEME_DSA_SHA224),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_DSA_SHA256",
                        CERT_SIG_SCHEME_DSA_SHA256),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_DSA_SHA384",
                        CERT_SIG_SCHEME_DSA_SHA384),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_DSA_SHA512",
                        CERT_SIG_SCHEME_DSA_SHA512),
  { "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
    NULL, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256 },
  { "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384",
    NULL, CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384 },
  { "CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512",
    NULL, CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512 },
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_SM2_SM3",
                        CERT_SIG_SCHEME_SM2_SM3),
  { "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256",
    NULL, CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256 },
  { "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384",
    NULL, CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384 },
  { "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512",
    NULL, CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512 },
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_ED25519", CERT_SIG_SCHEME_ED25519),
  HITLS_SIGALG_ALIAS_ID("CERT_SIG_SCHEME_ED448", CERT_SIG_SCHEME_ED448),
  { "CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256",
    NULL, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256 },
  { "CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384",
    NULL, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384 },
  { "CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512",
    NULL, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512 }
};

#undef HITLS_SIGALG_ALIAS_ID

static bool
hitls_sigalg_name_match(const char *token, size_t token_len, const char *name)
{
  size_t name_len = strlen(name);
  return (token_len == name_len) && curl_strnequal(token, name, token_len);
}

static bool
hitls_sigalg_parse_hex(const char *token, size_t token_len, uint16_t *id)
{
  unsigned long value = 0;
  size_t i;

  if(token_len < 3 || token[0] != '0' ||
     (token[1] != 'x' && token[1] != 'X'))
    return FALSE;

  for(i = 2; i < token_len; ++i) {
    char c = token[i];
    unsigned int v;
    if(c >= '0' && c <= '9')
      v = (unsigned int)(c - '0');
    else if(c >= 'a' && c <= 'f')
      v = (unsigned int)(c - 'a' + 10);
    else if(c >= 'A' && c <= 'F')
      v = (unsigned int)(c - 'A' + 10);
    else
      return FALSE;
    value = (value << 4) | v;
    if(value > 0xffff)
      return FALSE;
  }

  *id = (uint16_t)value;
  return TRUE;
}

static CURLcode
hitls_sigalg_get_by_name(HITLS_Config *config, const char *name, uint16_t *id,
                         bool *found)
{
  int32_t ret = HITLS_CFG_GetSignatureSchemeId(config, name, id);

  if(ret == HITLS_SUCCESS) {
    *found = TRUE;
    return CURLE_OK;
  }

  *found = FALSE;
  return CURLE_OK;
}

static CURLcode
hitls_sigalg_lookup(HITLS_Config *config, const char *token,
                    size_t token_len, uint16_t *id, bool *found)
{
  size_t i;

  *found = FALSE;
  if(hitls_sigalg_parse_hex(token, token_len, id)) {
    *found = TRUE;
    return CURLE_OK;
  }

  for(i = 0; i < CURL_ARRAYSIZE(hitls_sigalg_aliases); ++i) {
    if(hitls_sigalg_name_match(token, token_len,
                               hitls_sigalg_aliases[i].name)) {
      if(hitls_sigalg_aliases[i].hitls_name) {
        return hitls_sigalg_get_by_name(config,
                                        hitls_sigalg_aliases[i].hitls_name,
                                        id, found);
      }

      *id = hitls_sigalg_aliases[i].id;
      *found = TRUE;
      return CURLE_OK;
    }
  }

  {
    char *name = curlx_memdup0(token, token_len);
    CURLcode result;
    if(!name)
      return CURLE_OUT_OF_MEMORY;
    result = hitls_sigalg_get_by_name(config, name, id, found);
    curlx_free(name);
    return result;
  }
}

static CURLcode
hitls_set_signature_algorithms(struct Curl_easy *data,
                               HITLS_Config *config,
                               const char *signature_algorithms)
{
  uint16_t sigalgs[64];
  uint16_t sigalgs_count = 0;
  const char *token = signature_algorithms;
  int32_t ret;

  while(token && *token) {
    const char *end = strchr(token, ':');
    size_t token_len = end ? (size_t)(end - token) : strlen(token);
    uint16_t id;
    bool found;
    CURLcode result;

    if(!token_len || sigalgs_count >= CURL_ARRAYSIZE(sigalgs)) {
      failf(data, "OpenHiTLS: unsupported signature algorithm in '%s'",
            signature_algorithms);
      return CURLE_SSL_CIPHER;
    }
    result = hitls_sigalg_lookup(config, token, token_len, &id, &found);
    if(result != CURLE_OK)
      return result;

    if(!found) {
      failf(data, "OpenHiTLS: unsupported signature algorithm in '%s'",
            signature_algorithms);
      return CURLE_SSL_CIPHER;
    }

    sigalgs[sigalgs_count++] = id;
    if(!end)
      break;
    token = end + 1;
  }

  if(!sigalgs_count)
    return CURLE_OK;

  ret = HITLS_CFG_SetSignature(config, sigalgs, sigalgs_count);
  if(ret != HITLS_SUCCESS) {
    failf(data, "OpenHiTLS: failed setting signature algorithms '%s' "
          "(error: %d)", signature_algorithms, ret);
    return CURLE_SSL_CIPHER;
  }

  infof(data, "OpenHiTLS: signature algorithms: %s", signature_algorithms);
  return CURLE_OK;
}

#ifdef USE_OPENHITLS
/* Validate TLCP certificate configuration */
static CURLcode
validate_tlcp_config(struct Curl_easy *data,
                      struct ssl_config_data *ssl_config)
{
  bool has_enc_cert = (ssl_config->primary.tlcp_enc_cert != NULL ||
                       ssl_config->primary.tlcp_enc_cert_blob != NULL);
  bool has_enc_key = (ssl_config->primary.tlcp_enc_key != NULL ||
                      ssl_config->primary.tlcp_enc_key_blob != NULL);

  /* If any TLCP encryption parameter is configured, both cert and key must
     be present */
  if(has_enc_cert || has_enc_key) {
    if(!has_enc_cert || !has_enc_key) {
      failf(data, "OpenHiTLS: TLCP encryption certificate and private key "
            "must be configured together");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    infof(data, "TLCP encryption certificate configuration validated");
  }

  return CURLE_OK;
}
#endif

static CURLcode
hitls_verifyhost(struct Curl_easy *data, struct connectdata *conn,
                 struct ssl_peer *peer, HITLS_CERT_X509 *server_cert)
{
  CURLcode result = CURLE_OK;
  size_t hostlen;

  (void)conn;

  DEBUGASSERT(peer && peer->origin && peer->origin->hostname && server_cert);

  hostlen = strlen(peer->origin->hostname);

  switch(peer->type) {
  case CURL_SSL_PEER_DNS: {
    int32_t ret;
    uint32_t flags = 0; /* Use default RFC9525 mode */

    /* HITLS_CERT_X509 is typedef void*, cast to HITLS_X509_Cert* */
    HITLS_X509_Cert *cert = (HITLS_X509_Cert *)server_cert;

    ret = HITLS_X509_VerifyHostname(cert, flags, peer->origin->hostname,
                                    (uint32_t)hostlen);

    if(ret == HITLS_PKI_SUCCESS) {
      infof(data, " OpenHiTLS: verified hostname \"%s\"",
            peer->origin->user_hostname);
      result = CURLE_OK;
    }
    else {
      failf(data, "SSL: certificate subject name does not match "
            "target hostname '%s'", peer->origin->user_hostname);
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    break;
  }

  case CURL_SSL_PEER_IPV4:
  case CURL_SSL_PEER_IPV6: {
    /* IP address verification is not supported in current implementation */
    infof(data, " OpenHiTLS: IP address verification is not supported");
    failf(data, "OpenHiTLS: hostname verification for IP addresses is not "
          "implemented");
    result = CURLE_PEER_FAILED_VERIFICATION;
    break;
  }

  default:
    DEBUGASSERT(0);
    failf(data, "unexpected ssl peer type: %u", peer->type);
    result = CURLE_PEER_FAILED_VERIFICATION;
    break;
  }

  return result;
}

static CURLcode
Curl_hitls_setup_x509_store(struct Curl_cfilter *cf, struct Curl_easy *data,
                            HITLS_Config *config)
{
  /* In handshake step2, ClientHello is sent before setting CA store
   * This optimizes performance by avoiding unnecessary certificate loading
   */
  return hitls_populate_ca_store(cf, data, config);
}

static CURLcode hitls_init_ssl(struct hitls_ctx *hctx,
                               struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct ssl_peer *peer,
                               const struct alpn_spec *alpns_requested,
                               void *ssl_user_data)
{
  CURLcode result;

  (void)ssl_user_data;  /* Currently not used */
  (void)cf;  /* Currently not used */

  /* SSL object lifecycle management */
  if(hctx->ssl) {
    HITLS_Free(hctx->ssl);
    hctx->ssl = NULL;
  }

  /* Create SSL context (corresponds to SSL_new) */
  hctx->ssl = HITLS_New(hctx->config);
  if(!hctx->ssl) {
    failf(data, "OpenHiTLS: could not create SSL context");
    return CURLE_OUT_OF_MEMORY;
  }

  /* Note: Application data setting would go here if openHiTLS supported it */

  /* Configure SNI (Server Name Indication) */
  if(peer->sni) {
    int ret = HITLS_SetServerName(hctx->ssl, (uint8_t*)peer->sni,
                                  (uint32_t)strlen(peer->sni));
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set SNI");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Configure ALPN protocols */
  if(alpns_requested && alpns_requested->count > 0) {
    struct alpn_proto_buf proto;
    int ret;
    memset(&proto, 0, sizeof(proto));
    result = Curl_alpn_to_proto_buf(&proto, alpns_requested);
    if(result) {
      failf(data, "OpenHiTLS: Error determining ALPN");
      return CURLE_SSL_CONNECT_ERROR;
    }

    ret = HITLS_SetAlpnProtos(hctx->ssl, proto.data, (uint32_t)proto.len);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set ALPN protocols");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Note: Session resumption and additional ALPN handling would go here */

  return CURLE_OK;
}

static CURLcode
Curl_hitls_ctx_init(struct hitls_ctx *hctx, struct Curl_cfilter *cf,
                    struct Curl_easy *data, struct ssl_peer *peer,
                    const struct alpn_spec *alpns_requested,
                    void *ssl_user_data)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const bool verifypeer = conn_config->verifypeer;
  CURLcode result = CURLE_OK;

  (void)ssl_user_data;   /* Currently not used */

  /* Create config if not already done */
  if(!hctx->config) {
    hitls_protocol_type_t protocol_type;

    /* Validate version compatibility before creating config */
    if(conn_config->version || conn_config->version_max) {
      result = hitls_validate_version_compatibility(conn_config->version,
                                                   conn_config->version_max);
      if(result != CURLE_OK) {
        failf(data, "OpenHiTLS: Incompatible TLS version configuration");
        return result;
      }
    }

    /* Determine protocol type from version configuration */
    protocol_type = get_protocol_type_from_version(conn_config->version,
                                                  conn_config->version_max);

    /* Create appropriate config based on protocol type */
    switch(protocol_type) {
    case HITLS_PROTOCOL_TLCP:
      /* TLCP protocol: use dedicated config, version already included */
      hctx->config = HITLS_CFG_NewTLCPConfig();
      if(!hctx->config) {
        failf(data, "OpenHiTLS: Failed to create TLCP config");
        return CURLE_OUT_OF_MEMORY;
      }
      /* TLCP config already contains correct version, no need to set */
      break;

    case HITLS_PROTOCOL_TLS:
    default:
      /* Standard TLS protocol: need to manually set version */
      hctx->config = HITLS_CFG_NewTLSConfig();
      if(!hctx->config) {
        failf(data, "OpenHiTLS: Failed to create TLS config");
        return CURLE_OUT_OF_MEMORY;
      }

      /* Configure TLS version settings for TLS protocol only */
      if(conn_config->version || conn_config->version_max) {
        result = hitls_set_tls_version(hctx->config,
                                       conn_config->version,
                                       conn_config->version_max);
        if(result != CURLE_OK) {
          failf(data, "OpenHiTLS: Failed to set TLS version");
          return result;
        }
      }
      break;
    }
  }

  /* Configure cipher suites */
  if(conn_config->cipher_list || conn_config->cipher_list13) {
    result = hitls_set_selected_ciphers(data, hctx->config,
                                       conn_config->cipher_list,
                                       conn_config->cipher_list13);
    if(result != CURLE_OK) {
      failf(data, "OpenHiTLS: Failed to set cipher suites");
      return result;
    }
  }

  /* Configure curves/groups if specified (--curves) */
  if(conn_config->curves) {
    uint32_t len = (uint32_t)strlen(conn_config->curves);
    int32_t ret = HITLS_CFG_SetGroupList(hctx->config,
                                         conn_config->curves, len);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set curves list '%s' (error: %d)",
            conn_config->curves, ret);
      return CURLE_SSL_CIPHER;
    }
    infof(data, "OpenHiTLS: Curve/Group selection: %s", conn_config->curves);
  }

  if(conn_config->signature_algorithms) {
    result = hitls_set_signature_algorithms(data, hctx->config,
                                            conn_config->signature_algorithms);
    if(result != CURLE_OK)
      return result;
  }

#ifdef USE_OPENHITLS
  /* Validate TLCP configuration before proceeding */
  result = validate_tlcp_config(data, ssl_config);
  if(result != CURLE_OK)
    return result;
#endif

  /* Load client certificate if provided */
  if(ssl_config->primary.clientcert || ssl_config->primary.cert_blob) {
    result = hitls_client_cert(data, hctx->config,
                               ssl_config->primary.clientcert,
                               ssl_config->primary.cert_blob,
                               ssl_config->primary.cert_type,
                               ssl_config->primary.key,
                               ssl_config->primary.key_blob,
                               ssl_config->primary.key_type,
                               ssl_config->primary.key_passwd);
    if(result != CURLE_OK)
      return result;
  }

#ifdef USE_OPENHITLS
  /* Load TLCP encryption certificate if provided */
  if(ssl_config->primary.tlcp_enc_cert ||
     ssl_config->primary.tlcp_enc_cert_blob) {
    result = hitls_tlcp_enc_cert(data, hctx->config,
                                ssl_config->primary.tlcp_enc_cert,
                                ssl_config->primary.tlcp_enc_cert_blob,
                                ssl_config->primary.cert_type,
                                ssl_config->primary.tlcp_enc_key,
                                ssl_config->primary.tlcp_enc_key_blob,
                                ssl_config->primary.tlcp_enc_key_passwd);
    if(result != CURLE_OK)
      return result;
  }
#endif

  HITLS_CFG_SetVerifyNoneSupport(hctx->config, !verifypeer);
  HITLS_CFG_SetClientVerifySupport(hctx->config, verifypeer);

  /* Enable keylog callback if SSLKEYLOGFILE is set */
  if(Curl_tls_keylog_enabled()) {
    int ret = HITLS_CFG_SetKeyLogCb(hctx->config, hitls_keylog_callback);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set keylog callback");
      return CURLE_SSL_CONNECT_ERROR;
    }
    CURL_TRC_CF(data, cf, "OpenHiTLS: Keylog callback enabled");
  }

  if(!hctx->ca_store_setup) {
    result = Curl_hitls_setup_x509_store(cf, data, hctx->config);
    if(result)
      return result;
    hctx->ca_store_setup = TRUE;
  }

  if(data->set.ssl.fsslctx) {
    Curl_set_in_callback(data, TRUE);
    result = (*data->set.ssl.fsslctx)(data, hctx->config,
                                      data->set.ssl.fsslctxp);
    Curl_set_in_callback(data, FALSE);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }
  /* Initialize SSL object with all configurations */
  return hitls_init_ssl(hctx, cf, data, peer, alpns_requested, ssl_user_data);
}

/* Step 1: SSL context initialization */
static CURLcode
hitls_connect_step1(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *hctx = (struct hitls_ctx *)connssl->backend;
  int ret;
  CURLcode result;

  DEBUGASSERT(ssl_connect_1 == connssl->connecting_state);
  DEBUGASSERT(hctx);

  /* Initialize SSL context and configuration */
  result = Curl_hitls_ctx_init(hctx, cf, data, &connssl->peer,
                               connssl->alpn, cf);
  if(result)
    return result;

  if(!hctx->uio) {
    /* Create custom UIO method */
    if(!hctx->uio_method) {
      hctx->uio_method = curl_create_uio_method();
      if(!hctx->uio_method) {
        failf(data, "OpenHiTLS: Failed to create custom UIO method");
        return CURLE_OUT_OF_MEMORY;
      }
    }

    /* Create UIO with our custom method */
    hctx->uio = BSL_UIO_New(hctx->uio_method);
    if(!hctx->uio) {
      failf(data, "OpenHiTLS: Failed to create custom UIO");
      return CURLE_OUT_OF_MEMORY;
    }

    /* Set the connection filter as user data for the UIO */
    ret = BSL_UIO_SetUserData(hctx->uio, cf);
    if(ret != BSL_SUCCESS) {
      BSL_UIO_Free(hctx->uio);
      hctx->uio = NULL;
      failf(data, "OpenHiTLS: Failed to set UIO user data: %d", ret);
      return CURLE_SSL_CONNECT_ERROR;
    }

    ret = HITLS_SetUio(hctx->ssl, hctx->uio);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set UIO: %d", ret);
      return CURLE_SSL_CONNECT_ERROR;
    }

    CURL_TRC_CF(data, cf, "OpenHiTLS: Custom UIO created and configured");
  }

  if(connssl->alpn && (connssl->state != ssl_connection_deferred)) {
    struct alpn_proto_buf proto;
    memset(&proto, 0, sizeof(proto));
    Curl_alpn_to_proto_str(&proto, connssl->alpn);
    infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
  }

  /* Move to next step */
  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

/* Step 2: SSL handshake execution */
static CURLcode
hitls_connect_step2(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  int ret;
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *hctx = (struct hitls_ctx *)connssl->backend;

  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state);
  DEBUGASSERT(hctx);

  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  /* Set context before calling HITLS API that may trigger logs */
  HITLS_SET_CONTEXT(data, cf);

  /* Execute SSL handshake - may trigger openHiTLS logs */
  ret = HITLS_Connect(hctx->ssl);

  /* Restore previous context */
  HITLS_RESTORE_CONTEXT();

  /* X509 store is set before HITLS_New(). Keep this as a fallback in case
   * an alternate initialization path reaches the handshake without it. */
  if(!hctx->ca_store_setup) {
    CURLcode result = Curl_hitls_setup_x509_store(cf, data, hctx->config);
    if(result)
      return result;
    hctx->ca_store_setup = TRUE;
  }

  if(ret == HITLS_SUCCESS) {
    /* Handshake completed successfully, move to verification step */
    connssl->connecting_state = ssl_connect_3;

    if(connssl->alpn) {
      uint8_t *selected_proto = NULL;
      uint32_t selected_len = 0;
      int alpn_ret = HITLS_GetSelectedAlpnProto(hctx->ssl, &selected_proto,
                                                &selected_len);

      if(alpn_ret == HITLS_SUCCESS) {
        CURLcode alpn_result = Curl_alpn_set_negotiated(cf, data, connssl,
                                                        selected_proto,
                                                        selected_len);
        if(alpn_result != CURLE_OK) {
          return alpn_result;
        }
      }
    }

    return CURLE_OK;
  }
  else if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
          ret == HITLS_REC_NORMAL_IO_BUSY) {
    /* Need to continue handshake */
    if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
      connssl->io_need = CURL_SSL_IO_NEED_RECV;
    }
    else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
    }
    return CURLE_AGAIN;
  }
  else {
    /* Handshake error */
    int hitls_error = HITLS_GetError(hctx->ssl, ret);
    failf(data, "OpenHiTLS: SSL handshake failed: %d (error: %d)",
          ret, hitls_error);
    return hitls_translate_error(ret);
  }
}

/* Server certificate verification */
static CURLcode
Curl_hitls_check_peer_cert(struct Curl_cfilter *cf, struct Curl_easy *data,
                           struct hitls_ctx *hctx, struct ssl_peer *peer)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  HITLS_CERT_X509 *server_cert = NULL;
  CURLcode result = CURLE_OK;

  if(data->set.ssl.certinfo)
    (void)hitls_certchain(cf, data, hctx);

  /* Get server certificate */
  server_cert = HITLS_GetPeerCertificate(hctx->ssl);
  if(!server_cert) {
    if(conn_config->verifypeer) {
      failf(data, "OpenHiTLS: No server certificate received");
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    return CURLE_OK;
  }

  infof(data, "%s certificate:",
    Curl_ssl_cf_is_proxy(cf) ? "Proxy" : "Server");

  /* Basic certificate verification */
  if(conn_config->verifypeer) {
    HITLS_ERROR verify_result;
    int ret = HITLS_GetVerifyResult(hctx->ssl, &verify_result);
    if(ret != HITLS_SUCCESS || verify_result != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Certificate verification failed: %u",
            verify_result);
      result = CURLE_PEER_FAILED_VERIFICATION;
      goto cleanup;
    }
  }

  /* Hostname verification (future implementation) */
  if(conn_config->verifyhost) {
    result = hitls_verifyhost(data, cf->conn, peer, server_cert);
    if(result)
      goto cleanup;
  }

  result = hitls_check_pinned_pubkey(cf, data, server_cert);
  if(result)
    goto cleanup;

cleanup:
  if(server_cert) {
    HITLS_CFG_FreeCert(hctx->config, server_cert);
  }
  return result;
}

/* Step 3: Certificate verification */
static CURLcode
hitls_connect_step3(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *hctx = (struct hitls_ctx *)connssl->backend;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  /* Execute server certificate verification */
  result = Curl_hitls_check_peer_cert(cf, data, hctx, &connssl->peer);
  if(result) {
    /* Session cache cleanup on verification failure (future implementation) */
    return result;
  }

  return CURLE_OK;
}



static CURLcode
hitls_connect(struct Curl_cfilter *cf, struct Curl_easy *data,
              bool *done)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;

  /* Check if connection is already complete */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  /* Step 1: SSL context initialization */
  if(ssl_connect_1 == connssl->connecting_state) {
    CURL_TRC_CF(data, cf, "hitls_connect, step1");
    result = hitls_connect_step1(cf, data);
    if(result)
      goto out;
  }

  /* Step 2: SSL handshake */
  if(ssl_connect_2 == connssl->connecting_state) {
    CURL_TRC_CF(data, cf, "hitls_connect, step2");
    result = hitls_connect_step2(cf, data);
    if(result)
      goto out;
  }

  /* Step 3: Certificate verification */
  if(ssl_connect_3 == connssl->connecting_state) {
    CURL_TRC_CF(data, cf, "hitls_connect, step3");
    result = hitls_connect_step3(cf, data);
    if(result)
      goto out;
    connssl->connecting_state = ssl_connect_done;
  }

  /* Connection complete */
  if(ssl_connect_done == connssl->connecting_state) {
    CURL_TRC_CF(data, cf, "hitls_connect, done");
    connssl->state = ssl_connection_complete;
    infof(data, "OpenHiTLS: SSL connection completed");
  }

out:
  if(result == CURLE_AGAIN) {
    *done = FALSE;
    return CURLE_OK;
  }
  *done = ((connssl->state == ssl_connection_complete) ||
           (connssl->state == ssl_connection_deferred));
  return result;
}

static bool
hitls_data_pending(struct Curl_cfilter *cf, const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  (void)data;
  return connssl->input_pending;
}

static CURLcode
hitls_send(struct Curl_cfilter *cf, struct Curl_easy *data,
           const void *mem, size_t len, size_t *written)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;
  int ret;
  uint32_t writelen = 0;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(backend && backend->ssl);

  *written = 0;

  /* Set context before calling HITLS API */
  HITLS_SET_CONTEXT(data, cf);

  /* Write encrypted data - may trigger openHiTLS logs */
  ret = HITLS_Write(backend->ssl, (const uint8_t *)mem,
                    (uint32_t)len, &writelen);

  /* Restore context */
  HITLS_RESTORE_CONTEXT();

  if(ret == HITLS_SUCCESS) {
    *written = (size_t)writelen;
  }
  else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
    /* I/O operation would block */
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
  }
  else if(ret == HITLS_WANT_READ) {
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
  }
  else if(ret == HITLS_WANT_WRITE) {
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
  }
  else {
    /* Error occurred */
    int hitls_error = HITLS_GetError(backend->ssl, ret);
    failf(data, "OpenHiTLS: SSL write failed: %d (error: %d)",
          ret, hitls_error);
    result = hitls_translate_error(ret);
  }

  return result;
}


static CURLcode
hitls_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
           char *buf, size_t buffersize, size_t *nread)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;
  int ret;
  uint32_t readlen = 0;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(backend && backend->ssl);

  *nread = 0;

  /* Set context before calling HITLS API */
  HITLS_SET_CONTEXT(data, cf);

  /* Read decrypted data - may trigger openHiTLS logs */
  ret = HITLS_Read(backend->ssl, (uint8_t *)buf,
                   (uint32_t)buffersize, &readlen);

  /* Restore context */
  HITLS_RESTORE_CONTEXT();

  if(ret == HITLS_SUCCESS) {
    *nread = (size_t)readlen;
  }
  else if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
    /* No data available right now - not an error in non-blocking mode */
    result = CURLE_AGAIN;
  }
  else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
    /* I/O operation would block */
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
  }
  else if(ret == HITLS_WANT_READ) {
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
  }
  else if(ret == HITLS_WANT_WRITE) {
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
  }
  else if(ret == HITLS_CM_LINK_CLOSED ||
          ret == HITLS_REC_NORMAL_IO_EOF) {
    *nread = 0;
  }
  else {
    /* Error occurred */
    int hitls_error = HITLS_GetError(backend->ssl, ret);
    failf(data, "OpenHiTLS: SSL read failed: %d (error: %d)",
          ret, hitls_error);
    result = hitls_translate_error(ret);
  }

  if((!result && !*nread) || (result == CURLE_AGAIN)) {
    connssl->input_pending = FALSE;
  }

  CURL_TRC_CF(data, cf, "hitls_recv(len=%zu) -> %d, %zu (input_pending=%d)",
              buffersize, (int)result, *nread,
              connssl->input_pending ? 1 : 0);

  return result;
}

static CURLcode
hitls_get_channel_binding(struct Curl_easy *data, int sockindex,
                          struct dynbuf *binding)
{
  (void)data;
  (void)sockindex;
  (void)binding;
  return CURLE_NOT_BUILT_IN;
}

static size_t
hitls_version(char *buffer, size_t size)
{
  return curl_msnprintf(buffer, size, "OpenHiTLS");
}

static CURLcode
hitls_random(struct Curl_easy *data, unsigned char *entropy, size_t length)
{
  (void)data;
  (void)CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
  if(CRYPT_EAL_RandbytesEx(NULL, entropy, (uint32_t)length) == HITLS_SUCCESS) {
    return CURLE_OK;
  }
  return CURLE_FAILED_INIT;
}

static CURLcode
hitls_sha256sum(const unsigned char *input, size_t inputlen,
                unsigned char *sha256sum, size_t sha256sumlen)
{
  uint32_t outlen = (uint32_t)sha256sumlen;
  int ret;

  /* Verify output buffer size */
  if(sha256sumlen < CURL_SHA256_DIGEST_LENGTH) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  /* Calculate SHA256 using openHiTLS one-shot API */
  ret = CRYPT_EAL_Md(CRYPT_MD_SHA256, input, (uint32_t)inputlen,
                     sha256sum, &outlen);

  if(ret != CRYPT_SUCCESS) {
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Verify we got the expected digest length */
  if(outlen != CURL_SHA256_DIGEST_LENGTH) {
    return CURLE_SSL_CONNECT_ERROR;
  }

  return CURLE_OK;
}

static void *
hitls_get_internals(struct ssl_connect_data *connssl, CURLINFO info)
{
  struct hitls_ctx *hctx = (struct hitls_ctx *)connssl->backend;
  DEBUGASSERT(hctx);
  /* Return config for TLS_SESSION (legacy), SSL context for TLS_SSL_PTR */
  return info == CURLINFO_TLS_SESSION ?
    (void *)hctx->config : (void *)hctx->ssl;
}

const struct Curl_ssl Curl_ssl_openhitls = {
  { CURLSSLBACKEND_NONE, "openhitls" }, /* info */

  SSLSUPP_CA_PATH |
  SSLSUPP_CERTINFO |
  SSLSUPP_SSL_CTX |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_PINNEDPUBKEY |
  SSLSUPP_TLS13_CIPHERSUITES |
  SSLSUPP_SIGNATURE_ALGORITHMS |
  SSLSUPP_SSL_EC_CURVES |
  SSLSUPP_CIPHER_LIST |
  SSLSUPP_CRLFILE |
  SSLSUPP_CAINFO_BLOB,

  sizeof(struct hitls_ctx),

  hitls_init,                /* init */
  hitls_cleanup,             /* cleanup */
  hitls_version,             /* version */
  hitls_shutdown,            /* shutdown */
  hitls_data_pending,        /* data_pending */
  hitls_random,              /* random */
  NULL,                      /* cert_status_request */
  hitls_connect,             /* connect */
  Curl_ssl_adjust_pollset,   /* adjust_pollset */
  hitls_get_internals,       /* get_internals */
  hitls_close,               /* close_one */
  hitls_close_all,           /* close_all */
  NULL,                      /* set_engine */
  NULL,                      /* set_engine_default */
  NULL,                      /* engines_list */
  hitls_sha256sum,           /* sha256sum */
  hitls_recv,                /* recv decrypted data */
  hitls_send,                /* send data to encrypt */
  hitls_get_channel_binding  /* get_channel_binding */
};

#endif /* USE_OPENHITLS */
