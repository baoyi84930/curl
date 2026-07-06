#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************

AC_DEFUN([CURL_WITH_OPENHITLS], [
dnl ----------------------------------------------------
dnl check for openHiTLS
dnl ----------------------------------------------------

if test "x$OPT_OPENHITLS" != xno; then
  _cppflags=$CPPFLAGS
  _ldflags=$LDFLAGS
  _ldflagspc=$LDFLAGSPC

  ssl_msg=

  if test X"$OPT_OPENHITLS" != Xno; then

    if test "$OPT_OPENHITLS" = "yes"; then
      OPT_OPENHITLS=""
    fi

    addld=""
    addlib="-lhitls_tls -lhitls_pki -lhitls_crypto -lhitls_bsl"
    addcflags=""
    dnl use system defaults if user does not supply a path
    if test -n "$OPT_OPENHITLS"; then
      addld=-L$OPT_OPENHITLS/lib$libsuff
      addcflags="-I$OPT_OPENHITLS/include/hitls -I$OPT_OPENHITLS/include/hitls/tls -I$OPT_OPENHITLS/include/hitls/pki -I$OPT_OPENHITLS/include/hitls/crypto -I$OPT_OPENHITLS/include/hitls/bsl"
      openhitlslibpath=$OPT_OPENHITLS/lib$libsuff
    fi

    if test "$curl_cv_apple" = 'yes'; then
      addlib="$addlib -framework Security -framework CoreFoundation"
    else
      addlib="$addlib -lm"
    fi

    if test "x$USE_OPENHITLS" != "xyes"; then

      LDFLAGS="$LDFLAGS $addld"
      LDFLAGSPC="$LDFLAGSPC $addld"
      AC_MSG_NOTICE([Add $addld to LDFLAGS])
      if test "$addcflags" != "-I/usr/include"; then
        CPPFLAGS="$CPPFLAGS $addcflags"
        AC_MSG_NOTICE([Add $addcflags to CPPFLAGS])
      fi

      my_ac_save_LIBS="$LIBS"
      LIBS="$addlib $LIBS"
      AC_MSG_NOTICE([Add $addlib to LIBS])

      openhitls_version_ok=no
      AC_MSG_CHECKING([for openHiTLS >= 0.4.0])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          #include <bsl/bsl_version.h>
          #if OPENHITLS_VERSION_I < 0x00400000ULL
          #error openHiTLS 0.4.0 or later required
          #endif
        ]],[[
          return 0;
        ]])
      ],[
        AC_MSG_RESULT(yes)
        openhitls_version_ok=yes
      ],
      [
        AC_MSG_RESULT(no)
        CPPFLAGS=$_cppflags
        LDFLAGS=$_ldflags
        LDFLAGSPC=$_ldflagspc
        openhitlslibpath=""
      ])

      if test "x$openhitls_version_ok" = "xyes"; then
        AC_MSG_CHECKING([for HITLS_New in openHiTLS])
        AC_LINK_IFELSE([
          AC_LANG_PROGRAM([[
            #include <tls/hitls.h>
            #include <tls/hitls_config.h>
            #include <bsl/bsl_version.h>
            #if OPENHITLS_VERSION_I < 0x00400000ULL
            #error openHiTLS 0.4.0 or later required
            #endif
          ]],[[
            HITLS_Config *config = HITLS_CFG_NewTLSConfig();
            HITLS_Ctx *ctx = HITLS_New(config);
            if(ctx) HITLS_Free(ctx);
            if(config) HITLS_CFG_FreeConfig(config);
            return 0;
          ]])
        ],[
          AC_MSG_RESULT(yes)
          AC_DEFINE(USE_OPENHITLS, 1, [if openHiTLS is enabled])
          OPENHITLS_ENABLED=1
          USE_OPENHITLS="yes"
          ssl_msg="openHiTLS"
          test openhitls != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
        ],
        [
          AC_MSG_RESULT(no)
          CPPFLAGS=$_cppflags
          LDFLAGS=$_ldflags
          LDFLAGSPC=$_ldflagspc
          openhitlslibpath=""
        ])
      else
        AC_MSG_NOTICE([openHiTLS version too old])
      fi
      LIBS="$my_ac_save_LIBS"
    fi

    if test "x$USE_OPENHITLS" = "xyes"; then
      AC_MSG_NOTICE([detected openHiTLS])
      check_for_ca_bundle=1

      LIBS="$addlib $LIBS"

      dnl Check for essential openHiTLS functions
      AC_CHECK_FUNCS([HITLS_Connect \
                      HITLS_Accept \
                      HITLS_Read \
                      HITLS_Write \
                      HITLS_GetSelectedAlpnProto \
                      HITLS_SetAlpnProtos \
                      HITLS_CFG_LoadCertFile \
                      HITLS_CFG_LoadKeyFile \
                      HITLS_CFG_GetSignatureSchemeId \
                      HITLS_CFG_ParseCAList])

      if test -n "$openhitlslibpath"; then
        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl CURL_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$openhitlslibpath"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $openhitlslibpath to CURL_LIBRARY_PATH])
        fi
      fi
    else
      AC_MSG_ERROR([--with-openhitls but openHiTLS was not found or doesn't work])
    fi

  fi dnl openHiTLS not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi

])
