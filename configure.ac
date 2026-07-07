AC_INIT([strongswan-qkd-plugin], [1.0.0])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_PROG_AR
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT([disable-static])

# ── StrongSwan headers ────────────────────────────────────────────────────────
AC_ARG_WITH([strongswan-headers],
    [AS_HELP_STRING([--with-strongswan-headers=DIR],
                    [path to StrongSwan development headers])],
    [strongswan_headers="$withval"],
    [strongswan_headers="/usr/include/strongswan"])
AC_SUBST([strongswan_headers])

AC_CHECK_FILE([$strongswan_headers/library.h],
    [],
    [AC_MSG_ERROR([StrongSwan headers not found at $strongswan_headers. \
Pass --with-strongswan-headers=DIR to specify the correct path.])])

# ── Plugin installation directory ─────────────────────────────────────────────
AC_ARG_WITH([plugin-dir],
    [AS_HELP_STRING([--with-plugin-dir=DIR], [where to install the plugins])],
    [plugindir="$withval"],
    [plugindir="/usr/lib/ipsec/plugins"])
AC_SUBST([plugindir])

# ── QKD ETSI API library ──────────────────────────────────────────────────────
AC_ARG_WITH([qkd-etsi-api],
    [AS_HELP_STRING([--with-qkd-etsi-api=DIR],
                    [prefix where libqkd-etsi-api is installed])],
    [qkd_etsi_api="$withval"],
    [qkd_etsi_api="/usr/local"])
AC_SUBST([qkd_etsi_api])

QKD_ETSI_API_CFLAGS="-I${qkd_etsi_api}/include"
QKD_ETSI_API_LIBS="-L${qkd_etsi_api}/lib -lqkd-etsi-api"
AC_SUBST([QKD_ETSI_API_CFLAGS])
AC_SUBST([QKD_ETSI_API_LIBS])

# Verify the ETSI 014 header is reachable
saved_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS $QKD_ETSI_API_CFLAGS"
AC_CHECK_HEADER([qkd-etsi-api/api.h],
    [],
    [AC_MSG_WARN([ETSI 014 API header not found — check --with-qkd-etsi-api])])
CFLAGS=$saved_CFLAGS

# ── ETSI API version ──────────────────────────────────────────────────────────
# Only ETSI GS QKD 014 (REST JSON) is supported.
AC_DEFINE([ETSI_014_API], [1], [Using ETSI GS QKD 014 API])

# ── QKD initiation mode ───────────────────────────────────────────────────────
# Alice (IKE initiator) fetches the key and sends key_ID to Bob.
# Bob (IKE responder) uses the received key_ID to fetch the same key.
AC_DEFINE([QKD_CLIENT_INITIATED], [1], [Client-initiated QKD mode])

# ── uuid (required by the adapter for UUID parsing) ──────────────────────────
AC_SEARCH_LIBS([uuid_parse], [uuid], [],
    [AC_MSG_ERROR([libuuid not found])])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/qkd/Makefile
])
AC_OUTPUT

echo
echo "StrongSwan QKD plugin build configuration:"
echo "  StrongSwan headers : ${strongswan_headers}"
echo "  Plugin directory   : ${plugindir}"
echo "  ETSI API prefix    : ${qkd_etsi_api}"
echo "  ETSI API version   : 014 (ETSI GS QKD 014, fixed)"
  echo "  Initiation mode    : client (Alice fetches, sends key_ID to Bob, fixed)"
